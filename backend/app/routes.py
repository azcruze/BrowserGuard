import csv
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from io import BytesIO, StringIO

from flask import Blueprint, current_app, jsonify, request, send_file
from sqlalchemy import String, cast, or_, text
from sqlalchemy.exc import SQLAlchemyError

from app import db
from app.analyzers import ManifestError, analyze_manifest
from app.analyzers.manifest import parse_manifest
from app.analyzers.manifest import PERMISSION_CATALOG
from app.analyzers.uploads import read_uploaded_manifest
from app.models import AuditEvent, Extension, SecurityReport, Setting
from app.reports import create_comparison_report, create_report
from app.benchmark import SECTOR_PERMISSION_HINTS

api = Blueprint("api", __name__)

def _record(action, extension_id=None, **detail):
    db.session.add(AuditEvent(
        extension_id=extension_id,
        action=action,
        detail=detail,
        category=action.split("_", 1)[0],
        severity=str(detail.get("risk_level", "info")).lower(),
        result="success",
        description=detail.get("description", action.replace("_", " ").capitalize()),
        is_audit=True,
    ))


def _thresholds():
    setting = db.session.get(Setting, "risk_thresholds")
    return setting.value if setting else {"low": 24, "moderate": 49, "high": 74}


def _risk_weights():
    setting = db.session.get(Setting, "risk_weights")
    return setting.value if setting else {"permission_sensitivity": 45, "host_scope": 25, "permission_combinations": 20, "purpose_alignment": 10}


def _permission_weights():
    setting = db.session.get(Setting, "permission_weights")
    return setting.value if setting else {}


def _upload_restrictions():
    setting = db.session.get(Setting, "upload_restrictions")
    return setting.value if setting else {
        "upload_limit_mb": 16, "manifest_limit_mb": 2,
        "zip_entry_limit": 2000, "zip_expanded_size_mb": 16,
    }


def _report_preferences():
    setting = db.session.get(Setting, "report_preferences")
    return setting.value if setting else {"include_manifest_evidence": True, "format": "pdf"}


def _analysis_settings():
    setting = db.session.get(Setting, "analysis_settings")
    return setting.value if setting else {"purpose_matching": "keyword_heuristic", "run_extension_code": False}


def _extension_query():
    query = Extension.query
    search = request.args.get("search", "").strip()
    risk = request.args.get("risk", "").lower()
    sector = request.args.get("sector", "").strip()
    if search:
        term = f"%{search[:100]}%"
        query = query.filter(or_(
            Extension.name.ilike(term),
            Extension.description.ilike(term),
            Extension.original_filename.ilike(term),
            cast(Extension.manifest, String).ilike(term),
        ))
    if risk in {"low", "moderate", "high", "critical"}:
        query = query.filter_by(risk_level=risk)
    if sector:
        query = query.filter_by(sector=sector[:80])
    publisher = request.args.get("publisher", "").strip()
    if publisher:
        query = query.filter(Extension.publisher.ilike(f"%{publisher[:100]}%"))
    benchmark = request.args.get("benchmark")
    if benchmark in {"true", "false"}:
        query = query.filter_by(is_benchmark=benchmark == "true")
    return query


@api.get("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        counts = {
            "extensions": Extension.query.count(),
            "benchmark_extensions": Extension.query.filter_by(is_benchmark=True).count(),
            "user_extensions": Extension.query.filter_by(is_benchmark=False).count(),
            "activity_events": AuditEvent.query.count(),
            "audit_events": AuditEvent.query.filter_by(is_audit=True).count(),
            "reports": SecurityReport.query.count(),
        }
    except SQLAlchemyError as error:
        db.session.rollback()
        current_app.logger.exception("BrowserGuard health check could not reach SQLite")
        return jsonify({
            "status": "degraded",
            "service": "BrowserGuard API",
            "database": {"status": "disconnected", "error": error.__class__.__name__},
            "database_counts": {},
            "api_version": "1.1.0",
        }), 503
    return jsonify({
        "status": "ok",
        "service": "BrowserGuard API",
        "database": {"status": "connected"},
        "database_counts": counts,
        "api_version": "1.1.0",
    })


@api.post("/analyze")
@api.post("/extensions")
def analyze_upload():
    upload = request.files.get("file")
    if upload is None:
        return jsonify({"error": "Choose a manifest.json file or ZIP archive."}), 400
    restrictions = _upload_restrictions()
    content = upload.stream.read(restrictions["upload_limit_mb"] * 1024 * 1024 + 1)
    if not content:
        return jsonify({"error": "The uploaded file is empty."}), 400
    try:
        parsed, safe_filename = read_uploaded_manifest(upload.filename, content, restrictions)
    except ManifestError as error:
        return jsonify({"error": str(error)}), 400
    purpose = request.form.get("purpose", "").strip() or parsed["description"]
    sector = request.form.get("sector", "Unspecified").strip() or "Unspecified"
    if len(purpose) > 2000:
        return jsonify({"error": "Purpose must be 2,000 characters or fewer."}), 400
    if len(sector) > 80:
        return jsonify({"error": "Sector must be 80 characters or fewer."}), 400
    analysis_purpose = purpose if _analysis_settings().get("purpose_matching") != "disabled" else ""
    result = analyze_manifest(parsed, analysis_purpose, _thresholds(), _risk_weights(), _permission_weights())
    extension = Extension(
        name=parsed["name"], version=parsed["version"], manifest_version=parsed["manifest_version"],
        description=parsed["description"], original_filename=safe_filename,
        sha256=hashlib.sha256(content).hexdigest(), purpose=purpose, sector=sector,
        extension_key=f"BG-UPLOAD-{uuid.uuid4().hex[:12].upper()}",
        publisher=request.form.get("publisher", "").strip()[:200] or "User upload",
        is_benchmark=False,
        manifest=parsed["raw"], permissions=result["permissions"],
        permission_details=result["permission_details"], findings=result["findings"],
        combinations=result["combinations"], purpose_findings=result["purpose_findings"],
        privacy_findings=result["privacy_findings"], score_breakdown=result["score_breakdown"],
        risk_score=result["risk_score"], risk_level=result["risk_level"],
        requires_review=result["requires_review"],
        privacy_exposure_score=result["privacy_exposure_score"],
        purpose_alignment_score=result["purpose_alignment_score"],
    )
    db.session.add(extension)
    db.session.flush()
    _record("manifest_analyzed", extension.id, name=extension.name, risk_score=extension.risk_score, risk_level=extension.risk_level)
    db.session.commit()
    return jsonify(extension.to_dict()), 201


@api.get("/overview")
def overview():
    time_range = request.args.get("range", "7d")
    if time_range not in {"24h", "7d", "30d"}:
        return jsonify({"error": "range must be 24h, 7d, or 30d."}), 400
    extensions = Extension.query.order_by(Extension.analyzed_at.desc()).all()
    counts = {level: sum(item.risk_level == level for item in extensions) for level in ("critical", "high", "moderate", "low")}
    anomaly_count = sum(len(item.findings) + len(item.combinations) for item in extensions)
    critical_findings = sum(
        len(item.findings) + len(item.combinations)
        for item in extensions if item.risk_level == "critical"
    )
    high_risk_findings = sum(
        len(item.findings) + len(item.combinations)
        for item in extensions if item.risk_level == "high"
    )
    privacy_scores = [
        item.privacy_exposure_score if item.privacy_exposure_score is not None else item.risk_score
        for item in extensions
    ]
    permission_counts = {}
    for extension in extensions:
        for detail in extension.permission_details:
            permission = detail["name"]
            entry = permission_counts.setdefault(permission, {"name": permission, "count": 0, "category": detail["category"]})
            entry["count"] += 1
    frequent = sorted(permission_counts.values(), key=lambda item: (-item["count"], item["name"]))[:8]
    return jsonify({
        "extensions_analysed": len(extensions),
        "risk_counts": counts,
        "permission_anomalies": anomaly_count,
        "privacy_exposure_index": round(sum(privacy_scores) / len(privacy_scores)) if privacy_scores else 0,
        "critical_findings": critical_findings,
        "high_risk_findings": high_risk_findings,
        "reports_generated": SecurityReport.query.count(),
        "extensions_requiring_review": sum(item.requires_review for item in extensions),
        "risk_distribution": [{"name": level.title(), "value": counts[level], "color": color} for level, color in (("critical", "#d94734"), ("high", "#df7433"), ("moderate", "#e8a34c"), ("low", "#477b65"))],
        "permission_categories": [
            {"name": "Sensitive", "value": sum(item["count"] for item in permission_counts.values() if item["category"] == "high")},
            {"name": "Standard", "value": sum(item["count"] for item in permission_counts.values() if item["category"] in ("medium", "low"))},
            {"name": "Review", "value": sum(item["count"] for item in permission_counts.values() if item["category"] == "review")},
            {"name": "Optional", "value": sum(detail["source"] in ("optional", "optional_host_permissions") for extension in extensions for detail in extension.permission_details)},
        ],
        "frequent_permissions": frequent,
        "recent_extensions": [extension.to_dict() for extension in extensions[:8]],
        "activity": [event.to_dict() for event in AuditEvent.query.order_by(AuditEvent.created_at.desc()).limit(12).all()],
        "regions": _publisher_regions(extensions),
        "regional_data_notice": "Fictional publisher locations assigned to the synthetic benchmark only; not user locations, infrastructure attribution, or threat origins.",
        "sector_risk": _sector_metrics(extensions),
        "trend": _risk_trend(extensions, time_range),
    })


def _publisher_regions(extensions):
    grouped = {}
    for extension in extensions:
        if not extension.is_benchmark or not extension.publisher_country or extension.publisher_latitude is None or extension.publisher_longitude is None:
            continue
        region = grouped.setdefault(extension.publisher_country, {
            "id": extension.publisher_country.lower().replace(" ", "-"),
            "name": extension.publisher_country,
            "x": (extension.publisher_longitude + 180) / 360 * 100,
            "y": (90 - extension.publisher_latitude) / 180 * 100,
            "extensions": 0,
            "scores": [],
            "risk_counts": {"low": 0, "moderate": 0, "high": 0, "critical": 0},
            "basis": "Fictional publisher-location metadata assigned to this synthetic benchmark record.",
        })
        region["extensions"] += 1
        region["scores"].append(extension.risk_score)
        region["risk_counts"][extension.risk_level] += 1
    for region in grouped.values():
        region["score"] = round(sum(region.pop("scores")) / region["extensions"])
        region["risk"] = next(level for level in ("critical", "high", "moderate", "low") if region["risk_counts"][level] > 0)
    return list(grouped.values())


def _sector_metrics(extensions=None):
    extensions = extensions if extensions is not None else Extension.query.all()
    sectors = []
    for name, relevant in SECTOR_PERMISSION_HINTS.items():
        records = [extension for extension in extensions if extension.sector == name]
        sensitive = {}
        for record in records:
            for detail in record.permission_details:
                if detail["category"] == "high":
                    sensitive[detail["name"]] = sensitive.get(detail["name"], 0) + 1
        sectors.append({
            "name": name,
            "extensions": len(records),
            "score": round(sum(item.risk_score for item in records) / len(records)) if records else 0,
            "relevant_permissions": relevant,
            "high_risk_extensions": sum(item.risk_level in ("high", "critical") for item in records),
            "critical_extensions": sum(item.risk_level == "critical" for item in records),
            "average_permission_count": round(sum(len(item.permissions["all"]) for item in records) / len(records), 1) if records else 0,
            "privacy_exposure": round(sum((item.privacy_exposure_score if item.privacy_exposure_score is not None else item.risk_score) for item in records) / len(records)) if records else 0,
            "common_sensitive_permissions": [name for name, _ in sorted(sensitive.items(), key=lambda pair: (-pair[1], pair[0]))[:5]],
            "recommendations": [f"Verify the business need for {permission} access." for permission in relevant[:3]],
            "basis": "Mean computed manifest scores for sector-assigned records; synthetic benchmark records are not industry-wide measurements.",
        })
    return sectors


def _risk_trend(extensions, time_range):
    now = datetime.now(timezone.utc)
    if time_range == "24h":
        start = now - timedelta(hours=24)
        buckets = [(start + timedelta(hours=offset * 4), (start + timedelta(hours=(offset + 1) * 4))) for offset in range(6)]
        counts = []
        for bucket_start, bucket_end in buckets:
            count = 0
            for extension in extensions:
                analyzed_at = extension.analyzed_at
                if analyzed_at.tzinfo is None:
                    analyzed_at = analyzed_at.replace(tzinfo=timezone.utc)
                if bucket_start <= analyzed_at < bucket_end and extension.risk_level in ("high", "critical"):
                    count += 1
            counts.append({"day": bucket_start.strftime("%H:00"), "value": count})
        return counts
    day_count = 30 if time_range == "30d" else 7
    today = now.date()
    days = [today - timedelta(days=offset) for offset in range(day_count - 1, -1, -1)]
    counts = {day.isoformat(): 0 for day in days}
    for extension in extensions:
        day = extension.analyzed_at.date().isoformat()
        if day in counts and extension.risk_level in ("high", "critical"):
            counts[day] += 1
    return [{"day": day[5:], "value": count} for day, count in counts.items()]


@api.get("/extensions")
def list_extensions():
    try:
        page = max(1, min(int(request.args.get("page", 1)), 100000))
        per_page = max(1, min(int(request.args.get("per_page", 100)), 100))
    except ValueError:
        return jsonify({"error": "page and per_page must be integers."}), 400
    risk = request.args.get("risk", "").lower()
    if risk and risk not in {"low", "moderate", "high", "critical"}:
        return jsonify({"error": "risk must be low, moderate, high, or critical."}), 400
    sort = request.args.get("sort", "analyzed_at")
    sort_columns = {
        "analyzed_at": Extension.analyzed_at,
        "name": Extension.name,
        "risk_score": Extension.risk_score,
        "publisher": Extension.publisher,
    }
    if sort not in sort_columns:
        return jsonify({"error": "sort must be analyzed_at, name, risk_score, or publisher."}), 400
    ordering = sort_columns[sort].asc() if request.args.get("direction") == "asc" else sort_columns[sort].desc()
    query = _extension_query().order_by(ordering)
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({"items": [item.to_dict() for item in pagination.items], "page": page, "per_page": per_page, "total": pagination.total, "pages": pagination.pages})


@api.get("/extensions/<int:extension_id>")
def get_extension(extension_id):
    extension = db.session.get(Extension, extension_id)
    if extension is None:
        return jsonify({"error": "Extension analysis was not found."}), 404
    return jsonify(extension.to_dict())


@api.post("/extensions/<int:extension_id>/reanalyze")
def reanalyze_extension(extension_id):
    extension = db.session.get(Extension, extension_id)
    if extension is None:
        return jsonify({"error": "Extension analysis was not found."}), 404
    parsed = parse_manifest_for_record(extension.manifest)
    analysis_purpose = extension.purpose if _analysis_settings().get("purpose_matching") != "disabled" else ""
    result = analyze_manifest(parsed, analysis_purpose, _thresholds(), _risk_weights(), _permission_weights())
    extension.permissions = result["permissions"]
    extension.permission_details = result["permission_details"]
    extension.findings = result["findings"]
    extension.combinations = result["combinations"]
    extension.purpose_findings = result["purpose_findings"]
    extension.privacy_findings = result["privacy_findings"]
    extension.score_breakdown = result["score_breakdown"]
    extension.risk_score = result["risk_score"]
    extension.risk_level = result["risk_level"]
    extension.requires_review = result["requires_review"]
    extension.privacy_exposure_score = result["privacy_exposure_score"]
    extension.purpose_alignment_score = result["purpose_alignment_score"]
    extension.analyzed_at = datetime.now(timezone.utc)
    _record("analysis_recomputed", extension.id, name=extension.name, risk_score=extension.risk_score, risk_level=extension.risk_level)
    db.session.commit()
    return jsonify(extension.to_dict())


def parse_manifest_for_record(manifest):
    return parse_manifest(json.dumps(manifest).encode("utf-8"))


@api.delete("/extensions/<int:extension_id>")
def delete_extension(extension_id):
    extension = db.session.get(Extension, extension_id)
    if extension is None:
        return jsonify({"error": "Extension analysis was not found."}), 404
    for event in AuditEvent.query.filter_by(extension_id=extension_id):
        event.extension_id = None
    SecurityReport.query.filter_by(extension_id=extension_id).delete()
    name = extension.name
    db.session.delete(extension)
    _record("extension_deleted", None, name=name, deleted_extension_id=extension_id)
    db.session.commit()
    return jsonify({"deleted": True, "id": extension_id})


@api.post("/compare")
def compare_extensions():
    data = request.get_json(silent=True) or {}
    ids = data.get("ids")
    if not isinstance(ids, list) or len(ids) != 2 or any(type(item) is not int for item in ids) or ids[0] == ids[1]:
        return jsonify({"error": "Provide two different extension IDs."}), 400
    extensions = [db.session.get(Extension, extension_id) for extension_id in ids]
    if any(extension is None for extension in extensions):
        return jsonify({"error": "Both analyzed extensions must exist."}), 404
    left, right = extensions
    left_permissions, right_permissions = set(left.permissions["all"]), set(right.permissions["all"])
    return jsonify({
        "extensions": [left.to_dict(), right.to_dict()],
        "permission_differences": {"only_first": sorted(left_permissions - right_permissions), "only_second": sorted(right_permissions - left_permissions), "shared": sorted(left_permissions & right_permissions)},
        "host_scope_differences": {
            "only_first": sorted(set(left.permissions["host"] + left.permissions["optional_host"]) - set(right.permissions["host"] + right.permissions["optional_host"])),
            "only_second": sorted(set(right.permissions["host"] + right.permissions["optional_host"]) - set(left.permissions["host"] + left.permissions["optional_host"])),
            "shared": sorted(set(left.permissions["host"] + left.permissions["optional_host"]) & set(right.permissions["host"] + right.permissions["optional_host"])),
        },
        "score_difference": left.risk_score - right.risk_score,
        "privacy_exposure": [left.privacy_exposure_score, right.privacy_exposure_score],
        "purpose_alignment": [left.purpose_alignment_score, right.purpose_alignment_score],
        "summary": f"{left.name} scores {left.risk_score}/100 ({left.risk_level}); {right.name} scores {right.risk_score}/100 ({right.risk_level}).",
    })


@api.get("/permissions")
def permissions_catalog():
    extensions = Extension.query.all()
    occurrences = {}
    combination_counts = {}
    for extension in extensions:
        for detail in extension.permission_details:
            entry = occurrences.setdefault(detail["name"], {"name": detail["name"], "count": 0, "extension_ids": set(), "category": detail["category"]})
            entry["count"] += 1
            entry["extension_ids"].add(extension.id)
        for combination in extension.combinations:
            combination_counts[combination["id"]] = combination_counts.get(combination["id"], 0) + 1
    catalog = []
    for name, values in sorted(PERMISSION_CATALOG.items()):
        entry = occurrences.get(name, {"name": name, "count": 0, "extension_ids": set(), "category": values[0]})
        catalog.append({
            "name": name, "risk": values[0], "category": values[0], "capability": values[1],
            "privacy_impact": values[2], "recommended_action": values[3], "weight": values[4],
            "count": entry["count"], "affected_extensions": len(entry["extension_ids"]),
        })
    return jsonify({
        "catalog": catalog,
        "analyses": [item.to_dict() for item in Extension.query.order_by(Extension.analyzed_at.desc()).limit(100).all()],
        "permission_distribution": [
            {"name": detail["name"], "count": detail["count"], "category": detail["category"]}
            for detail in sorted(occurrences.values(), key=lambda item: (-item["count"], item["category"]))
        ],
        "combinations": [{"id": name, "count": count} for name, count in sorted(combination_counts.items(), key=lambda item: (-item[1], item[0]))],
    })


@api.get("/sectors")
def sector_metrics():
    name = request.args.get("name", "").strip()
    result = _sector_metrics()
    if name:
        result = [sector for sector in result if sector["name"].lower() == name.lower()]
    return jsonify({"items": result, "methodology": "Per-sector values derive only from persisted records assigned to that sector. Synthetic benchmark entries are labeled and are not industry-wide estimates."})


@api.get("/activity")
@api.get("/audit")
def audit_events():
    search = request.args.get("search", "").strip()
    action = request.args.get("action", "").strip()
    category = request.args.get("category", "").strip()
    severity = request.args.get("severity", "").strip().lower()
    audit_view = request.path.endswith("/audit")
    query = AuditEvent.query.outerjoin(Extension, AuditEvent.extension_id == Extension.id)
    if audit_view:
        query = query.filter(AuditEvent.is_audit.is_(True))
    if action:
        query = query.filter(AuditEvent.action == action[:100])
    if category:
        query = query.filter(AuditEvent.category == category[:80])
    if severity in {"info", "low", "moderate", "high", "critical"}:
        query = query.filter(AuditEvent.severity == severity)
    if search:
        term = f"%{search[:100]}%"
        query = query.filter(or_(
            AuditEvent.action.ilike(term),
            cast(AuditEvent.detail, String).ilike(term),
            Extension.name.ilike(term),
        ))
    events = query.order_by(AuditEvent.created_at.desc()).limit(500).all()
    if audit_view and request.args.get("format") == "csv":
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "action", "resource", "category", "severity", "result", "description", "created_at"])
        for event in events:
            data = event.to_dict()
            writer.writerow([data["id"], data["action"], data["resource"], data["category"], data["severity"], data["result"], data["description"], data["created_at"]])
        return send_file(BytesIO(output.getvalue().encode("utf-8-sig")), mimetype="text/csv", as_attachment=True, download_name="browserguard-audit.csv")
    return jsonify({"items": [event.to_dict() for event in events], "total": len(events)})


@api.get("/reports")
def list_reports():
    query = SecurityReport.query.join(Extension)
    search = request.args.get("search", "").strip()
    report_type = request.args.get("type", "").strip()
    if search:
        query = query.filter(Extension.name.ilike(f"%{search[:100]}%"))
    if report_type:
        query = query.filter(SecurityReport.report_type == report_type[:40])
    reports = query.order_by(SecurityReport.created_at.desc()).limit(500).all()
    return jsonify({"items": [{
        **report.to_dict(),
        "download_url": f"/reports/{report.id}/download",
    } for report in reports], "total": len(reports)})


@api.post("/extensions/<int:extension_id>/report")
def generate_report(extension_id):
    extension = db.session.get(Extension, extension_id)
    if extension is None:
        return jsonify({"error": "Extension analysis was not found."}), 404
    pdf = create_report(extension, include_evidence=_report_preferences().get("include_manifest_evidence", True))
    report = SecurityReport(extension_id=extension_id, report_type="risk_assessment", pdf_data=pdf)
    db.session.add(report)
    db.session.flush()
    _record("report_generated", extension_id, report_id=report.id)
    db.session.commit()
    return send_file(BytesIO(pdf), mimetype="application/pdf", as_attachment=True, download_name=f"browserguard-{extension.id}-assessment.pdf")


@api.get("/reports/<int:report_id>/download")
def download_report(report_id):
    report = db.session.get(SecurityReport, report_id)
    if report is None:
        return jsonify({"error": "Report was not found."}), 404
    extension = db.session.get(Extension, report.extension_id)
    if extension is None:
        return jsonify({"error": "The report's extension analysis no longer exists."}), 404
    _record("report_downloaded", extension.id, report_id=report.id)
    db.session.commit()
    pdf = report.pdf_data or create_report(extension, include_evidence=_report_preferences().get("include_manifest_evidence", True))
    return send_file(
        BytesIO(pdf),
        mimetype="application/pdf",
        as_attachment=request.args.get("inline") != "1",
        download_name=f"browserguard-{extension.id}-{report.report_type}.pdf",
    )


@api.post("/compare/report")
def generate_comparison_report():
    data = request.get_json(silent=True) or {}
    ids = data.get("ids")
    if not isinstance(ids, list) or len(ids) != 2 or any(type(item) is not int for item in ids) or ids[0] == ids[1]:
        return jsonify({"error": "Provide two different extension IDs."}), 400
    left, right = (db.session.get(Extension, item) for item in ids)
    if left is None or right is None:
        return jsonify({"error": "Both analyzed extensions must exist."}), 404
    pdf = create_comparison_report(left, right)
    report = SecurityReport(extension_id=left.id, report_type="comparison", pdf_data=pdf)
    db.session.add(report)
    db.session.flush()
    _record("comparison_report_generated", left.id, report_id=report.id, compared_extension=right.name)
    db.session.commit()
    return send_file(BytesIO(pdf), mimetype="application/pdf", as_attachment=True, download_name=f"browserguard-comparison-{left.id}-{right.id}.pdf")


@api.get("/settings")
def get_settings():
    return jsonify({
        "risk_thresholds": _thresholds(),
        "risk_weights": _risk_weights(),
        "permission_weights": _permission_weights(),
        "analysis_settings": _analysis_settings(),
        "report_preferences": _report_preferences(),
        "upload_restrictions": _upload_restrictions(),
        "permission_rules": [{"name": name, "risk": values[0], "weight": _permission_weights().get(name, values[4]), "capability": values[1]} for name, values in sorted(PERMISSION_CATALOG.items())],
    })


@api.put("/settings")
def update_settings():
    data = request.get_json(silent=True) or {}
    updates = {}
    if "risk_thresholds" in data:
        thresholds = data["risk_thresholds"]
        if not isinstance(thresholds, dict) or set(thresholds) != {"low", "moderate", "high"}:
            return jsonify({"error": "risk_thresholds must contain low, moderate, and high."}), 400
        values = [thresholds[key] for key in ("low", "moderate", "high")]
        if any(not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 99 for value in values) or not values[0] < values[1] < values[2]:
            return jsonify({"error": "Thresholds must be integers from 0 to 99 in strictly increasing order."}), 400
        updates["risk_thresholds"] = thresholds
    if "risk_weights" in data:
        weights = data["risk_weights"]
        expected = {"permission_sensitivity", "host_scope", "permission_combinations", "purpose_alignment"}
        if not isinstance(weights, dict) or set(weights) != expected or any(type(value) is not int or not 0 <= value <= 100 for value in weights.values()) or sum(weights.values()) > 100:
            return jsonify({"error": "risk_weights must define four integer caps from 0 to 100 whose total does not exceed 100."}), 400
        updates["risk_weights"] = weights
    if "permission_weights" in data:
        permission_weights = data["permission_weights"]
        if not isinstance(permission_weights, dict) or any(name not in PERMISSION_CATALOG or type(weight) is not int or not 0 <= weight <= 50 for name, weight in permission_weights.items()):
            return jsonify({"error": "permission_weights must map catalog permissions to integer weights from 0 to 50."}), 400
        updates["permission_weights"] = permission_weights
    if "upload_restrictions" in data:
        restrictions = data["upload_restrictions"]
        keys = {"upload_limit_mb", "manifest_limit_mb", "zip_entry_limit", "zip_expanded_size_mb"}
        if not isinstance(restrictions, dict) or set(restrictions) != keys:
            return jsonify({"error": "upload_restrictions must define upload_limit_mb, manifest_limit_mb, zip_entry_limit, and zip_expanded_size_mb."}), 400
        if (
            type(restrictions["upload_limit_mb"]) is not int or not 1 <= restrictions["upload_limit_mb"] <= 16
            or type(restrictions["manifest_limit_mb"]) is not int or not 1 <= restrictions["manifest_limit_mb"] <= 2
            or type(restrictions["zip_entry_limit"]) is not int or not 1 <= restrictions["zip_entry_limit"] <= 2000
            or type(restrictions["zip_expanded_size_mb"]) is not int or not 1 <= restrictions["zip_expanded_size_mb"] <= 16
            or restrictions["manifest_limit_mb"] > restrictions["upload_limit_mb"]
            or restrictions["zip_expanded_size_mb"] > restrictions["upload_limit_mb"]
        ):
            return jsonify({"error": "Upload limits must be positive integers within the platform's 16 MB upload, 2 MB manifest, and 2,000-entry safety caps."}), 400
        updates["upload_restrictions"] = restrictions
    for key in ("analysis_settings", "report_preferences"):
        if key in data:
            if not isinstance(data[key], dict):
                return jsonify({"error": f"{key} must be a JSON object."}), 400
            merged = {**(_analysis_settings() if key == "analysis_settings" else _report_preferences()), **data[key]}
            if key == "analysis_settings":
                if set(merged) - {"purpose_matching", "run_extension_code"} or merged.get("purpose_matching") not in {"keyword_heuristic", "disabled"} or merged.get("run_extension_code") is not False:
                    return jsonify({"error": "Analysis settings support keyword_heuristic or disabled purpose matching; extension code execution must remain disabled."}), 400
            elif set(merged) - {"include_manifest_evidence", "format"} or type(merged.get("include_manifest_evidence")) is not bool or merged.get("format") != "pdf":
                return jsonify({"error": "Report preferences support PDF format and a boolean include_manifest_evidence option."}), 400
            updates[key] = merged
    if not updates:
        return jsonify({"error": "Provide at least one supported settings section."}), 400
    for key, value in updates.items():
        setting = db.session.get(Setting, key)
        if setting is None:
            setting = Setting(key=key, value=value)
            db.session.add(setting)
        else:
            setting.value = value
    _record("settings_updated", None, settings_sections=sorted(updates))
    db.session.commit()
    return jsonify({"updated": sorted(updates), **{key: value for key, value in updates.items()}})
