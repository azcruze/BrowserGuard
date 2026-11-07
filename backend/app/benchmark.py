import hashlib
import json
from datetime import datetime, timedelta, timezone

from app import db
from app.analyzers import analyze_manifest
from app.analyzers.manifest import parse_manifest
from app.models import AuditEvent, Extension, SecurityReport
from app.reports import create_report

BENCHMARK_VERSION = "2026.1"

SECTOR_PERMISSION_HINTS = {
    "Productivity": ["tabs", "storage", "activeTab", "scripting"],
    "Shopping": ["tabs", "cookies", "webRequest", "storage"],
    "Finance": ["tabs", "history", "cookies", "webRequest"],
    "Healthcare": ["tabs", "geolocation", "scripting", "storage"],
    "Education": ["tabs", "bookmarks", "downloads", "scripting"],
    "Communication": ["tabs", "notifications", "microphone", "storage"],
    "Entertainment": ["tabs", "history", "webRequest", "storage"],
    "Developer Tools": ["scripting", "debugger", "tabs", "storage"],
    "Security": ["webRequest", "declarativeNetRequest", "tabs", "proxy"],
    "Accessibility": ["activeTab", "scripting", "storage", "clipboardRead"],
}

_NAME_PARTS = (
    "Amber", "Cedar", "Copper", "Dawn", "Elm", "Fern", "Grove", "Harbor",
    "Indigo", "Juniper", "Kite", "Lumen", "Maple", "North", "Ochre", "Pine",
    "Quartz", "River", "Sable", "Tandem", "Umber", "Vale", "Willow", "Yarrow",
    "Zephyr", "Arbor", "Beacon", "Clover", "Drift", "Ember", "Fable", "Glade",
    "Hearth", "Iris", "Jade", "Keystone", "Mosaic", "Nook", "Orbit", "Prairie",
)
_SECTOR_NAMES = tuple(SECTOR_PERMISSION_HINTS)
_PUBLISHERS = (
    "Fictional Alder Works", "Fictional Blue Lantern Studio",
    "Fictional Common Thread Lab", "Fictional Northwind Cooperative",
    "Fictional Paper Kite Collective", "Fictional Quiet Harbor Software",
    "Fictional Red Fern Workshop", "Fictional Stonebridge Research",
)
_LOCATIONS = (
    ("Canada", 56, -106), ("United States", 39, -98), ("Brazil", -10, -52),
    ("United Kingdom", 55, -3), ("Germany", 51, 10), ("Kenya", 0, 37),
    ("India", 22, 79), ("Japan", 36, 138), ("Australia", -25, 134),
    ("New Zealand", -41, 174),
)
_PERMISSION_POOL = (
    "activeTab", "storage", "tabs", "history", "cookies", "scripting",
    "webRequest", "webRequestBlocking", "bookmarks", "downloads",
    "clipboardRead", "clipboardWrite", "management", "geolocation",
    "notifications", "identity", "nativeMessaging", "privacy", "proxy",
    "declarativeNetRequest", "topSites", "sessions", "search", "fontSettings",
    "unlimitedStorage", "declarativeContent", "sidePanel", "offscreen",
    "debugger", "contentSettings", "tabGroups",
)
_PUBLISHER_LOCATIONS = {
    publisher: _LOCATIONS[index] for index, publisher in enumerate(_PUBLISHERS)
}


def _manifest_for(index, sector):
    profile = [permission for bit, permission in enumerate(_PERMISSION_POOL[:6]) if index & (1 << bit)]
    profile.append(_PERMISSION_POOL[6 + index % (len(_PERMISSION_POOL) - 6)])
    if index % 3 == 0:
        profile.append(_PERMISSION_POOL[6 + (index * 7 + 4) % (len(_PERMISSION_POOL) - 6)])
    if index % 4 == 0:
        profile.append("storage")
    profile = list(dict.fromkeys(profile))
    optional = []
    if index % 3 == 1:
        optional = [_PERMISSION_POOL[(index * 5 + 2) % len(_PERMISSION_POOL)]]
        profile = [permission for permission in profile if permission not in optional]

    host_mode = index % 5
    host_permissions = []
    if host_mode == 1:
        host_permissions = [f"https://{sector.lower().replace(' ', '-')}.example/*"]
    elif host_mode == 2:
        host_permissions = ["<all_urls>"]
    elif host_mode == 3:
        host_permissions = ["https://portal.example/*"]
        optional_hosts = ["https://*.workspace.example/*"]
    else:
        optional_hosts = []

    return {
        "manifest_version": 3,
        "name": f"{_NAME_PARTS[index]} {sector} Companion",
        "version": f"{1 + index // 10}.{index % 10}.0",
        "description": f"A fictional {sector.lower()} browser companion for the BrowserGuard benchmark dataset.",
        "permissions": profile,
        "optional_permissions": optional,
        "host_permissions": host_permissions,
        "optional_host_permissions": optional_hosts if host_mode == 3 else [],
        "content_scripts": [
            {"matches": ["https://reader.example/*"], "js": ["content.js"]}
        ] if index % 7 == 0 else [],
    }


def benchmark_profiles():
    profiles = []
    for index, name in enumerate(_NAME_PARTS):
        sector = _SECTOR_NAMES[index % len(_SECTOR_NAMES)]
        publisher = _PUBLISHERS[index % len(_PUBLISHERS)]
        country, latitude, longitude = _PUBLISHER_LOCATIONS[publisher]
        manifest = _manifest_for(index, sector)
        purpose = (
            f"Fictional benchmark profile for {sector.lower()} workflows; "
            "organizes browser tabs, saves user-selected settings, and reviews site access."
        )
        profiles.append({
            "index": index,
            "manifest": manifest,
            "sector": sector,
            "publisher": publisher,
            "country": country,
            "latitude": latitude,
            "longitude": longitude,
            "purpose": purpose,
        })
    return profiles


def seed_benchmark(reset=False):
    if reset:
        benchmark_ids = [item.id for item in Extension.query.filter_by(is_benchmark=True).all()]
        if benchmark_ids:
            SecurityReport.query.filter(SecurityReport.extension_id.in_(benchmark_ids)).delete(synchronize_session=False)
            AuditEvent.query.filter(AuditEvent.extension_id.in_(benchmark_ids)).delete(synchronize_session=False)
            Extension.query.filter(Extension.id.in_(benchmark_ids)).delete(synchronize_session=False)
            db.session.commit()

    existing = Extension.query.filter_by(is_benchmark=True).count()
    if existing:
        return {"seeded": False, "extensions": existing, "reason": "benchmark already initialized"}

    now = datetime.now(timezone.utc)
    records = []
    for profile in benchmark_profiles():
        manifest = profile["manifest"]
        parsed = parse_manifest(json.dumps(manifest, sort_keys=True).encode("utf-8"))
        analysis = analyze_manifest(parsed, profile["purpose"])
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(f"BrowserGuard benchmark {BENCHMARK_VERSION}\0{canonical}".encode()).hexdigest()
        extension = Extension(
            name=manifest["name"],
            version=manifest["version"],
            manifest_version=3,
            description=manifest["description"],
            original_filename=f"benchmark-{profile['index'] + 1:02d}-manifest.json",
            sha256=digest,
            extension_key=f"BG-BENCH-{profile['index'] + 1:04d}",
            purpose=profile["purpose"],
            sector=profile["sector"],
            publisher=profile["publisher"],
            publisher_country=profile["country"],
            publisher_latitude=profile["latitude"],
            publisher_longitude=profile["longitude"],
            is_benchmark=True,
            privacy_exposure_score=analysis["privacy_exposure_score"],
            purpose_alignment_score=analysis["purpose_alignment_score"],
            manifest=manifest,
            permissions=analysis["permissions"],
            permission_details=analysis["permission_details"],
            findings=analysis["findings"],
            combinations=analysis["combinations"],
            purpose_findings=analysis["purpose_findings"],
            privacy_findings=analysis["privacy_findings"],
            score_breakdown=analysis["score_breakdown"],
            risk_score=analysis["risk_score"],
            risk_level=analysis["risk_level"],
            requires_review=analysis["requires_review"],
            analyzed_at=now - timedelta(days=(39 - profile["index"]) % 30, hours=profile["index"] % 24),
        )
        records.append(extension)
    db.session.add_all(records)
    db.session.flush()

    for index in range(100):
        extension = records[index % len(records)]
        action = ("benchmark_review", "permission_assessed", "privacy_assessed", "risk_classified")[index % 4]
        db.session.add(AuditEvent(
            extension_id=extension.id,
            action=action,
            detail={"name": extension.name, "risk_level": extension.risk_level, "benchmark": True},
            category=("analysis", "permission", "privacy", "risk")[index % 4],
            severity=extension.risk_level,
            result="recorded",
            description=f"Synthetic benchmark activity: {action.replace('_', ' ')} for {extension.name}.",
            is_audit=False,
            created_at=now - timedelta(days=(99 - index) // 4, minutes=(99 - index) * 7),
        ))

    for index in range(30):
        extension = records[(index * 7) % len(records)]
        action = ("benchmark_initialized", "benchmark_record_reviewed", "benchmark_report_created")[index % 3]
        db.session.add(AuditEvent(
            extension_id=extension.id,
            action=action,
            detail={"name": extension.name, "benchmark": True, "sequence": index + 1},
            category="audit",
            severity=extension.risk_level,
            result="success",
            description=f"Persistent audit entry for the synthetic benchmark record {extension.name}.",
            is_audit=True,
            created_at=now - timedelta(days=(29 - index), minutes=index * 3),
        ))

    for index, extension in enumerate(records[:15]):
        db.session.add(SecurityReport(
            extension_id=extension.id,
            report_type="benchmark_risk_assessment",
            pdf_data=create_report(extension),
            created_at=now - timedelta(days=index),
        ))

    db.session.commit()
    return {"seeded": True, "extensions": len(records), "activity_events": 100, "audit_events": 30, "reports": 15}
