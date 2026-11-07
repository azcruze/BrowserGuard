import io
import json
import sqlite3
import zipfile

import pytest

from app import create_app, db
from app.benchmark import seed_benchmark
from app.analyzers import ManifestError, analyze_manifest
from app.analyzers.manifest import parse_manifest
from app.analyzers.uploads import read_uploaded_manifest
from app.models import AuditEvent, Extension


@pytest.fixture
def client():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "SQLALCHEMY_ENGINE_OPTIONS": {"connect_args": {"check_same_thread": False}},
        "SEED_BENCHMARK_DATA": False,
    })
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def manifest(**overrides):
    value = {"manifest_version": 3, "name": "Research Helper", "version": "1.2.0", "description": "Organize research tabs", "permissions": ["tabs", "history", "scripting"], "host_permissions": ["<all_urls>"]}
    value.update(overrides)
    return value


def test_manifest_analysis_explains_sensitive_combination_and_bounds_score():
    parsed = parse_manifest(json.dumps(manifest()).encode())
    result = analyze_manifest(parsed, "A browser tab organizer")
    assert result["risk_score"] == 85
    assert result["risk_level"] == "critical"
    assert {item["id"] for item in result["combinations"]} >= {"tabs-history", "tabs-scripting", "scripting-broad-host"}
    assert any(item["name"] == "<all_urls>" and item["source"] == "host_permissions" for item in result["permission_details"])
    assert next(item for item in result["purpose_findings"] if item["permission"] == "<all_urls>")["status"] == "requires_justification"


def test_manifest_validation_rejects_invalid_json_and_required_fields():
    with pytest.raises(ManifestError):
        parse_manifest(b"{nope")
    with pytest.raises(ManifestError, match="name"):
        parse_manifest(json.dumps({"manifest_version": 3, "version": "1"}).encode())
    with pytest.raises(ManifestError, match="numeric constant"):
        parse_manifest(b'{"manifest_version":3,"name":"x","version":"1","value":NaN}')


def test_v2_host_patterns_are_separated_from_api_permissions():
    parsed = parse_manifest(json.dumps(manifest(manifest_version=2, host_permissions=[], permissions=["tabs", "https://example.com/*"])).encode())
    assert parsed["permissions"] == ["tabs"]
    assert parsed["host_permissions"] == ["https://example.com/*"]


def test_wildcard_subdomain_is_treated_as_broad_host_scope():
    parsed = parse_manifest(json.dumps(manifest(permissions=[], host_permissions=["https://*.example.com/*"])).encode())
    result = analyze_manifest(parsed, "A notes application")
    assert result["score_breakdown"]["host_scope"] == 18


def test_zip_upload_reads_manifest_without_extracting():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("extension/manifest.json", json.dumps(manifest()))
    parsed, filename = read_uploaded_manifest("extension.zip", archive.getvalue())
    assert parsed["name"] == "Research Helper"
    assert filename == "extension.zip"


def test_zip_upload_rejects_traversal():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("../manifest.json", json.dumps(manifest()))
    with pytest.raises(ManifestError, match="unsafe path"):
        read_uploaded_manifest("unsafe.zip", archive.getvalue())


def test_optional_permission_combo_is_explained_but_weighted_lower():
    parsed = parse_manifest(json.dumps(manifest(permissions=["tabs"], optional_permissions=["history"])).encode())
    result = analyze_manifest(parsed)
    combination = next(item for item in result["combinations"] if item["id"] == "tabs-history")
    assert combination["requires_optional_grant"] is True
    assert combination["evidence"]["requires_optional_grant"] is True


def test_report_escapes_manifest_control_text(client):
    payload = json.dumps(manifest(permissions=["<font color='red'>unsafe</font>"])).encode()
    uploaded = client.post("/api/analyze", data={"file": (io.BytesIO(payload), "manifest.json"), "purpose": "Review extension"}, content_type="multipart/form-data")
    extension_id = uploaded.get_json()["id"]
    report = client.post(f"/api/extensions/{extension_id}/report")
    assert report.status_code == 200
    assert report.data.startswith(b"%PDF")


def test_upload_metrics_report_and_settings_workflow(client):
    assert client.get("/api/health").status_code == 200
    payload = json.dumps(manifest()).encode()
    uploaded = client.post("/api/analyze", data={"file": (io.BytesIO(payload), "manifest.json"), "purpose": "Organize browser tabs", "sector": "Technology"}, content_type="multipart/form-data")
    assert uploaded.status_code == 201
    extension = uploaded.get_json()
    extension_id = extension["id"]
    assert extension["risk_score"] > 0
    assert client.get("/api/overview").get_json()["extensions_analysed"] == 1
    assert client.get("/api/extensions").get_json()["total"] == 1
    pdf = client.post(f"/api/extensions/{extension_id}/report")
    assert pdf.status_code == 200
    assert pdf.mimetype == "application/pdf"
    assert pdf.data.startswith(b"%PDF")
    reports = client.get("/api/reports").get_json()
    assert reports["total"] == 1
    assert client.get(f"/api{reports['items'][0]['download_url']}").data.startswith(b"%PDF")
    update = client.put("/api/settings", json={"risk_thresholds": {"low": 20, "moderate": 50, "high": 80}})
    assert update.status_code == 200
    assert client.get("/api/settings").get_json()["risk_thresholds"]["low"] == 20
    assert client.delete(f"/api/extensions/{extension_id}").status_code == 200
    assert client.get("/api/overview").get_json()["extensions_analysed"] == 0


def test_remaining_dashboard_routes_and_invalid_requests(client):
    assert client.get("/api/health").headers["X-Content-Type-Options"] == "nosniff"
    assert client.get("/api/permissions").status_code == 200
    assert client.get("/api/sectors").status_code == 200
    assert client.get("/api/activity").status_code == 200
    assert client.get("/api/audit").status_code == 200
    assert client.get("/api/reports").status_code == 200
    assert client.get("/api/extensions?risk=unknown").status_code == 400
    assert client.post("/api/compare", json={"ids": [True, 1]}).status_code == 400
    assert client.put("/api/settings", json={"risk_thresholds": {"low": 50, "moderate": 50, "high": 80}}).status_code == 400
    assert client.post("/api/analyze").status_code == 400


def test_analysis_records_survive_application_restart(tmp_path):
    database_url = f"sqlite:///{(tmp_path / 'browserguard.sqlite3').as_posix()}"
    first_app = create_app({"TESTING": True, "SEED_BENCHMARK_DATA": False, "SQLALCHEMY_DATABASE_URI": database_url})
    payload = json.dumps(manifest()).encode()
    response = first_app.test_client().post(
        "/api/analyze",
        data={"file": (io.BytesIO(payload), "manifest.json")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 201
    second_app = create_app({"TESTING": True, "SEED_BENCHMARK_DATA": False, "SQLALCHEMY_DATABASE_URI": database_url})
    assert second_app.test_client().get("/api/overview").get_json()["extensions_analysed"] == 1


def test_legacy_extension_keys_are_backfilled_during_sqlite_migration(tmp_path):
    database_path = tmp_path / "legacy.sqlite3"
    database_url = f"sqlite:///{database_path.as_posix()}"
    app = create_app({"TESTING": True, "SEED_BENCHMARK_DATA": False, "SQLALCHEMY_DATABASE_URI": database_url})
    payload = json.dumps(manifest()).encode()
    response = app.test_client().post(
        "/api/analyze",
        data={"file": (io.BytesIO(payload), "manifest.json")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 201
    with app.app_context():
        db.session.remove()
        db.engine.dispose()

    with sqlite3.connect(database_path) as connection:
        connection.execute("DROP INDEX ix_extension_extension_key")
        connection.execute("ALTER TABLE extension DROP COLUMN extension_key")

    migrated_app = create_app({
        "TESTING": True,
        "SEED_BENCHMARK_DATA": False,
        "SQLALCHEMY_DATABASE_URI": database_url,
    })
    extension = migrated_app.test_client().get("/api/extensions?per_page=1").get_json()["items"][0]
    assert extension["extension_key"] == "BG-LEGACY-00000001"


def test_benchmark_seed_is_reproducible_complete_and_preserves_user_records(tmp_path):
    database_url = f"sqlite:///{(tmp_path / 'benchmark.sqlite3').as_posix()}"
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": database_url})
    client = app.test_client()
    health = client.get("/api/health").get_json()
    assert health["database_counts"] == {
        "extensions": 40,
        "benchmark_extensions": 40,
        "user_extensions": 0,
        "activity_events": 130,
        "audit_events": 30,
        "reports": 15,
    }

    extensions = client.get("/api/extensions?per_page=100").get_json()["items"]
    assert len({tuple(sorted(item["permissions"]["all"])) for item in extensions}) >= 25
    assert len({item["extension_key"] for item in extensions}) == 40
    assert all(item["manifest_version"] == 3 for item in extensions)
    assert len({finding["id"] for item in extensions for finding in item["combinations"]}) >= 25
    assert len({permission for item in extensions for permission in item["permissions"]["all"]}) >= 20
    assert sum(len(item["findings"]) for item in extensions) >= 80
    assert sum(len(item["privacy_findings"]) for item in extensions) >= 30
    assert all(item["purpose_alignment_score"] is not None for item in extensions)
    assert {item["risk_level"] for item in extensions} == {"low", "moderate", "high", "critical"}
    assert len({item["sector"] for item in extensions}) >= 8
    assert len(client.get("/api/overview").get_json()["regions"]) >= 8
    assert len(client.get("/api/sectors").get_json()["items"]) >= 8
    assert len(client.get("/api/activity").get_json()["items"]) >= 100
    assert len(client.get("/api/audit").get_json()["items"]) == 30

    first, second = extensions[0]["id"], extensions[1]["id"]
    assert client.post("/api/compare", json={"ids": [first, second]}).status_code == 200
    response = client.post("/api/compare/report", json={"ids": [first, second]})
    assert response.status_code == 200
    assert response.data.startswith(b"%PDF")
    assert client.get("/api/reports").get_json()["total"] == 16

    user_manifest = json.dumps(manifest(name="User Extension")).encode()
    uploaded = client.post(
        "/api/analyze",
        data={"file": (io.BytesIO(user_manifest), "manifest.json")},
        content_type="multipart/form-data",
    )
    assert uploaded.status_code == 201
    with app.app_context():
        db.session.add(AuditEvent(
            extension_id=uploaded.get_json()["id"],
            action="user_activity",
            detail={},
            is_audit=False,
        ))
        db.session.commit()
        assert seed_benchmark()["seeded"] is False
        assert seed_benchmark(reset=True)["seeded"] is True
        assert Extension.query.filter_by(is_benchmark=False).count() == 1
        assert Extension.query.filter_by(is_benchmark=True).count() == 40
        assert AuditEvent.query.filter_by(action="user_activity").count() == 1
