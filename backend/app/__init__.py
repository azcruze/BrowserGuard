from pathlib import Path

from flask import Flask, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text

from config import Config

db = SQLAlchemy()


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite:///"):
        database_file = app.config["SQLALCHEMY_DATABASE_URI"].removeprefix("sqlite:///")
        Path(database_file).parent.mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": [
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:5174", "http://127.0.0.1:5174",
    ]}})

    from app.models import AuditEvent, Extension, SecurityReport, Setting
    from app.routes import api

    app.register_blueprint(api, url_prefix="/api")
    with app.app_context():
        db.create_all()
        _migrate_sqlite_schema()
        if not db.session.get(Setting, "risk_thresholds"):
            db.session.add(Setting(key="risk_thresholds", value={"low": 24, "moderate": 49, "high": 74}))
        if not db.session.get(Setting, "risk_weights"):
            db.session.add(Setting(key="risk_weights", value={
                "permission_sensitivity": 45, "host_scope": 25,
                "permission_combinations": 20, "purpose_alignment": 10,
            }))
        if not db.session.get(Setting, "permission_weights"):
            db.session.add(Setting(key="permission_weights", value={}))
        if not db.session.get(Setting, "analysis_settings"):
            db.session.add(Setting(key="analysis_settings", value={"purpose_matching": "keyword_heuristic", "run_extension_code": False}))
        if not db.session.get(Setting, "report_preferences"):
            db.session.add(Setting(key="report_preferences", value={"include_manifest_evidence": True, "format": "pdf"}))
        if not db.session.get(Setting, "upload_restrictions"):
            db.session.add(Setting(key="upload_restrictions", value={
                "upload_limit_mb": 16, "manifest_limit_mb": 2,
                "zip_entry_limit": 2000, "zip_expanded_size_mb": 16,
            }))
        db.session.commit()
        if app.config.get("SEED_BENCHMARK_DATA"):
            from app.benchmark import seed_benchmark

            app.logger.info("BrowserGuard benchmark initialization: %s", seed_benchmark())

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify({"error": "Upload exceeds the 16 MB request limit."}), 413

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"error": "The requested API resource was not found."}), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        app.logger.exception("Unhandled BrowserGuard API error: %s", error)
        return jsonify({"error": "The server could not complete the request."}), 500

    @app.after_request
    def secure_response_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    return app


def _migrate_sqlite_schema():
    if db.engine.dialect.name != "sqlite":
        return
    migrations = {
        "extension": {
            "publisher": "VARCHAR(200) NOT NULL DEFAULT 'User upload'",
            "extension_key": "VARCHAR(80) NOT NULL DEFAULT ''",
            "publisher_country": "VARCHAR(100)",
            "publisher_latitude": "FLOAT",
            "publisher_longitude": "FLOAT",
            "is_benchmark": "BOOLEAN NOT NULL DEFAULT 0",
            "privacy_exposure_score": "INTEGER",
            "purpose_alignment_score": "INTEGER",
        },
        "audit_event": {
            "category": "VARCHAR(80) NOT NULL DEFAULT 'analysis'",
            "severity": "VARCHAR(20) NOT NULL DEFAULT 'info'",
            "result": "VARCHAR(40) NOT NULL DEFAULT 'recorded'",
            "description": "TEXT NOT NULL DEFAULT ''",
            "is_audit": "BOOLEAN NOT NULL DEFAULT 1",
        },
        "security_report": {
            "report_type": "VARCHAR(40) NOT NULL DEFAULT 'risk_assessment'",
            "pdf_data": "BLOB",
        },
    }
    inspector = inspect(db.engine)
    for table, columns in migrations.items():
        existing = {column["name"] for column in inspector.get_columns(table)}
        for name, declaration in columns.items():
            if name not in existing:
                db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}"))
    db.session.execute(text(
        "UPDATE extension SET extension_key = 'BG-LEGACY-' || printf('%08d', id) WHERE extension_key = ''"
    ))
    db.session.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_extension_extension_key ON extension (extension_key)"
    ))
    db.session.commit()
