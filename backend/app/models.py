from datetime import datetime, timezone

from app import db


def utc_now():
    return datetime.now(timezone.utc)


class Extension(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, index=True)
    version = db.Column(db.String(80), nullable=False)
    manifest_version = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    original_filename = db.Column(db.String(255), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    extension_key = db.Column(db.String(80), nullable=False, default="")
    purpose = db.Column(db.Text, nullable=False, default="")
    sector = db.Column(db.String(80), nullable=False, default="Unspecified")
    publisher = db.Column(db.String(200), nullable=False, default="User upload")
    publisher_country = db.Column(db.String(100), nullable=True)
    publisher_latitude = db.Column(db.Float, nullable=True)
    publisher_longitude = db.Column(db.Float, nullable=True)
    is_benchmark = db.Column(db.Boolean, nullable=False, default=False, index=True)
    privacy_exposure_score = db.Column(db.Integer, nullable=True)
    purpose_alignment_score = db.Column(db.Integer, nullable=True)
    manifest = db.Column(db.JSON, nullable=False)
    permissions = db.Column(db.JSON, nullable=False)
    permission_details = db.Column(db.JSON, nullable=False)
    findings = db.Column(db.JSON, nullable=False)
    combinations = db.Column(db.JSON, nullable=False)
    purpose_findings = db.Column(db.JSON, nullable=False)
    privacy_findings = db.Column(db.JSON, nullable=False)
    score_breakdown = db.Column(db.JSON, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False, index=True)
    risk_level = db.Column(db.String(20), nullable=False, index=True)
    requires_review = db.Column(db.Boolean, nullable=False, default=False)
    analyzed_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "manifest_version": self.manifest_version,
            "description": self.description,
            "original_filename": self.original_filename,
            "sha256": self.sha256,
            "extension_key": self.extension_key,
            "purpose": self.purpose,
            "sector": self.sector,
            "publisher": self.publisher,
            "publisher_country": self.publisher_country,
            "publisher_latitude": self.publisher_latitude,
            "publisher_longitude": self.publisher_longitude,
            "is_benchmark": self.is_benchmark,
            "privacy_exposure_score": self.privacy_exposure_score,
            "purpose_alignment_score": self.purpose_alignment_score,
            "manifest": self.manifest,
            "permissions": self.permissions,
            "permission_details": self.permission_details,
            "findings": self.findings,
            "combinations": self.combinations,
            "purpose_findings": self.purpose_findings,
            "privacy_findings": self.privacy_findings,
            "score_breakdown": self.score_breakdown,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "requires_review": self.requires_review,
            "analyzed_at": self.analyzed_at.isoformat(),
        }


class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    extension_id = db.Column(db.Integer, db.ForeignKey("extension.id", ondelete="SET NULL"), nullable=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    detail = db.Column(db.JSON, nullable=False, default=dict)
    category = db.Column(db.String(80), nullable=False, default="analysis")
    severity = db.Column(db.String(20), nullable=False, default="info")
    result = db.Column(db.String(40), nullable=False, default="recorded")
    description = db.Column(db.Text, nullable=False, default="")
    is_audit = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    extension = db.relationship("Extension")

    def to_dict(self):
        return {
            "id": self.id,
            "extension_id": self.extension_id,
            "action": self.action,
            "detail": self.detail,
            "category": self.category,
            "severity": self.severity,
            "result": self.result,
            "description": self.description,
            "resource": self.extension.name if self.extension else self.detail.get("name", "BrowserGuard"),
            "created_at": self.created_at.isoformat(),
        }


class SecurityReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    extension_id = db.Column(db.Integer, db.ForeignKey("extension.id", ondelete="CASCADE"), nullable=False, index=True)
    report_type = db.Column(db.String(40), nullable=False, default="risk_assessment")
    pdf_data = db.Column(db.LargeBinary, nullable=True)
    extension = db.relationship("Extension")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)

    def to_dict(self):
        return {
            "id": self.id,
            "extension_id": self.extension_id,
            "extension": self.extension.name if self.extension else "Deleted extension",
            "report_type": self.report_type,
            "created_at": self.created_at.isoformat(),
        }


class Setting(db.Model):
    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.JSON, nullable=False)
