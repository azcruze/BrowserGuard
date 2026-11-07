from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def create_report(extension, include_evidence=True):
    output = BytesIO()
    document = SimpleDocTemplate(output, pagesize=letter, rightMargin=0.65 * inch, leftMargin=0.65 * inch)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="BGTitle", parent=styles["Title"], textColor=colors.HexColor("#9a4a24"), alignment=0))
    styles.add(ParagraphStyle(name="BGBody", parent=styles["BodyText"], leading=14, spaceAfter=5))
    story = [
        Paragraph("BrowserGuard Security Assessment", styles["BGTitle"]),
        Paragraph("Permission and privacy risk review · informational analysis, not a malware verdict", styles["Italic"]),
        Spacer(1, 12),
    ]
    if extension.is_benchmark:
        story.append(Paragraph("SYNTHETIC BENCHMARK — fictional extension and publisher profile; not a real-world incident or security claim.", styles["Heading3"]))
    info = [
        ["Extension", extension.name],
        ["Version", extension.version],
        ["Manifest version", str(extension.manifest_version)],
        ["Risk score", f"{extension.risk_score}/100 — {extension.risk_level.title()}"],
        ["Analyzed at", extension.analyzed_at.isoformat()],
        ["SHA-256", extension.sha256],
        ["Purpose", extension.purpose or "Not provided"],
    ]
    table = Table(info, colWidths=[1.35 * inch, 5.65 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eee7e1")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#53351f")),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c9beb6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([table, Spacer(1, 12), Paragraph("Declared access", styles["Heading2"])])
    for label, key in (("Required permissions", "required"), ("Optional permissions", "optional"), ("Host permissions", "host"), ("Optional host permissions", "optional_host"), ("Content-script matches", "content_matches")):
        values = extension.permissions.get(key, [])
        story.append(Paragraph(f"<b>{label}:</b> {escape(', '.join(values)) if values else 'None declared'}", styles["BGBody"]))
    story.extend([Spacer(1, 5), Paragraph("Permission interpretation", styles["Heading2"])])
    if include_evidence:
        for detail in extension.permission_details:
            story.append(Paragraph(
                f"<b>{escape(str(detail['name']))}</b> ({escape(str(detail['source']))}; {escape(str(detail['category']))}) — "
                f"{escape(str(detail['capability']))} Privacy consideration: {escape(str(detail['privacy_impact']))} "
                f"Recommended: {escape(str(detail['recommended_action']))}",
                styles["BGBody"],
            ))
    story.extend([Spacer(1, 8), Paragraph("Risk score breakdown", styles["Heading2"])])
    for label, key in (("Permission sensitivity", "permission_sensitivity"), ("Host scope", "host_scope"), ("Permission combinations", "permission_combinations"), ("Purpose alignment", "purpose_alignment")):
        story.append(Paragraph(f"{label}: {extension.score_breakdown.get(key, 0)} points", styles["BGBody"]))
    story.append(Paragraph(extension.score_breakdown.get("method", ""), styles["Italic"]))
    story.extend([Spacer(1, 8), Paragraph("Findings", styles["Heading2"])])
    findings = extension.findings + [
        {"title": item["title"], "explanation": item["explanation"], "recommendation": item["recommended_action"], "evidence": item["evidence"]}
        for item in extension.combinations
    ]
    if not findings:
        story.append(Paragraph("No configured rule findings. This does not establish that the extension is safe.", styles["BGBody"]))
    for finding in findings:
        evidence = finding.get("evidence", {})
        evidence_text = evidence if isinstance(evidence, str) else str(evidence)
        story.append(Paragraph(f"<b>{escape(str(finding['title']))}</b>", styles["BGBody"]))
        finding_text = f"{escape(str(finding.get('explanation', '')))} "
        if include_evidence:
            finding_text += f"Evidence: {escape(evidence_text)} "
        finding_text += f"Recommendation: {escape(str(finding.get('recommendation', finding.get('recommended_action', 'Review the finding.'))))}"
        story.append(Paragraph(finding_text, styles["BGBody"]))
    story.extend([Spacer(1, 8), Paragraph("Purpose alignment", styles["Heading2"])])
    if not extension.purpose_findings:
        story.append(Paragraph("Purpose was not provided. Automated alignment could not be assessed.", styles["BGBody"]))
    for item in extension.purpose_findings:
        story.append(Paragraph(f"{escape(str(item['permission']))}: {escape(str(item['status']))} — {escape(str(item['explanation']))}", styles["BGBody"]))
    story.extend([Spacer(1, 8), Paragraph("Methodology and limitations", styles["Heading2"])])
    story.append(Paragraph("BrowserGuard statically inspects manifest declarations only. It does not execute, reverse engineer, or behaviorally inspect the extension. Permissions indicate potential capabilities, not proof of use or malicious intent. Scores prioritize analyst review; they are not probabilities of malware or formal compliance determinations.", styles["BGBody"]))
    document.build(story)
    return output.getvalue()


def create_comparison_report(left, right):
    output = BytesIO()
    document = SimpleDocTemplate(output, pagesize=letter, rightMargin=0.65 * inch, leftMargin=0.65 * inch)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="BGComparisonTitle", parent=styles["Title"], textColor=colors.HexColor("#9a4a24"), alignment=0))
    styles.add(ParagraphStyle(name="BGComparisonBody", parent=styles["BodyText"], leading=14, spaceAfter=5))
    story = [
        Paragraph("BrowserGuard Extension Comparison", styles["BGComparisonTitle"]),
        Paragraph("Manifest-based review; scores prioritize analyst attention and are not malware probabilities.", styles["Italic"]),
        Spacer(1, 12),
    ]
    if left.is_benchmark or right.is_benchmark:
        story.append(Paragraph("Synthetic benchmark records are fictional and do not represent real extensions, publishers, or incidents.", styles["Heading3"]))
    rows = [["Attribute", left.name, right.name]]
    rows.extend([
        ["Publisher", left.publisher, right.publisher],
        ["Sector", left.sector, right.sector],
        ["Risk score", f"{left.risk_score}/100 ({left.risk_level})", f"{right.risk_score}/100 ({right.risk_level})"],
        ["Privacy exposure", str(left.privacy_exposure_score), str(right.privacy_exposure_score)],
        ["Purpose alignment", str(left.purpose_alignment_score), str(right.purpose_alignment_score)],
        ["Declared permissions", str(len(left.permissions["all"])), str(len(right.permissions["all"]))],
        ["Host scope", ", ".join(left.permissions["host"] + left.permissions["optional_host"]) or "None", ", ".join(right.permissions["host"] + right.permissions["optional_host"]) or "None"],
    ])
    table = Table(rows, colWidths=[1.35 * inch, 2.85 * inch, 2.85 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#53351f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c9beb6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#eee7e1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([table, Spacer(1, 12)])
    shared = sorted(set(left.permissions["all"]) & set(right.permissions["all"]))
    for heading, values in (
        ("Shared permissions", shared),
        (f"Unique to {left.name}", sorted(set(left.permissions["all"]) - set(right.permissions["all"]))),
        (f"Unique to {right.name}", sorted(set(right.permissions["all"]) - set(left.permissions["all"]))),
    ):
        story.append(Paragraph(heading, styles["Heading2"]))
        story.append(Paragraph(escape(", ".join(values) if values else "None"), styles["BGComparisonBody"]))
    document.build(story)
    return output.getvalue()
