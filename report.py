import os
import re
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

TOOL_VERSION = "1.0"

VERDICT_COLORS = {
    "CLEAN": colors.HexColor("#1a7f3c"),
    "SUSPICIOUS": colors.HexColor("#d97706"),
    "MALICIOUS": colors.HexColor("#b91c1c"),
}

VERDICT_BG = {
    "CLEAN": colors.HexColor("#d1fae5"),
    "SUSPICIOUS": colors.HexColor("#fef3c7"),
    "MALICIOUS": colors.HexColor("#fee2e2"),
}

RECOMMENDATIONS = {
    "CLEAN": (
        "No malicious indicators were found for this target. No immediate action is required. "
        "Continue routine monitoring as part of standard security operations. "
        "Re-scan periodically if the target appears in new alerts or logs."
    ),
    "SUSPICIOUS": (
        "A low number of vendors flagged this target. Treat it with caution. "
        "Increase monitoring on any systems that have communicated with this target. "
        "Review related logs, check for anomalous traffic patterns, and investigate "
        "the context in which this target was observed. Consider blocking at the perimeter "
        "while investigation is ongoing."
    ),
    "MALICIOUS": (
        "Multiple vendors confirmed this target as malicious. Block it immediately across "
        "all perimeter controls including firewalls, DNS filters, and proxy layers. "
        "Identify all internal systems that contacted this target and initiate incident "
        "response procedures. Preserve logs for forensic analysis and assess the scope "
        "of potential exposure before resuming normal operations."
    ),
}


def _sanitize_target(target):
    return re.sub(r"[./\\]", "_", target)


def _build_styles():
    base = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=base["Title"],
        fontSize=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
        fontName="Helvetica-Bold",
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=base["Heading2"],
        fontSize=12,
        textColor=colors.HexColor("#1e3a5f"),
        spaceBefore=16,
        spaceAfter=6,
        fontName="Helvetica-Bold",
        borderPad=4,
    )

    meta_style = ParagraphStyle(
        "Meta",
        parent=base["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#475569"),
        spaceAfter=4,
        fontName="Helvetica",
    )

    body_style = ParagraphStyle(
        "Body",
        parent=base["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#1e293b"),
        leading=15,
        spaceAfter=8,
        fontName="Helvetica",
    )

    return {
        "title": title_style,
        "heading": heading_style,
        "meta": meta_style,
        "body": body_style,
    }


def _section_divider():
    data = [[""] ]
    t = Table(data, colWidths=[6.5 * inch])
    t.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return t


def _build_verdict_banner(verdict, styles):
    fg = VERDICT_COLORS.get(verdict, colors.black)
    bg = VERDICT_BG.get(verdict, colors.white)

    label = ParagraphStyle(
        "VerdictLabel",
        parent=styles["body"],
        fontSize=18,
        textColor=fg,
        fontName="Helvetica-Bold",
        alignment=1,
        spaceAfter=0,
    )

    text = Paragraph(verdict, label)
    banner = Table([[text]], colWidths=[6.5 * inch])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("ROUNDEDCORNERS", [6]),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("BOX", (0, 0), (-1, -1), 1.5, fg),
    ]))
    return banner


def _build_summary_table(scan_result):
    raw = scan_result.get("raw_data", {})
    harmless = raw.get("harmless_count", 0)
    undetected = raw.get("undetected_count", 0)

    header_style = ParagraphStyle(
        "TableHeader",
        fontSize=9,
        textColor=colors.white,
        fontName="Helvetica-Bold",
        alignment=1,
    )
    cell_style = ParagraphStyle(
        "TableCell",
        fontSize=10,
        textColor=colors.HexColor("#1e293b"),
        fontName="Helvetica",
        alignment=1,
    )

    headers = ["Metric", "Count"]
    rows = [
        ["Malicious", str(scan_result.get("malicious_count", 0))],
        ["Suspicious", str(scan_result.get("suspicious_count", 0))],
        ["Harmless", str(harmless)],
        ["Undetected", str(undetected)],
        ["Total Vendors Queried", str(scan_result.get("total_vendors", 0))],
    ]

    table_data = [
        [Paragraph(h, header_style) for h in headers]
    ] + [
        [Paragraph(r[0], cell_style), Paragraph(r[1], cell_style)] for r in rows
    ]

    col_widths = [4.0 * inch, 2.5 * inch]
    t = Table(table_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return t


def _build_raw_intel_table(raw_data):
    field_map_ip_domain = [
        ("country", "Country"),
        ("as_owner", "AS Owner"),
        ("network", "Network"),
        ("reputation", "Reputation Score"),
    ]
    field_map_hash = [
        ("meaningful_name", "File Name"),
        ("file_type", "File Type"),
        ("file_size", "File Size (bytes)"),
    ]

    fields = field_map_hash if "file_size" in raw_data else field_map_ip_domain

    header_style = ParagraphStyle(
        "IntelHeader",
        fontSize=9,
        textColor=colors.white,
        fontName="Helvetica-Bold",
        alignment=1,
    )
    key_style = ParagraphStyle(
        "IntelKey",
        fontSize=10,
        textColor=colors.HexColor("#374151"),
        fontName="Helvetica-Bold",
    )
    val_style = ParagraphStyle(
        "IntelVal",
        fontSize=10,
        textColor=colors.HexColor("#1e293b"),
        fontName="Helvetica",
    )

    rows = []
    for key, label in fields:
        val = raw_data.get(key)
        if val is not None:
            rows.append([Paragraph(label, key_style), Paragraph(str(val), val_style)])

    if not rows:
        rows = [[Paragraph("No additional data available.", val_style), Paragraph("", val_style)]]

    table_data = [[Paragraph("Field", header_style), Paragraph("Value", header_style)]] + rows
    col_widths = [2.5 * inch, 4.0 * inch]

    t = Table(table_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return t


def generate_report(scan_result, output_dir="."):
    target = scan_result.get("target", "unknown")
    target_type = scan_result.get("target_type", "unknown")
    verdict = scan_result.get("verdict", "CLEAN")
    raw_data = scan_result.get("raw_data", {})

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    safe_target = _sanitize_target(target)
    filename = f"threat_{safe_target}_{timestamp}.pdf"
    output_path = os.path.join(output_dir, filename)
    os.makedirs(output_dir, exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=1 * inch,
        rightMargin=1 * inch,
        topMargin=1 * inch,
        bottomMargin=1 * inch,
    )

    styles = _build_styles()
    story = []

    # Section 1: Header
    story.append(Paragraph("Threat Intelligence Report", styles["title"]))
    story.append(_section_divider())
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"<b>Target:</b> {target}", styles["meta"]))
    story.append(Paragraph(f"<b>Target Type:</b> {target_type.upper()}", styles["meta"]))
    story.append(Paragraph(f"<b>Scan Date:</b> {scan_date}", styles["meta"]))
    story.append(Paragraph(f"<b>Tool Version:</b> {TOOL_VERSION}", styles["meta"]))
    story.append(Spacer(1, 16))

    # Section 2: Verdict Banner
    story.append(Paragraph("Verdict", styles["heading"]))
    story.append(_section_divider())
    story.append(Spacer(1, 8))
    story.append(_build_verdict_banner(verdict, styles))
    story.append(Spacer(1, 16))

    # Section 3: Analysis Summary
    story.append(Paragraph("Analysis Summary", styles["heading"]))
    story.append(_section_divider())
    story.append(Spacer(1, 8))
    story.append(_build_summary_table(scan_result))
    story.append(Spacer(1, 16))

    # Section 4: Raw Intelligence
    story.append(Paragraph("Raw Intelligence", styles["heading"]))
    story.append(_section_divider())
    story.append(Spacer(1, 8))
    story.append(_build_raw_intel_table(raw_data))
    story.append(Spacer(1, 16))

    # Section 5: Recommendations
    story.append(Paragraph("Recommendations", styles["heading"]))
    story.append(_section_divider())
    story.append(Spacer(1, 8))
    rec_text = RECOMMENDATIONS.get(verdict, RECOMMENDATIONS["CLEAN"])
    story.append(Paragraph(rec_text, styles["body"]))

    doc.build(story)
    return output_path
