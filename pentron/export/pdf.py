"""PDF report generation (ReportLab)."""

import datetime
from html import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from . import common


def export_pdf(data: dict, output_dir: str) -> str:
    sl, tgt, date, risk, ai = common.session_summary(data)
    filename = common.safe_filename(output_dir, sl, tgt, "pdf")
    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
    )

    title_style = ParagraphStyle(
        "t",
        fontSize=22,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#c0392b"),
        spaceAfter=4,
    )
    sub_style = ParagraphStyle(
        "s",
        fontSize=10,
        fontName="Helvetica",
        textColor=colors.HexColor("#555555"),
        spaceAfter=2,
    )
    h1_style = ParagraphStyle(
        "h1",
        fontSize=13,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#2c3e50"),
        spaceBefore=10,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "b", fontSize=9, fontName="Helvetica", textColor=colors.black, leading=13
    )
    code_style = ParagraphStyle(
        "c",
        fontSize=7.5,
        fontName="Courier",
        textColor=colors.HexColor("#2c3e50"),
        backColor=colors.HexColor("#f4f4f4"),
        leading=11,
        leftIndent=6,
        rightIndent=6,
        spaceBefore=2,
        spaceAfter=2,
    )
    footer_style = ParagraphStyle(
        "f", fontSize=7, textColor=colors.HexColor("#aaaaaa"), alignment=TA_CENTER
    )
    story = []

    story.append(Paragraph("PENTRON", title_style))
    story.append(Paragraph("AI Penetration Testing Report", sub_style))
    story.append(
        HRFlowable(
            width="100%", thickness=1.5, color=colors.HexColor("#c0392b"), spaceAfter=8
        )
    )

    risk_color = colors.HexColor(common.RISK_COLORS.get(risk.upper(), "#7f8c8d"))
    meta = [
        ["Target", tgt],
        ["Scan Date", date],
        ["Session", f"SL# {sl}"],
        ["Risk Level", risk],
        ["Generated", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
    ]
    mt = Table(meta, colWidths=[35 * mm, 130 * mm])
    mt.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (1, 3), (1, 3), risk_color),
                ("FONTNAME", (1, 3), (1, 3), "Helvetica-Bold"),
                (
                    "ROWBACKGROUNDS",
                    (0, 0),
                    (-1, -1),
                    [colors.HexColor("#f9f9f9"), colors.white],
                ),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(mt)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Vulnerabilities", h1_style))
    story.append(
        HRFlowable(
            width="100%", thickness=0.5, color=colors.HexColor("#dddddd"), spaceAfter=6
        )
    )
    if data["vulns"]:
        vd = [["#", "Vulnerability", "Severity", "Port", "Service"]]
        for v in data["vulns"]:
            vd.append(
                [
                    str(v[0]),
                    str(v[2] or "-"),
                    str(v[3] or "-").upper(),
                    str(v[4] or "-"),
                    str(v[5] or "-"),
                ]
            )
        vt = Table(
            vd, colWidths=[10 * mm, 72 * mm, 24 * mm, 18 * mm, 28 * mm], repeatRows=1
        )
        vts = [
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
            ("PADDING", (0, 0), (-1, -1), 5),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [colors.HexColor("#f9f9f9"), colors.white],
            ),
        ]
        for i, v in enumerate(data["vulns"], 1):
            sc = colors.HexColor(
                common.SEVERITY_COLORS.get((v[3] or "unknown").lower(), "#7f8c8d")
            )
            vts.append(("TEXTCOLOR", (2, i), (2, i), sc))
            vts.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
        vt.setStyle(TableStyle(vts))
        story.append(vt)
        story.append(Spacer(1, 6))

        story.append(Paragraph("Vulnerability Details", h1_style))
        story.append(
            HRFlowable(
                width="100%",
                thickness=0.5,
                color=colors.HexColor("#dddddd"),
                spaceAfter=6,
            )
        )
        for v in data["vulns"]:
            sc = colors.HexColor(
                common.SEVERITY_COLORS.get((v[3] or "unknown").lower(), "#7f8c8d")
            )
            lbl = ParagraphStyle(
                "vl", fontSize=9, fontName="Helvetica-Bold", textColor=sc
            )
            label = escape(f"[{(v[3] or 'UNKNOWN').upper()}] {v[2]}")
            story.append(Paragraph(label, lbl))
            if v[6]:
                story.append(Paragraph(escape(str(v[6])), body_style))
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph("No vulnerabilities recorded.", body_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("Fixes & Mitigations", h1_style))
    story.append(
        HRFlowable(
            width="100%", thickness=0.5, color=colors.HexColor("#dddddd"), spaceAfter=6
        )
    )
    if data["fixes"]:
        for f in data["fixes"]:
            story.append(Paragraph(f"Fix for vuln id={f[2]}:", body_style))
            story.append(Paragraph(escape(str(f[3] or "-")), code_style))
            story.append(Spacer(1, 3))
    else:
        story.append(Paragraph("No fixes recorded.", body_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("Exploits Attempted", h1_style))
    story.append(
        HRFlowable(
            width="100%", thickness=0.5, color=colors.HexColor("#dddddd"), spaceAfter=6
        )
    )
    if data["exploits"]:
        ed = [["#", "Exploit", "Tool", "Result"]]
        for e in data["exploits"]:
            ed.append(
                [
                    str(e[0]),
                    str(e[2] or "-")[:60],
                    str(e[3] or "-")[:30],
                    str(e[5] or "-")[:30],
                ]
            )
        et = Table(ed, colWidths=[10 * mm, 80 * mm, 40 * mm, 28 * mm])
        et.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.HexColor("#f9f9f9"), colors.white],
                    ),
                ]
            )
        )
        story.append(et)
    else:
        story.append(Paragraph("No exploits recorded.", body_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("Suggested Exploit Paths", h1_style))
    if data.get("suggestions"):
        for suggestion in data["suggestions"]:
            story.append(Paragraph(escape(str(suggestion[2] or "-")), body_style))
            story.append(Paragraph(escape(str(suggestion[3] or "")), body_style))
    else:
        story.append(Paragraph("None recorded.", body_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("AI-dispatched Tool Calls", h1_style))
    if data.get("tool_calls"):
        for call in data["tool_calls"]:
            state = "blocked" if call[5] else "executed"
            text = escape(f"{call[2]}: {call[3]} ({state})")
            story.append(Paragraph(text, code_style))
    else:
        story.append(Paragraph("None executed.", body_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("AI Analysis Summary", h1_style))
    story.append(
        HRFlowable(
            width="100%", thickness=0.5, color=colors.HexColor("#dddddd"), spaceAfter=6
        )
    )
    if ai:
        for line in str(ai).split("\n"):
            line = line.strip()
            if line:
                story.append(Paragraph(escape(line), body_style))
                story.append(Spacer(1, 2))
    else:
        story.append(Paragraph("No AI analysis recorded.", body_style))

    story.append(Spacer(1, 10))
    story.append(
        HRFlowable(
            width="100%", thickness=0.5, color=colors.HexColor("#dddddd"), spaceAfter=4
        )
    )
    story.append(
        Paragraph(
            "Generated by PENTRON — AI Penetration Testing Assistant | "
            "github.com/SaiedZ/PenTron | For authorized use only.",
            footer_style,
        )
    )

    doc.build(story)
    return filename
