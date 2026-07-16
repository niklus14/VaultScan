#!/usr/bin/env python3
"""Generate VaultScan demo speech PDF (presentation script)."""
from __future__ import annotations

from pathlib import Path

from reportlab.lib.colors import HexColor, white
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    ListFlowable,
    ListItem,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)

OUT = Path(__file__).resolve().parent / "VaultScan_Demo_Speech.pdf"

# Brand colors
BG = HexColor("#0b0c10")
PANEL = HexColor("#111217")
BLUE = HexColor("#3874ff")
GREEN = HexColor("#00e676")
MUTED = HexColor("#6b7280")
TEXT = HexColor("#1a1a1a")
SOFT = HexColor("#374151")


def build() -> None:
    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="VaultScan — Live Demo Speech",
        author="VaultScan Team",
    )

    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "VSTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        textColor=HexColor("#0b0c10"),
        spaceAfter=4,
        alignment=TA_CENTER,
        leading=24,
    )
    subtitle = ParagraphStyle(
        "VSSub",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=MUTED,
        alignment=TA_CENTER,
        spaceAfter=10,
        leading=14,
    )
    section = ParagraphStyle(
        "VSSection",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        textColor=BLUE,
        spaceBefore=12,
        spaceAfter=6,
        leading=16,
    )
    body = ParagraphStyle(
        "VSBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10.5,
        textColor=TEXT,
        alignment=TA_JUSTIFY,
        leading=15,
        spaceAfter=8,
    )
    say = ParagraphStyle(
        "VSSay",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=10,
        textColor=SOFT,
        leading=14,
        leftIndent=8,
        spaceAfter=6,
        spaceBefore=2,
    )
    tip = ParagraphStyle(
        "VSTip",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        textColor=MUTED,
        leading=12,
        leftIndent=6,
        spaceAfter=8,
    )
    footer = ParagraphStyle(
        "VSFoot",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        textColor=MUTED,
        alignment=TA_CENTER,
    )

    story = []

    story.append(Paragraph("VaultScan", title))
    story.append(
        Paragraph(
            "Live Demo Speech Script · Cloud Security Posture Management",
            subtitle,
        )
    )
    story.append(
        Paragraph(
            "Polished English version for jury / presentation use · ~4–6 minutes depending on demo pace",
            subtitle,
        )
    )
    story.append(
        HRFlowable(width="100%", thickness=1.5, color=BLUE, spaceAfter=10)
    )

    # Opening
    story.append(Paragraph("1. Opening", section))
    story.append(
        Paragraph(
            "Good morning. Today we will walk you through <b>VaultScan</b> — "
            "our Cloud Security Posture Management platform. "
            "VaultScan finds dangerous cloud misconfigurations, explains how attackers "
            "can chain them, helps fix them safely, and proves the work with reports "
            "and email alerts. We will move through the product the same way a real team would use it.",
            body,
        )
    )

    # Settings
    story.append(Paragraph("2. Settings — Connecting the Cloud", section))
    story.append(
        Paragraph(
            "First, we open the <b>Settings</b> section. This is where the connection begins. "
            "Here we enter our <b>cloud credentials</b> — carefully, with limited access — "
            "or we switch to <b>Demo mode</b> when we want a safe practice environment. "
            "Once the connection is saved, VaultScan is ready to scan without asking for keys on every visit.",
            body,
        )
    )
    story.append(
        Paragraph(
            "<i>[On screen: Settings → Cloud Connection → Save → Test Connection]</i>",
            tip,
        )
    )

    # Schedule + Gmail
    story.append(
        Paragraph("3. Scheduled Checks &amp; Gmail Alerts — Continuous Protection", section)
    )
    story.append(
        Paragraph(
            "One of the most important strengths of VaultScan is that security does not stop when you leave the dashboard. "
            "In the same Settings area, you can configure a <b>timer</b> and your <b>Gmail</b>. "
            "With that, VaultScan can run automatic scans at any interval you choose — for example every hour, every 45 minutes, or every day. "
            "When the scan finishes, a clear alert is sent by email from <b>VaultScan Company</b>. "
            "That means you can see the result in your own inbox <b>without signing into the system again</b>.",
            body,
        )
    )
    story.append(
        Paragraph(
            "And when something serious appears, you are not left alone with a red list. "
            "Our integrated <b>LLM assistant</b> helps you understand critical and other misconfigurations "
            "in plain language, and guides you on how to stop the damage quickly.",
            body,
        )
    )
    story.append(
        Paragraph(
            "<i>[On screen: enable schedule + Gmail alerts → enter your Gmail → Save → optional Test email]</i>",
            tip,
        )
    )

    # Scan
    story.append(Paragraph("4. Launch Scan — From Connection to Evidence", section))
    story.append(
        Paragraph(
            "Because the connection is ready, we now run a live scan and look at the results. "
            "Press <b>Launch active scan</b>. VaultScan inspects the cloud configuration, "
            "scores the posture, and produces findings with evidence.",
            body,
        )
    )
    story.append(
        Paragraph(
            "<i>[On screen: Launch Active Scan — wait for LIVE results]</i>",
            tip,
        )
    )

    # Overview
    story.append(Paragraph("5. Overview — Risk at a Glance", section))
    story.append(
        Paragraph(
            "In the <b>Overview</b>, you immediately see how exposed the service is — "
            "from critical issues down to lower-severity misconfigurations. "
            "This is the command room for managers and engineers at the same time: "
            "one health score, severity breakdown, and clear status of the environment.",
            body,
        )
    )
    story.append(
        Paragraph(
            "We also show that the process is aligned with <b>industry standards</b> — "
            "mapping findings to well-known security and compliance expectations, "
            "not inventing random checks. "
            "On the chart, you can watch how the security level changes after each scan — "
            "improving when issues are fixed, or dropping when new risks appear.",
            body,
        )
    )

    # Report + Findings
    story.append(Paragraph("6. Generate Report &amp; Findings — Proof You Can Share", section))
    story.append(
        Paragraph(
            "Once a scan is complete, every problem and its remediation path can be opened in detail. "
            "From <b>Generate Report</b>, you can create and download a professional package — "
            "including explanations, priorities, and practical fix guidance — ready for leadership or auditors.",
            body,
        )
    )
    story.append(
        Paragraph(
            "In the activity stream and history views, you can filter and review problems discovered over time. "
            "The same issues are fully documented in the <b>Findings</b> tab: what is wrong, why it matters, "
            "how severe it is, and how to correct it.",
            body,
        )
    )

    # Attack paths
    story.append(Paragraph("7. Attack Paths — Understanding the Real Danger", section))
    story.append(
        Paragraph(
            "Now we move to <b>Attack Paths</b>. This section is critical for deep understanding. "
            "VaultScan does not only say “there is a problem.” "
            "It shows an <b>attack chain</b> — how small mistakes combine into a real breach story.",
            body,
        )
    )
    story.append(
        Paragraph(
            "Here you can see how a single weak setting can grow into full information exposure, "
            "and how the attack radius expands step by step. "
            "That is the difference between a checklist and true risk storytelling.",
            body,
        )
    )
    story.append(
        Paragraph(
            "<i>[On screen: open a critical path — walk the chain from entry to impact]</i>",
            tip,
        )
    )

    # Fixing
    story.append(Paragraph("8. Fixing Options — From Detection to Safe Repair", section))
    story.append(
        Paragraph(
            "VaultScan does not stop at scanning. In <b>Fixing Options</b>, you can resolve issues "
            "without fighting a confusing console full of raw cloud menus.",
            body,
        )
    )
    story.append(
        Paragraph(
            "First, we choose <b>Plan all fixes</b>. The platform builds a map of every problem that should be corrected. "
            "For each item, our model provides guidance and context so the team knows what will change and why.",
            body,
        )
    )
    story.append(
        Paragraph(
            "After reviewing the plan, you type the confirmation phrase and select <b>Apply fixes</b>. "
            "Misconfigurations are then corrected at the source. "
            "While the process runs, the system takes a <b>snapshot</b> of the previous state.",
            body,
        )
    )
    story.append(
        Paragraph(
            "With <b>Fix change report</b>, you can compare in detail how the cloud was configured before "
            "and what it looks like after the problems were resolved. "
            "And if anything unexpected happens, you can reverse the changes with "
            "<b>Please make it as before</b> — a controlled rollback path.",
            body,
        )
    )
    story.append(
        Paragraph(
            "Every important action is also expressed as <b>CLI commands</b>. "
            "You can copy them and run them directly in your cloud environment if you prefer a terminal workflow.",
            body,
        )
    )
    story.append(
        Paragraph(
            "<i>[On screen: Plan all fixes → review → confirm → Apply → Fix change report → optional rollback]</i>",
            tip,
        )
    )

    # History
    story.append(Paragraph("9. Scan History — Security as a Process", section))
    story.append(
        Paragraph(
            "Finally, in <b>Scan History</b>, every scan operation is recorded. "
            "Security is not a one-time event — it is continuous care. "
            "Here you can prove progress over time: before and after fixes, and after each scheduled check.",
            body,
        )
    )

    # Close
    story.append(Paragraph("10. Closing", section))
    story.append(
        Paragraph(
            "To summarize: VaultScan connects carefully, scans continuously, explains risk clearly, "
            "maps attack paths, fixes safely with plan–apply–rollback, emails results to your inbox, "
            "and keeps a full history of the journey. "
            "That is how we turn cloud misconfigurations from silent open doors into a controlled, "
            "auditable security process.",
            body,
        )
    )
    story.append(
        Paragraph(
            "<b>Scan the vault. Secure the cloud. Before someone else does.</b> "
            "Thank you — we are ready for questions.",
            body,
        )
    )

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.8, color=HexColor("#e5e7eb"), spaceAfter=8))
    story.append(
        Paragraph(
            "VaultScan Demo Speech · English presentation script · Academic / portfolio CSPM project",
            footer,
        )
    )

    # Optional short cue card page content as appendix
    story.append(Spacer(1, 14))
    story.append(Paragraph("Quick Cue Card (for the speaker)", section))
    cues = [
        "Settings → connect cloud or Demo",
        "Schedule + Gmail → automatic scans &amp; inbox alerts",
        "Launch scan → Overview score + standards + trend chart",
        "Generate Report / Findings → evidence &amp; remediations",
        "Attack Paths → chain / blast radius story",
        "Fixing Options → Plan → Apply → Change report → Rollback",
        "CLI commands + Scan History → continuous improvement",
        "Close with the full loop sentence",
    ]
    for i, c in enumerate(cues, 1):
        story.append(Paragraph(f"<b>{i}.</b>  {c}", tip))

    def _header_footer(canvas, doc_):
        canvas.saveState()
        canvas.setStrokeColor(BLUE)
        canvas.setLineWidth(2)
        canvas.line(18 * mm, A4[1] - 10 * mm, A4[0] - 18 * mm, A4[1] - 10 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, "VaultScan — Demo Speech")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    build()
