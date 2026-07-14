"""
Gmail / SMTP email alerts for VaultScan scheduled scans.
Uses Gmail App Password (not the normal account password).
"""
from __future__ import annotations

import html
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any


def _esc(v: Any) -> str:
    return html.escape(str(v if v is not None else ""))


def build_scan_email(
    scan: dict[str, Any],
    *,
    include_finding_details: bool = True,
    max_findings: int = 12,
) -> tuple[str, str, str]:
    """Return (subject, text_body, html_body)."""
    score = scan.get("score", "—")
    total = scan.get("total_findings", 0)
    summary = scan.get("summary") or {}
    critical = summary.get("CRITICAL", 0)
    high = summary.get("HIGH", 0)
    medium = summary.get("MEDIUM", 0)
    low = summary.get("LOW", 0)
    account = scan.get("account_id") or "n/a"
    region = scan.get("region") or "n/a"
    mode = scan.get("mode") or "n/a"
    scan_id = scan.get("scan_id") or "n/a"
    ts = scan.get("timestamp") or ""

    subject = (
        f"[VaultScan] Score {score}/100 · {critical} critical · {high} high "
        f"({total} findings)"
    )

    text_lines = [
        "VaultScan scheduled security check",
        "=================================",
        f"Scan ID:     {scan_id}",
        f"When:        {ts}",
        f"Account:     {account}",
        f"Region:      {region}",
        f"Mode:        {mode}",
        f"Score:       {score}/100",
        f"Findings:    {total} total",
        f"  CRITICAL:  {critical}",
        f"  HIGH:      {high}",
        f"  MEDIUM:    {medium}",
        f"  LOW:       {low}",
        "",
    ]

    findings = list(scan.get("findings") or scan.get("vulnerabilities") or [])
    if include_finding_details and findings:
        text_lines.append("Top findings")
        text_lines.append("------------")
        for f in findings[:max_findings]:
            sev = f.get("severity") or "?"
            title = f.get("title") or f.get("description") or "Finding"
            res = f.get("resource") or f.get("id") or ""
            text_lines.append(f"[{sev}] {title}")
            if res:
                text_lines.append(f"  Resource: {res}")
            rem = f.get("remediation") or ""
            if rem:
                text_lines.append(f"  Fix: {rem[:200]}")
            text_lines.append("")
    else:
        text_lines.append("Open VaultScan → Findings for full detail.")

    text_lines.append("")
    text_lines.append("— VaultScan automated alert")
    text_body = "\n".join(text_lines)

    rows = ""
    if include_finding_details and findings:
        for f in findings[:max_findings]:
            sev = _esc(f.get("severity") or "?")
            title = _esc(f.get("title") or f.get("description") or "Finding")
            res = _esc(f.get("resource") or f.get("id") or "—")
            color = {
                "CRITICAL": "#ff3d57",
                "HIGH": "#ff9900",
                "MEDIUM": "#3874ff",
                "LOW": "#6b7280",
            }.get(str(f.get("severity") or "").upper(), "#6b7280")
            rows += (
                f"<tr>"
                f"<td style='padding:8px;border-bottom:1px solid #222;color:{color};"
                f"font-weight:700;font-size:12px'>{sev}</td>"
                f"<td style='padding:8px;border-bottom:1px solid #222;color:#f4f6fb;"
                f"font-size:13px'>{title}<div style='color:#6b7280;font-size:11px;"
                f"margin-top:4px'>{res}</div></td>"
                f"</tr>"
            )

    findings_block = (
        f"""
        <h3 style="color:#f4f6fb;font-size:14px;margin:24px 0 8px">Top findings</h3>
        <table style="width:100%;border-collapse:collapse">{rows}</table>
        """
        if rows
        else "<p style='color:#6b7280;font-size:13px'>No findings listed, or detail disabled.</p>"
    )

    html_body = f"""
    <div style="font-family:Inter,Segoe UI,system-ui,sans-serif;background:#0b0c10;
         color:#f4f6fb;padding:24px">
      <div style="max-width:640px;margin:0 auto;background:#111217;border:1px solid
           rgba(255,255,255,0.08);border-radius:10px;padding:24px">
        <p style="color:#3874ff;font-size:11px;letter-spacing:0.14em;margin:0 0 8px">
          VAULTSCAN · SCHEDULED CHECK
        </p>
        <h1 style="margin:0 0 8px;font-size:22px">Cloud security alert</h1>
        <p style="color:#6b7280;font-size:13px;margin:0 0 20px">
          Scan {_esc(scan_id)} · {_esc(ts)}
        </p>
        <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px">
          <div style="background:#0b0c10;border:1px solid rgba(255,255,255,0.08);
               border-radius:8px;padding:12px 16px;min-width:100px">
            <div style="color:#6b7280;font-size:10px;letter-spacing:0.1em">SCORE</div>
            <div style="font-size:28px;font-weight:700;color:#f4f6fb">{_esc(score)}</div>
          </div>
          <div style="background:#0b0c10;border:1px solid rgba(255,255,255,0.08);
               border-radius:8px;padding:12px 16px;min-width:80px">
            <div style="color:#ff3d57;font-size:10px;letter-spacing:0.1em">CRITICAL</div>
            <div style="font-size:24px;font-weight:700">{_esc(critical)}</div>
          </div>
          <div style="background:#0b0c10;border:1px solid rgba(255,255,255,0.08);
               border-radius:8px;padding:12px 16px;min-width:80px">
            <div style="color:#ff9900;font-size:10px;letter-spacing:0.1em">HIGH</div>
            <div style="font-size:24px;font-weight:700">{_esc(high)}</div>
          </div>
          <div style="background:#0b0c10;border:1px solid rgba(255,255,255,0.08);
               border-radius:8px;padding:12px 16px;min-width:80px">
            <div style="color:#6b7280;font-size:10px;letter-spacing:0.1em">TOTAL</div>
            <div style="font-size:24px;font-weight:700">{_esc(total)}</div>
          </div>
        </div>
        <p style="color:#6b7280;font-size:12px;margin:0 0 8px">
          Account {_esc(account)} · {_esc(region)} · mode {_esc(mode)}
        </p>
        {findings_block}
        <p style="color:#3a3a3a;font-size:11px;margin:28px 0 0">
          Automated message from VaultScan. Open the dashboard for full report, attack paths, and fixes.
        </p>
      </div>
    </div>
    """
    return subject, text_body, html_body


def send_email(
    *,
    smtp_host: str,
    smtp_port: int,
    gmail_address: str,
    gmail_app_password: str,
    recipients: list[str],
    subject: str,
    text_body: str,
    html_body: str | None = None,
) -> None:
    if not gmail_address or not gmail_app_password:
        raise ValueError("Gmail address and App Password are required.")
    if not recipients:
        raise ValueError("At least one recipient is required.")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = gmail_address
    msg["To"] = ", ".join(recipients)
    msg.set_content(text_body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_host, int(smtp_port), timeout=45) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(gmail_address, gmail_app_password)
        server.send_message(msg)


def send_scan_alert(scan: dict[str, Any], profile: dict[str, Any]) -> str:
    from schedule_store import parse_recipients

    recipients = parse_recipients(profile.get("recipients"))
    subject, text_body, html_body = build_scan_email(
        scan,
        include_finding_details=bool(profile.get("include_finding_details", True)),
    )
    send_email(
        smtp_host=profile.get("smtp_host") or "smtp.gmail.com",
        smtp_port=int(profile.get("smtp_port") or 587),
        gmail_address=(profile.get("gmail_address") or "").strip(),
        gmail_app_password=(profile.get("gmail_app_password") or "").strip(),
        recipients=recipients,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
    )
    return f"Alert sent to {', '.join(recipients)}"


def send_test_email(profile: dict[str, Any]) -> str:
    from schedule_store import parse_recipients

    recipients = parse_recipients(profile.get("recipients"))
    if not recipients and profile.get("gmail_address"):
        recipients = [str(profile["gmail_address"]).strip()]
    subject = "[VaultScan] Test alert — email is working"
    text_body = (
        "This is a VaultScan test message.\n\n"
        "If you received this, Gmail SMTP settings are correct.\n"
        "Scheduled scan alerts will use the same channel.\n"
    )
    html_body = f"""
    <div style="font-family:system-ui,sans-serif;padding:24px;background:#0b0c10;color:#f4f6fb">
      <div style="max-width:520px;margin:0 auto;background:#111217;border-radius:10px;
           padding:24px;border:1px solid rgba(255,255,255,0.08)">
        <p style="color:#3874ff;font-size:11px;letter-spacing:0.14em">VAULTSCAN</p>
        <h2 style="margin:8px 0">Test alert OK</h2>
        <p style="color:#6b7280;font-size:14px">
          Gmail delivery works. Scheduled scans can email reports to your assigned recipients.
        </p>
      </div>
    </div>
    """
    send_email(
        smtp_host=profile.get("smtp_host") or "smtp.gmail.com",
        smtp_port=int(profile.get("smtp_port") or 587),
        gmail_address=(profile.get("gmail_address") or "").strip(),
        gmail_app_password=(profile.get("gmail_app_password") or "").strip(),
        recipients=recipients,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
    )
    return f"Test email sent to {', '.join(recipients)}"
