"""Cloud Assistant client for posture summaries, reports, and chat."""
from __future__ import annotations

import json
from typing import Any

import httpx

from config import settings

SYSTEM_PROMPT = """You are Cloud Assistant — VaultScan's built-in cloud security analyst.
You help users understand AWS misconfigurations, compliance impact, attack paths, and remediation steps.

Rules:
- Always identify yourself as Cloud Assistant (VaultScan). Never mention third-party model brands, API vendors, or underlying model names.
- Be precise, technical, and actionable.
- Prefer concrete AWS CLI / console remediation steps.
- Map issues to CIS AWS, NIST 800-53, GDPR, HIPAA, SOC2 when relevant.
- When scan findings are provided in context, ground answers in those findings.
- Keep answers concise unless the user asks for deep detail.
- Never invent AWS account IDs or findings that are not in the provided context.
"""


class GrokError(RuntimeError):
    pass


async def chat_completion(
    messages: list[dict[str, str]],
    *,
    temperature: float = 0.3,
    max_tokens: int = 1200,
) -> str:
    if not settings.grok_api_key:
        raise GrokError("GROK_API_KEY is not configured in backend/.env")

    url = f"{settings.grok_base_url}/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.grok_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": settings.grok_model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    async with httpx.AsyncClient(timeout=90.0) as client:
        resp = await client.post(url, headers=headers, json=payload)
        if resp.status_code >= 400:
            raise GrokError(f"Grok API {resp.status_code}: {resp.text[:500]}")
        data = resp.json()

    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise GrokError(f"Unexpected Grok response shape: {data}") from exc


def findings_context(scan: dict[str, Any] | None) -> str:
    if not scan:
        return "No scan has been run yet in this session."

    lines = [
        f"Scan ID: {scan.get('scan_id')}",
        f"Timestamp: {scan.get('timestamp')}",
        f"Mode: {scan.get('mode')}  Account: {scan.get('account_id')}  Region: {scan.get('region')}",
        f"Role: {scan.get('role_arn')}",
        f"Posture score: {scan.get('score')}/100",
        f"Summary: {scan.get('summary')}",
        f"Total findings: {scan.get('total_findings')}",
        "",
        "Findings:",
    ]
    for i, f in enumerate(scan.get("findings") or scan.get("vulnerabilities") or [], 1):
        lines.append(
            f"{i}. [{f.get('severity')}] {f.get('service')} {f.get('resource')}: "
            f"{f.get('title') or f.get('description')}"
        )
        if f.get("remediation"):
            lines.append(f"   Fix: {f['remediation']}")
    return "\n".join(lines)


async def summarize_scan(scan: dict[str, Any]) -> str:
    context = findings_context(scan)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Write an executive + technical summary of this VaultScan result.\n"
                "Include: overall risk, top 3 issues, business impact, and next actions.\n"
                "Use markdown with short sections.\n\n"
                f"{context}"
            ),
        },
    ]
    return await chat_completion(messages, temperature=0.2, max_tokens=1500)


async def generate_report_narrative(scan: dict[str, Any]) -> dict[str, str]:
    """
    Produce structured, plain-language report sections for the UI.

    Returns keys: headline, risk_level, executive_summary, what_this_means,
    priority_actions, technical_notes. Falls back to deterministic text if AI fails.
    """
    context = findings_context(scan)
    score = scan.get("score", 0)
    summary = scan.get("summary") or {}
    total = scan.get("total_findings", 0)

    if score >= 90:
        risk = "LOW"
    elif score >= 70:
        risk = "MODERATE"
    elif score >= 40:
        risk = "HIGH"
    else:
        risk = "CRITICAL"

    # Deterministic fallback (always available without AI)
    fallback = {
        "headline": f"Cloud security posture is {risk.lower()} ({score}/100)",
        "risk_level": risk,
        "executive_summary": (
            f"VaultScan reviewed this AWS environment and found {total} issue(s): "
            f"{summary.get('CRITICAL', 0)} critical, {summary.get('HIGH', 0)} high, "
            f"{summary.get('MEDIUM', 0)} medium, and {summary.get('LOW', 0)} low. "
            f"A posture score of {score}/100 means "
            + (
                "the environment is in good shape with only minor improvements needed."
                if score >= 90
                else "security gaps need attention before they can be exploited."
                if score >= 70
                else "attackers may be able to abuse exposed resources — prioritize fixes this week."
                if score >= 40
                else "urgent remediation is required; critical exposure is present."
            )
        ),
        "what_this_means": (
            "Each finding is a misconfiguration — a setting that is weaker than security best practice. "
            "Critical and High issues often mean public exposure (open storage, open admin ports) or "
            "over-powered identities. Fix those first. Medium and Low usually improve resilience "
            "(encryption, logging, versioning) and compliance scores."
        ),
        "priority_actions": _fallback_priority_actions(scan),
        "technical_notes": (
            "Findings are mapped to CIS AWS, NIST 800-53, GDPR, and related frameworks where applicable. "
            "Use the remediation commands in the findings table. Re-scan after each change to verify."
        ),
    }

    if not settings.grok_api_key:
        return fallback

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "You are writing a professional CSPM security report for both executives and engineers.\n"
                "Return ONLY valid JSON with these string fields (no markdown fences):\n"
                "{\n"
                '  "headline": "one short sentence, plain English",\n'
                '  "risk_level": "CRITICAL|HIGH|MODERATE|LOW",\n'
                '  "executive_summary": "2-4 sentences for a non-technical leader",\n'
                '  "what_this_means": "2-3 sentences explaining business risk in simple terms",\n'
                '  "priority_actions": "numbered list as a single string, 3-5 concrete next steps",\n'
                '  "technical_notes": "short notes for the security/engineering team"\n'
                "}\n"
                "Do not invent findings. Base everything on this scan:\n\n"
                f"{context}"
            ),
        },
    ]
    try:
        raw = await chat_completion(messages, temperature=0.2, max_tokens=1800)
        parsed = _parse_json_object(raw)
        if not parsed:
            return fallback
        out = dict(fallback)
        for key in out:
            if key in parsed and isinstance(parsed[key], str) and parsed[key].strip():
                out[key] = parsed[key].strip()
        # Normalize risk_level
        rl = out["risk_level"].upper()
        if rl not in ("CRITICAL", "HIGH", "MODERATE", "LOW"):
            out["risk_level"] = risk
        else:
            out["risk_level"] = rl
        return out
    except Exception:
        return fallback


def _fallback_priority_actions(scan: dict[str, Any]) -> str:
    findings = scan.get("findings") or scan.get("vulnerabilities") or []
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_f = sorted(
        findings,
        key=lambda f: order.get(str(f.get("severity", "LOW")).upper(), 9),
    )
    lines: list[str] = []
    for i, f in enumerate(sorted_f[:5], 1):
        title = f.get("title") or f.get("description") or "Issue"
        res = f.get("resource") or f.get("id") or "resource"
        sev = f.get("severity", "?")
        lines.append(f"{i}. [{sev}] Fix {res}: {title}")
    if not lines:
        lines.append("1. No open issues — maintain monitoring and schedule the next scan.")
    else:
        lines.append(f"{len(lines) + 1}. Re-run VaultScan after fixes to confirm posture score improves.")
    return "\n".join(lines)


def _parse_json_object(text: str) -> dict[str, Any] | None:
    import re

    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", text)
        if not match:
            return None
        try:
            data = json.loads(match.group(0))
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            return None


async def assistant_reply(
    user_message: str,
    history: list[dict[str, str]] | None = None,
    scan: dict[str, Any] | None = None,
) -> str:
    messages: list[dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.append(
        {
            "role": "system",
            "content": f"Current scan context:\n{findings_context(scan)}",
        }
    )
    for msg in history or []:
        role = msg.get("role", "user")
        if role not in ("user", "assistant", "system"):
            role = "user"
        messages.append({"role": role, "content": msg.get("content", "")})
    messages.append({"role": "user", "content": user_message})
    return await chat_completion(messages)


async def enrich_attack_paths(
    paths: list[dict[str, Any]],
    scan: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Add cinematic, executive-grade narrative fields to deterministic attack paths.

    For each path, AI may add: story, attacker_playbook, blast_radius,
    time_to_compromise, wow_headline. Falls back to strong static copy.
    """
    if not paths:
        return []

    enriched: list[dict[str, Any]] = []
    for p in paths:
        base = dict(p)
        base.setdefault(
            "wow_headline",
            f"{p.get('severity', 'HIGH')} risk chain: {p.get('name', 'Attack path')}",
        )
        base.setdefault(
            "story",
            (
                f"An attacker can chain {len(p.get('steps') or [])} misconfiguration(s) "
                f"toward: {p.get('outcome', 'serious impact')}. "
                f"{p.get('impact', '')}"
            ),
        )
        base.setdefault(
            "attacker_playbook",
            "1. Discover exposed surface\n2. Abuse misconfiguration\n"
            "3. Escalate using linked weaknesses\n4. Achieve impact",
        )
        base.setdefault("time_to_compromise", "Hours to days (depending on exposure)")
        base.setdefault(
            "blast_radius",
            p.get("impact") or "Account or data assets reachable via this chain",
        )
        base.setdefault("ai_enriched", False)
        enriched.append(base)

    if not settings.grok_api_key:
        return enriched

    # Compact path brief for the model
    brief_lines = []
    for i, p in enumerate(paths, 1):
        steps = p.get("steps") or []
        step_txt = " → ".join(
            f"[{s.get('severity')}] {s.get('service')}:{s.get('resource')} ({s.get('title')})"
            for s in steps
        )
        brief_lines.append(
            f"{i}. id={p.get('id')} name={p.get('name')} severity={p.get('severity')}\n"
            f"   chain: {step_txt}\n"
            f"   outcome: {p.get('outcome')}\n"
            f"   break: {'; '.join(p.get('break_chain') or [])}"
        )
    paths_brief = "\n".join(brief_lines)
    ctx = findings_context(scan) if scan else ""

    messages = [
        {
            "role": "system",
            "content": (
                SYSTEM_PROMPT
                + "\nYou write cinematic but accurate attack-path narratives for a CSPM product. "
                "Never invent resources or findings not listed. Never mention model vendors."
            ),
        },
        {
            "role": "user",
            "content": (
                "Enrich these VaultScan attack paths. Return ONLY a JSON array (no markdown fences). "
                "Each element must be an object with:\n"
                '  "id": string (same as input id),\n'
                '  "wow_headline": string (max 12 words, punchy, boardroom-ready),\n'
                '  "story": string (3-5 sentences: how an attacker moves step by step),\n'
                '  "attacker_playbook": string (numbered steps as one string with newlines),\n'
                '  "time_to_compromise": string (realistic estimate),\n'
                '  "blast_radius": string (what is at stake in business terms)\n'
                "Do not invent new paths or resources.\n\n"
                f"PATHS:\n{paths_brief}\n\nSCAN CONTEXT (reference only):\n{ctx[:4000]}"
            ),
        },
    ]
    try:
        raw = await chat_completion(messages, temperature=0.35, max_tokens=2500)
        parsed = _parse_json_array(raw)
        if not parsed:
            return enriched
        by_id = {str(x.get("id")): x for x in parsed if isinstance(x, dict)}
        for item in enriched:
            extra = by_id.get(str(item.get("id")))
            if not extra:
                continue
            for key in (
                "wow_headline",
                "story",
                "attacker_playbook",
                "time_to_compromise",
                "blast_radius",
            ):
                val = extra.get(key)
                if isinstance(val, str) and val.strip():
                    item[key] = val.strip()
            item["ai_enriched"] = True
        return enriched
    except Exception:
        return enriched


def _parse_json_array(text: str) -> list[Any] | None:
    import re

    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else None
    except json.JSONDecodeError:
        match = re.search(r"\[[\s\S]*\]", text)
        if not match:
            return None
        try:
            data = json.loads(match.group(0))
            return data if isinstance(data, list) else None
        except json.JSONDecodeError:
            return None

