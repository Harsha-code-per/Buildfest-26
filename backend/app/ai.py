"""AI-driven vulnerability patch prioritizer module (OpenAI GPT integration).

Uses httpx.AsyncClient for non-blocking API calls to OpenAI chat completions.
Best-effort and resilient: if the API key is missing or calls fail, returns (None, {})
so scoring and API response never crash.
"""
from __future__ import annotations

import json
import logging
import httpx

from .config import settings

logger = logging.getLogger("risksense.ai")

OPENAI_CHAT_URL = "https://api.openai.com/v1/chat/completions"


async def generate_ai_triage(results: list[dict]) -> tuple[str | None, dict[str, str]]:
    """Generate an AI executive summary and per-CVE remediation advice using OpenAI GPT.

    Returns:
        tuple[executive_summary, remediations_map]
    """
    api_key = settings.openai_api_key
    if not api_key:
        return None, {}

    # Build concise context summary for GPT prompt
    items_summary = []
    for r in results:
        cve = r.get("cve", "")
        action = r.get("ssvc", {}).get("action", "Track")
        score = r.get("score", 0.0)
        cvss = r.get("cvss")
        epss = r.get("epss")
        epss_pct = f"{epss * 100:.1f}%" if epss is not None else "N/A"
        in_kev = r.get("in_kev", False)
        ransomware = r.get("kev_ransomware", False)
        sla_label = r.get("sla", {}).get("label", "No deadline")

        items_summary.append(
            f"- {cve}: Action={action}, RiskScore={score}/100, CVSS={cvss or 'N/A'}, "
            f"EPSS={epss_pct}, KEV={in_kev} (Ransomware={ransomware}), SLA={sla_label}"
        )

    system_prompt = (
        "You are an expert Cybersecurity Triage & Remediation Advisor for lean IT and SysAdmin teams "
        "with limited patching bandwidth. Analyze the prioritized vulnerability scan results below "
        "(ranked by CISA/CMU-SEI SSVC decisions: Act > Attend > Track, CISA KEV active exploitation, and EPSS likelihood).\n\n"
        "Respond STRICTLY in valid JSON with this exact schema:\n"
        "{\n"
        '  "executive_summary": "2-3 crisp, high-impact sentences for lean IT teams summarizing what top priority actions to take today and why.",\n'
        '  "remediations": {\n'
        '    "CVE-YYYY-NNNN": "1-2 practical, direct mitigation or patching steps (e.g. specific patch, port blocking, configuration workaround)."\n'
        "  }\n"
        "}"
    )

    user_prompt = (
        "Vulnerability Triage Data:\n" + "\n".join(items_summary) +
        "\n\nProvide the executive summary and per-CVE remediation instructions for a lean IT team."
    )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": settings.openai_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.3,
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(OPENAI_CHAT_URL, headers=headers, json=payload, timeout=12.0)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            summary = parsed.get("executive_summary")
            raw_remediations = parsed.get("remediations", {})
            remediations = {}
            if isinstance(raw_remediations, dict):
                for k, v in raw_remediations.items():
                    clean_k = str(k).strip().upper().replace("_", "-")
                    remediations[clean_k] = str(v)
            return summary, remediations
    except Exception as e:
        logger.warning(f"AI triage generation failed or timed out: {e}")
        return None, {}

