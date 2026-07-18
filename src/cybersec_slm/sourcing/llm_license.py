#!/usr/bin/env python3
"""AI-powered license auditor.

Uses an LLM to definitively read a site's actual legal terms or scraped text 
and classify it as commercial, non-commercial, or unknown.
"""

from __future__ import annotations

import json
from .. import llm
from ..core import logger

SYSTEM_PROMPT = (
    "You are a legal expert determining if a provided text (Terms of Service, License, or Copyright notice) "
    "permits commercial use, specifically for AI training and data mining. "
    "You MUST classify the text into exactly one of three categories: 'commercial', 'non-commercial', or 'unknown'. "
    "'commercial' means the text explicitly allows or strongly implies commercial reuse is permitted (like MIT, Apache, CC-BY, or open government licenses). "
    "'non-commercial' means the text restricts commercial reuse, asserts 'all rights reserved', or forbids scraping/data mining for commercial gain (like CC-BY-NC). "
    "'unknown' means the text is too ambiguous or doesn't mention reuse rights. "
    "Reply with ONLY a JSON object, no prose and no code fence: "
    '{"verdict": "commercial"|"non-commercial"|"unknown", "reason": "<one short sentence explaining why>"}.'
)

def audit_text(text: str) -> dict:
    """Audit a block of text using the LLM to determine its commercial license status.
    
    Returns a dict with 'verdict' and 'reason'.
    """
    if not text or not str(text).strip():
        return {"verdict": "unknown", "reason": "No text provided."}

    if not llm.is_available():
        return {"verdict": "unknown", "reason": "LLM not configured or agent extra not installed."}

    prompt = f"Text to analyze:\n\n{text[:10000]}" # Limit text size for token context
    
    try:
        reply = llm.generate(prompt, system=SYSTEM_PROMPT, temp=0.1)
        # Parse JSON
        start = reply.find("{")
        end = reply.rfind("}")
        if start >= 0 and end > start:
            parsed = json.loads(reply[start:end+1])
            verdict = parsed.get("verdict", "unknown").lower()
            reason = parsed.get("reason", "No reason provided.")
            if verdict not in ("commercial", "non-commercial", "unknown"):
                verdict = "unknown"
            return {"verdict": verdict, "reason": reason}
        return {"verdict": "unknown", "reason": "Could not parse model JSON response."}
    except Exception as e:
        logger.warning(f"llm_license audit failed: {e}")
        return {"verdict": "unknown", "reason": f"Audit failed: {e}"}
