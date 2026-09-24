"""
AI Threat Explanation — per PRD 6.6 and TRD Section 10.

CRITICAL BOUNDARY: this service explains a decision the rule engine + ML
classifier already made. It never re-classifies, never adjusts the risk
score, and its output is validated before use. If the model is unavailable,
misconfigured, times out, or returns malformed output, this falls back to a
deterministic template — a scan result is NEVER blocked on the LLM being up.

TRD 10 requirements this satisfies:
- Input is structured evidence, not raw assumptions
- Output uses a fixed schema, validated before storage
- Malformed output is rejected (falls back to template)
- Model/version metadata is recorded on every report
"""
import json
import logging
from dataclasses import dataclass

from app.config import get_settings
from app.services.rule_engine import Evidence

logger = logging.getLogger(__name__)
settings = get_settings()

SYSTEM_INSTRUCTION = """You are a security analyst assistant inside KavachAI, a threat-detection \
platform. A deterministic rule engine and ML classifier have ALREADY computed a risk score, \
severity, and classification for a scanned URL or email. Your only job is to explain, in plain \
language, why the listed evidence supports that conclusion.

Rules you must follow:
- Do NOT invent evidence that wasn't provided.
- Do NOT change or contradict the given classification/severity — only explain it.
- Do NOT give specific action advice (recommendations are handled deterministically elsewhere).
- Keep the summary to one sentence. Keep each explanation point to one short sentence.
- Respond with ONLY valid JSON matching this exact shape, nothing else:
{"summary": "...", "explanation": ["...", "..."]}"""


@dataclass
class AIExplanation:
    summary: str
    explanation: list[str]
    model: str


def _template_fallback(
    severity: str, classification: str, evidence: list[Evidence], reason: str
) -> AIExplanation:
    """Deterministic, no-LLM explanation. Used whenever the AI call can't be trusted."""
    if not evidence:
        summary = f"No risk signals were detected; this scan came back {severity.lower()}."
        points = ["No evidence triggered any detection rule."]
    else:
        top = sorted(evidence, key=lambda e: e.weight, reverse=True)[:3]
        summary = (
            f"Classified as {classification} ({severity}) based on {len(evidence)} "
            f"detected signal{'s' if len(evidence) != 1 else ''}."
        )
        points = [e.description for e in top]

    logger.info("AI explanation fell back to template — reason: %s", reason)
    return AIExplanation(summary=summary, explanation=points, model="template-fallback")


def _validate_llm_json(raw_text: str) -> dict | None:
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    if not isinstance(data.get("summary"), str) or not data["summary"].strip():
        return None
    if not isinstance(data.get("explanation"), list) or not all(isinstance(x, str) for x in data["explanation"]):
        return None
    return data


def explain_threat(
    risk_score: int,
    severity: str,
    classification: str,
    evidence: list[Evidence],
    target: str,
) -> AIExplanation:
    if not settings.GEMINI_API_KEY:
        return _template_fallback(severity, classification, evidence, "GEMINI_API_KEY not configured")

    payload = {
        "target": target,
        "risk_score": risk_score,
        "severity": severity,
        "classification": classification,
        "signals": [{"signal": e.signal, "description": e.description, "weight": e.weight} for e in evidence],
    }

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=settings.GEMINI_API_KEY)
        response = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=json.dumps(payload),
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                response_mime_type="application/json",
                temperature=0.2,
                max_output_tokens=400,
                http_options=types.HttpOptions(
                    timeout=int(settings.AI_EXPLANATION_TIMEOUT_SECONDS * 1000)
                ),
            ),
        )
        raw_text = response.text
    except Exception as e:
        return _template_fallback(severity, classification, evidence, f"LLM call failed: {e}")

    parsed = _validate_llm_json(raw_text)
    if parsed is None:
        return _template_fallback(severity, classification, evidence, "LLM returned malformed/unvalidated JSON")

    return AIExplanation(
        summary=parsed["summary"].strip(),
        explanation=[s.strip() for s in parsed["explanation"] if s.strip()],
        model=settings.GEMINI_MODEL,
    )
