"""
policy_engine.py
----------------
Implements the configurable policy decision engine.

Decision logic:
  - Injection score > INJECTION_THRESHOLD  →  BLOCK
  - PII detected                           →  MASK
  - Otherwise                              →  ALLOW
"""

from dataclasses import dataclass
from typing import List, Optional

# ---------------------------------------------------------------------------
# Configurable thresholds — adjust here without touching business logic
# ---------------------------------------------------------------------------

INJECTION_THRESHOLD: float = 0.5   # Score above which a request is blocked
PII_CONFIDENCE_THRESHOLD: float = 0.4  # Minimum Presidio confidence to act on


@dataclass
class PolicyDecision:
    """Encapsulates the outcome of the policy engine for one request."""

    action: str                          # "ALLOW" | "MASK" | "BLOCK"
    output_text: str                     # Final text shown to the user
    injection_score: float               # Raw score from injection detector
    pii_entities: List[str]             # Entity types detected (may be empty)
    reason: str                          # Human-readable explanation


def apply_policy(
    user_input: str,
    injection_score: float,
    analyzer_results,          # List[RecognizerResult] from presidio_analyzer_module
    anonymized_text: str,
) -> PolicyDecision:
    """
    Apply the security policy to a processed request.

    Args:
        user_input (str): Original user-submitted text.
        injection_score (float): Score from injection_detector.
        analyzer_results: Presidio analysis results.
        anonymized_text (str): Text with PII masked by Presidio anonymizer.

    Returns:
        PolicyDecision: The resolved action and associated metadata.
    """

    # ------------------------------------------------------------------ BLOCK
    if injection_score > INJECTION_THRESHOLD:
        return PolicyDecision(
            action="BLOCK",
            output_text="Request blocked due to suspected prompt injection.",
            injection_score=injection_score,
            pii_entities=[],
            reason=(
                f"Injection score {injection_score:.2f} exceeds threshold "
                f"{INJECTION_THRESHOLD}."
            ),
        )

    # Filter PII results by confidence threshold
    significant_pii = [
        r for r in analyzer_results
        if r.score >= PII_CONFIDENCE_THRESHOLD
    ]

    # ------------------------------------------------------------------- MASK
    if significant_pii:
        detected_types = sorted({r.entity_type for r in significant_pii})
        return PolicyDecision(
            action="MASK",
            output_text=anonymized_text,
            injection_score=injection_score,
            pii_entities=detected_types,
            reason=(
                f"PII detected: {', '.join(detected_types)}. "
                "Sensitive fields have been masked."
            ),
        )

    # ------------------------------------------------------------------ ALLOW
    return PolicyDecision(
        action="ALLOW",
        output_text=user_input,
        injection_score=injection_score,
        pii_entities=[],
        reason="No injection or PII detected. Request is safe.",
    )
