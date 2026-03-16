"""
custom_recognizers.py
---------------------
Implements three custom Presidio recognizers as required by the assignment:
  1. API key recognizer  (regex-based)
  2. Employee ID recognizer (regex-based)
  3. Context-aware phone-number scorer (PatternRecognizer subclass)
"""

import re
from typing import List, Optional

from presidio_analyzer import PatternRecognizer, Pattern, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts


# ---------------------------------------------------------------------------
# 1. Custom API Key Recognizer
#    Matches patterns like: sk-AbCdEf1234567890
# ---------------------------------------------------------------------------

class ApiKeyRecognizer(PatternRecognizer):
    """
    Recognizes API keys in the format sk-[A-Za-z0-9]{10,}.
    Commonly seen in OpenAI-style API keys accidentally pasted into prompts.
    """

    PATTERNS = [
        Pattern(
            name="api_key_pattern",
            regex=r"\bsk-[A-Za-z0-9]{10,}\b",
            score=0.85,
        )
    ]

    CONTEXT = ["api", "key", "token", "secret", "authorization", "bearer"]

    def __init__(self):
        super().__init__(
            supported_entity="API_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="ApiKeyRecognizer",
        )


# ---------------------------------------------------------------------------
# 2. Employee ID Recognizer
#    Matches patterns like: EMP-00123
# ---------------------------------------------------------------------------

class EmployeeIdRecognizer(PatternRecognizer):
    """
    Recognizes internal employee IDs in the format EMP-<digits>.
    Prevents accidental leakage of internal HR identifiers.
    """

    PATTERNS = [
        Pattern(
            name="employee_id_pattern",
            regex=r"\bEMP-\d+\b",
            score=0.90,
        )
    ]

    CONTEXT = ["employee", "emp", "staff", "id", "identifier", "worker"]

    def __init__(self):
        super().__init__(
            supported_entity="EMPLOYEE_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="EmployeeIdRecognizer",
        )


# ---------------------------------------------------------------------------
# 3. Context-Aware Phone Number Recognizer
#    Boosts confidence when context words ("call", "phone", "contact")
#    appear near the matched phone number.
# ---------------------------------------------------------------------------

PHONE_CONTEXT_KEYWORDS = {"call", "phone", "contact", "reach", "dial", "mobile", "number"}
CONTEXT_BOOST = 0.15          # Amount added to the base score when context is found
CONTEXT_WINDOW_CHARS = 60     # Characters before/after the match to scan for context


class ContextAwarePhoneRecognizer(PatternRecognizer):
    """
    Extends the default phone number recognizer with context-aware confidence
    calibration. If nearby text contains telephony-related words, the
    confidence score is boosted, reducing false positives.
    """

    PATTERNS = [
        Pattern(
            name="pk_phone",
            regex=r"\b0\d{10}\b",          # Pakistani mobile: 03001234567
            score=0.60,
        ),
        Pattern(
            name="intl_phone",
            regex=r"\+\d{1,3}[\s\-]?\d{7,12}",   # International format
            score=0.60,
        ),
    ]

    def __init__(self):
        super().__init__(
            supported_entity="PHONE_NUMBER",
            patterns=self.PATTERNS,
            name="ContextAwarePhoneRecognizer",
        )

    def analyze(
        self,
        text: str,
        entities: List[str],
        nlp_artifacts: Optional[NlpArtifacts] = None,
    ) -> List[RecognizerResult]:
        """
        Run base pattern analysis, then boost score if context words are nearby.
        """
        results = super().analyze(text, entities, nlp_artifacts)

        boosted = []
        for result in results:
            # Extract a window of text around the match
            start = max(0, result.start - CONTEXT_WINDOW_CHARS)
            end = min(len(text), result.end + CONTEXT_WINDOW_CHARS)
            window = text[start:end].lower()

            # Check if any context keyword appears in the window
            if any(kw in window for kw in PHONE_CONTEXT_KEYWORDS):
                new_score = min(result.score + CONTEXT_BOOST, 1.0)
                boosted.append(
                    RecognizerResult(
                        entity_type=result.entity_type,
                        start=result.start,
                        end=result.end,
                        score=new_score,
                        analysis_explanation=result.analysis_explanation,
                        recognition_metadata=result.recognition_metadata,
                    )
                )
            else:
                boosted.append(result)

        return boosted
