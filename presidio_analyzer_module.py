"""
presidio_analyzer_module.py
---------------------------
Sets up the Presidio AnalyzerEngine with built-in and custom recognizers.

NLP Engine strategy:
  - Tries to load spaCy en_core_web_lg (best, enables PERSON NER).
  - Falls back to en_core_web_sm.
  - Falls back to spacy.blank('en') so the gateway always starts with
    zero extra downloads (PERSON detection disabled in blank mode,
    all regex/pattern recognizers work normally).

Install a spaCy model for full PERSON detection:
    pip install https://github.com/explosion/spacy-models/releases/download/
                en_core_web_lg-3.7.1/en_core_web_lg-3.7.1-py3-none-any.whl
"""

from typing import List

import spacy
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_anonymizer import AnonymizerEngine

from custom_recognizers import (
    ApiKeyRecognizer,
    ContextAwarePhoneRecognizer,
    EmployeeIdRecognizer,
)


# ---------------------------------------------------------------------------
# NLP Engine: tries full models → falls back to blank spaCy
# ---------------------------------------------------------------------------

def _build_nlp_engine() -> SpacyNlpEngine:
    """
    Return a SpacyNlpEngine using the best available spaCy model.
    A blank model is used as a zero-download fallback; it supports all
    pattern/regex recognizers but skips ML-based named entity recognition.
    """
    for model_name in ("en_core_web_lg", "en_core_web_sm"):
        try:
            spacy.load(model_name)
            engine = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": model_name}])
            engine.load()
            print(f"[INFO] NLP engine: spaCy {model_name}")
            return engine
        except OSError:
            continue

    # Blank model fallback — no download required
    nlp_blank = spacy.blank("en")
    engine = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": "blank"}])
    engine.nlp = {"en": nlp_blank}
    print("[INFO] NLP engine: spacy.blank('en') — pattern recognizers active, PERSON NER disabled")
    return engine


_nlp_engine = _build_nlp_engine()


# ---------------------------------------------------------------------------
# Recognizer Registry: built-ins + 3 custom recognizers
# ---------------------------------------------------------------------------

_registry = RecognizerRegistry()
_registry.load_predefined_recognizers(nlp_engine=_nlp_engine)

# Custom recognizer 1: API keys  (regex: sk-[A-Za-z0-9]{10,})
_registry.add_recognizer(ApiKeyRecognizer())
# Custom recognizer 2: Employee IDs  (regex: EMP-\d+)
_registry.add_recognizer(EmployeeIdRecognizer())
# Custom recognizer 3: Context-aware phone number scorer
_registry.add_recognizer(ContextAwarePhoneRecognizer())


# ---------------------------------------------------------------------------
# Analyzer + Anonymizer singletons
# ---------------------------------------------------------------------------

_analyzer = AnalyzerEngine(
    registry=_registry,
    nlp_engine=_nlp_engine,
    supported_languages=["en"],
)

_anonymizer = AnonymizerEngine()


# Entity types monitored by the gateway
SUPPORTED_ENTITIES: List[str] = [
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "PERSON",
    "API_KEY",
    "EMPLOYEE_ID",
]


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def analyze_text(text: str):
    """
    Run Presidio PII analysis on the supplied text.

    Args:
        text (str): Raw user input.

    Returns:
        List[RecognizerResult]: Detected entities with character positions and scores.
    """
    return _analyzer.analyze(
        text=text,
        entities=SUPPORTED_ENTITIES,
        language="en",
    )


def anonymize_text(text: str, analyzer_results) -> str:
    """
    Replace detected PII entities with <ENTITY_TYPE> placeholders.

    Args:
        text (str): Original user input.
        analyzer_results: Output of analyze_text().

    Returns:
        str: Anonymized text safe to forward downstream.
    """
    if not analyzer_results:
        return text
    return _anonymizer.anonymize(
        text=text,
        analyzer_results=analyzer_results,
    ).text
