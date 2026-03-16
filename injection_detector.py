"""
injection_detector.py
---------------------
Detects prompt injection and jailbreak attempts using a keyword-based
scoring mechanism. Returns a risk score between 0.0 and 1.0.
"""

import re

# Known injection/jailbreak phrases and their individual weights
INJECTION_PATTERNS = [
    (r"ignore\s+(previous|all|prior)\s+instructions?", 0.9),
    (r"disregard\s+(previous|all|prior)\s+instructions?", 0.85),
    (r"reveal\s+(the\s+)?system\s+prompt", 0.9),
    (r"what\s+is\s+your\s+system\s+prompt", 0.85),
    (r"developer\s+mode", 0.7),
    (r"bypass\s+safety", 0.8),
    (r"show\s+(me\s+)?(the\s+)?(hidden\s+)?prompt", 0.85),
    (r"hidden\s+prompt", 0.85),
    (r"jailbreak", 0.9),
    (r"act\s+as\s+(if\s+you\s+are\s+)?DAN", 0.9),
    (r"pretend\s+you\s+(are|have\s+no)\s+(restrictions?|limits?)", 0.75),
    (r"you\s+are\s+now\s+(in\s+)?unrestricted\s+mode", 0.8),
    (r"override\s+(safety|alignment|restrictions?)", 0.85),
    (r"forget\s+(you\s+are\s+(an?\s+)?AI|your\s+training)", 0.75),
    (r"act\s+as\s+(an?\s+)?unrestricted", 0.8),
    (r"no\s+restrictions?\s+and\s+help", 0.75),
]


def compute_injection_score(user_input: str) -> float:
    """
    Compute an injection risk score for the given user input.

    Scans the input against a set of known injection patterns. The final
    score is capped at 1.0 and represents the maximum risk found.

    Args:
        user_input (str): The raw text submitted by the user.

    Returns:
        float: A risk score in [0.0, 1.0]. Higher means more suspicious.
    """
    text = user_input.lower()
    max_score = 0.0

    for pattern, weight in INJECTION_PATTERNS:
        if re.search(pattern, text):
            if weight > max_score:
                max_score = weight

    # Cap at 1.0 just in case of floating-point edge cases
    return min(max_score, 1.0)
