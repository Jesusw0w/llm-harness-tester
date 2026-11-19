"""Adversarial test harness for prompt injection in LLM applications.

Point the harness at an application entry point; it runs a corpus of cited
injection payloads and reports which ones got through, with a reproducible case
for each. It tests applications, not models, and it never attempts to elicit
harmful content — every payload asks the target to emit a harmless canary token.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
