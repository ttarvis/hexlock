"""
hexlock — format-preserving PII anonymization for LLM pipelines.

Quick start:
    import hexlock

    client = hexlock.Client()
    anonymized = client.anonymize("call me at 234-555-6666, ssn 123-45-6789")
    # send anonymized text to your LLM...
    original = client.deanonymize(llm_response)

Cross-session use:
    key = hexlock.generate_key()
    client = hexlock.Client(key=key)
    anonymized = client.anonymize("my card is 4111-1111-1111-1111")
    blob = client.save_session()
    # store key and blob, restore later:
    client = hexlock.Client(key=key, session=blob)
    original = client.deanonymize(llm_response)
"""

from .client import Client, generate_key
from importlib.metadata import version

__all__ = ["Client", "generate_key"]
__version__ = version("hexlock")
