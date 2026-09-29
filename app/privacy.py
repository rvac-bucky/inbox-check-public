"""Conservative recognizable-secret masking; not a DLP guarantee or a PHI scrubber."""
import re

CONTEXT=re.compile(r'(?i)\b(?:password|passcode|pin|otp|mfa|verification|recovery|sign[ -]?in|login|authentication|security code|api[ _-]?key|secret|token)\b')
LABEL=re.compile(r'''(?ix)(\b(?:password|passcode|pin|otp|mfa\s+code|verification\s+code|recovery\s+code|sign[ -]?in\s+code|login\s+code|api[ _-]?key|access\s+token|secret)\s*(?:is\s*|[:=]\s*)["']?)([^\s<>"',;\[\]]{4,200})''')
NUMERIC=re.compile(r'(?<!\w)(?:\d[ -]?){3,7}\d(?!\w)')

def redact(text,links=False):
    text=re.sub(r'-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----.*?-----END (?:[A-Z ]*PRIVATE KEY)-----','[private key omitted]',text,flags=re.S)
    text=re.sub(r'\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b','[token omitted]',text)
    text=LABEL.sub(lambda m:m.group(1)+'[sensitive value omitted]',text)
    source=text
    text=NUMERIC.sub(lambda m:'[code omitted]' if CONTEXT.search(source[max(0,m.start()-100):min(len(source),m.end()+40)]) else m.group(0),text)
    # Long mixed-character recovery/token values near explicit sensitive context.
    source=text
    text=re.sub(r'\b(?=[A-Za-z0-9_-]{8,}\b)(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{8,}\b',lambda m:'[token omitted]' if CONTEXT.search(source[max(0,m.start()-80):m.end()+30]) else m.group(0),text)
    if links:
        text=re.sub(r'(?i)(?:https?://|www\.)[^\s<>]+','[link omitted]',text)
    return text
