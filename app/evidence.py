"""Deterministic, bounded excerpt selection. No additional model call or generated advice."""
import re
from .privacy import redact
PATTERNS={
 'requests_secrets':r'\b(password|passcode|verification code|mfa|recovery code|private key|otp)\b',
 'payment_pressure':r'\b(wire|payment|bank|invoice|gift card|crypto|bitcoin|account details)\b',
 'identity_mismatch':r'(^from:|^reply-to:|declared link:|https?://)',
 'coercion':r'\b(urgent|immediately|suspend|deleted|within|today|expire|deadline)\b',
 'marketing':r'\b(sale|offer|discount|subscribe|unsubscribe)\b',
}

def explain(text,assessment):
    from .core import fallback_explanation
    result=fallback_explanation(assessment)
    reasons={'requests_secrets':'a request for passwords or verification codes','payment_pressure':'an unusual payment or bank-change request','identity_mismatch':'a possible identity or domain mismatch','coercion':'pressure to act quickly'}
    flagged=[reasons[s['id']] for s in assessment['signals'] if s['id'] in reasons and s['strength'] in ('strong','possible')]
    if flagged and assessment['risk'] in ('likely_phishing','suspicious'):
        result['summary']='The screening flagged '+', '.join(flagged[:3])+'. Verify the request independently.'
    lines=[x.strip() for x in re.split(r'\n+|(?<=[.!?])\s+',text) if x.strip()]
    chosen=[]
    for signal in assessment['signals']:
        if signal['strength'] not in ('strong','possible') or signal['id'] not in PATTERNS:continue
        for line in lines:
            if re.search(PATTERNS[signal['id']],line,re.I):
                quoted=redact(line,links=True)
                if len(quoted)>300:quoted=quoted[:297]+'…'
                if quoted not in chosen:chosen.append(quoted)
                break
        if len(chosen)==3:break
    # Avoid generic "no evidence" presentation for an ordinary message, while making
    # no claim that an arbitrary excerpt demonstrates authenticity.
    if not chosen and assessment['risk']=='no_obvious_warning_signs':
        for line in lines:
            if not re.match(r'^(from|to|subject|date|reply-to):',line,re.I):
                quoted=redact(line,links=True)
                chosen=[quoted[:297]+'…' if len(quoted)>300 else quoted];break
    if chosen:
        result['evidence'] += ['From the supplied message (unverified): “'+line+'”' for line in chosen]
    result['limitations']='Only the supplied content was checked. Sender identity, link destinations and attachment safety are not verified.'
    return result
