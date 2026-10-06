import json, re
from pathlib import Path
from app.core import VERDICTS, verdict_view, fallback_explanation

STATIC = Path(__file__).resolve().parent.parent / 'app' / 'static'
VENDORS = re.compile(r'\b(jev|azure|openrouter|openai)\b', re.I)


def test_three_verdicts_and_failures_never_green():
    assert {v['label'].split(' — ')[0] for v in VERDICTS.values()} == {'🔴 RED', '🟡 YELLOW', '🟢 GREEN'}
    assert verdict_view('insufficient_evidence')['color'] == 'yellow'
    assert verdict_view('anything_unexpected')['color'] == 'yellow'
    assert verdict_view('no_obvious_warning_signs')['color'] == 'green'


def test_web_ui_uses_the_same_verdict_text():
    js = (STATIC / 'app.js').read_text()
    for v in VERDICTS.values():
        assert v['label'] in js and v['detail'] in js


def test_no_vendor_names_in_static_assets():
    for f in STATIC.iterdir():
        if f.suffix in ('.js', '.html', '.css'):
            assert not VENDORS.search(f.read_text()), f.name


def test_fallback_guidance_names_no_vendor():
    sig = [{'id': k, 'label': k, 'strength': 'strong'} for k in ('requests_secrets', 'identity_mismatch', 'ai_manipulation')]
    for risk in VERDICTS:
        e = fallback_explanation({'risk': risk, 'signals': sig})
        assert not VENDORS.search(json.dumps(e)), risk
