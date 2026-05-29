"""
ai_assistant.py

Minimal AI Security Assistant for Secure Vault.
This file provides a simple rule-based assistant endpoint used by the Flask app
to summarize recent threats and explain risk decisions. It's intentionally
lightweight and local so it can be extended later with a real model.
"""
from flask import jsonify
import json


def summarize_login_attempts(attempts_rows):
    """Create a short summary from login_attempts rows (iterable of dict-like rows)."""
    total = len(attempts_rows)
    high = sum(1 for r in attempts_rows if r.get('risk_level') == 'high')
    med = sum(1 for r in attempts_rows if r.get('risk_level') == 'medium')
    low = sum(1 for r in attempts_rows if r.get('risk_level') == 'low')

    top_factors = {}
    for r in attempts_rows:
        try:
            f = json.loads(r.get('factors') or '{}')
            for k in f.keys():
                top_factors[k] = top_factors.get(k, 0) + 1
        except Exception:
            continue

    most_common = sorted(top_factors.items(), key=lambda x: x[1], reverse=True)[:3]

    return {
        'total_attempts': total,
        'high_risk': high,
        'medium_risk': med,
        'low_risk': low,
        'most_common_factors': most_common,
    }


def handle_query(query: str, context: dict):
    """Basic rule-based query handler. Returns a dict response."""
    q = (query or '').lower()
    if 'why' in q or 'explain' in q:
        # try to explain a recent high risk event
        attempts = context.get('attempts', [])
        if not attempts:
            return {'answer': 'No recent login attempts found to explain.'}

        # find latest high or medium risk
        candidate = None
        for a in attempts:
            if a.get('risk_level') in ('high', 'medium'):
                candidate = a
                break
        if not candidate:
            candidate = attempts[0]

        factors = candidate.get('factors')
        try:
            factors = json.loads(factors or '{}')
        except Exception:
            factors = {}

        explanation = []
        for k in factors.keys():
            if k == 'new_device':
                explanation.append('A new device fingerprint was detected for this login.')
            elif k == 'new_location' or k == 'geolocation_change':
                explanation.append('Login originated from a different IP or geographic region.')
            elif k == 'failed_attempts':
                explanation.append('Several failed login attempts were recorded recently.')
            else:
                explanation.append(f'{k} appears in risk factors.')

        if not explanation:
            explanation = ['Risk was elevated due to anomaly in behavioral signals.']

        return {
            'answer': 'I found a recent flagged login. Summary: ' + candidate.get('risk_level', 'unknown'),
            'explanation': explanation,
            'attempt': candidate,
        }

    if 'summary' in q or 'report' in q:
        summary = summarize_login_attempts(context.get('attempts', []))
        return {'answer': 'Security summary generated.', 'summary': summary}

    return {'answer': 'Sorry, I cannot handle that query yet. Try: "Explain recent login" or "Generate security summary"'}
