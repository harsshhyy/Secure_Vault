"""
decoy.py

Decoy Vault / Honeypot security helpers.
Provides functions to trigger decoy mode for a session and log attacker interactions.
"""
import os
import sqlite3
from datetime import datetime
from flask import session


DB_PATH = os.environ.get('SECURE_VAULT_DB', os.path.join(os.getcwd(), 'secure_vault.db'))


def _conn():
    return sqlite3.connect(DB_PATH)


def trigger_decoy_for_session(user_id, username, ip_address, device_fingerprint, reason, risk_score):
    """Mark the session as redirected to decoy and record a trigger entry in DB."""
    session['decoy'] = True
    session['decoy_triggered_at'] = datetime.utcnow().isoformat()
    session['decoy_reason'] = reason

    try:
        conn = _conn()
        cur = conn.cursor()
        cur.execute('INSERT INTO decoy_triggers (user_id, username, ip_address, device_fingerprint, reason, risk_score, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    [user_id, username, ip_address, device_fingerprint, reason, int(risk_score), datetime.utcnow().isoformat()])
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass


def log_decoy_interaction(user_id_or_null, action, details=''):
    """Record an interaction inside the decoy environment."""
    try:
        conn = _conn()
        cur = conn.cursor()
        cur.execute('INSERT INTO decoy_interactions (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)',
                    [user_id_or_null, action, details, datetime.utcnow().isoformat()])
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass
