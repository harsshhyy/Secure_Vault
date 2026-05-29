"""
risk_engine.py

Lightweight rule-based session risk calculator for Secure Vault.
This is a prototype engine used by the Flask app to produce realtime
risk scores from contextual and behavioral signals.
"""
from datetime import datetime
import json

# Risk thresholds and weights (tunable)
RISK_LOW_THRESHOLD = 30
RISK_MEDIUM_THRESHOLD = 60
RISK_HIGH_THRESHOLD = 100

RISK_WEIGHTS = {
    'new_device': 25,
    'new_location': 20,
    'typing_anomaly': 20,
    'mouse_anomaly': 15,
    'navigation_anomaly': 10,
    'abnormal_time': 10,
    'failed_attempts': 15,
}


def _score_from_trust(trust_score: int) -> int:
    """Convert a 0-100 trust score into a risk contribution (higher trust -> lower risk)."""
    # risk contribution inversely proportional to trust
    return max(0, 100 - int(trust_score)) // 2


def calculate_session_risk(user_row: dict, ip_address: str = None, device_fingerprint: str = None, feature_vector=None, recent_failures=0, geo_info: dict = None):
    """
    Calculate a session-level risk score and return (risk_score, risk_level, factors_dict).

    - user_row: dict of user fields (may include last_login_ip, trusted_devices JSON)
    - ip_address: client IP
    - device_fingerprint: fingerprint string
    - feature_vector: list of behavioral features [typing_speed, key_delay, mouse_speed, click_rate, scroll_velocity]
    - recent_failures: integer count of recent failed logins
    - geo_info: optional dict with 'country' or 'region'
    """
    risk_score = 0
    factors = {}

    # Unknown or new device
    trusted = []
    if user_row.get('trusted_devices'):
        try:
            trusted = json.loads(user_row.get('trusted_devices') or '[]')
        except Exception:
            trusted = []

    if device_fingerprint and device_fingerprint not in trusted:
        risk_score += RISK_WEIGHTS['new_device']
        factors['new_device'] = RISK_WEIGHTS['new_device']

    # Untrusted / changed IP
    last_ip = user_row.get('last_login_ip')
    if ip_address and last_ip and ip_address != last_ip:
        risk_score += RISK_WEIGHTS['new_location'] if 'new_location' in RISK_WEIGHTS else 20
        factors['new_location'] = RISK_WEIGHTS.get('new_location', 20)

    # Recent failed attempts
    if recent_failures and recent_failures > 0:
        add = min(RISK_WEIGHTS['failed_attempts'], recent_failures * 5)
        risk_score += add
        factors['failed_attempts'] = add

    # Behavioral features -> convert to trust then to risk
    if isinstance(feature_vector, (list, tuple)) and len(feature_vector) >= 5:
        typing_speed, key_delay, mouse_speed, click_rate, scroll_velocity = feature_vector[:5]
        # Simple heuristics for anomalies
        typing_anom = 1 if typing_speed < 3 or typing_speed > 20 else 0
        mouse_anom = 1 if mouse_speed < 100 or mouse_speed > 3000 else 0
        nav_anom = 0
        # build a simple trust score (reuse simple linear rules)
        trust = 100
        trust -= min(max((typing_speed - 8) * 4, 0), 25)
        trust -= min(max((key_delay - 0.3) * 16, 0), 20)
        trust -= min(max((mouse_speed - 400) / 30, 0), 20)
        trust -= min(max((click_rate - 2.5) * 10, 0), 15)
        trust -= min(max((scroll_velocity - 500) / 50, 0), 10)
        trust = max(0, min(100, int(trust)))

        trust_contrib = _score_from_trust(trust)
        risk_score += trust_contrib
        factors['behavior_trust'] = trust_contrib

        if typing_anom:
            risk_score += RISK_WEIGHTS.get('typing_anomaly', 10)
            factors['typing_anomaly'] = RISK_WEIGHTS.get('typing_anomaly', 10)
        if mouse_anom:
            risk_score += RISK_WEIGHTS.get('mouse_anomaly', 10)
            factors['mouse_anomaly'] = RISK_WEIGHTS.get('mouse_anomaly', 10)

    # Geolocation/Impossible travel (very simple delta check if geo_info provided)
    if geo_info and user_row.get('last_login_ip'):
        prev_country = user_row.get('last_login_country')
        curr_country = geo_info.get('country')
        if prev_country and curr_country and prev_country != curr_country:
            # mark as higher risk
            risk_score += 30
            factors['geolocation_change'] = 30

    # Cap and classify
    risk_score = max(0, min(100, int(risk_score)))

    if risk_score <= RISK_LOW_THRESHOLD:
        level = 'low'
    elif risk_score <= RISK_MEDIUM_THRESHOLD:
        level = 'medium'
    else:
        level = 'high'

    return risk_score, level, factors
