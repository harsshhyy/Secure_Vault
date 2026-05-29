"""
explainable.py

Provide simple explainability utilities for anomaly and risk explanations.
This module produces human-readable reasons for anomalies using feature
threshold comparisons and session context.
"""
def explain_behavioral_features(feature_vector):
    """Return a list of human-readable reasons based on a feature vector."""
    reasons = []
    if not feature_vector or len(feature_vector) < 5:
        reasons.append('Insufficient behavioral data for analysis')
        return reasons

    typing_speed, key_delay, mouse_speed, click_rate, scroll_velocity = feature_vector[:5]

    if typing_speed < 3:
        reasons.append('Typing speed unusually low')
    elif typing_speed > 20:
        reasons.append('Typing speed unusually high')

    if key_delay > 1.0:
        reasons.append('Long key press delays detected')

    if mouse_speed < 100:
        reasons.append('Very slow mouse movement')
    elif mouse_speed > 3000:
        reasons.append('Very fast mouse movement')

    if click_rate < 0.5:
        reasons.append('Very low click frequency')
    elif click_rate > 10:
        reasons.append('Very high click frequency')

    if scroll_velocity < 50:
        reasons.append('Minimal scrolling detected')

    return reasons


def explain_risk_factors(factors: dict):
    """Turn risk factor dictionary into readable explanation list."""
    reasons = []
    for k, v in (factors or {}).items():
        if k == 'new_device':
            reasons.append('New device fingerprint detected')
        elif k == 'new_location' or k == 'geolocation_change':
            reasons.append('Login from a different location or IP')
        elif k == 'typing_anomaly':
            reasons.append('Keystroke dynamics differ from usual')
        elif k == 'mouse_anomaly':
            reasons.append('Mouse movement pattern abnormal')
        elif k == 'failed_attempts':
            reasons.append('Multiple recent failed login attempts')
        elif k == 'behavior_trust':
            reasons.append('Behavior-based trust score was low')
        else:
            reasons.append(f'{k}: {v}')
    return reasons
