#!/usr/bin/env python3
"""
Risk-Based Adaptive Authentication Testing Script
Tests the risk scoring and authentication flow
"""

import json
from datetime import datetime, timedelta

# Risk constants
RISK_LOW_THRESHOLD = 30
RISK_MEDIUM_THRESHOLD = 70
RISK_HIGH_THRESHOLD = 100

RISK_WEIGHTS = {
    'new_device': 25,
    'new_location': 20,
    'unusual_time': 10,
    'failed_attempts': 15,
    'anomalous_behavior': 30,
}


def calculate_risk(factors):
    """Calculate risk score from factors"""
    score = 0
    details = {}
    
    for factor, weight in RISK_WEIGHTS.items():
        if factors.get(factor, False):
            score += weight
            details[factor] = weight
    
    if score < RISK_LOW_THRESHOLD:
        level = 'low'
    elif score < RISK_MEDIUM_THRESHOLD:
        level = 'medium'
    else:
        level = 'high'
    
    return score, level, details


def test_scenario(name, factors, expected_level):
    """Test a scenario"""
    print(f"\n{'='*60}")
    print(f"SCENARIO: {name}")
    print(f"{'='*60}")
    
    print("\nRisk Factors:")
    for factor, weight in RISK_WEIGHTS.items():
        status = "✓" if factors.get(factor) else "✗"
        print(f"  {status} {factor.upper()}: {'+' + str(weight) if factors.get(factor) else '0'}")
    
    score, level, details = calculate_risk(factors)
    
    print(f"\nRisk Score: {score}/100")
    print(f"Risk Level: {level.upper()}")
    print(f"Factors Applied: {sum(details.values())}")
    
    if level == 'low':
        print("\n✅ ACTION: IMMEDIATE ACCESS GRANTED")
        auth_method = "Username/Password"
    elif level == 'medium':
        print("\n🔒 ACTION: OTP VERIFICATION REQUIRED")
        auth_method = "Username/Password + OTP"
    else:
        print("\n🚨 ACTION: LOGIN BLOCKED + ALERT SENT")
        auth_method = "Blocked"
    
    print(f"Authentication Method: {auth_method}")
    print(f"Expected Level: {expected_level}")
    print(f"Test Result: {'✓ PASS' if level == expected_level else '✗ FAIL'}")
    
    return level == expected_level


def main():
    print("\n" + "="*60)
    print("RISK-BASED ADAPTIVE AUTHENTICATION TEST SUITE")
    print("="*60)
    
    results = []
    
    # Test 1: Regular login, same device, same IP
    results.append(test_scenario(
        "Regular User, Same Device",
        {
            'new_device': False,
            'new_location': False,
            'unusual_time': False,
            'failed_attempts': False,
            'anomalous_behavior': False,
        },
        'low'
    ))
    
    # Test 2: Traveling user, new device, different IP
    results.append(test_scenario(
        "Traveling User, New Device & Location",
        {
            'new_device': True,
            'new_location': True,
            'unusual_time': False,
            'failed_attempts': False,
            'anomalous_behavior': False,
        },
        'medium'
    ))
    
    # Test 3: Failed login attempts
    results.append(test_scenario(
        "Multiple Failed Attempts",
        {
            'new_device': False,
            'new_location': False,
            'unusual_time': False,
            'failed_attempts': True,
            'anomalous_behavior': False,
        },
        'low'  # Just failed attempts = low risk
    ))
    
    # Test 4: All risk factors
    results.append(test_scenario(
        "Credential Stuffing Attack",
        {
            'new_device': True,
            'new_location': True,
            'unusual_time': True,
            'failed_attempts': True,
            'anomalous_behavior': True,
        },
        'high'
    ))
    
    # Test 5: New device + recent anomalies
    results.append(test_scenario(
        "Account Compromise Detection",
        {
            'new_device': True,
            'new_location': False,
            'unusual_time': False,
            'failed_attempts': False,
            'anomalous_behavior': True,
        },
        'high'
    ))
    
    # Test 6: Unusual time of login
    results.append(test_scenario(
        "Unusual Login Time",
        {
            'new_device': False,
            'new_location': False,
            'unusual_time': True,
            'failed_attempts': False,
            'anomalous_behavior': False,
        },
        'low'
    ))
    
    # Test 7: New location only
    results.append(test_scenario(
        "VPN/Proxy Usage Detection",
        {
            'new_device': False,
            'new_location': True,
            'unusual_time': False,
            'failed_attempts': False,
            'anomalous_behavior': False,
        },
        'low'
    ))
    
    # Summary
    print(f"\n\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("\n✓ All tests passed!")
    else:
        print(f"\n✗ {total - passed} test(s) failed!")
    
    # Risk distribution chart
    print(f"\n{'='*60}")
    print("RISK LEVEL DISTRIBUTION")
    print(f"{'='*60}")
    print(f"Low Risk (0-{RISK_LOW_THRESHOLD}):          {RISK_LOW_THRESHOLD} points")
    print(f"Medium Risk ({RISK_LOW_THRESHOLD}-{RISK_MEDIUM_THRESHOLD}):     {RISK_MEDIUM_THRESHOLD - RISK_LOW_THRESHOLD} points")
    print(f"High Risk ({RISK_MEDIUM_THRESHOLD}+):           {100 - RISK_MEDIUM_THRESHOLD}+ points")
    
    # Risk weights visualization
    print(f"\n{'='*60}")
    print("RISK FACTOR WEIGHTS")
    print(f"{'='*60}")
    total_weight = sum(RISK_WEIGHTS.values())
    for factor, weight in sorted(RISK_WEIGHTS.items(), key=lambda x: x[1], reverse=True):
        percentage = (weight / total_weight) * 100
        bar = "█" * int(percentage / 5)
        print(f"{factor.upper():<25} {weight:>2} pts  {bar} {percentage:>5.1f}%")
    print(f"{'TOTAL':<25} {total_weight:>2} pts")
    
    # Real-world examples
    print(f"\n{'='*60}")
    print("REAL-WORLD EXAMPLES")
    print(f"{'='*60}")
    
    examples = [
        ("Bank-Grade Security", {'new_device': True, 'new_location': True, 'unusual_time': True, 'failed_attempts': False, 'anomalous_behavior': False}, "medium→high"),
        ("Enterprise VPN", {'new_device': True, 'new_location': True, 'unusual_time': False, 'failed_attempts': False, 'anomalous_behavior': False}, "medium"),
        ("Social Media", {'new_device': True, 'new_location': False, 'unusual_time': False, 'failed_attempts': False, 'anomalous_behavior': False}, "low"),
        ("Attacker", {'new_device': True, 'new_location': True, 'unusual_time': True, 'failed_attempts': True, 'anomalous_behavior': True}, "high"),
    ]
    
    for example_name, factors, expected in examples:
        score, level, _ = calculate_risk(factors)
        print(f"{example_name:<30} Score: {score:>3}/100  Level: {level.upper():<6}  Expected: {expected}")


if __name__ == '__main__':
    main()
    print("\n" + "="*60)
    print("Testing complete!")
    print("="*60)
