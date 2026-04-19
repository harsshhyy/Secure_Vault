# Risk-Based Adaptive Authentication - Quick Reference

## 🚀 What Got Implemented

Your Secure Vault now has **bank-grade, dynamic authentication** that adapts to login risk!

### Three Authentication Levels

```
LOW RISK (0-30)       → ✅ Immediate Access
MEDIUM RISK (30-70)   → 🔒 OTP Required
HIGH RISK (70+)       → 🚨 Block + Alert
```

## 📊 Risk Scoring (What Gets Points)

| Factor | Points | Trigger |
|--------|--------|---------|
| New Device | +25 | Device not in trusted list |
| New Location | +20 | Different IP address |
| Unusual Time | +10 | Login outside user's pattern |
| Failed Attempts | +15 | 3+ failed logins in 30 min |
| Anomalies | +30 | Recent suspicious behavior |

## 🔐 Example Flows

### User 1: Regular Login (Same Device)
```
Score: 0 → LOW RISK
Action: Login immediately ✅
```

### User 2: Traveling on New Laptop
```
New device: +25
Different IP: +20
Score: 45 → MEDIUM RISK
Action: Ask for OTP code from authenticator 🔒
User enters 6-digit code → Granted access
Device saved as trusted
```

### User 3: Attacker with Stolen Credentials
```
New device: +25
Different IP: +20
Failed 5 times: +15
Unusual time: +10
Recent anomalies: +30
Score: 100 → HIGH RISK
Action: Block + Email user + Alert ⛔
```

## 🛠️ Configuration Points

Want stricter security? In `app.py`:

```python
# Tighter security
RISK_LOW_THRESHOLD = 20      # Lower = stricter
RISK_MEDIUM_THRESHOLD = 50   # Lower = more OTP

# For bank: these values work great
# For casual app: increase to 40 and 80
```

Adjust risk weights:
```python
RISK_WEIGHTS = {
    'new_device': 30,           # Increase to 40 if very strict
    'new_location': 25,         # Increase to 35 if paranoid
    'unusual_time': 10,         # Keep low
    'failed_attempts': 20,      # Increase to 25 for brute-force protection
    'anomalous_behavior': 30,   # Keep high (ML detected a problem!)
}
```

## 📁 New Database Tables

### `login_attempts` - Tracks all login attempts
```
user_id | username | ip_address | device_fingerprint | 
risk_score | risk_level | factors | success | otp_verified | timestamp
```

### `users` table updates
```
last_login_ip           → Last IP used for login
trusted_devices         → JSON list of known device fingerprints (up to 10)
last_successful_login   → Timestamp of last successful login
```

## 🔍 Monitoring Commands

**Find blocked logins:**
```sql
SELECT * FROM login_attempts WHERE risk_level = 'high' 
ORDER BY timestamp DESC LIMIT 20;
```

**Find OTP usage:**
```sql
SELECT COUNT(*) FROM login_attempts 
WHERE otp_verified = 1 
AND timestamp > datetime('now', '-24 hours');
```

**Find risky IP addresses:**
```sql
SELECT ip_address, COUNT(*) as attempts 
FROM login_attempts 
WHERE risk_level IN ('medium', 'high')
GROUP BY ip_address 
ORDER BY attempts DESC;
```

## 🎯 Real-World Scenarios

### Scenario A: Bank Login
```python
RISK_LOW_THRESHOLD = 20
RISK_WEIGHTS['new_device'] = 40

Result: Any new device triggers OTP
Perfect for: Banking, highly sensitive
```

### Scenario B: Enterprise VPN
```python
RISK_LOW_THRESHOLD = 15
RISK_WEIGHTS['new_location'] = 40

Result: New location = high risk
Perfect for: Corporate, fixed workforce
```

### Scenario C: Social Media
```python
RISK_LOW_THRESHOLD = 50
RISK_MEDIUM_THRESHOLD = 80

Result: Only obvious attacks trigger OTP
Perfect for: Casual use, usability first
```

## 🧪 How to Test

### Test 1: Normal Login (Low Risk)
- Use your regular device
- Same IP as before
- Should get instant access ✅

### Test 2: Medium Risk Login
- New device (incognito mode / different browser)
- Different IP (VPN)
- Should ask for OTP 🔒
- Enter OTP → Access granted
- Device saved as trusted

### Test 3: High Risk Login
- Try to brute force password
- Use new device + new IP + failed attempts
- Should see "Login blocked" + email sent 🚨

## 📱 What Users See

### Low Risk
```
✅ Login successful!
→ Redirects to dashboard
```

### Medium Risk
```
⚠️ Security Verification Required
Risk Score: 45/100
Risk Factors:
  ✓ New device detected
  ✓ Different IP address

Enter your 6-digit authentication code:
[  ]
```

### High Risk
```
🚨 Login blocked due to unusual activity
Risk Factors:
  ✓ New device detected
  ✓ Different IP address
  ✓ Multiple failed login attempts
  ✓ Anomalous behavior detected

A security alert has been sent to your email.
If this was you, please try again in a few minutes.
If not, change your password immediately.
```

## 🔗 How It Integrates

```
ML Anomaly Detection ← Feeds risk scores
                        If user had suspicious behavior
                        → Anomalies = +30 risk points
                        → Can trigger high-risk login
```

## ⚙️ Under the Hood

### Device Fingerprinting (Private, No Tracking)
Collects:
- Browser type
- Screen resolution
- Timezone
- Language
- Plugins

Creates unique device ID WITHOUT cookies or tracking

### Risk Calculation
```python
def calculate_login_risk(user_id, ip_address, device_fingerprint):
    score = 0
    
    # Check each risk factor
    if new_device: score += 25
    if new_location: score += 20
    if unusual_time: score += 10
    if failed_attempts: score += 15
    if anomalies: score += 30
    
    return score  # 0-100
```

### Session Handling
```
Low Risk:  Create session immediately
           Device marked as trusted
           
Medium:    Store temp login state
           User completes OTP
           Then create session
           Mark device as trusted
           
High:      Reject
           Log attempt
           Send alert
           No session created
```

## 🚨 Security Benefits

1. **Stops Credential Stuffing** - New device + failed attempts = blocked
2. **Detects Account Takeover** - Different device + anomalies = OTP
3. **Prevents Brute Force** - Failed attempts add +15 per 3 failures
4. **Catches Phishing** - Unusual location/time triggers caution
5. **ML Integration** - Recent ML-detected anomalies add +30

## 📈 Future Upgrades (Ideas)

- Geolocation (detect impossible travel)
- Device reputation tracking
- Vacation mode (lower security)
- User-managed trusted devices list
- Risk prediction with ML
- Integration with breach databases

## 🐛 Troubleshooting

**Users always get OTP?**
- Check if trusted_devices is saving correctly
- May need to increase RISK_LOW_THRESHOLD

**Legitimate users getting blocked?**
- Increase RISK_MEDIUM_THRESHOLD
- Reduce new_device or new_location weights
- Check failed_attempts logic

**No one getting blocked?**
- Increase risk_weights
- Lower RISK_HIGH_THRESHOLD

## 📞 Support

Check the full documentation:
- `RISK_BASED_AUTH.md` - Complete technical guide
- `test_risk_auth.py` - Test scenarios
- `app.py` - Implementation code

---

**Summary**: Your app now has enterprise-grade authentication that learns user patterns and adapts security accordingly. It's like having a smart security guard that gets to know your users better over time! 🛡️
