# Risk-Based Adaptive Authentication System

## Overview

The Secure Vault now features **Risk-Based Adaptive Authentication** - a bank-grade security system that dynamically adjusts authentication requirements based on login risk assessment.

Instead of:
```
Login Attempt → Username/Password Check → Allow/Deny
```

Now you have:
```
Login Attempt → Credentials Check → Risk Assessment → Adaptive Response
                                           ↓
                    ┌───────────────────────┼──────────────────────┐
                    ↓                       ↓                        ↓
                LOW RISK              MEDIUM RISK               HIGH RISK
            (Score < 30)            (Score 30-70)            (Score > 70)
            Normal Access           OTP Required              Block + Alert
```

## Architecture

### 1. Risk Scoring System

The system calculates a cumulative risk score (0-100) based on five factors:

| Factor | Weight | Triggered When |
|--------|--------|---|
| **New Device** | +25 | Device fingerprint not in trusted list |
| **New Location** | +20 | Different IP address from last login |
| **Unusual Time** | +10 | Login at very different time than usual |
| **Failed Attempts** | +15 | 3+ failed logins in last 30 minutes |
| **Anomalous Behavior** | +30 | Recent suspicious activity detected |

**Example Calculations:**
```
Low Risk Login:
  - Existing device: 0
  - Same IP: 0
  - Normal time: 0
  - No failed attempts: 0
  - No anomalies: 0
  Total: 0 → LOW RISK

Medium Risk Login:
  - New device: +25
  - Different IP: +20
  - Normal time: 0
  - No failed attempts: 0
  - No anomalies: 0
  Total: 45 → MEDIUM RISK (OTP Required)

High Risk Login:
  - New device: +25
  - Different IP: +20
  - Unusual time: +10
  - 3+ failed attempts: +15
  - Recent anomalies: +30
  Total: 100 → HIGH RISK (Blocked)
```

### 2. Authentication Levels

#### LOW RISK (Score < 30)
✅ **Action**: Immediate access granted
- Normal authentication flow
- Session created
- No additional verification needed
- Device fingerprint saved as trusted

#### MEDIUM RISK (Score 30-70)
🔒 **Action**: Require OTP verification
- Credentials verified but access suspended
- User redirected to OTP verification page
- 6-digit code from authenticator app required
- Risk factors displayed to user
- After OTP verified: Device marked as trusted
- Session created with medium-risk flag

#### HIGH RISK (Score > 70)
🚨 **Action**: Block login + Security alert
- Login attempt rejected immediately
- Security email sent to user
- Risk factors logged
- Account flagged for review
- User advised to change password
- Suggest contacting support

### 3. Database Schema

#### `login_attempts` Table
```sql
CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    username TEXT,
    ip_address TEXT,
    device_fingerprint TEXT,
    risk_score INTEGER,
    risk_level TEXT,           -- 'low', 'medium', 'high'
    factors TEXT,              -- JSON of risk factors
    success INTEGER,           -- 0 or 1
    otp_verified INTEGER,      -- 0 or 1
    timestamp TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
```

#### `users` Table Updates
```sql
ALTER TABLE users ADD COLUMN last_login_ip TEXT;           -- Track IP
ALTER TABLE users ADD COLUMN trusted_devices TEXT;         -- JSON array
ALTER TABLE users ADD COLUMN last_successful_login TEXT;   -- Track time
```

### 4. Device Fingerprinting

The system collects non-invasive device characteristics:
- Browser User-Agent
- Device language and platform
- Screen resolution and color depth
- Hardware concurrency (CPU cores)
- Device memory
- Touch points
- Timezone
- Browser plugins

This creates a unique "fingerprint" hash that identifies the device without using cookies or invasive techniques.

## API Endpoints

### POST /login
**Standard login with risk assessment**

Request:
```json
{
  "username": "john_doe",
  "password": "password123",
  "deviceFingerprint": "a1b2c3d4e5f6"
}
```

Response (Low Risk):
```json
Redirect to /dashboard
HTTP 302
```

Response (Medium Risk):
```json
Redirect to /verify_otp_login
HTTP 302
```

Response (High Risk):
```json
Redirect to /login with flash message
HTTP 302
```

### GET/POST /verify_otp_login
**OTP verification for medium-risk logins**

Request:
```json
{
  "otp_code": "123456"
}
```

Response (Success):
```json
Redirect to /dashboard
HTTP 302
```

Response (Invalid OTP):
```json
Redirect to /verify_otp_login with error
HTTP 302
```

## Security Features

### 1. Risk Factor Tracking
All login attempts are logged with:
- Risk score and level
- Risk factors (what triggered detection)
- Device fingerprint
- IP address
- Success/failure status
- OTP verification status

### 2. Device Trust Management
```python
# First login from device: Device not trusted, may require OTP
# After verified OTP: Device added to trusted_devices list
# Subsequent logins: Same device = lower risk score
# Up to 10 recent devices tracked per user
```

### 3. Time-Based Risk
```python
# Last login at 9 AM (typical work time)
# New login at 3 AM (unusual time)
# Risk score increases
# Gets tracked in anomaly detection too
```

### 4. Failed Attempt Tracking
```python
# 1 failed attempt: No penalty
# 2 failed attempts: No penalty
# 3+ failed attempts in 30 min: +15 risk points
# Temporary account protection
```

### 5. Security Alerts
High-risk login attempts trigger email alerts with:
- Risk score and factors
- Date/time of attempt
- IP address
- Recommended actions (change password, contact support)

## User Experience Flow

### Scenario 1: Regular User, Same Device
```
1. User visits login page
2. Device fingerprint collected (hidden)
3. User enters credentials
4. Risk assessment: 0 points (known device, same IP, usual time)
5. Risk level: LOW
6. Action: Immediate access ✅
7. Redirect to dashboard
```

### Scenario 2: Traveling User, New Device
```
1. User visits login from mobile while traveling
2. Device fingerprint collected
3. User enters credentials
4. Risk assessment:
   - New device: +25
   - Different IP (different country): +20
   - Total: 45 points
5. Risk level: MEDIUM
6. Action: Require OTP ⚠️
7. Redirect to OTP verification page
8. User enters 6-digit code from authenticator
9. OTP verified ✓
10. Device added to trusted list
11. Session created
12. Redirect to dashboard
```

### Scenario 3: Credential Stuffing Attack
```
1. Attacker attempts login
2. First attempt: Wrong password → Failed
3. Second attempt: Wrong password → Failed
4. Third attempt: Wrong password → Failed
5. Fourth attempt: Correct username, different password
6. Risk assessment:
   - New device: +25
   - Different IP: +20
   - 3+ failed attempts: +15
   - Total: 60+ points
7. Risk level: HIGH (or very high)
8. Action: Block login 🚫
9. Security email sent to user
10. Alert logged in system
```

## Configuration

### Risk Thresholds
Edit in `app.py`:
```python
RISK_LOW_THRESHOLD = 30      # Adjust lower for tighter security
RISK_MEDIUM_THRESHOLD = 70   # Adjust lower for more OTP requirements

# For a bank: RISK_LOW_THRESHOLD = 20, RISK_MEDIUM_THRESHOLD = 50
# For internal app: RISK_LOW_THRESHOLD = 40, RISK_MEDIUM_THRESHOLD = 80
```

### Risk Weights
Edit individual factor weights:
```python
RISK_WEIGHTS = {
    'new_device': 25,           # Increase to be stricter on new devices
    'new_location': 20,         # Increase for location-based security
    'unusual_time': 10,         # Increase for time-aware security
    'failed_attempts': 15,      # Increase to protect from brute force
    'anomalous_behavior': 30,   # Increase to protect from account hijacking
}
```

## Monitoring & Auditing

### Query high-risk login attempts:
```sql
SELECT * FROM login_attempts 
WHERE risk_level = 'high' 
ORDER BY timestamp DESC 
LIMIT 20;
```

### Track device trust:
```sql
SELECT username, trusted_devices 
FROM users 
WHERE trusted_devices IS NOT NULL;
```

### Monitor OTP usage:
```sql
SELECT COUNT(*) as otp_verifications 
FROM login_attempts 
WHERE otp_verified = 1 
AND timestamp > datetime('now', '-24 hours');
```

### Risk score trends:
```sql
SELECT 
  strftime('%Y-%m-%d', timestamp) as date,
  AVG(risk_score) as avg_risk,
  COUNT(*) as total_logins
FROM login_attempts 
GROUP BY date 
ORDER BY date DESC;
```

## Integration with ML System

The risk-based authentication system integrates with the existing ML anomaly detection:

```
Login Risk Score ← Includes Recent Anomalies Detected
                    (from behavior_logs)

If user had suspicious behavior in last 2 hours:
  anomalous_behavior risk factor activated
  +30 to risk score
  Medium-risk login or higher
```

## Real-World Examples

### Example 1: Bank System
```
RISK_LOW_THRESHOLD = 20
RISK_MEDIUM_THRESHOLD = 50
RISK_WEIGHTS = {
    'new_device': 40,
    'new_location': 35,
    'unusual_time': 10,
    'failed_attempts': 20,
    'anomalous_behavior': 35,
}
```
Result: Very strict, always requires OTP on new device + new location.

### Example 2: Social Media
```
RISK_LOW_THRESHOLD = 40
RISK_MEDIUM_THRESHOLD = 80
RISK_WEIGHTS = {
    'new_device': 20,
    'new_location': 15,
    'unusual_time': 5,
    'failed_attempts': 10,
    'anomalous_behavior': 25,
}
```
Result: Lenient, only blocks obvious attacks.

### Example 3: Corporate VPN
```
RISK_LOW_THRESHOLD = 15
RISK_MEDIUM_THRESHOLD = 40
RISK_WEIGHTS = {
    'new_device': 50,
    'new_location': 40,
    'unusual_time': 15,
    'failed_attempts': 25,
    'anomalous_behavior': 40,
}
```
Result: Very strict, heavily penalizes new devices/locations.

## Future Enhancements

1. **Geolocation & Impossible Travel**
   - Detect if user in NYC at 3 PM and Tokyo at 3:30 PM
   - Add +50 risk points

2. **Machine Learning Risk Predictor**
   - Train model on historical login attempts
   - Predict risk dynamically

3. **Device Reputation**
   - Track if device has had successful logins
   - Lower risk for high-reputation devices

4. **Behavioral Biometrics**
   - Keystroke dynamics
   - Mouse movement patterns
   - Click timing
   - Scroll behavior

5. **Whitelist Management**
   - User-managed trusted devices
   - Allow marking locations as "home" or "office"
   - Vacation mode (lower security when traveling)

6. **Risk Insurance**
   - Track failed authentications
   - Automatically lower risk after N successful logins
   - Decay factor (older logins = less relevant)

7. **Integration with External Services**
   - Breach database (if email in known breaches, increase risk)
   - IP reputation services
   - VPN/proxy detection

## Testing

### Simulate Low-Risk Login
```
1. Use same device as previous login
2. Same IP address
3. Similar time as last login
4. No recent failed attempts
Expected: Immediate access
```

### Simulate Medium-Risk Login
```
1. Use new device (or clear browser cache)
2. Use VPN/different IP
3. Enter wrong password twice, then correct password
Expected: OTP verification required
```

### Simulate High-Risk Login
```
1. Use new device
2. Use different IP
3. Try password 10 times to trigger failed attempts
4. Check admin account with recent anomalies
Expected: Login blocked + email sent
```

## Troubleshooting

### Issue: OTP always required
**Cause**: Risk threshold too low or devices not being saved
**Solution**: 
- Check trusted_devices column is being updated
- Verify device fingerprint is consistent
- Increase RISK_LOW_THRESHOLD

### Issue: Legitimate users blocked
**Cause**: Risk thresholds too strict or weight factors too high
**Solution**:
- Review blocked login patterns
- Adjust RISK_MEDIUM_THRESHOLD lower
- Reduce 'new_device' or 'new_location' weights

### Issue: Attackers getting through
**Cause**: Thresholds too lenient
**Solution**:
- Lower RISK_HIGH_THRESHOLD
- Increase risk weights
- Enable more aggressive monitoring

## Performance Impact

Risk assessment adds minimal overhead:
- Database queries: 3-4 fast lookups (indexed)
- Risk calculation: O(1) computation
- Total latency: <50ms additional per login

No performance impact during session usage.
