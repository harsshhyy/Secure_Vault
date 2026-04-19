# ML Anomaly Detection System - Implementation Guide

## Overview

The Secure Vault application now features a **full-fledged Isolation Forest machine learning model** for detecting anomalous user behavior. This replaces the basic rule-based detection with a sophisticated ML-powered system.

## Architecture

### 1. Feature Vector (5 Dimensions)

The system captures and analyzes five key behavioral features:

```
[typing_speed, key_delay, mouse_speed, click_rate, scroll_velocity]
```

| Feature | Unit | Normal Range | What it Detects |
|---------|------|--------------|-----------------|
| `typing_speed` | keys/sec | 6-10 | Unusual typing patterns (bot detection) |
| `key_delay` | seconds | 0.2-0.5 | Keyboard usage rhythm changes |
| `mouse_speed` | pixels/sec | 300-600 | Motor control changes (bot/automation) |
| `click_rate` | clicks/min | 1-4 | Interaction intensity changes |
| `scroll_velocity` | pixels/sec | 400-700 | Navigation pattern changes |

### 2. Data Pipeline

```
┌─────────────────────────────────────────────────┐
│     Browser (JavaScript - behaviour.js)         │
│  Collects real-time behavioral metrics          │
└────────────┬────────────────────────────────────┘
             │ Sends feature_vector via /log_behavior
             ▼
┌─────────────────────────────────────────────────┐
│     Flask Backend (/log_behavior endpoint)      │
│  1. Receives feature vector                     │
│  2. Standardizes features                       │
│  3. Runs anomaly detection                      │
│  4. Stores in database                          │
└────────────┬────────────────────────────────────┘
             │ Stores with metadata
             ▼
┌─────────────────────────────────────────────────┐
│        SQLite Database (behavior_logs)          │
│  Schema:                                        │
│  - id, user_id, action, details                 │
│  - features (JSON), trust_score, anomaly_score  │
│  - is_anomaly, timestamp                        │
└────────────┬────────────────────────────────────┘
             │ Training data
             ▼
┌─────────────────────────────────────────────────┐
│    Isolation Forest ML Model (per user)         │
│  - Trained on 20+ historical samples            │
│  - Uses StandardScaler normalization            │
│  - 100 estimators, 10% contamination rate       │
└─────────────────────────────────────────────────┘
```

### 3. Detection Process

```
Feature Vector Input
        │
        ▼
    [Check if ML model exists]
        │
        ├─ No model? → Train from 20+ historical samples
        │
        ▼
    [Normalize features with StandardScaler]
        │
        ▼
    [Get anomaly score from Isolation Forest]
        │
        ├─ Score range: -1 to +1
        │   └─ -1 = highly anomalous
        │   └─ +1 = very normal
        │
        ▼
    [Compare to ANOMALY_THRESHOLD (-0.5)]
        │
        ├─ Score < -0.5? → ANOMALY DETECTED
        │   └─ Trust Score: 0-25
        │   └─ Force logout, send alert email
        │
        └─ Score >= -0.5? → NORMAL
            └─ Trust Score: 25-100
            └─ Allow continued session
```

### 4. Constants & Configuration

```python
MIN_SAMPLES_FOR_TRAINING = 20          # Minimum historical samples to train
ANOMALY_THRESHOLD = -0.5               # ML score threshold for anomaly
CONTAMINATION_RATE = 0.1               # Expected % of anomalies in normal data
```

## Database Schema Updates

### New behavior_logs Columns

```sql
features TEXT              -- JSON array of feature vector [5 floats]
anomaly_score REAL         -- ML model score (-1 to +1)
is_anomaly INTEGER (0/1)   -- Binary anomaly flag
```

### Example Record

```json
{
  "id": 142,
  "user_id": 5,
  "action": "behavior_analysis",
  "details": "action=page_load method=isolation_forest",
  "features": "[8.2, 0.35, 425, 2.6, 530]",
  "trust_score": 72,
  "anomaly_score": 0.28,
  "is_anomaly": 0,
  "timestamp": "2026-04-19T14:32:15.123456"
}
```

## ML Model Training

### When Training Occurs

1. **First time**: After user has 20+ behavior samples
2. **Automatic**: Model retrains on each new batch of behavior data
3. **Per-user**: Each user gets their own trained model (personalized)

### Training Process

```python
def train_user_model(user_id):
    1. Fetch up to 500 recent behavior records with feature vectors
    2. Validate and parse JSON feature vectors
    3. Check if >= 20 valid samples exist
    4. Normalize using StandardScaler (mean=0, std=1)
    5. Train IsolationForest with:
       - contamination=0.1
       - n_estimators=100
       - max_samples='auto'
       - random_state=42
    6. Store model and scaler in memory
    7. Log success with sample count
```

### Example Training Output

```
[ML] Successfully trained model for user 5 with 78 samples
```

## Anomaly Detection

### Detection Methods

1. **Primary (Isolation Forest)**: ML-based, requires 20+ samples
2. **Fallback (Rule-based)**: Used when not enough samples yet

### Anomaly Scoring

**Isolation Forest Score** → **Trust Score** Conversion:

```
Trust Score = ((anomaly_score + 1) * 50)

Examples:
  anomaly_score = -0.9  →  Trust Score =  5  (High anomaly)
  anomaly_score = -0.5  →  Trust Score = 25  (Threshold)
  anomaly_score =  0.0  →  Trust Score = 50  (Neutral)
  anomaly_score = +0.8  →  Trust Score = 90  (Very normal)
```

### When Anomalies Trigger Logout

```
IF trust_score < ANOMALY_THRESHOLD (-0.5)
  THEN
    - Log: 'anomaly_detected' record
    - Store: anomaly_score, features
    - Send: Email alert to user
    - Action: Force session logout (401 response)
    - Response: {status: 'logout', anomaly: true, method: 'isolation_forest'}
```

## Endpoint Changes

### POST /log_behavior

**Request:**
```json
{
  "action": "page_load",
  "details": "Loaded dashboard",
  "featureVector": [8.2, 0.35, 425, 2.6, 530]
}
```

**Response (Normal):**
```json
{
  "status": "ok",
  "trustScore": 72,
  "anomaly": false,
  "method": "isolation_forest"
}
```

**Response (Anomaly):**
```json
{
  "status": "logout",
  "trustScore": 0,
  "anomaly": true,
  "method": "isolation_forest",
  "message": "Anomalous behavior detected. Session terminated for security."
}
```

### GET /log_behavior

Returns last 100 behavior records with parsed feature vectors:
```json
[
  {
    "id": 142,
    "action": "behavior_analysis",
    "features": [8.2, 0.35, 425, 2.6, 530],
    "trust_score": 72,
    "anomaly_score": 0.28,
    "is_anomaly": 0,
    "timestamp": "2026-04-19T14:32:15"
  }
]
```

## Security Features

### 1. Email Alerts
When anomaly detected:
- Email sent to user with details
- Includes instructions to change password
- Recommends password change if account compromised

### 2. Session Management
- Automatic logout on anomaly detection
- Session data cleared
- 401 response prevents re-authentication

### 3. Feature Normalization
- StandardScaler prevents scale bias
- Each user's model personalized
- Historical context preserved

### 4. Multi-Method Detection
- Primary: ML-based (high accuracy when trained)
- Fallback: Rule-based (immediate protection)
- Graceful degradation

## Testing

Run the included test script:
```bash
python ml_test.py
```

This tests:
- Isolation Forest training on synthetic data
- Normal behavior classification
- Anomaly detection
- Feature storage/retrieval

## Monitoring

### Console Output

```
[ML] Successfully trained model for user 5 with 78 samples
[ANOMALY DETECTION] User john_doe: anomaly=False, score=72, method=isolation_forest
[ALERT] Anomaly detected for user jane_smith (score: 15, method: isolation_forest)
[EMAIL] Anomaly alert sent to jane@example.com
```

### Database Queries

**Find anomalies for a user:**
```sql
SELECT * FROM behavior_logs 
WHERE user_id = 5 AND is_anomaly = 1 
ORDER BY timestamp DESC;
```

**Get trust score statistics:**
```sql
SELECT AVG(trust_score) as avg_score, MIN(trust_score) as min_score, 
       MAX(trust_score) as max_score 
FROM behavior_logs 
WHERE user_id = 5;
```

**Check model training status:**
```sql
SELECT COUNT(*) as sample_count 
FROM behavior_logs 
WHERE user_id = 5 AND features IS NOT NULL;
```

## Configuration Tuning

### Adjust Sensitivity

```python
# More sensitive (catch more anomalies):
ANOMALY_THRESHOLD = -0.3      # Lower value = more anomalies caught
CONTAMINATION_RATE = 0.15      # Higher % = expect more anomalies

# Less sensitive (fewer false positives):
ANOMALY_THRESHOLD = -0.7       # Higher value = fewer anomalies caught
CONTAMINATION_RATE = 0.05      # Lower % = expect fewer anomalies
```

### Training Data Size

```python
# Faster training with less data:
MIN_SAMPLES_FOR_TRAINING = 10  # Start training earlier

# More robust models:
MIN_SAMPLES_FOR_TRAINING = 50  # Wait for more samples
```

## Troubleshooting

### Issue: "Not enough data to train model"
- **Cause**: User has <20 behavior samples
- **Solution**: Wait for more activity, fallback rule-based detection in use
- **Status**: Will switch to ML automatically after 20 samples

### Issue: "Model not detecting anomalies"
- **Cause**: Anomaly threshold too high or contamination rate too low
- **Solution**: Adjust constants, check database for features
- **Test**: Run `ml_test.py` to verify Isolation Forest works

### Issue: "False positives (legitimate users flagged)"
- **Cause**: Threshold too low or user behavior changed
- **Solution**: Increase ANOMALY_THRESHOLD, retrain models
- **Monitor**: Check email alerts for patterns

## Future Enhancements

1. **Device Fingerprinting**: Add 5 device features to vector
2. **Geolocation**: Detect impossible travel patterns
3. **Time-based**: Different models for different times/days
4. **Ensemble**: Combine Isolation Forest with One-Class SVM
5. **Retraining**: Automatic online model updates
6. **Feature Importance**: Show which behaviors triggered alert
7. **Whitelist**: Allow "known good" anomalies after verification
