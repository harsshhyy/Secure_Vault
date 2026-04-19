#!/usr/bin/env python3
"""
ML Model Testing Script for Secure Vault Anomaly Detection
This script tests the Isolation Forest model training and anomaly detection capabilities.
"""

import json
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Test Configuration
MIN_SAMPLES_FOR_TRAINING = 20
ANOMALY_THRESHOLD = -0.5
CONTAMINATION_RATE = 0.1


def test_ml_model():
    """Test the Isolation Forest model with synthetic behavioral data."""
    
    print("=" * 60)
    print("ISOLATION FOREST ANOMALY DETECTION TEST")
    print("=" * 60)
    
    # Generate synthetic normal behavior data (5 features)
    # Features: [typing_speed, key_delay, mouse_speed, click_rate, scroll_velocity]
    print("\n1. Generating synthetic normal behavioral data...")
    normal_data = []
    
    # User's normal behavior pattern
    for i in range(50):
        typing_speed = np.random.normal(8.5, 1.2)  # keys per second
        key_delay = np.random.normal(0.35, 0.08)   # seconds
        mouse_speed = np.random.normal(450, 80)    # pixels per second
        click_rate = np.random.normal(2.8, 0.5)    # clicks per minute
        scroll_velocity = np.random.normal(550, 100)  # pixels per second
        
        normal_data.append([typing_speed, key_delay, mouse_speed, click_rate, scroll_velocity])
    
    print(f"   Generated {len(normal_data)} normal behavior samples")
    print(f"   Sample 1: {normal_data[0]}")
    
    # Generate anomalous behavior data
    print("\n2. Generating synthetic anomalous behavioral data...")
    anomalous_data = []
    
    # Suspicious patterns
    for i in range(10):
        typing_speed = np.random.normal(1.5, 0.5)   # Very slow typing
        key_delay = np.random.normal(2.5, 0.3)      # Unusually long delays
        mouse_speed = np.random.normal(100, 50)     # Very slow mouse
        click_rate = np.random.normal(0.2, 0.1)     # Barely any clicks
        scroll_velocity = np.random.normal(50, 20)  # Minimal scrolling
        
        anomalous_data.append([typing_speed, key_delay, mouse_speed, click_rate, scroll_velocity])
    
    print(f"   Generated {len(anomalous_data)} anomalous behavior samples")
    print(f"   Anomalous sample: {anomalous_data[0]}")
    
    # Train the model
    print("\n3. Training Isolation Forest model...")
    features_array = np.array(normal_data)
    
    # Standardize features
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features_array)
    
    # Train model
    model = IsolationForest(
        contamination=CONTAMINATION_RATE,
        random_state=42,
        n_estimators=100,
        max_samples='auto',
        n_jobs=-1
    )
    model.fit(scaled_features)
    print("   Model training complete!")
    print(f"   Contamination rate: {CONTAMINATION_RATE * 100}%")
    print(f"   Number of estimators: 100")
    
    # Test on normal data
    print("\n4. Testing on normal behavioral data...")
    test_normal = np.array(normal_data[:5])
    scaled_test_normal = scaler.transform(test_normal)
    
    predictions = model.predict(scaled_test_normal)
    anomaly_scores = model.score_samples(scaled_test_normal)
    
    for i, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
        trust_score = max(0, min(100, int((score + 1) * 50)))
        is_anomaly = score < ANOMALY_THRESHOLD
        status = "NORMAL" if not is_anomaly else "ANOMALY"
        print(f"   Sample {i+1}: {status} | Score: {score:.3f} | Trust: {trust_score}/100")
    
    # Test on anomalous data
    print("\n5. Testing on anomalous behavioral data...")
    test_anomaly = np.array(anomalous_data[:5])
    scaled_test_anomaly = scaler.transform(test_anomaly)
    
    predictions = model.predict(scaled_test_anomaly)
    anomaly_scores = model.score_samples(scaled_test_anomaly)
    
    for i, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
        trust_score = max(0, min(100, int((score + 1) * 50)))
        is_anomaly = score < ANOMALY_THRESHOLD
        status = "NORMAL" if not is_anomaly else "ANOMALY"
        print(f"   Sample {i+1}: {status} | Score: {score:.3f} | Trust: {trust_score}/100")
    
    # Statistics
    print("\n6. Model Performance Statistics...")
    all_normal_scores = model.score_samples(scaled_features)
    all_anomaly_scores = model.score_samples(scaler.transform(np.array(anomalous_data)))
    
    print(f"   Normal data - Mean score: {all_normal_scores.mean():.3f}, Std: {all_normal_scores.std():.3f}")
    print(f"   Anomaly data - Mean score: {all_anomaly_scores.mean():.3f}, Std: {all_anomaly_scores.std():.3f}")
    print(f"   Anomaly threshold: {ANOMALY_THRESHOLD}")
    print(f"   Normal samples flagged as anomalies: {sum(all_normal_scores < ANOMALY_THRESHOLD)} / {len(all_normal_scores)}")
    print(f"   Anomaly samples flagged as anomalies: {sum(all_anomaly_scores < ANOMALY_THRESHOLD)} / {len(all_anomaly_scores)}")
    
    print("\n" + "=" * 60)
    print("TEST COMPLETE!")
    print("=" * 60)


def test_feature_storage():
    """Test feature storage and retrieval as JSON."""
    
    print("\n" + "=" * 60)
    print("FEATURE STORAGE TEST")
    print("=" * 60)
    
    # Create a feature vector
    feature_vector = [8.5, 0.35, 450, 2.8, 550]
    
    # Store as JSON
    print("\n1. Converting feature vector to JSON...")
    features_json = json.dumps(feature_vector)
    print(f"   JSON: {features_json}")
    
    # Retrieve from JSON
    print("\n2. Retrieving feature vector from JSON...")
    retrieved = json.loads(features_json)
    print(f"   Retrieved: {retrieved}")
    print(f"   Match: {retrieved == feature_vector}")
    
    print("\n" + "=" * 60)
    print("TEST COMPLETE!")
    print("=" * 60)


if __name__ == '__main__':
    test_ml_model()
    test_feature_storage()
    
    print("\n✓ All tests completed successfully!")
    print("\nNext steps:")
    print("1. Start the Flask app: python app.py")
    print("2. Create user accounts and login")
    print("3. The ML model will begin training after ~20 behavior samples")
    print("4. Anomalies will be detected and reported")
