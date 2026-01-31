"""
TOR-UNVEIL Risk Model Trainer
=============================

Trains Random Forest models for:
- Risk score regression (0-1 continuous)
- Risk level classification (LOW/MEDIUM/HIGH)

Author: TOR-UNVEIL Team
"""

import numpy as np
import pandas as pd
import joblib
import os
import json
from datetime import datetime
from typing import Tuple, Dict, Any

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix,
    mean_squared_error, r2_score, accuracy_score
)


class RiskModelTrainer:
    """ML model trainer for traffic risk analysis."""
    
    FEATURE_COLUMNS = [
        'correlation_score',
        'peak_time_lag',
        'burst_alignment_score',
        'flow_duration',
        'packet_rate_mean',
        'packet_rate_variance'
    ]
    
    def __init__(self, model_dir: str = None):
        if model_dir is None:
            model_dir = os.path.join(os.path.dirname(__file__), 'models')
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        self.regressor = RandomForestRegressor(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        )
        
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        
        self.feature_importance = {}
        self.metrics = {}
        self.is_trained = False
    
    def prepare_data(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Prepare features and labels."""
        X = df[self.FEATURE_COLUMNS].values
        y_score = df['final_risk_score'].values if 'final_risk_score' in df.columns else df['risk_score'].values
        y_level = self.label_encoder.fit_transform(df['risk_level'].values)
        return X, y_score, y_level
    
    def train(self, df: pd.DataFrame, test_size: float = 0.2) -> Dict[str, Any]:
        """Train both models."""
        print("\n" + "=" * 50)
        print("TRAINING RISK MODELS")
        print("=" * 50)
        
        X, y_score, y_level = self.prepare_data(df)
        X_scaled = self.scaler.fit_transform(X)
        
        X_train, X_test, y_score_train, y_score_test, y_level_train, y_level_test = \
            train_test_split(X_scaled, y_score, y_level, test_size=test_size, random_state=42)
        
        print(f"\nTrain: {len(X_train)}, Test: {len(X_test)}")
        
        # Train regressor
        print("\n--- Regressor ---")
        self.regressor.fit(X_train, y_score_train)
        y_pred_score = self.regressor.predict(X_test)
        reg_mse = mean_squared_error(y_score_test, y_pred_score)
        reg_r2 = r2_score(y_score_test, y_pred_score)
        print(f"MSE: {reg_mse:.4f}, R²: {reg_r2:.4f}")
        
        # Train classifier
        print("\n--- Classifier ---")
        self.classifier.fit(X_train, y_level_train)
        y_pred_level = self.classifier.predict(X_test)
        clf_acc = accuracy_score(y_level_test, y_pred_level)
        print(f"Accuracy: {clf_acc:.4f}")
        print("\nClassification Report:")
        print(classification_report(y_level_test, y_pred_level, target_names=self.label_encoder.classes_))
        
        # Feature importance
        self.feature_importance = dict(zip(
            self.FEATURE_COLUMNS,
            self.classifier.feature_importances_
        ))
        
        print("\n--- Feature Importance ---")
        for feat, imp in sorted(self.feature_importance.items(), key=lambda x: -x[1]):
            print(f"  {feat}: {imp:.4f}")
        
        self.metrics = {
            'regressor': {'mse': float(reg_mse), 'r2': float(reg_r2)},
            'classifier': {'accuracy': float(clf_acc)},
            'feature_importance': self.feature_importance,
            'trained_at': datetime.now().isoformat()
        }
        
        self.is_trained = True
        return self.metrics
    
    def predict(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict risk scores and levels."""
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")
        
        X_scaled = self.scaler.transform(features)
        risk_scores = self.regressor.predict(X_scaled)
        risk_levels = self.label_encoder.inverse_transform(
            self.classifier.predict(X_scaled)
        )
        return risk_scores, risk_levels
    
    def predict_proba(self, features: np.ndarray) -> np.ndarray:
        """Get class probabilities."""
        X_scaled = self.scaler.transform(features)
        return self.classifier.predict_proba(X_scaled)
    
    def save(self, prefix: str = 'risk_model'):
        """Save models to disk."""
        joblib.dump(self.regressor, os.path.join(self.model_dir, f'{prefix}_regressor.joblib'))
        joblib.dump(self.classifier, os.path.join(self.model_dir, f'{prefix}_classifier.joblib'))
        joblib.dump(self.scaler, os.path.join(self.model_dir, f'{prefix}_scaler.joblib'))
        joblib.dump(self.label_encoder, os.path.join(self.model_dir, f'{prefix}_encoder.joblib'))
        
        with open(os.path.join(self.model_dir, f'{prefix}_metrics.json'), 'w') as f:
            json.dump(self.metrics, f, indent=2)
        
        print(f"\nModels saved to {self.model_dir}")
    
    def load(self, prefix: str = 'risk_model'):
        """Load models from disk."""
        self.regressor = joblib.load(os.path.join(self.model_dir, f'{prefix}_regressor.joblib'))
        self.classifier = joblib.load(os.path.join(self.model_dir, f'{prefix}_classifier.joblib'))
        self.scaler = joblib.load(os.path.join(self.model_dir, f'{prefix}_scaler.joblib'))
        self.label_encoder = joblib.load(os.path.join(self.model_dir, f'{prefix}_encoder.joblib'))
        
        metrics_path = os.path.join(self.model_dir, f'{prefix}_metrics.json')
        if os.path.exists(metrics_path):
            with open(metrics_path) as f:
                self.metrics = json.load(f)
            self.feature_importance = self.metrics.get('feature_importance', {})
        
        self.is_trained = True
        print(f"Models loaded from {self.model_dir}")
        return self


def train_models():
    """Train and save models on generated data."""
    try:
        from data_generator import TrafficDataGenerator
    except ImportError:
        from .data_generator import TrafficDataGenerator
    
    gen = TrafficDataGenerator(seed=42)
    df = gen.generate_dataset(n_normal=400, n_suspicious=250, n_high_risk=120, n_edge=30)
    
    trainer = RiskModelTrainer()
    trainer.train(df)
    trainer.save()
    
    return trainer


if __name__ == '__main__':
    train_models()
