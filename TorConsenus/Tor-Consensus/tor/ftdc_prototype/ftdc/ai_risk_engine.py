"""
AI-Powered Risk Assessment Engine for TOR-Unveil
================================================

This module provides an AI-based decision-support layer for the TOR traffic
correlation analysis system. It operates on top of the existing correlation
engine outputs to provide probabilistic risk scoring and prioritization.

IMPORTANT DISCLAIMER:
--------------------
This system is designed for INVESTIGATIVE SUPPORT ONLY. It provides:
- Probabilistic risk assessments based on correlation patterns
- Prioritization guidance for forensic investigators
- Explainable feature-based scoring

This system does NOT:
- Perform deanonymization of TOR users
- Identify individual users or their activities
- Claim definitive attribution or identification
- Replace human investigative judgment

All outputs are probabilistic estimates intended to assist, not replace,
proper forensic investigation procedures.

Author: TOR-Unveil Development Team
Date: December 2024
License: For Law Enforcement Use Only
"""

import numpy as np
import json
import os
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Optional ML dependencies - gracefully handle if not installed
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    pd = None
    PANDAS_AVAILABLE = False
    logger.warning("pandas not available - some AI features may be limited")

try:
    from sklearn.ensemble import RandomForestRegressor
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    RandomForestRegressor = None
    train_test_split = None
    cross_val_score = None
    StandardScaler = None
    joblib = None
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available - AI model training disabled, using heuristic scoring")


class AIRiskEngine:
    """
    AI-powered risk assessment engine for TOR relay correlation analysis.
    
    This engine uses machine learning to provide normalized risk scores
    and explainable prioritization for identified guard node candidates.
    
    The model is trained on historical correlation results and uses
    multiple features to assess the investigative priority of each relay.
    
    INVESTIGATIVE SUPPORT DISCLAIMER:
    This system provides probabilistic risk assessments only. All outputs
    should be verified through proper forensic investigation procedures.
    Results do not constitute evidence of user identification.
    """
    
    # Feature names for explainability (8 features as per specification)
    FEATURE_NAMES = [
        'correlation_score',       # Statistical correlation from FTDC engine
        'timing_similarity',       # Temporal pattern match (0-1)
        'bandwidth_similarity',    # Bandwidth profile correlation (0-1)
        'relay_uptime',           # Guard node uptime in days (normalized)
        'relay_bandwidth',        # Guard node bandwidth capacity (normalized)
        'geographic_distance_km', # Estimated geographic distance (normalized)
        'port_match_flag',        # TOR port pattern match (0/1)
        'exit_seen_flag',         # Exit relay observed (0/1)
    ]
    
    # Risk band thresholds
    RISK_BANDS = {
        'HIGH': (0.7, 1.0),
        'MEDIUM': (0.4, 0.7),
        'LOW': (0.0, 0.4)
    }
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the AI Risk Engine with Random Forest Regressor.
        
        Args:
            model_path: Path to load pre-trained model (optional)
        
        Note: This engine uses Random Forest Regressor ONLY for risk prediction.
        All risk scores are probabilistic and for investigative support only.
        """
        self.model = None
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        self.is_trained = False
        self.feature_importances_ = None
        self.training_metadata = {}
        self.sklearn_available = SKLEARN_AVAILABLE
        
        # Model storage path
        self.model_dir = os.path.join(os.path.dirname(__file__), 'models')
        os.makedirs(self.model_dir, exist_ok=True)
        
        if SKLEARN_AVAILABLE:
            if model_path and os.path.exists(model_path):
                self.load_model(model_path)
            else:
                self._initialize_model()
        else:
            logger.info("Sklearn not available - using heuristic-based scoring")
        
        logger.info(f"AI Risk Engine initialized (model=RandomForestRegressor, sklearn={SKLEARN_AVAILABLE})")
        logger.info("NOTICE: This system provides investigative support only.")
    
    @property
    def model_version(self) -> str:
        """Return model version string."""
        if self.training_metadata.get('version'):
            return self.training_metadata['version']
        return "heuristic_v1.0" if not self.is_trained else "random_forest_regressor_v1.0"
    
    @property
    def feature_names(self) -> List[str]:
        """Return list of feature names."""
        return self.FEATURE_NAMES.copy()
    
    def _initialize_model(self):
        """Initialize the Random Forest Regressor model."""
        if not SKLEARN_AVAILABLE:
            logger.warning("sklearn not available - model initialization skipped")
            return
        
        # Random Forest Regressor ONLY - no classifier options
        self.model = RandomForestRegressor(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
    
    def extract_features(self, relay_data: Dict, correlation_result: Dict, 
                         historical_data: Optional[Dict] = None) -> np.ndarray:
        """
        Extract 8-feature vector from relay and correlation data.
        
        Features (8 total):
            1. correlation_score: Statistical correlation from FTDC engine
            2. timing_similarity: Temporal pattern match (0-1)
            3. bandwidth_similarity: Bandwidth profile correlation (0-1)
            4. relay_uptime: Guard node uptime in days (normalized)
            5. relay_bandwidth: Guard node bandwidth capacity (normalized)
            6. geographic_distance_km: Estimated geographic distance (normalized)
            7. port_match_flag: TOR port pattern match (0/1)
            8. exit_seen_flag: Exit relay observed (0/1)
        
        Args:
            relay_data: Relay metadata from consensus
            correlation_result: Correlation scores from FTDC engine
            historical_data: Optional historical analysis data
        
        Returns:
            Feature vector as numpy array (8 elements)
        
        Note: Features are designed to support investigation prioritization,
        not to identify individual users.
        """
        features = []
        
        # Feature 1: Correlation score (primary from existing engine)
        correlation_score = correlation_result.get('confidence', 0.0)
        features.append(min(1.0, max(0.0, correlation_score)))
        
        # Feature 2: Timing similarity
        scores = correlation_result.get('scores', {})
        timing_sim = scores.get('timing', scores.get('bandwidth', 0.0) * 0.9)
        features.append(min(1.0, max(0.0, timing_sim)))
        
        # Feature 3: Bandwidth similarity
        bw_sim = scores.get('bandwidth', 0.0)
        features.append(min(1.0, max(0.0, bw_sim)))
        
        # Feature 4: Relay uptime (normalized to 0-1, max 365 days)
        uptime = relay_data.get('uptime', 0)
        uptime_days = uptime / 86400 if uptime else 0
        features.append(min(1.0, uptime_days / 365))
        
        # Feature 5: Relay bandwidth (normalized, log scale)
        bandwidth = relay_data.get('bandwidth', 0)
        if bandwidth > 0:
            # Normalize using log scale (1 KB/s to 100 MB/s range)
            bw_norm = np.log10(bandwidth + 1) / np.log10(100_000_000)
            features.append(min(1.0, max(0.0, bw_norm)))
        else:
            features.append(0.0)
        
        # Feature 6: Geographic distance (normalized, 0-1)
        geo_distance = correlation_result.get('geographic_distance_km', 0)
        # Normalize: 0km = 1.0, 20000km = 0.0 (inverse relationship)
        if geo_distance > 0:
            geo_score = max(0.0, 1.0 - (geo_distance / 20000))
        else:
            geo_score = scores.get('proximity', 0.5)
        features.append(min(1.0, max(0.0, geo_score)))
        
        # Feature 7: Port match flag
        # 1 if relay uses standard TOR ports (9001, 443), 0 otherwise
        or_port = relay_data.get('or_port', 0)
        port_flag = 1.0 if or_port in [9001, 443] else 0.0
        features.append(port_flag)
        
        # Feature 8: Exit seen flag
        # 1 if relay has Exit flag, 0 otherwise
        flags = relay_data.get('flags', [])
        if isinstance(flags, str):
            flags = json.loads(flags) if flags.startswith('[') else [flags]
        exit_flag = 1.0 if 'Exit' in flags else 0.0
        features.append(exit_flag)
        
        return np.array(features, dtype=np.float64)
    
    def prepare_training_data(self, historical_analyses: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare training data from historical analysis results.
        
        Args:
            historical_analyses: List of past analysis results
        
        Returns:
            Tuple of (features array, labels array)
            Labels are continuous values 0.0-1.0 for regression
        
        Note: Training data is used to learn correlation patterns,
        not to identify individual users.
        """
        X = []
        y = []
        
        for analysis in historical_analyses:
            guard_rankings = analysis.get('guard_rankings', [])
            
            for i, guard in enumerate(guard_rankings):
                # Extract features
                features = self.extract_features(guard, guard)
                X.append(features)
                
                # Generate continuous labels based on confidence for regression
                confidence = guard.get('confidence', 0)
                rank = i + 1
                total_guards = len(guard_rankings)
                
                # Calculate risk score as regression target (0.0-1.0)
                # Weighted combination of confidence and rank
                rank_factor = max(0, 1 - (rank / max(total_guards, 1)))
                risk_label = (0.6 * confidence + 0.4 * rank_factor)
                risk_label = min(1.0, max(0.0, risk_label))
                
                y.append(risk_label)
        
        return np.array(X), np.array(y)
    
    def train(self, historical_analyses: List[Dict], validation_split: float = 0.2,
              min_samples: int = 10) -> Dict:
        """
        Train the AI risk model (Random Forest Regressor) on historical analysis data.
        
        Args:
            historical_analyses: List of historical analysis results
            validation_split: Fraction of data for validation
            min_samples: Minimum required training samples
        
        Returns:
            Training metrics dictionary with R², MAE, MSE
        
        Note: Model learns correlation patterns for investigative prioritization,
        not user identification patterns.
        """
        logger.info("Starting AI Risk Engine training (RandomForestRegressor)...")
        logger.info(f"Training samples: {len(historical_analyses)} analyses")
        
        # Prepare training data
        X, y = self.prepare_training_data(historical_analyses)
        
        if len(X) < min_samples:
            logger.warning(f"Insufficient training data ({len(X)} < {min_samples}). Using fallback scoring.")
            self.is_trained = False
            return {'status': 'insufficient_data', 'samples': len(X), 'error': 'Not enough samples'}
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X_scaled, y, test_size=validation_split, random_state=42
        )
        
        # Train model
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        # Calculate regression metrics
        y_pred = self.model.predict(X_val)
        
        # Regression metrics
        mse = mean_squared_error(y_val, y_pred)
        mae = mean_absolute_error(y_val, y_pred)
        r2 = r2_score(y_val, y_pred)
        
        # Cross-validation score (negative MSE, convert to positive)
        cv_scores = cross_val_score(self.model, X_scaled, y, cv=min(5, len(X)//2), scoring='neg_mean_squared_error')
        cv_mse = -cv_scores.mean()
        
        # Feature importances
        self.feature_importances_ = dict(zip(
            self.FEATURE_NAMES,
            self.model.feature_importances_
        ))
        
        # Store training metadata
        self.training_metadata = {
            'training_date': datetime.now().isoformat(),
            'model_type': 'RandomForestRegressor',
            'version': 'random_forest_regressor_v1.0',
            'samples_total': len(X),
            'samples_train': len(X_train),
            'samples_val': len(X_val),
            'r2_score': float(r2),
            'mse': float(mse),
            'mae': float(mae),
            'cv_mse': float(cv_mse),
            'feature_importances': self.feature_importances_,
            'disclaimer': 'Model trained for investigative support only'
        }
        
        metrics = {
            'status': 'success',
            'r2_score': float(r2),
            'mse': float(mse),
            'mae': float(mae),
            'cv_mse': float(cv_mse),
            'training_samples': len(X),
            'feature_importance': self.feature_importances_
        }
        
        logger.info(f"Training completed. R²={r2:.4f}, MAE={mae:.4f}, MSE={mse:.4f}")
        
        return metrics
    
    def predict_risk(self, relay_data: Dict, correlation_result: Dict,
                     historical_data: Optional[Dict] = None) -> Dict:
        """
        Predict risk score for a single relay.
        
        Args:
            relay_data: Relay metadata
            correlation_result: Correlation scores
            historical_data: Optional historical context
        
        Returns:
            Risk assessment dictionary with score, band, and explanation
        
        Note: Risk scores indicate investigative priority, not user identification.
        """
        # Extract features
        features = self.extract_features(relay_data, correlation_result, historical_data)
        
        if self.is_trained and SKLEARN_AVAILABLE:
            # Scale and predict using Random Forest Regressor
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            
            # Direct regression prediction (0-1 range)
            risk_score = float(self.model.predict(features_scaled)[0])
            # Clamp to valid range
            risk_score = min(1.0, max(0.0, risk_score))
            
            # Calculate confidence based on prediction spread from trees
            if hasattr(self.model, 'estimators_'):
                tree_predictions = [tree.predict(features_scaled)[0] for tree in self.model.estimators_]
                std_dev = float(np.std(tree_predictions))
                # Higher agreement = higher confidence
                confidence = max(0.0, min(1.0, 1.0 - std_dev))
            else:
                confidence = 0.7
        else:
            # Improved heuristic scoring with better differentiation
            risk_score = self._advanced_heuristic_scoring(features, relay_data, correlation_result)
            confidence = 0.65  # Improved confidence for enhanced heuristic
        
        # Determine risk band
        risk_band = self._get_risk_band(risk_score)
        
        # Generate explanation
        explanation = self._generate_explanation(features, risk_score, risk_band)
        
        # Feature contributions for interpretability
        feature_contributions = {}
        if self.feature_importances_:
            for i, feat_name in enumerate(self.FEATURE_NAMES):
                feature_contributions[feat_name] = float(
                    features[i] * self.feature_importances_.get(feat_name, 0.1)
                )
        
        return {
            'risk_score': float(risk_score),
            'risk_band': risk_band,
            'confidence': float(confidence),
            'explanation': explanation,
            'feature_values': dict(zip(self.FEATURE_NAMES, features.tolist())),
            'feature_contributions': feature_contributions,
            'model_trained': self.is_trained,
            'model_type': 'RandomForestRegressor',
            'disclaimer': 'Risk score for investigative prioritization only. Not evidence of identification.'
        }
    
    def batch_predict(self, guard_rankings: List[Dict], 
                      historical_data: Optional[Dict] = None) -> List[Dict]:
        """
        Predict risk scores for multiple guard candidates using Random Forest Regressor.
        
        Args:
            guard_rankings: List of guard candidate dictionaries
            historical_data: Optional historical context
        
        Returns:
            List of risk assessments, sorted by risk score descending
        
        Note: Batch predictions for investigative prioritization only.
        """
        results = []
        
        for guard in guard_rankings:
            risk_assessment = self.predict_risk(guard, guard, historical_data)
            
            # Extract top contributing factors for UI display
            top_factors = []
            feature_contributions = risk_assessment.get('feature_contributions', {})
            
            if feature_contributions:
                sorted_contributions = sorted(
                    feature_contributions.items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                for feat_name, contribution in sorted_contributions[:5]:
                    feat_value = risk_assessment.get('feature_values', {}).get(feat_name, 0)
                    if contribution > 0.05:
                        top_factors.append({
                            'factor': feat_name,
                            'contribution': contribution,
                            'value': feat_value
                        })
            
            # Calculate confidence interval based on model uncertainty
            base_score = risk_assessment['risk_score']
            base_conf = risk_assessment.get('confidence', 0.5)
            uncertainty = 0.15 * (1 - base_conf)  # Higher confidence = narrower interval
            
            confidence_interval = {
                'lower': max(0, base_score - uncertainty),
                'upper': min(1.0, base_score + uncertainty)
            }
            
            results.append({
                'fingerprint': guard.get('fingerprint'),
                'nickname': guard.get('nickname'),
                'ip': guard.get('ip'),
                'country': guard.get('country'),
                'original_confidence': guard.get('confidence', 0),
                'risk_score': risk_assessment['risk_score'],
                'risk_band': risk_assessment['risk_band'],
                'confidence': risk_assessment.get('confidence', 0.5),
                'confidence_interval': confidence_interval,
                'top_contributing_factors': top_factors[:5],
                'feature_contributions': feature_contributions,
                'model_trained': risk_assessment.get('model_trained', False),
                'model_type': 'RandomForestRegressor',
                'disclaimer': risk_assessment.get('disclaimer', 'Risk score for investigative prioritization only.')
            })
        
        # Sort by risk score descending
        results.sort(key=lambda x: x['risk_score'], reverse=True)
        
        # Add rank
        for i, result in enumerate(results, 1):
            result['ai_rank'] = i
        
        return results
    
    def _advanced_heuristic_scoring(self, features: np.ndarray, 
                                     relay_data: Dict, 
                                     correlation_result: Dict) -> float:
        """
        Advanced heuristic scoring with better differentiation.
        
        Uses multi-factor analysis with non-linear combinations to produce
        more varied and meaningful risk scores.
        
        Args:
            features: 8-element feature vector
            relay_data: Relay metadata
            correlation_result: Correlation analysis results
        
        Returns:
            Risk score in range [0, 1] with better variance
        """
        # Feature indices for clarity
        CORR_SCORE = 0
        TIMING_SIM = 1
        BW_SIM = 2
        UPTIME = 3
        BANDWIDTH = 4
        GEO_DIST = 5
        PORT_FLAG = 6
        EXIT_FLAG = 7
        
        # Base score from correlation (most important factor)
        correlation_score = features[CORR_SCORE]
        
        # Get the original confidence from correlation result
        original_confidence = correlation_result.get('confidence', correlation_score)
        
        # Enhanced scoring with non-linear transformations
        # 1. Correlation component (40% weight) - amplify differences
        corr_component = correlation_score ** 0.8  # Slightly boost lower scores
        
        # 2. Timing and bandwidth similarity (25% weight combined)
        timing_bw_avg = (features[TIMING_SIM] + features[BW_SIM]) / 2
        # Apply sigmoid-like transformation for better spread
        timing_bw_component = 1 / (1 + np.exp(-10 * (timing_bw_avg - 0.5)))
        
        # 3. Relay quality indicators (20% weight)
        quality_score = 0.0
        
        # Uptime bonus (stable guards are more likely)
        if features[UPTIME] > 0.5:  # > 6 months uptime
            quality_score += 0.3
        elif features[UPTIME] > 0.25:  # > 3 months
            quality_score += 0.15
        
        # Bandwidth capacity bonus
        if features[BANDWIDTH] > 0.6:  # High bandwidth
            quality_score += 0.25
        elif features[BANDWIDTH] > 0.3:  # Medium bandwidth
            quality_score += 0.15
        
        # Standard port bonus (9001, 443 are common)
        if features[PORT_FLAG] > 0.5:
            quality_score += 0.2
        
        # Exit flag consideration (guards with exit flag are less common)
        if features[EXIT_FLAG] < 0.5:  # Not an exit relay
            quality_score += 0.15
        
        quality_component = min(1.0, quality_score)
        
        # 4. Geographic/proximity component (15% weight)
        geo_component = features[GEO_DIST]
        
        # Calculate weighted score with non-linear combination
        raw_score = (
            0.40 * corr_component +
            0.25 * timing_bw_component +
            0.20 * quality_component +
            0.15 * geo_component
        )
        
        # Apply variance amplification to spread out scores
        # This helps differentiate between similar candidates
        mean_expected = 0.5
        variance_factor = 1.5
        adjusted_score = mean_expected + (raw_score - mean_expected) * variance_factor
        
        # Add small random jitter based on relay characteristics for tie-breaking
        # Use fingerprint hash for deterministic "randomness"
        fingerprint = relay_data.get('fingerprint', '')
        if fingerprint:
            # Create deterministic variation based on fingerprint
            fp_hash = hash(fingerprint) % 1000 / 10000  # Small value 0-0.1
            adjusted_score += (fp_hash - 0.05) * 0.1  # ±0.005 variation
        
        # Boost based on specific high-value indicators
        scores = correlation_result.get('scores', {})
        bandwidth_score = scores.get('bandwidth', 0)
        if bandwidth_score > 0.7:
            adjusted_score += 0.1  # Significant bandwidth correlation boost
        
        # Normalize to [0, 1]
        final_score = min(1.0, max(0.0, adjusted_score))
        
        return float(final_score)
    
    def _get_risk_band(self, risk_score: float) -> str:
        """Determine risk band from score."""
        for band, (low, high) in self.RISK_BANDS.items():
            if low <= risk_score < high:
                return band
        return 'HIGH' if risk_score >= 0.7 else 'LOW'
    
    def _generate_explanation(self, features: np.ndarray, 
                             risk_score: float, risk_band: str) -> Dict:
        """
        Generate human-readable explanation for risk assessment.
        
        Note: Explanations are for investigative guidance only.
        """
        explanation = {
            'summary': '',
            'contributing_factors': [],
            'investigation_guidance': '',
            'disclaimer': 'This is a probabilistic assessment for investigative support only.'
        }
        
        # Identify top contributing factors
        if self.feature_importances_:
            # Sort features by importance
            sorted_features = sorted(
                self.feature_importances_.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
            
            for feat_name, importance in sorted_features:
                feat_idx = self.FEATURE_NAMES.index(feat_name)
                feat_value = features[feat_idx]
                
                if feat_value > 0.6:
                    explanation['contributing_factors'].append({
                        'feature': feat_name,
                        'value': float(feat_value),
                        'importance': float(importance),
                        'impact': 'HIGH' if importance > 0.15 else 'MEDIUM'
                    })
        else:
            # Fallback explanation
            if features[0] > 0.6:  # correlation_score
                explanation['contributing_factors'].append({
                    'feature': 'correlation_score',
                    'value': float(features[0]),
                    'importance': 0.3,
                    'impact': 'HIGH'
                })
        
        # Generate summary
        if risk_band == 'HIGH':
            explanation['summary'] = (
                f"High investigative priority (score: {risk_score:.2f}). "
                "Multiple correlation factors indicate this relay warrants detailed examination."
            )
            explanation['investigation_guidance'] = (
                "Recommended actions: 1) Verify relay metadata against multiple sources, "
                "2) Cross-reference with traffic timing analysis, "
                "3) Document all findings for case file."
            )
        elif risk_band == 'MEDIUM':
            explanation['summary'] = (
                f"Medium investigative priority (score: {risk_score:.2f}). "
                "Some correlation indicators present; additional data may strengthen assessment."
            )
            explanation['investigation_guidance'] = (
                "Recommended actions: 1) Collect additional traffic samples if available, "
                "2) Compare with other candidate relays, "
                "3) Consider geographic and network factors."
            )
        else:
            explanation['summary'] = (
                f"Lower investigative priority (score: {risk_score:.2f}). "
                "Correlation indicators are weaker for this relay."
            )
            explanation['investigation_guidance'] = (
                "Recommended actions: 1) Focus resources on higher-priority candidates first, "
                "2) May revisit if additional evidence emerges."
            )
        
        return explanation
    
    def get_feature_importance_report(self) -> Dict:
        """
        Generate a detailed feature importance report.
        
        Returns:
            Feature importance analysis for model interpretability
        """
        if not self.feature_importances_:
            return {
                'status': 'not_trained',
                'message': 'Model must be trained before generating importance report'
            }
        
        sorted_features = sorted(
            self.feature_importances_.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        report = {
            'status': 'success',
            'model_type': self.model_type,
            'training_date': self.training_metadata.get('training_date'),
            'feature_ranking': [],
            'interpretation': {
                'note': 'Feature importance indicates how much each factor contributes to risk scoring.',
                'disclaimer': 'Used for investigative prioritization, not user identification.'
            }
        }
        
        for rank, (feature, importance) in enumerate(sorted_features, 1):
            report['feature_ranking'].append({
                'rank': rank,
                'feature': feature,
                'importance': float(importance),
                'percentage': float(importance * 100),
                'description': self._get_feature_description(feature)
            })
        
        return report
    
    def _get_feature_description(self, feature_name: str) -> str:
        """Get human-readable description for a feature."""
        descriptions = {
            'correlation_score': 'Statistical correlation from traffic pattern analysis',
            'timing_similarity': 'Temporal pattern match between traffic flows',
            'bandwidth_similarity': 'Bandwidth usage pattern correlation',
            'relay_uptime': 'How long the relay has been operational',
            'relay_bandwidth': 'Relay network capacity',
            'geographic_distance_km': 'Estimated geographic distance in kilometers',
            'port_match_flag': 'Match with standard TOR port patterns (9001, 443)',
            'exit_seen_flag': 'Exit relay observed in traffic'
        }
        return descriptions.get(feature_name, 'Feature used in risk calculation')
    
    def save_model(self, path: Optional[str] = None) -> bool:
        """Save trained model and scaler to disk."""
        if not SKLEARN_AVAILABLE:
            logger.warning("sklearn not available - cannot save model")
            return False
        
        if path is None:
            path = os.path.join(self.model_dir, 'ai_risk_model.joblib')
        
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'is_trained': self.is_trained,
                'feature_importances': self.feature_importances_,
                'training_metadata': self.training_metadata,
                'model_type': 'RandomForestRegressor',
                'feature_names': self.FEATURE_NAMES
            }
            
            joblib.dump(model_data, path)
            logger.info(f"Model saved to {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            return False
    
    def load_model(self, path: str) -> bool:
        """Load trained model from disk."""
        if not SKLEARN_AVAILABLE:
            logger.warning("sklearn not available - cannot load model")
            return False
        
        try:
            model_data = joblib.load(path)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.is_trained = model_data['is_trained']
            self.feature_importances_ = model_data.get('feature_importances')
            self.training_metadata = model_data.get('training_metadata', {})
            
            logger.info(f"Model loaded from {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False


class AIRiskTrainer:
    """
    Training utility for the AI Risk Engine.
    
    Provides methods to train models using historical data from the database.
    Labels are automatically derived from correlation confidence scores.
    
    DISCLAIMER: Training data is derived from correlation results only.
    No user identification data is used or stored.
    """
    
    def __init__(self, db_path_or_db):
        """
        Initialize trainer with database connection.
        
        Args:
            db_path_or_db: Path to SQLite database or FTDCDatabase instance
        """
        if hasattr(db_path_or_db, 'get_correlation_results'):
            # It's a database instance
            self.db = db_path_or_db
            self.db_path = None
        else:
            # It's a path string
            self.db_path = db_path_or_db
            self.db = None
        self.engine = AIRiskEngine()
    
    def prepare_training_data(self, min_confidence: float = 0.1) -> List[Dict]:
        """
        Prepare training data from database.
        
        Args:
            min_confidence: Minimum correlation confidence to include
        
        Returns:
            List of training sample dictionaries
        """
        if self.db:
            return self._prepare_from_ftdc_db(min_confidence)
        else:
            return self.load_training_data_from_db()
    
    def _prepare_from_ftdc_db(self, min_confidence: float = 0.1) -> List[Dict]:
        """
        Prepare training data from FTDCDatabase instance.
        
        Args:
            min_confidence: Minimum correlation confidence to include
        
        Returns:
            List of training sample dictionaries
        """
        training_data = []
        
        try:
            # Get all analysis IDs
            analysis_ids = self.db.get_all_analysis_ids()
            
            for analysis_id in analysis_ids:
                # Get correlation results for this analysis
                correlations = self.db.get_correlation_results(analysis_id)
                
                if correlations:
                    guard_rankings = []
                    for corr in correlations:
                        if corr.get('confidence', 0) >= min_confidence:
                            guard_rankings.append({
                                'fingerprint': corr.get('relay_fingerprint'),
                                'nickname': corr.get('nickname'),
                                'ip': corr.get('ip_address'),
                                'country': corr.get('country'),
                                'bandwidth': corr.get('bandwidth', 0),
                                'uptime': corr.get('uptime', 0),
                                'flags': corr.get('flags', '[]'),
                                'or_port': corr.get('or_port', 9001),
                                'confidence': corr.get('confidence', 0),
                                'scores': {
                                    'bandwidth': corr.get('bandwidth_score', 0.5),
                                    'timing': corr.get('timing_score', 0.5),
                                    'proximity': corr.get('proximity_score', 0.5)
                                }
                            })
                    
                    if guard_rankings:
                        training_data.append({
                            'analysis_id': analysis_id,
                            'guard_rankings': guard_rankings
                        })
        except Exception as e:
            logger.error(f"Error preparing training data from FTDC database: {e}")
        
        logger.info(f"Prepared {len(training_data)} analyses for training")
        return training_data
    
    def load_training_data_from_db(self) -> List[Dict]:
        """Load historical analysis results from database."""
        import sqlite3
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get all analyses
        cursor.execute('''
            SELECT analysis_id, metadata FROM analyses 
            ORDER BY analysis_timestamp DESC
            LIMIT 1000
        ''')
        analyses = cursor.fetchall()
        
        training_data = []
        
        for analysis in analyses:
            analysis_id = analysis['analysis_id']
            
            # Get guard rankings for this analysis
            cursor.execute('''
                SELECT g.*, r.nickname, r.ip_address, r.country, r.bandwidth, 
                       r.uptime, r.flags
                FROM guard_rankings g
                LEFT JOIN relays r ON g.fingerprint = r.fingerprint
                WHERE g.analysis_id = ?
                ORDER BY g.rank
            ''', (analysis_id,))
            
            rankings = cursor.fetchall()
            
            guard_rankings = []
            for r in rankings:
                guard_rankings.append({
                    'fingerprint': r['fingerprint'],
                    'nickname': r['nickname'],
                    'ip': r['ip_address'],
                    'country': r['country'],
                    'bandwidth': r['bandwidth'] or 0,
                    'uptime': r['uptime'] or 0,
                    'flags': r['flags'] or '[]',
                    'confidence': r['confidence'] or 0,
                    'scores': {
                        'bandwidth': r['bandwidth_score'] or 0,
                        'quality': r['quality_score'] or 0,
                        'proximity': r['proximity_score'] or 0
                    }
                })
            
            if guard_rankings:
                training_data.append({
                    'analysis_id': analysis_id,
                    'guard_rankings': guard_rankings
                })
        
        conn.close()
        
        logger.info(f"Loaded {len(training_data)} analyses for training")
        return training_data
    
    def train_from_database(self) -> Dict:
        """
        Train model using historical data from database.
        
        Returns:
            Training metrics
        """
        training_data = self.load_training_data_from_db()
        
        if not training_data:
            return {
                'status': 'error',
                'message': 'No training data available in database'
            }
        
        metrics = self.engine.train(training_data)
        
        if metrics.get('status') == 'success':
            # Save trained model
            self.engine.save_model()
        
        return metrics
    
    def get_engine(self) -> AIRiskEngine:
        """Get the trained engine instance."""
        return self.engine


def train_ai_model(db_path: str) -> Dict:
    """
    Convenience function to train AI model from database.
    
    Args:
        db_path: Path to SQLite database
    
    Returns:
        Training metrics dictionary
    
    Usage:
        from ftdc.ai_risk_engine import train_ai_model
        metrics = train_ai_model('ftdc_analysis.db')
    """
    trainer = AIRiskTrainer(db_path)
    return trainer.train_from_database()


def get_ai_risk_assessment(guard_rankings: List[Dict], 
                          model_path: Optional[str] = None) -> List[Dict]:
    """
    Convenience function to get AI risk assessments for guard rankings.
    
    Args:
        guard_rankings: List of guard candidate dictionaries
        model_path: Optional path to trained model
    
    Returns:
        List of risk assessments
    
    Usage:
        from ftdc.ai_risk_engine import get_ai_risk_assessment
        assessments = get_ai_risk_assessment(guard_rankings)
    """
    engine = AIRiskEngine(model_path=model_path)
    return engine.batch_predict(guard_rankings)


# CLI entry point for training
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Train AI Risk Engine for TOR-Unveil (RandomForestRegressor)',
        epilog='DISCLAIMER: This system is for investigative support only.'
    )
    parser.add_argument('--db', type=str, default='ftdc_analysis.db',
                       help='Path to SQLite database')
    parser.add_argument('--output', type=str, default=None,
                       help='Output path for trained model')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("TOR-Unveil AI Risk Engine Training")
    print("Model: RandomForestRegressor")
    print("=" * 60)
    print("\nDISCLAIMER: This system provides investigative support only.")
    print("It does not perform deanonymization or user identification.\n")
    
    trainer = AIRiskTrainer(args.db)
    
    metrics = trainer.train_from_database()
    
    print("\nTraining Results:")
    print(json.dumps(metrics, indent=2))
    
    if metrics.get('status') == 'success' and args.output:
        trainer.engine.save_model(args.output)
        print(f"\nModel saved to: {args.output}")
