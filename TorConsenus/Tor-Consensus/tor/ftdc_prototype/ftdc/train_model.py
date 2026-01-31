#!/usr/bin/env python3
"""
AI Model Training Script for TOR-Unveil
========================================

Trains the Random Forest Regressor model using historical correlation data.

LABEL GENERATION DOCUMENTATION:
------------------------------
Labels are derived from correlation strength (confidence scores) from
historical FTDC analysis runs. No real criminal data is required.

The model learns to predict risk scores based on:
- correlation_score: Statistical correlation from traffic analysis
- timing_similarity: Temporal pattern matching
- bandwidth_similarity: Bandwidth profile correlation
- relay_uptime: Historical uptime (stability indicator)
- relay_bandwidth: Capacity matching
- geographic_distance_km: Proximity indicator
- port_match_flag: TOR port pattern
- exit_seen_flag: Exit relay observation

Usage:
    python train_model.py [--data-path PATH] [--output-path PATH] [--min-samples N]

Example:
    python train_model.py --output-path models/ai_risk_model.joblib
"""

import os
import sys
import argparse
import json
import logging
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ftdc.ai_risk_engine import AIRiskEngine, AIRiskTrainer, SKLEARN_AVAILABLE
from ftdc.database import FTDCDatabase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('train_model')


def main():
    parser = argparse.ArgumentParser(
        description='Train AI Risk Assessment Model for TOR-Unveil',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
LABEL GENERATION:
  Labels are automatically derived from correlation confidence scores.
  No manual labeling or criminal data is required.

  High correlation (>0.7) → High risk label
  Medium correlation (0.4-0.7) → Medium risk label  
  Low correlation (<0.4) → Low risk label

EXAMPLE:
  python train_model.py --output-path models/risk_model.joblib --min-samples 20
        """
    )
    
    parser.add_argument(
        '--db-path',
        type=str,
        default='ftdc_analysis.db',
        help='Path to SQLite database (default: ftdc_analysis.db)'
    )
    
    parser.add_argument(
        '--output-path',
        type=str,
        default='models/ai_risk_model.joblib',
        help='Output path for trained model (default: models/ai_risk_model.joblib)'
    )
    
    parser.add_argument(
        '--min-samples',
        type=int,
        default=10,
        help='Minimum training samples required (default: 10)'
    )
    
    parser.add_argument(
        '--min-confidence',
        type=float,
        default=0.1,
        help='Minimum correlation confidence to include (default: 0.1)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Check sklearn availability
    if not SKLEARN_AVAILABLE:
        logger.error("scikit-learn is not installed. Install with: pip install scikit-learn")
        sys.exit(1)
    
    # Initialize database
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), args.db_path)
    if not os.path.exists(db_path):
        logger.error(f"Database not found: {db_path}")
        logger.info("Run some FTDC analyses first to build training data.")
        sys.exit(1)
    
    logger.info(f"Loading database: {db_path}")
    db = FTDCDatabase(db_path)
    
    # Initialize engine and trainer
    engine = AIRiskEngine()
    trainer = AIRiskTrainer(db)
    
    # Prepare training data
    logger.info(f"Preparing training data (min_confidence={args.min_confidence})")
    training_data = trainer.prepare_training_data(min_confidence=args.min_confidence)
    
    if len(training_data) < args.min_samples:
        logger.error(f"Insufficient training data: {len(training_data)} samples (need >= {args.min_samples})")
        logger.info("Run more FTDC analyses to build training dataset.")
        sys.exit(1)
    
    logger.info(f"Found {len(training_data)} training samples")
    
    # Train model
    logger.info("Training Random Forest Regressor model...")
    metrics = engine.train(training_data, min_samples=args.min_samples)
    
    if metrics.get('status') != 'success':
        logger.error(f"Training failed: {metrics.get('error', 'Unknown error')}")
        sys.exit(1)
    
    # Save model
    output_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), args.output_path)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    if engine.save_model(output_path):
        logger.info(f"Model saved to: {output_path}")
    else:
        logger.error("Failed to save model")
        sys.exit(1)
    
    # Print results
    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)
    print(f"Algorithm: RandomForestRegressor")
    print(f"Training samples: {metrics['training_samples']}")
    print(f"Model version: {engine.model_version}")
    print(f"R² Score: {metrics['r2_score']:.4f}")
    print(f"Mean Absolute Error: {metrics['mae']:.4f}")
    print(f"Mean Squared Error: {metrics['mse']:.4f}")
    print(f"\nModel saved to: {output_path}")
    
    print("\nFeature Importance:")
    print("-"*40)
    for i, (feature, importance) in enumerate(
        sorted(metrics['feature_importance'].items(), key=lambda x: x[1], reverse=True), 1
    ):
        print(f"  {i}. {feature}: {importance:.4f}")
    
    print("\n" + "="*60)
    print("DISCLAIMER: This model provides investigative prioritization only.")
    print("Results do not identify individual users or prove attribution.")
    print("="*60)
    
    # Save metrics
    metrics_path = output_path.replace('.joblib', '_metrics.json')
    with open(metrics_path, 'w') as f:
        json.dump({
            'trained_at': datetime.utcnow().isoformat(),
            'model_version': engine.model_version,
            'metrics': metrics
        }, f, indent=2)
    logger.info(f"Metrics saved to: {metrics_path}")


if __name__ == '__main__':
    main()
