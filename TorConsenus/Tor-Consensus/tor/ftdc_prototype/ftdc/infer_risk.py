#!/usr/bin/env python3
"""
AI Risk Inference Script for TOR-Unveil
========================================

Performs risk inference on correlation results using trained model.

Usage:
    python infer_risk.py --analysis-id UUID [--model-path PATH]
    python infer_risk.py --batch [--output-format json|csv]

Example:
    python infer_risk.py --analysis-id abc123 --model-path models/ai_risk_model.joblib
"""

import os
import sys
import argparse
import json
import csv
import logging
from datetime import datetime
from io import StringIO

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ftdc.ai_risk_engine import AIRiskEngine, SKLEARN_AVAILABLE
from ftdc.database import FTDCDatabase
from ftdc.recommendations import RecommendationEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('infer_risk')


def format_output_json(risk_scores: list, recommendations: dict = None) -> str:
    """Format risk scores as JSON."""
    output = {
        'timestamp': datetime.utcnow().isoformat(),
        'risk_scores': risk_scores,
        'summary': {
            'total': len(risk_scores),
            'high_risk': sum(1 for r in risk_scores if r['risk_band'] == 'HIGH'),
            'medium_risk': sum(1 for r in risk_scores if r['risk_band'] == 'MEDIUM'),
            'low_risk': sum(1 for r in risk_scores if r['risk_band'] == 'LOW')
        }
    }
    if recommendations:
        output['recommendations'] = recommendations
    return json.dumps(output, indent=2)


def format_output_csv(risk_scores: list) -> str:
    """Format risk scores as CSV."""
    output = StringIO()
    fieldnames = ['relay_fingerprint', 'risk_score', 'risk_band', 'confidence', 'explanation']
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for score in risk_scores:
        writer.writerow({
            'relay_fingerprint': score.get('relay_fingerprint', 'N/A'),
            'risk_score': f"{score['risk_score']:.4f}",
            'risk_band': score['risk_band'],
            'confidence': f"{score.get('confidence', 0):.4f}",
            'explanation': score.get('explanation', '')
        })
    
    return output.getvalue()


def format_output_table(risk_scores: list) -> str:
    """Format risk scores as human-readable table."""
    lines = []
    lines.append("="*80)
    lines.append("AI RISK ASSESSMENT RESULTS")
    lines.append("="*80)
    
    # Summary
    total = len(risk_scores)
    high = sum(1 for r in risk_scores if r['risk_band'] == 'HIGH')
    medium = sum(1 for r in risk_scores if r['risk_band'] == 'MEDIUM')
    low = sum(1 for r in risk_scores if r['risk_band'] == 'LOW')
    
    lines.append(f"\nSUMMARY: {total} relays assessed")
    lines.append(f"  HIGH:   {high} ({100*high/total:.1f}%)" if total > 0 else "  HIGH:   0")
    lines.append(f"  MEDIUM: {medium} ({100*medium/total:.1f}%)" if total > 0 else "  MEDIUM: 0")
    lines.append(f"  LOW:    {low} ({100*low/total:.1f}%)" if total > 0 else "  LOW:    0")
    
    lines.append("\n" + "-"*80)
    lines.append(f"{'RELAY FINGERPRINT':<45} {'SCORE':>8} {'BAND':>8} {'CONF':>6}")
    lines.append("-"*80)
    
    # Sort by risk score descending
    for score in sorted(risk_scores, key=lambda x: x['risk_score'], reverse=True):
        fp = score.get('relay_fingerprint', 'N/A')[:42]
        risk = score['risk_score']
        band = score['risk_band']
        conf = score.get('confidence', 0)
        
        lines.append(f"{fp:<45} {risk:>8.4f} {band:>8} {conf:>6.2f}")
    
    lines.append("-"*80)
    
    # High risk details
    high_risk = [r for r in risk_scores if r['risk_band'] == 'HIGH']
    if high_risk:
        lines.append("\nHIGH RISK RELAY DETAILS:")
        lines.append("-"*80)
        for score in high_risk:
            lines.append(f"\n  Relay: {score.get('relay_fingerprint', 'N/A')}")
            lines.append(f"  Risk Score: {score['risk_score']:.4f}")
            if 'explanation' in score:
                lines.append(f"  Explanation: {score['explanation']}")
            if 'top_features' in score:
                lines.append("  Top Contributing Factors:")
                for feature, importance in list(score['top_features'].items())[:3]:
                    lines.append(f"    - {feature}: {importance:.4f}")
    
    lines.append("\n" + "="*80)
    lines.append("DISCLAIMER: Risk scores are for investigative prioritization only.")
    lines.append("Results do not identify individuals or prove criminal attribution.")
    lines.append("="*80)
    
    return '\n'.join(lines)


def infer_single_analysis(args, db: FTDCDatabase, engine: AIRiskEngine):
    """Perform inference on a single analysis."""
    analysis_id = args.analysis_id
    
    # Get correlation results
    logger.info(f"Loading correlation results for analysis: {analysis_id}")
    
    # Try to get results from database
    results = db.get_correlation_results(analysis_id)
    if not results:
        logger.error(f"No correlation results found for analysis: {analysis_id}")
        sys.exit(1)
    
    logger.info(f"Found {len(results)} correlation results")
    
    # Perform risk assessment
    logger.info("Performing AI risk assessment...")
    risk_scores = engine.assess_correlation_results(results)
    
    if not risk_scores:
        logger.warning("No risk scores generated")
        print("No risk scores could be generated for the given analysis.")
        return
    
    # Get recommendations if available
    recommendations = None
    if args.with_recommendations:
        rec_engine = RecommendationEngine()
        recommendations = rec_engine.generate_recommendations({'correlations': results})
    
    # Output results
    if args.output_format == 'json':
        print(format_output_json(risk_scores, recommendations))
    elif args.output_format == 'csv':
        print(format_output_csv(risk_scores))
    else:
        print(format_output_table(risk_scores))
        if recommendations:
            print("\nRECOMMENDATIONS:")
            print("-"*80)
            for rec in recommendations.get('recommendations', []):
                print(f"  [{rec['priority']}] {rec['action']}")
                print(f"       Reason: {rec['reason']}")
    
    # Store results if requested
    if args.store_results:
        logger.info("Storing risk scores to database...")
        for score in risk_scores:
            db.store_ai_risk_score(
                analysis_id=analysis_id,
                relay_fingerprint=score.get('relay_fingerprint', 'unknown'),
                risk_score=score['risk_score'],
                risk_band=score['risk_band'],
                confidence=score.get('confidence', 0),
                explanation=score.get('explanation', ''),
                feature_contributions=score.get('feature_contributions', {}),
                model_version=engine.model_version
            )
        logger.info("Risk scores stored successfully")


def infer_batch(args, db: FTDCDatabase, engine: AIRiskEngine):
    """Perform inference on all unprocessed analyses."""
    logger.info("Running batch inference on all analyses...")
    
    # Get all analysis IDs that don't have AI risk scores yet
    all_analyses = db.get_all_analysis_ids()
    processed = db.get_analyses_with_ai_scores()
    
    unprocessed = [a for a in all_analyses if a not in processed]
    
    if not unprocessed:
        logger.info("All analyses already have AI risk scores")
        print("No unprocessed analyses found.")
        return
    
    logger.info(f"Found {len(unprocessed)} unprocessed analyses")
    
    all_scores = []
    for analysis_id in unprocessed:
        logger.info(f"Processing analysis: {analysis_id}")
        
        results = db.get_correlation_results(analysis_id)
        if results:
            scores = engine.assess_correlation_results(results)
            
            for score in scores:
                db.store_ai_risk_score(
                    analysis_id=analysis_id,
                    relay_fingerprint=score.get('relay_fingerprint', 'unknown'),
                    risk_score=score['risk_score'],
                    risk_band=score['risk_band'],
                    confidence=score.get('confidence', 0),
                    explanation=score.get('explanation', ''),
                    feature_contributions=score.get('feature_contributions', {}),
                    model_version=engine.model_version
                )
                all_scores.append({**score, 'analysis_id': analysis_id})
    
    logger.info(f"Batch inference complete. Processed {len(unprocessed)} analyses, {len(all_scores)} scores")
    
    if args.output_format == 'json':
        print(format_output_json(all_scores))
    elif args.output_format == 'csv':
        print(format_output_csv(all_scores))
    else:
        print(format_output_table(all_scores))


def main():
    parser = argparse.ArgumentParser(
        description='Perform AI Risk Inference on TOR Correlation Results',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Single analysis
  python infer_risk.py --analysis-id abc123-def456

  # Batch processing
  python infer_risk.py --batch --output-format json

  # With recommendations
  python infer_risk.py --analysis-id abc123 --with-recommendations
        """
    )
    
    parser.add_argument(
        '--analysis-id',
        type=str,
        help='Analysis ID to perform inference on'
    )
    
    parser.add_argument(
        '--batch',
        action='store_true',
        help='Process all unprocessed analyses'
    )
    
    parser.add_argument(
        '--model-path',
        type=str,
        default='models/ai_risk_model.joblib',
        help='Path to trained model (default: models/ai_risk_model.joblib)'
    )
    
    parser.add_argument(
        '--db-path',
        type=str,
        default='ftdc_analysis.db',
        help='Path to SQLite database (default: ftdc_analysis.db)'
    )
    
    parser.add_argument(
        '--output-format',
        choices=['table', 'json', 'csv'],
        default='table',
        help='Output format (default: table)'
    )
    
    parser.add_argument(
        '--with-recommendations',
        action='store_true',
        help='Include investigator recommendations'
    )
    
    parser.add_argument(
        '--store-results',
        action='store_true',
        default=True,
        help='Store results in database (default: True)'
    )
    
    parser.add_argument(
        '--no-store',
        action='store_true',
        help='Do not store results in database'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    if args.no_store:
        args.store_results = False
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if not args.analysis_id and not args.batch:
        parser.error("Must specify either --analysis-id or --batch")
    
    # Initialize database
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), args.db_path)
    if not os.path.exists(db_path):
        logger.error(f"Database not found: {db_path}")
        sys.exit(1)
    
    db = FTDCDatabase(db_path)
    
    # Initialize engine
    engine = AIRiskEngine()
    
    # Load model if available
    model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), args.model_path)
    if os.path.exists(model_path) and SKLEARN_AVAILABLE:
        if engine.load_model(model_path):
            logger.info(f"Loaded trained model: {model_path}")
        else:
            logger.warning("Failed to load model, using heuristic scoring")
    else:
        logger.info("No trained model found, using heuristic scoring")
    
    # Run inference
    if args.batch:
        infer_batch(args, db, engine)
    else:
        infer_single_analysis(args, db, engine)


if __name__ == '__main__':
    main()
