"""
Recommendation Engine for TOR-Unveil AI Risk Assessment
=========================================================

Rule-based module that generates investigator recommendations
based on AI risk assessment results.

Risk Band → Action Mapping:
  HIGH (0.7-1.0)   → "Correlate with ISP logs"
  MEDIUM (0.4-0.7) → "Monitor across future cases"  
  LOW (0.0-0.4)    → "Archive for reference"

Author: TOR-Unveil Team
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class RecommendationPriority(Enum):
    """Recommendation priority levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Recommendation:
    """Individual recommendation with context."""
    priority: RecommendationPriority
    action: str
    reason: str
    category: str
    relay_fingerprint: Optional[str] = None
    risk_score: Optional[float] = None
    supporting_evidence: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert recommendation to dictionary."""
        return {
            'priority': self.priority.value,
            'action': self.action,
            'reason': self.reason,
            'category': self.category,
            'relay_fingerprint': self.relay_fingerprint,
            'risk_score': self.risk_score,
            'supporting_evidence': self.supporting_evidence
        }


class RecommendationEngine:
    """
    Rule-based recommendation engine for investigator guidance.
    
    Generates actionable recommendations based on:
    - AI risk assessment results
    - Correlation patterns
    - Analysis statistics
    
    RISK BAND ACTIONS:
      HIGH   → Correlate with ISP logs, priority investigation
      MEDIUM → Monitor across future cases, add to watchlist
      LOW    → Archive for reference, no immediate action
    """
    
    # Risk band thresholds
    HIGH_RISK_THRESHOLD = 0.7
    MEDIUM_RISK_THRESHOLD = 0.4
    
    # Minimum counts for pattern detection
    MIN_HIGH_RISK_FOR_ALERT = 1
    MIN_CORRELATIONS_FOR_PATTERN = 3
    
    def __init__(self, custom_rules: Optional[Dict[str, Any]] = None):
        """
        Initialize recommendation engine.
        
        Args:
            custom_rules: Optional custom rule overrides
        """
        self.custom_rules = custom_rules or {}
        self._load_rules()
    
    def _load_rules(self):
        """Load recommendation rules."""
        # Default rules for risk bands
        self.risk_band_rules = {
            'HIGH': {
                'action': 'Correlate with ISP logs',
                'priority': RecommendationPriority.HIGH,
                'category': 'investigation',
                'additional_actions': [
                    'Cross-reference with known entry/exit relay lists',
                    'Check temporal patterns for session duration',
                    'Coordinate with upstream ISP for connection metadata'
                ]
            },
            'MEDIUM': {
                'action': 'Monitor across future cases',
                'priority': RecommendationPriority.MEDIUM,
                'category': 'monitoring',
                'additional_actions': [
                    'Add relay to watchlist',
                    'Flag for pattern analysis in future captures',
                    'Document bandwidth and timing characteristics'
                ]
            },
            'LOW': {
                'action': 'Archive for reference',
                'priority': RecommendationPriority.LOW,
                'category': 'archive',
                'additional_actions': [
                    'Store correlation data for historical analysis',
                    'No immediate investigative action required'
                ]
            }
        }
        
        # Pattern-based rules
        self.pattern_rules = {
            'multiple_high_risk': {
                'threshold': 3,
                'action': 'Prioritize multi-relay correlation analysis',
                'priority': RecommendationPriority.CRITICAL,
                'reason': 'Multiple high-risk relays detected suggests significant TOR circuit presence'
            },
            'timing_cluster': {
                'threshold': 0.8,
                'action': 'Investigate temporal connection patterns',
                'priority': RecommendationPriority.HIGH,
                'reason': 'Strong timing correlation may indicate same user session'
            },
            'bandwidth_anomaly': {
                'threshold': 2.0,  # Standard deviations
                'action': 'Analyze bandwidth spike patterns',
                'priority': RecommendationPriority.MEDIUM,
                'reason': 'Unusual bandwidth patterns detected'
            },
            'exit_relay_cluster': {
                'threshold': 2,
                'action': 'Map exit relay usage patterns',
                'priority': RecommendationPriority.HIGH,
                'reason': 'Multiple exit relays may indicate destination correlation opportunity'
            }
        }
        
        # Override with custom rules
        if 'risk_band_rules' in self.custom_rules:
            self.risk_band_rules.update(self.custom_rules['risk_band_rules'])
        if 'pattern_rules' in self.custom_rules:
            self.pattern_rules.update(self.custom_rules['pattern_rules'])
    
    def generate_recommendations(
        self,
        analysis_results: Dict[str, Any],
        risk_scores: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive recommendations from analysis results.
        
        Args:
            analysis_results: Full analysis results dictionary
            risk_scores: Optional list of AI risk scores
            
        Returns:
            Dictionary with recommendations and summary
        """
        recommendations = []
        
        # Process risk scores if provided
        if risk_scores:
            recommendations.extend(self._process_risk_scores(risk_scores))
        
        # Process correlation results
        if 'correlations' in analysis_results:
            recommendations.extend(
                self._process_correlations(analysis_results['correlations'])
            )
        
        # Process AI risk data from analysis results
        if 'ai_risk_assessment' in analysis_results:
            ai_data = analysis_results['ai_risk_assessment']
            if 'scores' in ai_data:
                recommendations.extend(self._process_risk_scores(ai_data['scores']))
        
        # Detect patterns and add pattern-based recommendations
        pattern_recs = self._detect_patterns(analysis_results, risk_scores)
        recommendations.extend(pattern_recs)
        
        # Add general investigation guidance
        recommendations.extend(self._generate_general_guidance(analysis_results))
        
        # Deduplicate and prioritize
        recommendations = self._deduplicate_recommendations(recommendations)
        recommendations = sorted(
            recommendations,
            key=lambda r: list(RecommendationPriority).index(r.priority)
        )
        
        # Build response
        return {
            'generated_at': datetime.utcnow().isoformat(),
            'total_recommendations': len(recommendations),
            'recommendations': [r.to_dict() for r in recommendations],
            'summary': self._generate_summary(recommendations, analysis_results),
            'disclaimer': (
                "These recommendations are for investigative prioritization only. "
                "AI risk scores do not identify individual users or prove attribution. "
                "All findings require verification through proper legal channels."
            )
        }
    
    def _process_risk_scores(
        self,
        risk_scores: List[Dict[str, Any]]
    ) -> List[Recommendation]:
        """Process risk scores and generate recommendations."""
        recommendations = []
        
        for score in risk_scores:
            risk_band = score.get('risk_band', 'LOW')
            risk_value = score.get('risk_score', 0.0)
            fingerprint = score.get('relay_fingerprint')
            
            rule = self.risk_band_rules.get(risk_band, self.risk_band_rules['LOW'])
            
            # Create main recommendation
            rec = Recommendation(
                priority=rule['priority'],
                action=rule['action'],
                reason=f"Risk score {risk_value:.3f} ({risk_band})",
                category=rule['category'],
                relay_fingerprint=fingerprint,
                risk_score=risk_value,
                supporting_evidence=score.get('supporting_evidence', [])
            )
            recommendations.append(rec)
            
            # Add additional actions for high risk
            if risk_band == 'HIGH':
                for additional_action in rule.get('additional_actions', []):
                    rec = Recommendation(
                        priority=RecommendationPriority.MEDIUM,
                        action=additional_action,
                        reason=f"Follow-up for high-risk relay",
                        category='follow_up',
                        relay_fingerprint=fingerprint,
                        risk_score=risk_value
                    )
                    recommendations.append(rec)
        
        return recommendations
    
    def _process_correlations(
        self,
        correlations: List[Dict[str, Any]]
    ) -> List[Recommendation]:
        """Process correlation results for recommendations."""
        recommendations = []
        
        # Group by confidence level
        high_conf = [c for c in correlations if c.get('confidence', 0) >= 0.7]
        
        if high_conf:
            rec = Recommendation(
                priority=RecommendationPriority.HIGH,
                action="Review high-confidence correlations",
                reason=f"{len(high_conf)} correlations with confidence >= 0.7",
                category='correlation_review',
                supporting_evidence=[
                    f"Relay: {c.get('relay_fingerprint', 'N/A')[:16]}... Conf: {c.get('confidence', 0):.2f}"
                    for c in high_conf[:5]
                ]
            )
            recommendations.append(rec)
        
        return recommendations
    
    def _detect_patterns(
        self,
        analysis_results: Dict[str, Any],
        risk_scores: Optional[List[Dict[str, Any]]]
    ) -> List[Recommendation]:
        """Detect patterns and generate pattern-based recommendations."""
        recommendations = []
        
        if not risk_scores:
            return recommendations
        
        # Check for multiple high-risk relays
        high_risk_count = sum(
            1 for s in risk_scores if s.get('risk_band') == 'HIGH'
        )
        
        if high_risk_count >= self.pattern_rules['multiple_high_risk']['threshold']:
            rule = self.pattern_rules['multiple_high_risk']
            rec = Recommendation(
                priority=rule['priority'],
                action=rule['action'],
                reason=f"{high_risk_count} high-risk relays detected - {rule['reason']}",
                category='pattern_detection',
                supporting_evidence=[
                    f"High-risk relay count: {high_risk_count}"
                ]
            )
            recommendations.append(rec)
        
        # Check for exit relay clustering
        exit_relays = [
            s for s in risk_scores
            if s.get('feature_contributions', {}).get('exit_seen_flag', 0) > 0.5
        ]
        
        if len(exit_relays) >= self.pattern_rules['exit_relay_cluster']['threshold']:
            rule = self.pattern_rules['exit_relay_cluster']
            rec = Recommendation(
                priority=rule['priority'],
                action=rule['action'],
                reason=rule['reason'],
                category='pattern_detection',
                supporting_evidence=[
                    f"Exit relays detected: {len(exit_relays)}"
                ]
            )
            recommendations.append(rec)
        
        return recommendations
    
    def _generate_general_guidance(
        self,
        analysis_results: Dict[str, Any]
    ) -> List[Recommendation]:
        """Generate general investigative guidance."""
        recommendations = []
        
        # Always add data preservation recommendation
        rec = Recommendation(
            priority=RecommendationPriority.INFO,
            action="Preserve all PCAP data and analysis outputs",
            reason="Evidence chain integrity",
            category='general',
            supporting_evidence=[
                "Maintain chain of custody documentation",
                "Store original PCAP files with hash verification"
            ]
        )
        recommendations.append(rec)
        
        # Add temporal analysis suggestion if timestamps present
        if analysis_results.get('timestamp_analysis'):
            rec = Recommendation(
                priority=RecommendationPriority.LOW,
                action="Cross-reference with case timeline",
                reason="Temporal correlation with incident",
                category='general'
            )
            recommendations.append(rec)
        
        return recommendations
    
    def _deduplicate_recommendations(
        self,
        recommendations: List[Recommendation]
    ) -> List[Recommendation]:
        """Remove duplicate recommendations."""
        seen = set()
        unique = []
        
        for rec in recommendations:
            key = (rec.action, rec.relay_fingerprint)
            if key not in seen:
                seen.add(key)
                unique.append(rec)
        
        return unique
    
    def _generate_summary(
        self,
        recommendations: List[Recommendation],
        analysis_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate summary statistics."""
        priority_counts = {}
        for rec in recommendations:
            priority = rec.priority.value
            priority_counts[priority] = priority_counts.get(priority, 0) + 1
        
        category_counts = {}
        for rec in recommendations:
            category_counts[rec.category] = category_counts.get(rec.category, 0) + 1
        
        return {
            'by_priority': priority_counts,
            'by_category': category_counts,
            'requires_immediate_action': any(
                r.priority in [RecommendationPriority.CRITICAL, RecommendationPriority.HIGH]
                for r in recommendations
            ),
            'high_risk_relay_count': sum(
                1 for r in recommendations
                if r.risk_score and r.risk_score >= self.HIGH_RISK_THRESHOLD
            )
        }
    
    def get_relay_recommendations(
        self,
        relay_fingerprint: str,
        risk_score: float,
        risk_band: str,
        feature_contributions: Optional[Dict[str, float]] = None
    ) -> Dict[str, Any]:
        """
        Get recommendations for a specific relay.
        
        Args:
            relay_fingerprint: Relay fingerprint
            risk_score: Calculated risk score
            risk_band: Risk band (HIGH, MEDIUM, LOW)
            feature_contributions: Feature importance values
            
        Returns:
            Dictionary with relay-specific recommendations
        """
        recommendations = []
        
        # Get base recommendation from risk band
        rule = self.risk_band_rules.get(risk_band, self.risk_band_rules['LOW'])
        
        rec = Recommendation(
            priority=rule['priority'],
            action=rule['action'],
            reason=f"Risk assessment: {risk_score:.3f} ({risk_band})",
            category=rule['category'],
            relay_fingerprint=relay_fingerprint,
            risk_score=risk_score
        )
        recommendations.append(rec)
        
        # Add feature-based recommendations
        if feature_contributions:
            sorted_features = sorted(
                feature_contributions.items(),
                key=lambda x: x[1],
                reverse=True
            )
            
            for feature, importance in sorted_features[:3]:
                if importance > 0.2:  # Significant contribution
                    rec = Recommendation(
                        priority=RecommendationPriority.INFO,
                        action=self._get_feature_action(feature),
                        reason=f"High {feature} contribution ({importance:.3f})",
                        category='feature_analysis',
                        relay_fingerprint=relay_fingerprint,
                        risk_score=risk_score
                    )
                    recommendations.append(rec)
        
        return {
            'relay_fingerprint': relay_fingerprint,
            'risk_score': risk_score,
            'risk_band': risk_band,
            'recommendations': [r.to_dict() for r in recommendations]
        }
    
    def _get_feature_action(self, feature: str) -> str:
        """Get action recommendation based on feature."""
        feature_actions = {
            'correlation_score': 'Verify correlation methodology and confidence',
            'timing_similarity': 'Analyze connection timing patterns in detail',
            'bandwidth_similarity': 'Compare bandwidth profiles with known patterns',
            'relay_uptime': 'Check relay stability and historical presence',
            'relay_bandwidth': 'Evaluate relay capacity significance',
            'geographic_distance_km': 'Map geographic distribution of connections',
            'port_match_flag': 'Verify TOR port usage patterns',
            'exit_seen_flag': 'Investigate exit relay traffic patterns'
        }
        return feature_actions.get(feature, f'Review {feature} contribution')
    
    def format_recommendations_text(
        self,
        recommendations: Dict[str, Any]
    ) -> str:
        """Format recommendations as human-readable text."""
        lines = []
        lines.append("=" * 70)
        lines.append("INVESTIGATOR RECOMMENDATIONS")
        lines.append("=" * 70)
        
        lines.append(f"\nGenerated: {recommendations['generated_at']}")
        lines.append(f"Total Recommendations: {recommendations['total_recommendations']}")
        
        summary = recommendations.get('summary', {})
        if summary.get('requires_immediate_action'):
            lines.append("\n⚠️  IMMEDIATE ACTION REQUIRED")
        
        lines.append("\n" + "-" * 70)
        
        for rec in recommendations['recommendations']:
            priority = rec['priority']
            action = rec['action']
            reason = rec['reason']
            
            priority_icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢',
                'INFO': 'ℹ️'
            }.get(priority, '•')
            
            lines.append(f"\n{priority_icon} [{priority}] {action}")
            lines.append(f"   Reason: {reason}")
            
            if rec.get('relay_fingerprint'):
                lines.append(f"   Relay: {rec['relay_fingerprint'][:32]}...")
            
            if rec.get('supporting_evidence'):
                lines.append("   Evidence:")
                for evidence in rec['supporting_evidence']:
                    lines.append(f"     - {evidence}")
        
        lines.append("\n" + "-" * 70)
        lines.append("\nDISCLAIMER:")
        lines.append(recommendations.get('disclaimer', ''))
        lines.append("=" * 70)
        
        return '\n'.join(lines)


# Convenience function for direct usage
def generate_recommendations(
    analysis_results: Dict[str, Any],
    risk_scores: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Convenience function to generate recommendations.
    
    Args:
        analysis_results: Analysis results dictionary
        risk_scores: Optional risk scores list
        
    Returns:
        Recommendations dictionary
    """
    engine = RecommendationEngine()
    return engine.generate_recommendations(analysis_results, risk_scores)
