"""
TOR-UNVEIL Synthetic Data Generator
===================================

Generates realistic synthetic traffic flow data for ML training
and dashboard demonstration purposes.

Features per flow:
- correlation_score (0-1)
- peak_time_lag (ms)
- burst_alignment_score (0-1)
- flow_duration (seconds)
- packet_rate_mean (pps)
- packet_rate_variance

Author: TOR-UNVEIL Team
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import os
import json
from typing import Dict, List, Tuple

np.random.seed(42)


class TrafficDataGenerator:
    """
    Generates realistic synthetic TOR traffic datasets.
    
    Creates three traffic patterns:
    1. Normal - Low correlation, typical browsing
    2. Suspicious - Medium correlation, warrants investigation
    3. High-risk - Strong correlation, immediate review needed
    """
    
    FEATURE_COLUMNS = [
        'correlation_score',
        'peak_time_lag',
        'burst_alignment_score',
        'flow_duration',
        'packet_rate_mean',
        'packet_rate_variance'
    ]
    
    RISK_THRESHOLDS = {
        'LOW': (0.0, 0.4),
        'MEDIUM': (0.4, 0.7),
        'HIGH': (0.7, 1.0)
    }
    
    RELAY_COUNTRIES = ['DE', 'US', 'FR', 'NL', 'GB', 'SE', 'CH', 'FI', 'AT', 'RU', 'CA', 'JP']
    COUNTRY_WEIGHTS = [0.20, 0.18, 0.12, 0.10, 0.08, 0.06, 0.06, 0.05, 0.05, 0.04, 0.03, 0.03]
    
    def __init__(self, seed: int = 42):
        np.random.seed(seed)
        self.seed = seed
    
    def _generate_flow_id(self, index: int, timestamp: datetime) -> str:
        ts_str = timestamp.strftime('%Y%m%d%H%M%S')
        return f"FLOW-{index:05d}-{ts_str}"
    
    def _generate_fingerprint(self) -> str:
        chars = '0123456789ABCDEF'
        return ''.join(np.random.choice(list(chars), 8))
    
    def _generate_ip(self, is_relay: bool = False) -> str:
        if is_relay:
            prefixes = ['185.220.', '195.176.', '104.244.', '45.129.', '77.247.']
            return f"{np.random.choice(prefixes)}{np.random.randint(1, 255)}.x"
        return f"192.168.{np.random.randint(1, 255)}.x"
    
    def _generate_normal_traffic(self, n: int) -> pd.DataFrame:
        """Normal traffic: low correlation, random patterns."""
        return pd.DataFrame({
            'correlation_score': np.random.beta(2, 8, n) * 0.5,
            'peak_time_lag': np.random.exponential(500, n) + np.random.uniform(100, 2000, n),
            'burst_alignment_score': np.random.beta(2, 6, n) * 0.5,
            'flow_duration': np.random.lognormal(3, 1.2, n).clip(1, 1800),
            'packet_rate_mean': np.random.lognormal(5, 0.8, n).clip(10, 5000),
            'packet_rate_variance': np.random.exponential(500, n).clip(10, 10000),
            'traffic_type': 'normal'
        })
    
    def _generate_suspicious_traffic(self, n: int) -> pd.DataFrame:
        """Suspicious traffic: medium correlation, some patterns."""
        return pd.DataFrame({
            'correlation_score': np.random.beta(5, 5, n) * 0.4 + 0.35,
            'peak_time_lag': np.random.normal(300, 100, n).clip(50, 1000),
            'burst_alignment_score': np.random.beta(4, 4, n) * 0.4 + 0.3,
            'flow_duration': np.random.normal(120, 40, n).clip(30, 600),
            'packet_rate_mean': np.random.normal(400, 150, n).clip(50, 2000),
            'packet_rate_variance': np.random.normal(1500, 500, n).clip(200, 5000),
            'traffic_type': 'suspicious'
        })
    
    def _generate_high_risk_traffic(self, n: int) -> pd.DataFrame:
        """High-risk traffic: strong correlation, clear patterns."""
        return pd.DataFrame({
            'correlation_score': np.random.beta(8, 2, n) * 0.3 + 0.65,
            'peak_time_lag': np.random.normal(150, 50, n).clip(20, 400),
            'burst_alignment_score': np.random.beta(7, 2, n) * 0.3 + 0.65,
            'flow_duration': np.random.normal(90, 30, n).clip(20, 300),
            'packet_rate_mean': np.random.normal(600, 200, n).clip(100, 3000),
            'packet_rate_variance': np.random.normal(800, 300, n).clip(100, 3000),
            'traffic_type': 'high_risk'
        })
    
    def _generate_edge_cases(self, n: int) -> pd.DataFrame:
        """Edge cases: short bursts, long flows, extreme rates."""
        n_each = max(1, n // 4)
        
        short_bursts = pd.DataFrame({
            'correlation_score': np.random.uniform(0.3, 0.8, n_each),
            'peak_time_lag': np.random.uniform(10, 100, n_each),
            'burst_alignment_score': np.random.uniform(0.4, 0.9, n_each),
            'flow_duration': np.random.uniform(0.5, 5, n_each),
            'packet_rate_mean': np.random.uniform(1000, 8000, n_each),
            'packet_rate_variance': np.random.uniform(5000, 40000, n_each),
            'traffic_type': 'edge_short'
        })
        
        long_flows = pd.DataFrame({
            'correlation_score': np.random.uniform(0.2, 0.6, n_each),
            'peak_time_lag': np.random.uniform(500, 3000, n_each),
            'burst_alignment_score': np.random.uniform(0.2, 0.5, n_each),
            'flow_duration': np.random.uniform(1800, 3600, n_each),
            'packet_rate_mean': np.random.uniform(50, 300, n_each),
            'packet_rate_variance': np.random.uniform(100, 1000, n_each),
            'traffic_type': 'edge_long'
        })
        
        high_rate = pd.DataFrame({
            'correlation_score': np.random.uniform(0.5, 0.9, n_each),
            'peak_time_lag': np.random.uniform(20, 200, n_each),
            'burst_alignment_score': np.random.uniform(0.6, 0.95, n_each),
            'flow_duration': np.random.uniform(10, 60, n_each),
            'packet_rate_mean': np.random.uniform(5000, 10000, n_each),
            'packet_rate_variance': np.random.uniform(10000, 50000, n_each),
            'traffic_type': 'edge_high_rate'
        })
        
        steady = pd.DataFrame({
            'correlation_score': np.random.uniform(0.4, 0.7, n_each),
            'peak_time_lag': np.random.uniform(100, 500, n_each),
            'burst_alignment_score': np.random.uniform(0.3, 0.6, n_each),
            'flow_duration': np.random.uniform(60, 300, n_each),
            'packet_rate_mean': np.random.uniform(200, 600, n_each),
            'packet_rate_variance': np.random.uniform(1, 50, n_each),
            'traffic_type': 'edge_steady'
        })
        
        return pd.concat([short_bursts, long_flows, high_rate, steady], ignore_index=True)
    
    def _calculate_risk_score(self, row: pd.Series) -> float:
        """Calculate risk score from features."""
        weights = {
            'correlation': 0.35,
            'burst': 0.25,
            'time_lag': 0.20,
            'rate': 0.10,
            'duration': 0.10
        }
        
        time_lag_norm = 1.0 - min(1.0, row['peak_time_lag'] / 2000)
        rate = row['packet_rate_mean']
        rate_factor = np.exp(-((rate - 500) ** 2) / (2 * 300 ** 2))
        dur = row['flow_duration']
        dur_factor = np.exp(-((dur - 75) ** 2) / (2 * 50 ** 2))
        
        score = (
            weights['correlation'] * row['correlation_score'] +
            weights['burst'] * row['burst_alignment_score'] +
            weights['time_lag'] * time_lag_norm +
            weights['rate'] * rate_factor +
            weights['duration'] * dur_factor
        )
        
        score += np.random.normal(0, 0.03)
        return np.clip(score, 0.0, 1.0)
    
    def _calculate_anomaly_score(self, row: pd.Series) -> float:
        """Calculate anomaly score based on deviation from baseline."""
        baseline = {
            'correlation_score': 0.25,
            'burst_alignment_score': 0.25,
            'peak_time_lag': 800,
            'flow_duration': 200,
            'packet_rate_mean': 300
        }
        
        deviations = []
        deviations.append(abs(row['correlation_score'] - baseline['correlation_score']) / 0.75)
        deviations.append(abs(row['burst_alignment_score'] - baseline['burst_alignment_score']) / 0.75)
        deviations.append(1 - min(1, row['peak_time_lag'] / baseline['peak_time_lag']))
        
        anomaly = np.mean(deviations) + np.random.normal(0, 0.05)
        return np.clip(anomaly, 0.0, 1.0)
    
    def _assign_risk_level(self, score: float) -> str:
        if score >= 0.7:
            return 'HIGH'
        elif score >= 0.4:
            return 'MEDIUM'
        return 'LOW'
    
    def _generate_feature_importance(self, row: pd.Series) -> Dict[str, float]:
        """Generate feature importance for explainability."""
        base_importance = {
            'correlation_score': 0.35 + np.random.uniform(-0.05, 0.05),
            'burst_alignment_score': 0.25 + np.random.uniform(-0.05, 0.05),
            'peak_time_lag': 0.18 + np.random.uniform(-0.03, 0.03),
            'flow_duration': 0.08 + np.random.uniform(-0.02, 0.02),
            'packet_rate_mean': 0.07 + np.random.uniform(-0.02, 0.02),
            'packet_rate_variance': 0.07 + np.random.uniform(-0.02, 0.02)
        }
        
        # Adjust based on actual values
        if row['correlation_score'] > 0.7:
            base_importance['correlation_score'] += 0.1
        if row['burst_alignment_score'] > 0.6:
            base_importance['burst_alignment_score'] += 0.08
        if row['peak_time_lag'] < 200:
            base_importance['peak_time_lag'] += 0.05
        
        # Normalize
        total = sum(base_importance.values())
        return {k: round(v / total, 3) for k, v in base_importance.items()}
    
    def _generate_explanation(self, row: pd.Series) -> str:
        """Generate plain-English explanation."""
        risk_level = row['risk_level']
        corr = row['correlation_score']
        burst = row['burst_alignment_score']
        
        if risk_level == 'HIGH':
            return (
                f"This traffic flow shows strong timing correlation ({corr:.0%}) "
                f"with burst alignment of {burst:.0%}. The pattern suggests "
                f"potential guard node identification. Recommended for immediate review."
            )
        elif risk_level == 'MEDIUM':
            return (
                f"Moderate correlation detected ({corr:.0%}) with partial burst "
                f"alignment ({burst:.0%}). Pattern warrants monitoring and may "
                f"require additional analysis if pattern persists."
            )
        else:
            return (
                f"Traffic shows typical patterns with low correlation ({corr:.0%}). "
                f"No significant timing anomalies detected. Consistent with "
                f"normal encrypted traffic behavior."
            )
    
    def generate_dataset(
        self,
        n_normal: int = 500,
        n_suspicious: int = 300,
        n_high_risk: int = 150,
        n_edge: int = 50,
        start_time: datetime = None
    ) -> pd.DataFrame:
        """Generate complete labeled dataset."""
        
        if start_time is None:
            start_time = datetime.now() - timedelta(hours=24)
        
        print(f"Generating traffic dataset...")
        print(f"  Normal: {n_normal}, Suspicious: {n_suspicious}")
        print(f"  High-risk: {n_high_risk}, Edge cases: {n_edge}")
        
        # Generate each type
        df_normal = self._generate_normal_traffic(n_normal)
        df_suspicious = self._generate_suspicious_traffic(n_suspicious)
        df_high = self._generate_high_risk_traffic(n_high_risk)
        df_edge = self._generate_edge_cases(n_edge)
        
        # Combine and shuffle
        df = pd.concat([df_normal, df_suspicious, df_high, df_edge], ignore_index=True)
        df = df.sample(frac=1, random_state=self.seed).reset_index(drop=True)
        
        total = len(df)
        
        # Add metadata
        timestamps = [
            start_time + timedelta(seconds=i * 30 + np.random.randint(0, 20))
            for i in range(total)
        ]
        
        df['timestamp'] = timestamps
        df['flow_id'] = [self._generate_flow_id(i, ts) for i, ts in enumerate(timestamps)]
        df['source_ip'] = [self._generate_ip(False) for _ in range(total)]
        df['dest_ip'] = [self._generate_ip(True) for _ in range(total)]
        df['relay_fingerprint'] = [self._generate_fingerprint() for _ in range(total)]
        df['relay_country'] = np.random.choice(
            self.RELAY_COUNTRIES, size=total, p=self.COUNTRY_WEIGHTS
        )
        
        # Calculate scores
        print("Calculating risk scores...")
        df['risk_score'] = df.apply(self._calculate_risk_score, axis=1)
        df['anomaly_score'] = df.apply(self._calculate_anomaly_score, axis=1)
        df['final_risk_score'] = (df['risk_score'] * 0.7 + df['anomaly_score'] * 0.3).clip(0, 1)
        df['risk_level'] = df['final_risk_score'].apply(self._assign_risk_level)
        
        # Generate explanations
        df['feature_importance'] = df.apply(
            lambda r: json.dumps(self._generate_feature_importance(r)), axis=1
        )
        df['explanation_text'] = df.apply(self._generate_explanation, axis=1)
        
        # Reorder columns
        column_order = [
            'flow_id', 'timestamp', 'source_ip', 'dest_ip',
            'relay_fingerprint', 'relay_country',
            'correlation_score', 'peak_time_lag', 'burst_alignment_score',
            'flow_duration', 'packet_rate_mean', 'packet_rate_variance',
            'risk_score', 'anomaly_score', 'final_risk_score', 'risk_level',
            'feature_importance', 'explanation_text', 'traffic_type'
        ]
        df = df[column_order]
        
        print(f"\nGenerated {len(df)} samples")
        print(f"Risk distribution:\n{df['risk_level'].value_counts()}")
        
        return df
    
    def save_dataset(self, df: pd.DataFrame, output_dir: str, prefix: str = 'traffic_data'):
        """Save dataset to CSV."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        csv_path = os.path.join(output_dir, f'{prefix}_{timestamp}.csv')
        df.to_csv(csv_path, index=False)
        print(f"Saved: {csv_path}")
        
        # Save metadata
        meta = {
            'generated_at': datetime.now().isoformat(),
            'total_samples': len(df),
            'risk_distribution': df['risk_level'].value_counts().to_dict(),
            'risk_thresholds': self.RISK_THRESHOLDS
        }
        meta_path = os.path.join(output_dir, f'{prefix}_meta_{timestamp}.json')
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2, default=str)
        
        return csv_path


def generate_demo_data():
    """Generate demo datasets."""
    gen = TrafficDataGenerator(seed=42)
    output_dir = os.path.join(os.path.dirname(__file__), 'data')
    
    df = gen.generate_dataset(
        n_normal=400,
        n_suspicious=250,
        n_high_risk=120,
        n_edge=30
    )
    
    gen.save_dataset(df, output_dir, 'demo_traffic')
    return df


if __name__ == '__main__':
    generate_demo_data()
