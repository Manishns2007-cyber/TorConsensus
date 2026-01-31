"""
Database integration for TOR-Unveil FTDC Analysis System
Stores relay metadata, analysis results, and correlation history
"""
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional
import os


class FTDCDatabase:
    """SQLite database for storing TOR analysis data"""
    
    def __init__(self, db_path='ftdc_analysis.db'):
        """Initialize database connection and create tables if needed"""
        self.db_path = db_path
        self.conn = None
        self._connect()
        self._create_tables()
    
    def _connect(self):
        """Establish database connection"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
    
    def _create_tables(self):
        """Create database schema"""
        cursor = self.conn.cursor()
        
        # Relay metadata table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS relays (
                fingerprint TEXT PRIMARY KEY,
                nickname TEXT,
                ip_address TEXT,
                country TEXT,
                as_number TEXT,
                as_name TEXT,
                bandwidth INTEGER,
                uptime INTEGER,
                flags TEXT,
                exit_policy TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Analysis results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analyses (
                analysis_id TEXT PRIMARY KEY,
                pcap_filename TEXT,
                analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                analysis_duration REAL,
                total_guards_identified INTEGER,
                avg_confidence REAL,
                improvement_factor REAL,
                case_id TEXT,
                investigator TEXT,
                status TEXT DEFAULT 'completed',
                metadata TEXT
            )
        ''')
        
        # Guard rankings table (links analyses to relays)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS guard_rankings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT,
                fingerprint TEXT,
                rank INTEGER,
                confidence REAL,
                bandwidth_score REAL,
                quality_score REAL,
                proximity_score REAL,
                FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id),
                FOREIGN KEY (fingerprint) REFERENCES relays(fingerprint)
            )
        ''')
        
        # Circuit paths table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS circuit_paths (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT,
                rank INTEGER,
                guard_fingerprint TEXT,
                middle_fingerprint TEXT,
                exit_fingerprint TEXT,
                confidence REAL,
                FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id)
            )
        ''')
        
        # Correlation history table (for iterative improvement)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS correlation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                exit_fingerprint TEXT,
                guard_fingerprint TEXT,
                correlation_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                correlation_score REAL,
                time_offset REAL,
                confidence REAL
            )
        ''')
        
        # AI Risk Scores table (for AI-powered decision support)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ai_risk_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT,
                fingerprint TEXT,
                risk_score REAL,
                risk_band TEXT,
                ai_rank INTEGER,
                correlation_score REAL,
                timing_similarity REAL,
                bandwidth_similarity REAL,
                explanation_summary TEXT,
                contributing_factors TEXT,
                investigation_guidance TEXT,
                model_trained INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id),
                FOREIGN KEY (fingerprint) REFERENCES relays(fingerprint)
            )
        ''')
        
        # AI Model metadata table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ai_model_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_type TEXT,
                training_date TIMESTAMP,
                samples_count INTEGER,
                cv_score REAL,
                feature_importances TEXT,
                model_path TEXT,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for better query performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_relays_ip ON relays(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_relays_country ON relays(country)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_analyses_timestamp ON analyses(analysis_timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_guard_rankings_analysis ON guard_rankings(analysis_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_guard_rankings_confidence ON guard_rankings(confidence)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_correlation_history_exit ON correlation_history(exit_fingerprint)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_correlation_history_guard ON correlation_history(guard_fingerprint)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ai_risk_scores_analysis ON ai_risk_scores(analysis_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ai_risk_scores_risk ON ai_risk_scores(risk_score)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ai_risk_scores_band ON ai_risk_scores(risk_band)')
        
        self.conn.commit()
    
    def store_relay(self, relay_data: Dict):
        """Store or update relay metadata"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO relays 
            (fingerprint, nickname, ip_address, country, as_number, as_name, 
             bandwidth, uptime, flags, exit_policy, first_seen, last_seen, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            relay_data.get('fingerprint'),
            relay_data.get('nickname'),
            relay_data.get('ip'),
            relay_data.get('country'),
            relay_data.get('as_number'),
            relay_data.get('as_name'),
            relay_data.get('bandwidth', 0),
            relay_data.get('uptime', 0),
            json.dumps(relay_data.get('flags', [])),
            relay_data.get('exit_policy'),
            relay_data.get('first_seen'),
            relay_data.get('last_seen'),
            datetime.now()
        ))
        
        self.conn.commit()
    
    def store_analysis(self, analysis_id: str, result: Dict, case_metadata: Optional[Dict] = None):
        """Store complete analysis results"""
        cursor = self.conn.cursor()
        
        # Store main analysis record
        cursor.execute('''
            INSERT INTO analyses 
            (analysis_id, pcap_filename, analysis_duration, total_guards_identified, 
             avg_confidence, improvement_factor, case_id, investigator, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            analysis_id,
            result.get('pcap_filename'),
            result.get('analysis_duration', 0),
            len(result.get('guard_rankings', [])),
            result.get('correlation_stats', {}).get('avg_confidence', 0),
            result.get('improvement_factor', 0),
            case_metadata.get('case_id') if case_metadata else None,
            case_metadata.get('investigator') if case_metadata else None,
            json.dumps(case_metadata) if case_metadata else None
        ))
        
        # Store guard rankings
        for i, guard in enumerate(result.get('guard_rankings', []), 1):
            # First store relay metadata
            self.store_relay(guard)
            
            # Then store ranking
            cursor.execute('''
                INSERT INTO guard_rankings 
                (analysis_id, fingerprint, rank, confidence, bandwidth_score, 
                 quality_score, proximity_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis_id,
                guard.get('fingerprint'),
                i,
                guard.get('confidence', 0),
                guard.get('bandwidth_score', 0),
                guard.get('quality_score', 0),
                guard.get('proximity_score', 0)
            ))
        
        # Store circuit paths
        for i, path_info in enumerate(result.get('paths', []), 1):
            path_nodes = path_info.get('path', [])
            if len(path_nodes) >= 3:
                cursor.execute('''
                    INSERT INTO circuit_paths 
                    (analysis_id, rank, guard_fingerprint, middle_fingerprint, 
                     exit_fingerprint, confidence)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    analysis_id,
                    i,
                    path_nodes[0].get('fingerprint'),
                    path_nodes[1].get('fingerprint'),
                    path_nodes[2].get('fingerprint'),
                    path_info.get('confidence', 0)
                ))
        
        self.conn.commit()
    
    def store_correlation(self, exit_fp: str, guard_fp: str, score: float, 
                         time_offset: float, confidence: float):
        """Store correlation event for learning"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            INSERT INTO correlation_history 
            (exit_fingerprint, guard_fingerprint, correlation_score, time_offset, confidence)
            VALUES (?, ?, ?, ?, ?)
        ''', (exit_fp, guard_fp, score, time_offset, confidence))
        
        self.conn.commit()
    
    def get_relay_by_fingerprint(self, fingerprint: str) -> Optional[Dict]:
        """Retrieve relay metadata by fingerprint"""
        cursor = self.conn.cursor()
        
        cursor.execute('SELECT * FROM relays WHERE fingerprint = ?', (fingerprint,))
        row = cursor.fetchone()
        
        if row:
            return dict(row)
        return None
    
    def get_relay_by_ip(self, ip_address: str) -> Optional[Dict]:
        """Retrieve relay by IP address"""
        cursor = self.conn.cursor()
        
        cursor.execute('SELECT * FROM relays WHERE ip_address = ?', (ip_address,))
        row = cursor.fetchone()
        
        if row:
            return dict(row)
        return None
    
    def get_analysis(self, analysis_id: str) -> Optional[Dict]:
        """Retrieve analysis results"""
        cursor = self.conn.cursor()
        
        cursor.execute('SELECT * FROM analyses WHERE analysis_id = ?', (analysis_id,))
        analysis = cursor.fetchone()
        
        if not analysis:
            return None
        
        result = dict(analysis)
        
        # Get guard rankings
        cursor.execute('''
            SELECT gr.*, r.* FROM guard_rankings gr
            JOIN relays r ON gr.fingerprint = r.fingerprint
            WHERE gr.analysis_id = ?
            ORDER BY gr.rank
        ''', (analysis_id,))
        
        result['guard_rankings'] = [dict(row) for row in cursor.fetchall()]
        
        # Get circuit paths
        cursor.execute('''
            SELECT * FROM circuit_paths
            WHERE analysis_id = ?
            ORDER BY rank
        ''', (analysis_id,))
        
        result['circuit_paths'] = [dict(row) for row in cursor.fetchall()]
        
        return result
    
    def get_correlation_history(self, exit_fp: str, guard_fp: str, 
                               limit: int = 100) -> List[Dict]:
        """Get historical correlation data for learning"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT * FROM correlation_history
            WHERE exit_fingerprint = ? AND guard_fingerprint = ?
            ORDER BY correlation_timestamp DESC
            LIMIT ?
        ''', (exit_fp, guard_fp, limit))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict:
        """Get overall system statistics"""
        cursor = self.conn.cursor()
        
        stats = {}
        
        # Total analyses
        cursor.execute('SELECT COUNT(*) as count FROM analyses')
        stats['total_analyses'] = cursor.fetchone()['count']
        
        # Average confidence across all analyses
        cursor.execute('SELECT AVG(avg_confidence) as avg FROM analyses')
        stats['overall_avg_confidence'] = cursor.fetchone()['avg'] or 0
        
        # Total unique relays tracked
        cursor.execute('SELECT COUNT(*) as count FROM relays')
        stats['total_relays'] = cursor.fetchone()['count']
        
        # Guard relays
        cursor.execute("SELECT COUNT(*) as count FROM relays WHERE flags LIKE '%Guard%'")
        stats['guard_relays'] = cursor.fetchone()['count']
        
        # Exit relays
        cursor.execute("SELECT COUNT(*) as count FROM relays WHERE flags LIKE '%Exit%'")
        stats['exit_relays'] = cursor.fetchone()['count']
        
        # Recent analyses (last 7 days)
        cursor.execute('''
            SELECT COUNT(*) as count FROM analyses 
            WHERE analysis_timestamp > datetime('now', '-7 days')
        ''')
        stats['recent_analyses'] = cursor.fetchone()['count']
        
        # Top countries by relay count
        cursor.execute('''
            SELECT country, COUNT(*) as count FROM relays 
            GROUP BY country 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        stats['top_countries'] = [dict(row) for row in cursor.fetchall()]
        
        return stats
    
    def get_all_analyses(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Get list of all analyses"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT analysis_id, pcap_filename, analysis_timestamp, 
                   total_guards_identified, avg_confidence, status
            FROM analyses
            ORDER BY analysis_timestamp DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def search_relays(self, query: str, search_type: str = 'nickname') -> List[Dict]:
        """Search relays by nickname, IP, or country"""
        cursor = self.conn.cursor()
        
        if search_type == 'nickname':
            cursor.execute('''
                SELECT * FROM relays 
                WHERE nickname LIKE ? 
                ORDER BY nickname 
                LIMIT 50
            ''', (f'%{query}%',))
        elif search_type == 'ip':
            cursor.execute('''
                SELECT * FROM relays 
                WHERE ip_address LIKE ? 
                LIMIT 50
            ''', (f'%{query}%',))
        elif search_type == 'country':
            cursor.execute('''
                SELECT * FROM relays 
                WHERE country = ? 
                ORDER BY bandwidth DESC 
                LIMIT 50
            ''', (query,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    # ==================== AI RISK SCORE METHODS ====================
    
    def store_ai_risk_scores(self, analysis_id: str, risk_assessments: List[Dict]):
        """
        Store AI risk assessments for an analysis.
        
        Args:
            analysis_id: The analysis ID
            risk_assessments: List of risk assessment dictionaries from AIRiskEngine
        
        Note: This stores AI-generated investigative support data only.
        """
        cursor = self.conn.cursor()
        
        for assessment in risk_assessments:
            explanation = assessment.get('explanation', {})
            
            cursor.execute('''
                INSERT INTO ai_risk_scores 
                (analysis_id, fingerprint, risk_score, risk_band, ai_rank,
                 correlation_score, timing_similarity, bandwidth_similarity,
                 explanation_summary, contributing_factors, investigation_guidance,
                 model_trained)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis_id,
                assessment.get('fingerprint'),
                assessment.get('risk_score', 0),
                assessment.get('risk_band', 'LOW'),
                assessment.get('ai_rank', 0),
                assessment.get('original_confidence', 0),
                assessment.get('feature_values', {}).get('timing_similarity', 0),
                assessment.get('feature_values', {}).get('bandwidth_similarity', 0),
                explanation.get('summary', ''),
                json.dumps(explanation.get('contributing_factors', [])),
                explanation.get('investigation_guidance', ''),
                1 if assessment.get('model_trained', False) else 0
            ))
        
        self.conn.commit()
    
    def get_ai_risk_scores(self, analysis_id: str) -> List[Dict]:
        """
        Retrieve AI risk scores for an analysis.
        
        Args:
            analysis_id: The analysis ID
        
        Returns:
            List of risk score dictionaries
        """
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT a.*, r.nickname, r.ip_address, r.country
            FROM ai_risk_scores a
            LEFT JOIN relays r ON a.fingerprint = r.fingerprint
            WHERE a.analysis_id = ?
            ORDER BY a.risk_score DESC
        ''', (analysis_id,))
        
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            # Parse contributing factors JSON
            if row_dict.get('contributing_factors'):
                try:
                    row_dict['contributing_factors'] = json.loads(row_dict['contributing_factors'])
                except:
                    row_dict['contributing_factors'] = []
            results.append(row_dict)
        
        return results
    
    def get_high_risk_relays(self, min_score: float = 0.7, limit: int = 50) -> List[Dict]:
        """
        Get relays with high AI risk scores across all analyses.
        
        Args:
            min_score: Minimum risk score threshold
            limit: Maximum results to return
        
        Returns:
            List of high-risk relay assessments
        """
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT a.fingerprint, r.nickname, r.ip_address, r.country,
                   AVG(a.risk_score) as avg_risk_score,
                   COUNT(*) as occurrence_count,
                   MAX(a.risk_score) as max_risk_score,
                   GROUP_CONCAT(DISTINCT a.risk_band) as risk_bands
            FROM ai_risk_scores a
            LEFT JOIN relays r ON a.fingerprint = r.fingerprint
            WHERE a.risk_score >= ?
            GROUP BY a.fingerprint
            ORDER BY avg_risk_score DESC
            LIMIT ?
        ''', (min_score, limit))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def store_ai_model_metadata(self, metadata: Dict):
        """Store AI model training metadata."""
        cursor = self.conn.cursor()
        
        # Deactivate previous models
        cursor.execute('UPDATE ai_model_metadata SET is_active = 0')
        
        cursor.execute('''
            INSERT INTO ai_model_metadata 
            (model_type, training_date, samples_count, cv_score, 
             feature_importances, model_path, is_active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
        ''', (
            metadata.get('model_type'),
            metadata.get('training_date'),
            metadata.get('samples_total', 0),
            metadata.get('cv_score_mean', 0),
            json.dumps(metadata.get('feature_importances', {})),
            metadata.get('model_path')
        ))
        
        self.conn.commit()
    
    def get_active_ai_model(self) -> Optional[Dict]:
        """Get metadata for the currently active AI model."""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT * FROM ai_model_metadata 
            WHERE is_active = 1 
            ORDER BY created_at DESC 
            LIMIT 1
        ''')
        
        row = cursor.fetchone()
        if row:
            result = dict(row)
            if result.get('feature_importances'):
                try:
                    result['feature_importances'] = json.loads(result['feature_importances'])
                except:
                    pass
            return result
        return None
    
    def get_ai_statistics(self) -> Dict:
        """Get AI risk scoring statistics."""
        cursor = self.conn.cursor()
        stats = {}
        
        # Total AI assessments
        cursor.execute('SELECT COUNT(*) as count FROM ai_risk_scores')
        stats['total_assessments'] = cursor.fetchone()['count']
        
        # Risk band distribution
        cursor.execute('''
            SELECT risk_band, COUNT(*) as count 
            FROM ai_risk_scores 
            GROUP BY risk_band
        ''')
        stats['risk_distribution'] = {row['risk_band']: row['count'] for row in cursor.fetchall()}
        
        # Average risk score
        cursor.execute('SELECT AVG(risk_score) as avg FROM ai_risk_scores')
        stats['avg_risk_score'] = cursor.fetchone()['avg'] or 0
        
        # High risk relay count
        cursor.execute('''
            SELECT COUNT(DISTINCT fingerprint) as count 
            FROM ai_risk_scores 
            WHERE risk_band = 'HIGH'
        ''')
        stats['high_risk_relays'] = cursor.fetchone()['count']
        
        # Active model info
        stats['active_model'] = self.get_active_ai_model()
        
        return stats
    
    # ==================== METHODS FOR AI TRAINING ====================
    
    def get_all_analysis_ids(self) -> List[str]:
        """
        Get all analysis IDs from the database.
        
        Returns:
            List of analysis ID strings
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT DISTINCT analysis_id FROM analyses ORDER BY analysis_timestamp DESC')
        return [row['analysis_id'] for row in cursor.fetchall()]
    
    def get_analyses_with_ai_scores(self) -> List[str]:
        """
        Get analysis IDs that already have AI risk scores.
        
        Returns:
            List of analysis ID strings
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT DISTINCT analysis_id FROM ai_risk_scores')
        return [row['analysis_id'] for row in cursor.fetchall()]
    
    def get_correlation_results(self, analysis_id: str) -> List[Dict]:
        """
        Get correlation results for a specific analysis.
        
        Args:
            analysis_id: The analysis ID to retrieve
        
        Returns:
            List of correlation result dictionaries
        """
        cursor = self.conn.cursor()
        
        # Get guard rankings with relay info
        cursor.execute('''
            SELECT g.*, r.nickname, r.ip_address, r.country, r.bandwidth, 
                   r.uptime, r.flags, r.or_port
            FROM guard_rankings g
            LEFT JOIN relays r ON g.fingerprint = r.fingerprint
            WHERE g.analysis_id = ?
            ORDER BY g.rank
        ''', (analysis_id,))
        
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            results.append({
                'relay_fingerprint': row_dict.get('fingerprint'),
                'nickname': row_dict.get('nickname'),
                'ip_address': row_dict.get('ip_address'),
                'country': row_dict.get('country'),
                'bandwidth': row_dict.get('bandwidth', 0),
                'uptime': row_dict.get('uptime', 0),
                'flags': row_dict.get('flags', '[]'),
                'or_port': row_dict.get('or_port', 9001),
                'confidence': row_dict.get('confidence', 0),
                'bandwidth_score': row_dict.get('bandwidth_score', 0.5),
                'timing_score': row_dict.get('timing_score', 0.5),
                'proximity_score': row_dict.get('proximity_score', 0.5),
                'quality_score': row_dict.get('quality_score', 0.5),
                'rank': row_dict.get('rank', 0)
            })
        
        return results
    
    def store_ai_risk_score(self, analysis_id: str, relay_fingerprint: str,
                           risk_score: float, risk_band: str, confidence: float,
                           explanation: str = '', feature_contributions: Dict = None,
                           model_version: str = ''):
        """
        Store a single AI risk score.
        
        Args:
            analysis_id: Analysis ID
            relay_fingerprint: Relay fingerprint
            risk_score: Calculated risk score (0-1)
            risk_band: Risk band (HIGH, MEDIUM, LOW)
            confidence: Model confidence
            explanation: Human-readable explanation
            feature_contributions: Feature contribution dictionary
            model_version: Model version string
        """
        cursor = self.conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO ai_risk_scores 
            (analysis_id, fingerprint, risk_score, risk_band, ai_rank,
             correlation_score, explanation_summary, contributing_factors,
             model_trained)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            analysis_id,
            relay_fingerprint,
            risk_score,
            risk_band,
            0,  # ai_rank - will be updated in batch
            confidence,
            explanation,
            json.dumps(feature_contributions or {}),
            1
        ))
        
        self.conn.commit()
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
