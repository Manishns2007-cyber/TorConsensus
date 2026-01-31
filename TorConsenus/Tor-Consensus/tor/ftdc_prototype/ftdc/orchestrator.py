"""
TOR-Unveil: Comprehensive Analysis Orchestrator
Coordinates all analysis components for end-to-end TOR traffic investigation
"""
import os
import json
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from ftdc.consensus import TorConsensusCollector
from ftdc.extractor import FTDCExtractor
from ftdc.node_correlation import NodeCorrelationEngine
from ftdc.correlation import combined_score
from ftdc.path import infer_paths
from ftdc.database import FTDCDatabase
from ftdc.report_generator import ForensicReportGenerator
from ftdc.visualization import (
    plot_density_overlay,
    create_network_path_diagram,
    create_timeline_reconstruction,
    create_confidence_heatmap,
    create_geographic_relay_map,
    create_density_overlay_plotly,
    generate_html_report
)


class TorAnalysisOrchestrator:
    """
    Main orchestrator for TOR traffic analysis.
    Coordinates data collection, correlation, visualization, and reporting.
    """
    
    def __init__(self, db_path='ftdc_analysis.db', results_dir='results'):
        """
        Initialize the analysis orchestrator.
        
        Args:
            db_path: Path to SQLite database
            results_dir: Directory for output files
        """
        self.consensus_collector = TorConsensusCollector()
        self.node_correlator = NodeCorrelationEngine()
        self.database = FTDCDatabase(db_path)
        self.report_generator = ForensicReportGenerator()
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)
        
        self.current_analysis = None
        self.analysis_history = []
    
    def full_analysis(self, pcap_path: str, case_metadata: Optional[Dict] = None,
                     window_ms: int = 50, visualizations: bool = True) -> Dict:
        """
        Perform complete end-to-end TOR traffic analysis.
        
        Args:
            pcap_path: Path to PCAP file
            case_metadata: Optional case information (investigator, case_id, etc.)
            window_ms: Window size for FTDC analysis (milliseconds)
            visualizations: Whether to generate visualizations
        
        Returns:
            dict: Complete analysis results
        """
        analysis_id = str(uuid.uuid4())
        start_time = time.time()
        
        print(f"🔍 Starting TOR Analysis: {analysis_id}")
        print(f"📁 PCAP: {os.path.basename(pcap_path)}")
        
        self.current_analysis = {
            'id': analysis_id,
            'pcap_path': pcap_path,
            'start_time': start_time,
            'status': 'running',
            'progress': 0
        }
        
        results = {
            'analysis_id': analysis_id,
            'pcap_filename': os.path.basename(pcap_path),
            'timestamp': datetime.now().isoformat(),
            'case_metadata': case_metadata or {}
        }
        
        try:
            # Step 1: Fetch TOR consensus data
            print("\n[1/7] Fetching TOR consensus data...")
            self.current_analysis['progress'] = 10
            consensus = self.consensus_collector.fetch_consensus()
            detailed = self.consensus_collector.fetch_detailed_consensus()
            relays = self.consensus_collector.parse_consensus(consensus, detailed)
            
            print(f"✓ Loaded {len(relays)} relays")
            results['total_relays'] = len(relays)
            results['consensus_summary'] = self.consensus_collector.get_consensus_summary()
            
            # Store relays in database
            for relay in relays[:100]:  # Store top relays
                self.database.store_relay(relay)
            
            # Step 2: Extract traffic signatures from PCAP
            print("\n[2/7] Extracting traffic signatures...")
            self.current_analysis['progress'] = 25
            extractor = FTDCExtractor(window_ms=window_ms)
            signatures = extractor.extract_signatures(pcap_path)
            
            print(f"✓ Extracted {len(signatures)} flow signatures")
            results['flows_extracted'] = len(signatures)
            
            if not signatures:
                raise ValueError("No flows extracted from PCAP")
            
            # Identify primary exit flow
            flow_summaries = [
                (key, sum(sig['timeseries']['total_bytes']))
                for key, sig in signatures.items()
            ]
            flow_summaries.sort(key=lambda x: x[1], reverse=True)
            exit_flow_key = flow_summaries[0][0]
            exit_flow = signatures[exit_flow_key]
            
            print(f"✓ Primary exit flow: {exit_flow_key}")
            results['exit_flow'] = str(exit_flow_key)
            
            # Step 3: Identify guard relay candidates
            print("\n[3/7] Identifying guard relay candidates...")
            self.current_analysis['progress'] = 40
            guard_relays = self.consensus_collector.get_guard_relays()
            guard_candidates = [r['fingerprint'] for r in guard_relays]
            
            print(f"✓ Found {len(guard_candidates)} guard relays")
            results['guard_candidates_count'] = len(guard_candidates)
            
            # Step 4: Advanced node correlation
            print("\n[4/7] Performing advanced node correlation...")
            self.current_analysis['progress'] = 55
            guard_scores = self.node_correlator.circuit_pattern_matching(
                exit_flow, guard_candidates[:100], relays
            )
            
            print(f"✓ Correlated {len(guard_scores)} guards")
            results['guard_scores'] = guard_scores[:20]  # Top 20
            
            # Step 5: Path reconstruction
            print("\n[5/7] Reconstructing circuit paths...")
            self.current_analysis['progress'] = 70
            exit_relay = relays[0] if relays else {'fingerprint': 'unknown', 'ip': None}
            guard_score_tuples = [(g['fingerprint'], g['confidence']) for g in guard_scores[:20]]
            paths = infer_paths(guard_score_tuples, exit_relay, relays, top_n=10)
            
            print(f"✓ Reconstructed {len(paths)} probable paths")
            results['circuit_paths'] = paths
            
            # Step 6: Iterative improvement
            print("\n[6/7] Applying iterative improvement...")
            self.current_analysis['progress'] = 80
            improvement_factor = self.node_correlator.iterative_improvement(exit_flow)
            correlation_stats = self.node_correlator.get_correlation_statistics()
            
            print(f"✓ Improvement factor: {improvement_factor:.2f}x")
            results['improvement_factor'] = improvement_factor
            results['correlation_statistics'] = correlation_stats
            
            # Step 7: Generate visualizations and reports
            if visualizations:
                print("\n[7/7] Generating visualizations and reports...")
                self.current_analysis['progress'] = 90
                
                viz_results = self._generate_visualizations(
                    analysis_id, exit_flow, guard_scores, paths, relays
                )
                results['visualizations'] = viz_results
            
            # Calculate final metrics
            duration = time.time() - start_time
            results['analysis_duration'] = duration
            results['status'] = 'completed'
            
            # Store in database
            self.database.store_analysis(analysis_id, results, case_metadata)
            
            # Store guard rankings
            for rank, guard in enumerate(guard_scores[:20], 1):
                self.database.store_guard_ranking(
                    analysis_id=analysis_id,
                    fingerprint=guard['fingerprint'],
                    rank=rank,
                    confidence=guard['confidence'],
                    bandwidth_score=guard['scores'].get('bandwidth', 0),
                    quality_score=guard['scores'].get('quality', 0),
                    proximity_score=guard['scores'].get('proximity', 0)
                )
            
            # Store circuit paths
            for rank, path in enumerate(paths[:10], 1):
                path_nodes = path.get('path', [])
                if len(path_nodes) >= 3:
                    self.database.store_circuit_path(
                        analysis_id=analysis_id,
                        rank=rank,
                        guard_fingerprint=path_nodes[0].get('fingerprint'),
                        middle_fingerprint=path_nodes[1].get('fingerprint'),
                        exit_fingerprint=path_nodes[2].get('fingerprint'),
                        confidence=path.get('confidence', 0.0)
                    )
            
            # Generate comprehensive forensic report
            pdf_path = os.path.join(self.results_dir, f"{analysis_id}_report.pdf")
            self.report_generator.generate_report(results, pdf_path, case_metadata)
            results['pdf_report'] = pdf_path
            
            print(f"\n✅ Analysis complete in {duration:.2f}s")
            print(f"📊 Top guard confidence: {guard_scores[0]['confidence']:.1%}")
            print(f"📄 Report: {pdf_path}")
            
            self.current_analysis['status'] = 'completed'
            self.current_analysis['progress'] = 100
            self.analysis_history.append(results)
            
            return results
        
        except Exception as e:
            print(f"\n❌ Analysis failed: {e}")
            import traceback
            traceback.print_exc()
            
            results['status'] = 'failed'
            results['error'] = str(e)
            results['analysis_duration'] = time.time() - start_time
            
            self.current_analysis['status'] = 'failed'
            self.current_analysis['error'] = str(e)
            
            return results
    
    def _generate_visualizations(self, analysis_id: str, exit_flow: Dict,
                                guard_scores: List[Dict], paths: List[Dict],
                                relays: List[Dict]) -> Dict:
        """Generate all visualizations for the analysis."""
        viz_paths = {}
        
        try:
            # Get density data
            exit_density = exit_flow.get('timeseries', {}).get('density', [])
            
            # Simulate guard density (in production, use actual guard-side capture)
            import random
            import numpy as np
            guard_density = [max(0, x + random.normalvariate(0, 0.02)) for x in exit_density]
            
            # 1. Static density overlay (for backwards compatibility)
            static_path = os.path.join(self.results_dir, f"{analysis_id}_overlay.png")
            plot_density_overlay(exit_density, guard_density, static_path)
            viz_paths['static_overlay'] = static_path
            
            # 2. Interactive Plotly density overlay
            try:
                from ftdc.visualization import PLOTLY_AVAILABLE
                if PLOTLY_AVAILABLE:
                    plotly_html = create_density_overlay_plotly(exit_density, guard_density)
                    if plotly_html:
                        viz_paths['density_overlay'] = plotly_html
            except Exception as e:
                print(f"Plotly density overlay failed: {e}")
            
            # 3. Network path diagram
            try:
                if PLOTLY_AVAILABLE:
                    network_html = create_network_path_diagram(paths)
                    if network_html:
                        viz_paths['network_diagram'] = network_html
            except Exception as e:
                print(f"Network diagram failed: {e}")
            
            # 4. Confidence heatmap
            try:
                if PLOTLY_AVAILABLE:
                    heatmap_html = create_confidence_heatmap(guard_scores)
                    if heatmap_html:
                        viz_paths['confidence_heatmap'] = heatmap_html
            except Exception as e:
                print(f"Confidence heatmap failed: {e}")
            
            # 5. Geographic map
            try:
                if PLOTLY_AVAILABLE:
                    geo_html = create_geographic_relay_map(relays)
                    if geo_html:
                        viz_paths['geographic_map'] = geo_html
            except Exception as e:
                print(f"Geographic map failed: {e}")
            
            print(f"✓ Generated {len(viz_paths)} visualizations")
        
        except Exception as e:
            print(f"⚠️  Visualization generation partially failed: {e}")
        
        return viz_paths
    
    def export_results(self, analysis_id: str, format: str = 'json') -> Optional[str]:
        """
        Export analysis results in various formats.
        
        Args:
            analysis_id: Analysis ID to export
            format: Export format ('json', 'csv', 'html')
        
        Returns:
            str: Path to exported file
        """
        analysis = self.database.get_analysis(analysis_id)
        if not analysis:
            print(f"❌ Analysis {analysis_id} not found")
            return None
        
        output_path = os.path.join(self.results_dir, f"{analysis_id}.{format}")
        
        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump(dict(analysis), f, indent=2, default=str)
        
        elif format == 'csv':
            import csv
            guards = self.database.get_guard_rankings(analysis_id)
            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['rank', 'fingerprint', 'confidence', 
                                                       'bandwidth_score', 'quality_score', 
                                                       'proximity_score'])
                writer.writeheader()
                for guard in guards:
                    writer.writerow(dict(guard))
        
        elif format == 'html':
            guards = self.database.get_guard_rankings(analysis_id)
            paths = self.database.get_circuit_paths(analysis_id)
            
            result_data = {
                'analysis': dict(analysis),
                'guard_rankings': [dict(g) for g in guards],
                'circuit_paths': [dict(p) for p in paths]
            }
            
            generate_html_report(analysis_id, result_data, output_path)
        
        print(f"✅ Exported to {output_path}")
        return output_path
    
    def get_analysis_summary(self, analysis_id: str) -> Optional[Dict]:
        """Get summary of a completed analysis."""
        analysis = self.database.get_analysis(analysis_id)
        if not analysis:
            return None
        
        guards = self.database.get_guard_rankings(analysis_id, limit=10)
        paths = self.database.get_circuit_paths(analysis_id, limit=5)
        
        return {
            'analysis_id': analysis_id,
            'timestamp': analysis['analysis_timestamp'],
            'duration': analysis['analysis_duration'],
            'pcap': analysis['pcap_filename'],
            'total_guards': analysis['total_guards_identified'],
            'avg_confidence': analysis['avg_confidence'],
            'top_guards': [
                {
                    'rank': g['rank'],
                    'fingerprint': g['fingerprint'][:16],
                    'confidence': f"{g['confidence']:.1%}"
                }
                for g in guards[:5]
            ],
            'top_paths': len(paths)
        }
    
    def list_analyses(self, limit: int = 10) -> List[Dict]:
        """List recent analyses."""
        analyses = self.database.list_analyses(limit=limit)
        return [
            {
                'id': a['analysis_id'],
                'timestamp': a['analysis_timestamp'],
                'pcap': a['pcap_filename'],
                'status': a['status'],
                'guards': a['total_guards_identified']
            }
            for a in analyses
        ]
    
    def enable_auto_refresh(self):
        """Enable automatic consensus data refresh."""
        self.consensus_collector.enable_auto_refresh(interval_seconds=3600)
    
    def disable_auto_refresh(self):
        """Disable automatic consensus data refresh."""
        self.consensus_collector.disable_auto_refresh()


def main():
    """Command-line interface for TOR analysis."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='TOR-Unveil: Comprehensive TOR Traffic Analysis System'
    )
    parser.add_argument('pcap', help='Path to PCAP file')
    parser.add_argument('-o', '--output-dir', default='results', help='Output directory')
    parser.add_argument('-w', '--window', type=int, default=50, help='FTDC window size (ms)')
    parser.add_argument('--case-id', help='Case ID for forensic report')
    parser.add_argument('--investigator', help='Investigator name')
    parser.add_argument('--agency', default='TN Police Cybercrime', help='Agency name')
    parser.add_argument('--no-viz', action='store_true', help='Skip visualizations')
    parser.add_argument('--export', choices=['json', 'csv', 'html'], help='Export format')
    
    args = parser.parse_args()
    
    # Prepare case metadata
    case_metadata = None
    if args.case_id or args.investigator:
        case_metadata = {
            'case_id': args.case_id,
            'investigator': args.investigator,
            'agency': args.agency
        }
    
    # Create orchestrator
    orchestrator = TorAnalysisOrchestrator(results_dir=args.output_dir)
    
    # Run analysis
    results = orchestrator.full_analysis(
        pcap_path=args.pcap,
        case_metadata=case_metadata,
        window_ms=args.window,
        visualizations=not args.no_viz
    )
    
    # Export if requested
    if args.export and results.get('status') == 'completed':
        orchestrator.export_results(results['analysis_id'], args.export)
    
    return 0 if results.get('status') == 'completed' else 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
