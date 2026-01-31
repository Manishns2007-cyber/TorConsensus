"""
Comprehensive TOR Analysis Module
Provides detailed geographical, circuit, and onion routing analysis.
"""
import json
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime
import statistics


class ComprehensiveTorAnalysis:
    """Enhanced analysis providing deep insights into TOR circuits and routing."""
    
    def __init__(self):
        self.analysis_cache = {}
        
    def analyze_circuit_path(self, paths: List[Dict], relays: List[Dict]) -> Dict[str, Any]:
        """
        Complete circuit path analysis showing guard → middle → exit flow.
        
        Args:
            paths: List of reconstructed paths with nodes
            relays: All relay metadata
            
        Returns:
            Comprehensive circuit analysis including all hops
        """
        if not paths:
            return {
                'status': 'no_paths',
                'message': 'No complete circuits could be reconstructed',
                'circuits': []
            }
        
        circuits = []
        for idx, path_info in enumerate(paths[:10]):  # Top 10 circuits
            nodes = path_info.get('path', [])
            confidence = path_info.get('confidence', 0.0)
            
            # Analyze each hop in the circuit
            hops = []
            for hop_num, node in enumerate(nodes):
                hop_type = self._determine_hop_type(hop_num, len(nodes), node)
                hop_analysis = {
                    'hop_number': hop_num + 1,
                    'type': hop_type,
                    'fingerprint': node.get('fingerprint', 'unknown'),
                    'ip': node.get('ip', 'N/A'),
                    'nickname': node.get('nickname', 'unknown'),
                    'country': node.get('country', 'unknown'),
                    'country_name': self._get_country_name(node.get('country', 'unknown')),
                    'as_number': node.get('as_number', 'N/A'),
                    'as_name': node.get('as_name', 'Unknown ASN'),
                    'bandwidth': node.get('bandwidth', 0),
                    'flags': node.get('flags', []),
                    'uptime': node.get('uptime', 'unknown'),
                    'latitude': node.get('latitude', None),
                    'longitude': node.get('longitude', None),
                }
                hops.append(hop_analysis)
            
            # Calculate circuit metrics
            circuit_analysis = {
                'circuit_id': f"Circuit_{idx + 1}",
                'confidence_score': round(confidence * 100, 2),
                'total_hops': len(hops),
                'complete_path': ' → '.join([h['nickname'] for h in hops]),
                'geographic_path': ' → '.join([h['country_name'] for h in hops]),
                'hops': hops,
                'circuit_characteristics': self._analyze_circuit_characteristics(hops),
                'security_assessment': self._assess_circuit_security(hops)
            }
            circuits.append(circuit_analysis)
        
        return {
            'status': 'success',
            'total_circuits_found': len(circuits),
            'circuits': circuits,
            'summary': self._generate_circuit_summary(circuits)
        }
    
    def analyze_onion_routing(self, exit_flow: Dict, paths: List[Dict], relays: List[Dict]) -> Dict[str, Any]:
        """
        Detailed onion routing analysis showing layer-by-layer encryption.
        
        Args:
            exit_flow: Exit node traffic signature
            paths: Reconstructed circuit paths
            relays: All relay metadata
            
        Returns:
            Onion routing analysis with encryption layers
        """
        if not paths:
            return {'status': 'insufficient_data'}
        
        # Get the most probable path
        best_path = paths[0] if paths else None
        if not best_path:
            return {'status': 'no_path'}
        
        nodes = best_path.get('path', [])
        
        # Analyze encryption layers (onion layers)
        encryption_layers = []
        for layer_num, node in enumerate(nodes):
            layer = {
                'layer_number': len(nodes) - layer_num,  # Countdown from exit
                'encrypted_by': node.get('nickname', 'unknown'),
                'fingerprint': node.get('fingerprint', 'unknown'),
                'decryption_point': self._determine_decryption_point(layer_num, len(nodes)),
                'visible_to': self._determine_visibility(layer_num, len(nodes)),
                'encryption_info': {
                    'can_see_destination': layer_num == len(nodes) - 1,  # Only exit sees destination
                    'can_see_source': layer_num == 0,  # Only guard sees source
                    'knows_full_path': False,  # No node knows full path
                    'role': self._determine_hop_type(layer_num, len(nodes), node)
                }
            }
            encryption_layers.append(layer)
        
        # Traffic flow analysis
        traffic_flow = {
            'entry_point': nodes[0].get('nickname', 'unknown') if nodes else 'unknown',
            'exit_point': nodes[-1].get('nickname', 'unknown') if nodes else 'unknown',
            'middle_nodes': [n.get('nickname', 'unknown') for n in nodes[1:-1]] if len(nodes) > 2 else [],
            'total_encrypted_hops': len(nodes),
            'encryption_scheme': 'AES-256 (per hop)',
            'traffic_pattern': self._analyze_traffic_pattern(exit_flow)
        }
        
        return {
            'status': 'success',
            'onion_layers': encryption_layers,
            'traffic_flow': traffic_flow,
            'routing_explanation': self._generate_routing_explanation(nodes),
            'anonymity_assessment': self._assess_anonymity_level(nodes)
        }
    
    def analyze_guard_node(self, guard_scores: List[Dict], relays: List[Dict]) -> Dict[str, Any]:
        """
        Deep analysis of identified guard nodes.
        
        Args:
            guard_scores: Ranked guard candidates with confidence scores
            relays: All relay metadata
            
        Returns:
            Detailed guard node analysis
        """
        if not guard_scores:
            return {
                'status': 'no_guards',
                'message': 'No guard nodes identified'
            }
        
        # Analyze top guard candidates
        top_guards = []
        for rank, guard_data in enumerate(guard_scores[:10]):
            fingerprint = guard_data.get('fingerprint', '')
            
            # Find full relay metadata
            relay = self._find_relay(fingerprint, relays)
            
            guard_analysis = {
                'rank': rank + 1,
                'confidence': round(guard_data.get('confidence', 0) * 100, 2),
                'fingerprint': fingerprint,
                'nickname': relay.get('nickname', guard_data.get('nickname', 'unknown')),
                'ip_address': relay.get('ip', guard_data.get('ip', 'N/A')),
                'country': relay.get('country', 'unknown'),
                'country_name': self._get_country_name(relay.get('country', 'unknown')),
                'as_info': {
                    'as_number': relay.get('as_number', 'N/A'),
                    'as_name': relay.get('as_name', 'Unknown ASN'),
                    'organization': relay.get('as_name', 'Unknown')
                },
                'geographic_location': {
                    'latitude': relay.get('latitude'),
                    'longitude': relay.get('longitude'),
                    'city': relay.get('city', 'Unknown'),
                    'region': relay.get('region', 'Unknown')
                },
                'node_characteristics': {
                    'bandwidth': relay.get('bandwidth', 0),
                    'flags': relay.get('flags', []),
                    'is_stable': 'Stable' in relay.get('flags', []),
                    'is_fast': 'Fast' in relay.get('flags', []),
                    'is_guard': 'Guard' in relay.get('flags', []),
                    'uptime': relay.get('uptime', 'unknown'),
                    'consensus_weight': relay.get('consensus_weight', 0)
                },
                'correlation_metrics': guard_data.get('metrics', {}),
                'identification_reason': self._explain_guard_identification(guard_data)
            }
            top_guards.append(guard_analysis)
        
        return {
            'status': 'success',
            'total_candidates': len(guard_scores),
            'high_confidence_guards': len([g for g in guard_scores if g.get('confidence', 0) > 0.7]),
            'top_guards': top_guards,
            'summary': self._generate_guard_summary(top_guards),
            'recommendation': self._generate_investigation_recommendation(top_guards)
        }
    
    def analyze_exit_node(self, exit_flow: Dict, relays: List[Dict]) -> Dict[str, Any]:
        """
        Detailed exit node analysis.
        
        Args:
            exit_flow: Exit node traffic signature
            relays: All relay metadata
            
        Returns:
            Exit node analysis
        """
        # Extract exit node information from flow
        exit_info = {
            'status': 'identified',
            'flow_key': exit_flow.get('flow_key', 'unknown'),
            'traffic_volume': sum(exit_flow.get('timeseries', {}).get('total_bytes', [])),
            'packet_count': sum(exit_flow.get('timeseries', {}).get('packet_counts', [])),
            'duration': len(exit_flow.get('timeseries', {}).get('density', [])),
            'traffic_pattern': self._analyze_traffic_pattern(exit_flow),
            'characteristics': {
                'burst_activity': self._detect_burst_activity(exit_flow),
                'steady_state': self._detect_steady_state(exit_flow),
                'peak_bandwidth': self._calculate_peak_bandwidth(exit_flow)
            }
        }
        
        return exit_info
    
    def analyze_geographic_distribution(self, paths: List[Dict], guard_scores: List[Dict], 
                                       relays: List[Dict]) -> Dict[str, Any]:
        """
        Complete geographic analysis of TOR circuit nodes.
        
        Args:
            paths: Reconstructed circuit paths
            guard_scores: Guard node candidates
            relays: All relay metadata
            
        Returns:
            Geographic distribution analysis
        """
        geographic_data = {
            'guard_locations': {},
            'middle_locations': {},
            'exit_locations': {},
            'circuit_paths': [],
            'country_statistics': {}
        }
        
        # Analyze guard node locations
        for guard in guard_scores[:20]:
            fingerprint = guard.get('fingerprint', '')
            relay = self._find_relay(fingerprint, relays)
            country = relay.get('country', 'unknown')
            country_name = self._get_country_name(country)
            
            if country_name not in geographic_data['guard_locations']:
                geographic_data['guard_locations'][country_name] = {
                    'count': 0,
                    'nodes': [],
                    'avg_confidence': 0,
                    'country_code': country
                }
            
            geographic_data['guard_locations'][country_name]['count'] += 1
            geographic_data['guard_locations'][country_name]['nodes'].append({
                'nickname': relay.get('nickname', 'unknown'),
                'confidence': guard.get('confidence', 0),
                'ip': relay.get('ip', 'N/A')
            })
        
        # Calculate average confidence per country
        for country_data in geographic_data['guard_locations'].values():
            if country_data['nodes']:
                country_data['avg_confidence'] = statistics.mean(
                    [n['confidence'] for n in country_data['nodes']]
                )
        
        # Analyze circuit geographic paths
        for path_info in paths[:10]:
            nodes = path_info.get('path', [])
            geo_path = {
                'confidence': path_info.get('confidence', 0),
                'countries': [self._get_country_name(n.get('country', 'unknown')) for n in nodes],
                'cities': [n.get('city', 'Unknown') for n in nodes],
                'coordinates': [(n.get('latitude'), n.get('longitude')) for n in nodes],
                'cross_border_hops': self._count_border_crossings(nodes)
            }
            geographic_data['circuit_paths'].append(geo_path)
        
        # Country statistics
        all_countries = []
        for path_info in paths:
            for node in path_info.get('path', []):
                country = self._get_country_name(node.get('country', 'unknown'))
                all_countries.append(country)
        
        for country in set(all_countries):
            geographic_data['country_statistics'][country] = {
                'frequency': all_countries.count(country),
                'percentage': round((all_countries.count(country) / len(all_countries)) * 100, 2) if all_countries else 0
            }
        
        return {
            'status': 'success',
            'geographic_data': geographic_data,
            'summary': self._generate_geographic_summary(geographic_data),
            'risk_assessment': self._assess_geographic_risk(geographic_data)
        }
    
    # Helper methods
    
    def _determine_hop_type(self, hop_num: int, total_hops: int, node: Dict) -> str:
        """Determine the type of hop in the circuit."""
        if hop_num == 0:
            return 'Guard/Entry Node'
        elif hop_num == total_hops - 1:
            return 'Exit Node'
        else:
            return f'Middle Node (Hop {hop_num + 1})'
    
    def _determine_decryption_point(self, layer_num: int, total_layers: int) -> str:
        """Determine where each encryption layer is decrypted."""
        if layer_num == 0:
            return 'Decrypted at Guard Node'
        elif layer_num == total_layers - 1:
            return 'Decrypted at Exit Node'
        else:
            return f'Decrypted at Middle Node {layer_num}'
    
    def _determine_visibility(self, layer_num: int, total_layers: int) -> List[str]:
        """Determine what each node can see."""
        visibility = []
        if layer_num == 0:
            visibility.append('Source IP Address')
            visibility.append('Next hop in circuit')
        elif layer_num == total_layers - 1:
            visibility.append('Destination address')
            visibility.append('Previous hop in circuit')
        else:
            visibility.append('Previous and next hops only')
        return visibility
    
    def _analyze_circuit_characteristics(self, hops: List[Dict]) -> Dict[str, Any]:
        """Analyze circuit characteristics."""
        total_bandwidth = sum(h.get('bandwidth', 0) for h in hops)
        countries = [h.get('country', 'unknown') for h in hops]
        unique_countries = len(set(countries))
        
        return {
            'total_bandwidth': total_bandwidth,
            'avg_bandwidth_per_hop': total_bandwidth / len(hops) if hops else 0,
            'geographic_diversity': unique_countries,
            'countries_traversed': list(set([h.get('country_name', 'unknown') for h in hops])),
            'all_nodes_stable': all('Stable' in h.get('flags', []) for h in hops),
            'all_nodes_fast': all('Fast' in h.get('flags', []) for h in hops)
        }
    
    def _assess_circuit_security(self, hops: List[Dict]) -> Dict[str, Any]:
        """Assess circuit security characteristics."""
        security_score = 100.0
        issues = []
        strengths = []
        
        # Check for all stable nodes
        if all('Stable' in h.get('flags', []) for h in hops):
            strengths.append('All nodes have Stable flag')
        else:
            security_score -= 10
            issues.append('Some nodes lack Stable flag')
        
        # Check for geographic diversity
        unique_countries = len(set(h.get('country', 'unknown') for h in hops))
        if unique_countries >= 3:
            strengths.append(f'High geographic diversity ({unique_countries} countries)')
        elif unique_countries == 1:
            security_score -= 20
            issues.append('All nodes in same country (jurisdiction risk)')
        
        # Check bandwidth
        avg_bandwidth = statistics.mean([h.get('bandwidth', 0) for h in hops]) if hops else 0
        if avg_bandwidth > 1000000:  # > 1 MB/s
            strengths.append('High bandwidth nodes')
        
        return {
            'security_score': max(0, security_score),
            'issues': issues,
            'strengths': strengths,
            'overall_assessment': 'Strong' if security_score >= 80 else ('Moderate' if security_score >= 60 else 'Weak')
        }
    
    def _generate_circuit_summary(self, circuits: List[Dict]) -> Dict[str, Any]:
        """Generate summary of circuit analysis."""
        if not circuits:
            return {}
        
        avg_confidence = statistics.mean([c['confidence_score'] for c in circuits])
        avg_hops = statistics.mean([c['total_hops'] for c in circuits])
        
        return {
            'total_circuits_analyzed': len(circuits),
            'average_confidence': round(avg_confidence, 2),
            'average_hops': round(avg_hops, 1),
            'highest_confidence_circuit': max(circuits, key=lambda c: c['confidence_score'])['circuit_id']
        }
    
    def _generate_routing_explanation(self, nodes: List[Dict]) -> str:
        """Generate human-readable routing explanation."""
        if not nodes:
            return "No routing information available"
        
        guard = nodes[0].get('nickname', 'unknown')
        exit_node = nodes[-1].get('nickname', 'unknown')
        middle_count = len(nodes) - 2
        
        explanation = (
            f"Traffic flows through {len(nodes)} nodes: "
            f"Starting at Guard Node '{guard}', passing through {middle_count} middle relay(s), "
            f"and exiting via Exit Node '{exit_node}'. Each node only knows its immediate predecessor "
            f"and successor, ensuring anonymity. The source IP is only visible to the guard node, "
            f"while the destination is only visible to the exit node."
        )
        
        return explanation
    
    def _assess_anonymity_level(self, nodes: List[Dict]) -> Dict[str, Any]:
        """Assess the anonymity level provided by this circuit."""
        anonymity_score = 0
        factors = []
        
        # Base points for having a circuit
        if len(nodes) >= 3:
            anonymity_score += 40
            factors.append('Standard 3-hop circuit')
        
        # Geographic diversity
        unique_countries = len(set(n.get('country', 'unknown') for n in nodes))
        anonymity_score += min(30, unique_countries * 10)
        factors.append(f'Geographic diversity: {unique_countries} countries')
        
        # Node flags
        stable_nodes = sum(1 for n in nodes if 'Stable' in n.get('flags', []))
        anonymity_score += min(30, stable_nodes * 10)
        factors.append(f'{stable_nodes} stable nodes')
        
        level = 'High' if anonymity_score >= 80 else ('Medium' if anonymity_score >= 60 else 'Low')
        
        return {
            'anonymity_score': min(100, anonymity_score),
            'level': level,
            'contributing_factors': factors
        }
    
    def _analyze_traffic_pattern(self, flow_data: Dict) -> Dict[str, str]:
        """Analyze traffic pattern characteristics."""
        timeseries = flow_data.get('timeseries', {})
        density = timeseries.get('density', [])
        
        if not density:
            return {'pattern': 'unknown', 'description': 'Insufficient data'}
        
        # Calculate statistics
        avg_density = statistics.mean(density)
        std_density = statistics.stdev(density) if len(density) > 1 else 0
        
        # Determine pattern
        if std_density < avg_density * 0.3:
            pattern = 'Steady streaming'
            description = 'Consistent traffic flow suggesting continuous streaming or file transfer'
        elif std_density > avg_density * 0.7:
            pattern = 'Bursty'
            description = 'Irregular bursts suggesting interactive browsing or messaging'
        else:
            pattern = 'Mixed'
            description = 'Mixed traffic pattern with both steady and burst characteristics'
        
        return {
            'pattern': pattern,
            'description': description,
            'avg_density': round(avg_density, 4),
            'variability': round(std_density, 4)
        }
    
    def _detect_burst_activity(self, flow_data: Dict) -> bool:
        """Detect if traffic shows burst activity."""
        timeseries = flow_data.get('timeseries', {})
        density = timeseries.get('density', [])
        
        if len(density) < 2:
            return False
        
        avg = statistics.mean(density)
        return any(d > avg * 2 for d in density)
    
    def _detect_steady_state(self, flow_data: Dict) -> bool:
        """Detect if traffic shows steady state behavior."""
        timeseries = flow_data.get('timeseries', {})
        density = timeseries.get('density', [])
        
        if len(density) < 2:
            return False
        
        std_dev = statistics.stdev(density)
        avg = statistics.mean(density)
        
        return std_dev < avg * 0.3
    
    def _calculate_peak_bandwidth(self, flow_data: Dict) -> float:
        """Calculate peak bandwidth from flow data."""
        timeseries = flow_data.get('timeseries', {})
        total_bytes = timeseries.get('total_bytes', [])
        
        return max(total_bytes) if total_bytes else 0.0
    
    def _find_relay(self, fingerprint: str, relays: List[Dict]) -> Dict:
        """Find relay by fingerprint."""
        for relay in relays:
            if relay.get('fingerprint') == fingerprint:
                return relay
        return {}
    
    def _explain_guard_identification(self, guard_data: Dict) -> str:
        """Explain why this guard was identified."""
        confidence = guard_data.get('confidence', 0)
        metrics = guard_data.get('metrics', {})
        
        reasons = []
        
        if confidence > 0.8:
            reasons.append('High correlation with exit flow timing')
        elif confidence > 0.6:
            reasons.append('Moderate correlation with exit flow')
        else:
            reasons.append('Low correlation - requires further investigation')
        
        if metrics.get('temporal_score', 0) > 0.7:
            reasons.append('Strong temporal pattern match')
        
        if metrics.get('bandwidth_score', 0) > 0.7:
            reasons.append('Bandwidth pattern correlation')
        
        return ' | '.join(reasons) if reasons else 'Statistical correlation analysis'
    
    def _generate_guard_summary(self, top_guards: List[Dict]) -> Dict[str, Any]:
        """Generate summary of guard analysis."""
        if not top_guards:
            return {}
        
        countries = [g['country_name'] for g in top_guards]
        unique_countries = len(set(countries))
        avg_confidence = statistics.mean([g['confidence'] for g in top_guards])
        
        return {
            'total_analyzed': len(top_guards),
            'unique_countries': unique_countries,
            'average_confidence': round(avg_confidence, 2),
            'most_common_country': max(set(countries), key=countries.count) if countries else 'Unknown',
            'top_candidate': top_guards[0] if top_guards else None
        }
    
    def _generate_investigation_recommendation(self, top_guards: List[Dict]) -> Dict[str, Any]:
        """Generate investigation recommendations."""
        if not top_guards:
            return {'priority': 'none', 'recommendation': 'No guards identified'}
        
        best_guard = top_guards[0]
        confidence = best_guard['confidence']
        
        if confidence >= 80:
            priority = 'HIGH'
            recommendation = f"Strong candidate identified. Recommend immediate investigation of {best_guard['ip_address']} ({best_guard['nickname']})"
        elif confidence >= 60:
            priority = 'MEDIUM'
            recommendation = f"Moderate confidence. Cross-reference top {min(3, len(top_guards))} candidates with other intelligence"
        else:
            priority = 'LOW'
            recommendation = "Low confidence matches. Recommend collecting additional traffic samples for correlation"
        
        return {
            'priority': priority,
            'recommendation': recommendation,
            'suggested_actions': self._generate_suggested_actions(confidence, top_guards)
        }
    
    def _generate_suggested_actions(self, confidence: float, guards: List[Dict]) -> List[str]:
        """Generate suggested investigation actions."""
        actions = []
        
        if confidence >= 80:
            actions.append("Initiate formal investigation of top candidate")
            actions.append("Request ISP logs for guard node IP")
            actions.append("Monitor for additional TOR activity from same source")
        elif confidence >= 60:
            actions.append("Cross-reference top 3 candidates with historical data")
            actions.append("Collect additional PCAP samples for improved correlation")
            actions.append("Analyze timing patterns for confirmation")
        else:
            actions.append("Continue monitoring and data collection")
            actions.append("Expand capture window for better correlation")
            actions.append("Consider alternative analysis methods")
        
        return actions
    
    def _generate_geographic_summary(self, geo_data: Dict) -> Dict[str, Any]:
        """Generate geographic analysis summary."""
        guard_locs = geo_data.get('guard_locations', {})
        country_stats = geo_data.get('country_statistics', {})
        
        total_countries = len(set(list(guard_locs.keys()) + list(country_stats.keys())))
        
        return {
            'total_countries_involved': total_countries,
            'guard_countries': len(guard_locs),
            'most_common_guard_country': max(guard_locs.items(), key=lambda x: x[1]['count'])[0] if guard_locs else 'Unknown',
            'geographic_diversity': 'High' if total_countries >= 5 else ('Medium' if total_countries >= 3 else 'Low')
        }
    
    def _assess_geographic_risk(self, geo_data: Dict) -> Dict[str, Any]:
        """Assess geographic risk factors."""
        guard_locs = geo_data.get('guard_locations', {})
        
        risks = []
        mitigations = []
        
        # Check for concentration in specific countries
        if guard_locs:
            max_country = max(guard_locs.items(), key=lambda x: x[1]['count'])
            if max_country[1]['count'] / sum(g['count'] for g in guard_locs.values()) > 0.5:
                risks.append(f"High concentration in {max_country[0]} ({max_country[1]['count']} nodes)")
        
        # Check for hostile jurisdictions
        high_surveillance_countries = ['CN', 'RU', 'IR', 'KP']
        for country_name, data in guard_locs.items():
            if data['country_code'] in high_surveillance_countries:
                risks.append(f"Nodes in high-surveillance jurisdiction: {country_name}")
        
        if len(guard_locs) >= 5:
            mitigations.append("Good geographic diversity reduces jurisdiction risk")
        
        return {
            'risk_level': 'High' if len(risks) > 2 else ('Medium' if len(risks) > 0 else 'Low'),
            'identified_risks': risks,
            'mitigating_factors': mitigations
        }
    
    def _count_border_crossings(self, nodes: List[Dict]) -> int:
        """Count number of international border crossings."""
        if len(nodes) < 2:
            return 0
        
        crossings = 0
        for i in range(len(nodes) - 1):
            if nodes[i].get('country') != nodes[i + 1].get('country'):
                crossings += 1
        
        return crossings
    
    def _get_country_name(self, country_code: str) -> str:
        """Convert country code to full name."""
        # ISO 3166-1 alpha-2 to country name mapping (subset)
        country_map = {
            'US': 'United States', 'GB': 'United Kingdom', 'DE': 'Germany',
            'FR': 'France', 'NL': 'Netherlands', 'SE': 'Sweden', 'CH': 'Switzerland',
            'CA': 'Canada', 'AU': 'Australia', 'JP': 'Japan', 'KR': 'South Korea',
            'SG': 'Singapore', 'HK': 'Hong Kong', 'IN': 'India', 'BR': 'Brazil',
            'RU': 'Russia', 'CN': 'China', 'IT': 'Italy', 'ES': 'Spain',
            'NO': 'Norway', 'DK': 'Denmark', 'FI': 'Finland', 'PL': 'Poland',
            'CZ': 'Czech Republic', 'AT': 'Austria', 'BE': 'Belgium', 'IE': 'Ireland',
            'RO': 'Romania', 'UA': 'Ukraine', 'IL': 'Israel', 'TR': 'Turkey',
            'MX': 'Mexico', 'AR': 'Argentina', 'CL': 'Chile', 'ZA': 'South Africa',
            'NG': 'Nigeria', 'EG': 'Egypt', 'TH': 'Thailand', 'MY': 'Malaysia',
            'ID': 'Indonesia', 'PH': 'Philippines', 'VN': 'Vietnam', 'BD': 'Bangladesh',
            'PK': 'Pakistan', 'IR': 'Iran', 'IQ': 'Iraq', 'SA': 'Saudi Arabia',
            'AE': 'UAE', 'NZ': 'New Zealand', 'GR': 'Greece', 'PT': 'Portugal',
            'HU': 'Hungary', 'BG': 'Bulgaria', 'HR': 'Croatia', 'RS': 'Serbia',
            'SK': 'Slovakia', 'SI': 'Slovenia', 'LT': 'Lithuania', 'LV': 'Latvia',
            'EE': 'Estonia', 'LU': 'Luxembourg', 'CY': 'Cyprus', 'MT': 'Malta',
            'IS': 'Iceland', 'MD': 'Moldova', 'BY': 'Belarus', 'GE': 'Georgia',
            'AM': 'Armenia', 'AZ': 'Azerbaijan', 'KZ': 'Kazakhstan', 'UZ': 'Uzbekistan',
            'KE': 'Kenya', 'GH': 'Ghana', 'TZ': 'Tanzania', 'UG': 'Uganda',
            'CO': 'Colombia', 'VE': 'Venezuela', 'PE': 'Peru', 'EC': 'Ecuador',
            'BO': 'Bolivia', 'PY': 'Paraguay', 'UY': 'Uruguay', 'CR': 'Costa Rica',
            'PA': 'Panama', 'GT': 'Guatemala', 'CU': 'Cuba', 'DO': 'Dominican Republic',
            'PR': 'Puerto Rico', 'JM': 'Jamaica', 'TT': 'Trinidad and Tobago',
            'KP': 'North Korea', 'MM': 'Myanmar', 'KH': 'Cambodia', 'LA': 'Laos',
            'NP': 'Nepal', 'LK': 'Sri Lanka', 'AF': 'Afghanistan', 'KW': 'Kuwait',
            'OM': 'Oman', 'QA': 'Qatar', 'BH': 'Bahrain', 'JO': 'Jordan', 'LB': 'Lebanon',
            'SY': 'Syria', 'YE': 'Yemen', 'DZ': 'Algeria', 'MA': 'Morocco', 'TN': 'Tunisia',
            'LY': 'Libya', 'SD': 'Sudan', 'ET': 'Ethiopia', 'AO': 'Angola', 'MZ': 'Mozambique',
            'ZW': 'Zimbabwe', 'ZM': 'Zambia', 'BW': 'Botswana', 'NA': 'Namibia',
            'MU': 'Mauritius', 'MG': 'Madagascar', 'CI': 'Ivory Coast', 'SN': 'Senegal',
            'CM': 'Cameroon', 'CD': 'DR Congo', 'MW': 'Malawi', 'MZ': 'Mozambique'
        }
        
        return country_map.get(country_code.upper(), country_code.upper() if country_code else 'Unknown')
