"""
Real-time TOR Traffic Capture and Monitoring System
Provides live PCAP capture, filtering, and correlation capabilities
"""
import os
import sys
import time
import threading
import queue
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, AsyncSniffer, wrpcap, TCP, UDP, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available - real-time capture disabled")


class RealTimeTorCapture:
    """Real-time TOR traffic capture and analysis system."""
    
    def __init__(self, interface='eth0', tor_ports=None):
        """
        Initialize real-time capture system.
        
        Args:
            interface: Network interface to capture from
            tor_ports: List of TOR-related ports to monitor
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for real-time capture")
        
        self.interface = interface
        self.tor_ports = tor_ports or [9001, 9050, 9051, 443, 80, 8080]
        self.capture_active = False
        self.sniffer = None
        self.packet_queue = queue.Queue(maxsize=10000)
        self.statistics = {
            'packets_captured': 0,
            'tor_packets': 0,
            'flows_detected': 0,
            'start_time': None,
            'last_packet_time': None
        }
        self.flow_cache = defaultdict(list)
        self.callbacks = []
    
    def is_tor_packet(self, packet):
        """Determine if packet is likely TOR traffic."""
        try:
            if not packet.haslayer(TCP) and not packet.haslayer(UDP):
                return False
            
            sport = packet.sport if hasattr(packet, 'sport') else None
            dport = packet.dport if hasattr(packet, 'dport') else None
            
            return (sport in self.tor_ports) or (dport in self.tor_ports)
        except Exception:
            return False
    
    def packet_handler(self, packet):
        """Handle captured packets."""
        self.statistics['packets_captured'] += 1
        
        if self.is_tor_packet(packet):
            self.statistics['tor_packets'] += 1
            self.statistics['last_packet_time'] = time.time()
            
            # Add to queue for processing
            try:
                self.packet_queue.put_nowait({
                    'timestamp': packet.time if hasattr(packet, 'time') else time.time(),
                    'packet': packet,
                    'size': len(packet)
                })
            except queue.Full:
                # Queue full, drop packet
                pass
            
            # Call registered callbacks
            for callback in self.callbacks:
                try:
                    callback(packet)
                except Exception as e:
                    print(f"Callback error: {e}")
    
    def start_capture(self, duration=None, packet_count=None):
        """
        Start capturing TOR traffic.
        
        Args:
            duration: Maximum capture duration in seconds (None for unlimited)
            packet_count: Maximum packets to capture (None for unlimited)
        
        Returns:
            bool: True if capture started successfully
        """
        if self.capture_active:
            print("⚠️  Capture already active")
            return False
        
        print(f"🔍 Starting TOR traffic capture on {self.interface}")
        print(f"   Monitoring ports: {self.tor_ports}")
        
        self.capture_active = True
        self.statistics['start_time'] = time.time()
        
        try:
            # Start async sniffer
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self.packet_handler,
                store=False,
                count=packet_count
            )
            self.sniffer.start()
            
            print("✅ Capture started successfully")
            
            # If duration specified, schedule stop
            if duration:
                def stop_after_duration():
                    time.sleep(duration)
                    self.stop_capture()
                
                threading.Thread(target=stop_after_duration, daemon=True).start()
            
            return True
        
        except PermissionError:
            print("❌ Permission denied - run with sudo/root privileges")
            self.capture_active = False
            return False
        except Exception as e:
            print(f"❌ Capture failed: {e}")
            self.capture_active = False
            return False
    
    def stop_capture(self):
        """Stop the active capture."""
        if not self.capture_active:
            print("⚠️  No active capture to stop")
            return
        
        print("🛑 Stopping capture...")
        self.capture_active = False
        
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
        
        duration = time.time() - self.statistics['start_time']
        print(f"✅ Capture stopped")
        print(f"   Duration: {duration:.1f}s")
        print(f"   Total packets: {self.statistics['packets_captured']}")
        print(f"   TOR packets: {self.statistics['tor_packets']}")
    
    def save_capture(self, output_path):
        """Save captured packets to PCAP file."""
        if self.packet_queue.empty():
            print("⚠️  No packets to save")
            return False
        
        packets = []
        while not self.packet_queue.empty():
            try:
                pkt_data = self.packet_queue.get_nowait()
                packets.append(pkt_data['packet'])
            except queue.Empty:
                break
        
        if packets:
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            wrpcap(output_path, packets)
            print(f"✅ Saved {len(packets)} packets to {output_path}")
            return True
        
        return False
    
    def register_callback(self, callback):
        """Register a callback function to be called for each TOR packet."""
        self.callbacks.append(callback)
    
    def get_statistics(self):
        """Get current capture statistics."""
        stats = self.statistics.copy()
        if stats['start_time']:
            stats['duration'] = time.time() - stats['start_time']
            if stats['duration'] > 0:
                stats['packets_per_second'] = stats['packets_captured'] / stats['duration']
        return stats
    
    def get_flow_summary(self):
        """Get summary of detected flows."""
        return {
            'total_flows': len(self.flow_cache),
            'flows': dict(self.flow_cache)
        }


class LiveCorrelationEngine:
    """Correlate live traffic with TOR consensus data in real-time."""
    
    def __init__(self, consensus_collector, correlation_engine):
        """
        Initialize live correlation engine.
        
        Args:
            consensus_collector: TorConsensusCollector instance
            correlation_engine: NodeCorrelationEngine instance
        """
        self.consensus_collector = consensus_collector
        self.correlation_engine = correlation_engine
        self.active_flows = {}
        self.guard_detections = []
        self.correlation_updates = []
    
    def process_packet(self, packet):
        """Process a single packet for correlation."""
        try:
            if not packet.haslayer(IP):
                return
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Check if IPs match known TOR relays
            src_relays = self.consensus_collector.get_relay_by_ip(src_ip)
            dst_relays = self.consensus_collector.get_relay_by_ip(dst_ip)
            
            timestamp = packet.time if hasattr(packet, 'time') else time.time()
            
            if src_relays:
                self._record_relay_activity(src_relays[0], timestamp, 'source')
            
            if dst_relays:
                self._record_relay_activity(dst_relays[0], timestamp, 'destination')
        
        except Exception as e:
            print(f"Packet processing error: {e}")
    
    def _record_relay_activity(self, relay, timestamp, direction):
        """Record relay activity for correlation."""
        fingerprint = relay.get('fingerprint')
        
        if fingerprint not in self.active_flows:
            self.active_flows[fingerprint] = {
                'relay': relay,
                'timestamps': [],
                'directions': []
            }
        
        self.active_flows[fingerprint]['timestamps'].append(timestamp)
        self.active_flows[fingerprint]['directions'].append(direction)
        
        # Check if this could be a guard node
        if 'Guard' in relay.get('flags', []):
            self.guard_detections.append({
                'fingerprint': fingerprint,
                'timestamp': timestamp,
                'relay': relay
            })
    
    def get_probable_guards(self, time_window=300):
        """Get list of probable guard nodes based on recent activity."""
        current_time = time.time()
        recent_guards = [
            g for g in self.guard_detections
            if current_time - g['timestamp'] <= time_window
        ]
        
        # Count occurrences
        guard_counts = defaultdict(int)
        for g in recent_guards:
            guard_counts[g['fingerprint']] += 1
        
        # Sort by frequency
        sorted_guards = sorted(
            guard_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [
            {
                'fingerprint': fp,
                'detections': count,
                'confidence': min(1.0, count / 10.0)
            }
            for fp, count in sorted_guards
        ]
    
    def generate_correlation_report(self):
        """Generate real-time correlation report."""
        return {
            'active_flows': len(self.active_flows),
            'guard_detections': len(self.guard_detections),
            'probable_guards': self.get_probable_guards(),
            'timestamp': datetime.now().isoformat()
        }


def capture_tor_traffic_cli():
    """Command-line interface for TOR traffic capture."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Real-time TOR traffic capture and analysis')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface')
    parser.add_argument('-d', '--duration', type=int, help='Capture duration (seconds)')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-o', '--output', default='tor_capture.pcap', help='Output PCAP file')
    parser.add_argument('--ports', nargs='+', type=int, help='TOR ports to monitor')
    
    args = parser.parse_args()
    
    if not SCAPY_AVAILABLE:
        print("❌ Scapy not installed. Install with: pip install scapy")
        return 1
    
    # Create capture instance
    capture = RealTimeTorCapture(
        interface=args.interface,
        tor_ports=args.ports
    )
    
    # Start capture
    if not capture.start_capture(duration=args.duration, packet_count=args.count):
        return 1
    
    # Wait for capture to complete
    try:
        if args.duration:
            time.sleep(args.duration + 1)
        elif args.count:
            while capture.capture_active:
                time.sleep(1)
        else:
            print("Press Ctrl+C to stop capture...")
            while capture.capture_active:
                time.sleep(1)
                # Print statistics every 5 seconds
                if int(time.time()) % 5 == 0:
                    stats = capture.get_statistics()
                    print(f"   Captured: {stats['tor_packets']} TOR packets")
    
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted by user")
    
    finally:
        capture.stop_capture()
        capture.save_capture(args.output)
    
    return 0


if __name__ == '__main__':
    sys.exit(capture_tor_traffic_cli())
