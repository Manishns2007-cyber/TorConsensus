"""FTDC extractor: PCAP d time-density signatures.

For very large PCAPs, reading and processing every packet can make the
background analysis thread appear "stuck" from the web UI's perspective.
To keep the dashboard responsive, we cap the maximum number of packets
loaded per capture. The cap is configurable via the ``FTDC_MAX_PACKETS``
environment variable.
"""
import os
import numpy as np
from collections import defaultdict

try:
    from scapy.all import rdpcap
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


MAX_PACKETS = int(os.environ.get("FTDC_MAX_PACKETS", "50000"))


def _flow_key(pkt):
    try:
        proto = pkt.payload.name
        src = pkt[0][1].src
        dst = pkt[0][1].dst
        sport = getattr(pkt, 'sport', None)
        dport = getattr(pkt, 'dport', None)
        return (src, dst, sport, dport, proto)
    except Exception:
        return None


class FTDCExtractor:
    def __init__(self, window_ms=50, step_ms=None):
        self.window_ms = window_ms
        self.step_ms = step_ms or max(1, window_ms // 2)

    def read_pcap(self, path):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required to parse PCAP data.")
        # Limit packets to avoid huge captures making the analysis thread
        # (and therefore the browser tab) feel frozen for several minutes.
        try:
            packets = rdpcap(path, count=MAX_PACKETS)
        except TypeError:
            # Older scapy versions: no ``count`` kwarg; slice after load.
            packets = rdpcap(path)[:MAX_PACKETS]
        return packets

    def _build_flows(self, packets):
        flows = defaultdict(list)
        for pkt in packets:
            if not hasattr(pkt, 'time'):
                continue
            key = _flow_key(pkt)
            if key is None:
                continue
            size = len(pkt)
            flows[key].append({'time': pkt.time, 'size': size, 'src': key[0], 'dst': key[1]})
        for key in list(flows.keys()):
            flows[key] = sorted(flows[key], key=lambda entry: entry['time'])
        return flows

    def _sliding_windows(self, times, window_s, step_s):
        start = times[0]
        end = times[-1]
        windows = []
        t = start
        while t <= end:
            t_end = t + window_s
            idxs = np.where((times >= t) & (times < t_end))[0]
            windows.append(idxs)
            t += step_s
        return windows

    def extract_signatures(self, pcap_path):
        packets = self.read_pcap(pcap_path)
        flows = self._build_flows(packets)
        signatures = {}
        window_s = self.window_ms / 1000.0
        step_s = self.step_ms / 1000.0
        for key, packets in flows.items():
            times = np.array([p['time'] for p in packets])
            sizes = np.array([p['size'] for p in packets])
            first_src = packets[0]['src']
            dirs = np.array([1 if p['src'] == first_src else -1 for p in packets])

            windows = []
            if len(times) > 0:
                windows = self._sliding_windows(times, window_s, step_s)

            pkt_count = []
            total_bytes = []
            dir_changes = []
            burst_intensity = []
            for idxs in windows:
                if len(idxs) == 0:
                    pkt_count.append(0)
                    total_bytes.append(0)
                    dir_changes.append(0)
                    burst_intensity.append(0)
                    continue
                w_dirs = dirs[idxs]
                w_sizes = sizes[idxs]
                pkt_count.append(len(idxs))
                total_bytes.append(int(w_sizes.sum()))
                dc = int(np.sum(np.abs(np.diff(w_dirs)) > 0))
                dir_changes.append(dc)
                max_run = 1
                cur_run = 1
                for a, b in zip(w_dirs[:-1], w_dirs[1:]):
                    if a == b:
                        cur_run += 1
                        max_run = max(max_run, cur_run)
                    else:
                        cur_run = 1
                burst_intensity.append(max_run / len(idxs))

            pkt_count_arr = np.array(pkt_count, dtype=float)
            density = pkt_count_arr / pkt_count_arr.sum() if pkt_count_arr.sum() > 0 else pkt_count_arr

            signatures[str(key)] = {
                'flow_key': key,
                'timeseries': {
                    'packet_count': pkt_count_arr.tolist(),
                    'total_bytes': np.array(total_bytes).tolist(),
                    'dir_changes': np.array(dir_changes).tolist(),
                    'burst_intensity': np.array(burst_intensity).tolist(),
                    'density': density.tolist()
                }
            }
        return signatures
