"""Path reconstruction helper.

Infer probable guard->middle->exit paths using consensus metadata.
"""

def infer_paths(guard_candidates, exit_relay, relays_meta, top_n=5):
    guards = [g for g, _ in guard_candidates][:top_n]
    middles = [relay for relay in relays_meta if 'Exit' not in relay.get('flags', [])]
    middles = sorted(middles, key=lambda x: (x.get('bandwidth') or 0), reverse=True)[:top_n]

    paths = []
    for guard_id in guards:
        guard_meta = next((r for r in relays_meta if r.get('fingerprint') == guard_id), None)
        if not guard_meta:
            continue
        for middle in middles:
            if middle.get('fingerprint') == guard_meta.get('fingerprint'):
                continue
            if middle.get('ip') == guard_meta.get('ip'):
                continue
            guard_score = next((s for (fid, s) in guard_candidates if fid == guard_id), 0.0)
            mid_bw = middle.get('bandwidth') or 0
            mid_conf = min(1.0, mid_bw / 1e6) if mid_bw else 0.1
            confidence = guard_score * (0.5 + 0.5 * mid_conf)
            paths.append({'path': [guard_meta, middle, exit_relay], 'confidence': confidence})
    return sorted(paths, key=lambda entry: entry['confidence'], reverse=True)
