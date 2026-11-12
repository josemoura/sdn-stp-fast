"""Failure-window metrics from the raw files of run_experiments.py (used by analyze_results.py)."""
import json, os, re

def ping_window(path, interval, t_fail, n_sent):
    """Interruption at the failure for one ping run: the longest gap between consecutive
    replies that starts within [t_f - interval - 0.2, t_f + 0.5] s, minus the interval,
    or the longest run of lost probes, whichever is longer. Also the maximum RTT and the
    number of delayed probes (RTT > 10 ms) among the probes sent in [t_f - 0.2, t_f + 3]."""
    st, seqrtt = [], {}
    with open(path) as f:
        for line in f:
            m = re.search(r'^\[(\d+\.\d+)\].*icmp_seq=(\d+).*time=([\d.]+) ms', line)
            if m:
                t, s, r = float(m.group(1)), int(m.group(2)), float(m.group(3))
                if s not in seqrtt:
                    seqrtt[s] = (t, r)
                    st.append(t)
    if len(st) < 2:
        return None
    st.sort()
    # first send time: arrival of the reply of seq 1 minus its RTT (ping starts at popen)
    s1 = min(seqrtt)
    t0 = seqrtt[s1][0] - seqrtt[s1][1] / 1000.0 - (s1 - 1) * interval
    tf = t0 + t_fail
    gaps = [(st[i + 1] - st[i], st[i]) for i in range(len(st) - 1)
            if tf - interval - 0.2 <= st[i] <= tf + 0.5]
    g = max([x[0] for x in gaps] or [0.0]) - interval
    longest = run = 0
    for k in range(1, n_sent + 1):
        run = run + 1 if k not in seqrtt else 0
        longest = max(longest, run)
    # probes sent in the window; send time of seq k = arrival - rtt
    win = [r for (t, r) in seqrtt.values() if tf - 0.2 <= t - r / 1000.0 <= tf + 3.0]
    return {'int_fail_s': max(0.0, g, longest * interval),
            'rtt_max_win_ms': max(win) if win else 0.0,
            'delayed_win': sum(1 for r in win if r > 10.0)}


def disruption_window(dis_path, tx, rx, t_fail, start_win=(-0.1, 1.0)):
    """Interruption at the failure from the per-10-ms disruption file of udp_probe.py
    (bins of SEND time, kernel receive timestamps): the longest run of bins in which more
    than half of the packets sent were lost or late, starting within start_win of the
    failure. Bins without packets (sender pauses) neither extend nor break a run."""
    rows = []
    with open(dis_path) as f:
        next(f)
        for line in f:
            t, o, l, x = line.strip().split(',')
            rows.append((float(t), int(o), int(l), int(x)))
    if not rows:
        return None
    width = rows[1][0] - rows[0][0] if len(rows) > 1 else 0.01
    tf = t_fail - (rx.get('first_send', tx['t_start']) - tx['t_start'])
    best = run = 0
    start = None
    late = lost = 0
    for t, o, l, x in rows + [(1e9, 1, 0, 0)]:
        n = o + l + x
        if n == 0:
            continue
        if (l + x) > 0.5 * n:
            if run == 0:
                start = t
            run += 1
        else:
            if run and tf + start_win[0] <= start <= tf + start_win[1]:
                best = max(best, run)
            run = 0
        if tf - 0.1 <= t <= tf + 3.0:
            late += l
            lost += x
    return {'int_fail_s': best * width, 'late_fail': late, 'lost_fail': lost}


def udp_window(tx_path, rx_path, tl_path, t_fail):
    """Interruption at the failure for one UDP run: the longer of the longest run of
    consecutive missing datagrams and the longest run of 100-ms bins with fewer than half
    the nominal datagrams that starts within [t_f - 0.5, t_f + 1.0] s (t_f relative to the
    first received datagram)."""
    if not (os.path.exists(tx_path) and os.path.exists(rx_path) and os.path.exists(tl_path)):
        return None
    t = json.load(open(tx_path))
    r = json.load(open(rx_path))
    if 't_first' not in r:
        return {'int_fail_s': float('nan')}
    dis = tl_path.replace('_timeline.csv', '_disruption.csv')
    if os.path.exists(dis):
        res = disruption_window(dis, t, r, t_fail)
        if res is not None:
            return res
    tf = t_fail - (r['t_first'] - t['t_start'])
    nom = t['pps'] * 0.1
    rows = []
    with open(tl_path) as f:
        next(f)
        for line in f:
            a, b = line.strip().split(',')
            rows.append((float(a), int(b)))
    best = run = 0
    start = None
    for ts, n in rows + [(1e9, 10 ** 9)]:
        if n < 0.5 * nom:
            if run == 0:
                start = ts
            run += 1
        else:
            if run and tf - 0.5 <= start <= tf + 1.0:
                best = max(best, run)
            run = 0
    hole = r.get('max_hole_pkts', 0) * t['gap_s']
    return {'int_fail_s': max(best * 0.1, hole)}
