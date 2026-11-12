#!/usr/bin/env python3
"""
udp_probe.py - constant-bit-rate UDP probe with per-packet sequence numbers and
send timestamps, used to measure loss, outage, reordering, duplicates and
one-way delay during a spanning-tree reconfiguration.

All Mininet hosts share the kernel clock of the VM, so the one-way delay
(receive time - send time) is meaningful without clock synchronisation.

Sender:   udp_probe.py send  --dst 10.0.0.3 --rate 10 --size 1400 --duration 60 --out tx.json
Receiver: udp_probe.py recv  --duration 60 --out rx.json [--timeline rx_timeline.csv]

Packet payload: !IdI = seq (uint32), t_send (double, seconds), run_id (uint32),
padded with zeros to --size bytes of UDP payload.

Arrival times are the kernel receive timestamps of the socket (SO_TIMESTAMPNS), not the
time at which Python reads the packet: if the receiver process is descheduled (a pause of
the virtual machine), the packets wait in the socket buffer but keep their true arrival
time, so the pause is not counted as delay or outage.

--disruption writes, per 10-ms bin of SEND time, how many packets arrived on time, late
(one-way delay above --late-ms) or never. A pause of the sender leaves empty bins, which
are neither on time nor disrupted, so only the network can create a disruption.
"""
import argparse
import json
import socket
import struct
import sys
import time

HDR = struct.Struct('!IdI')
PORT = 5001
SO_TIMESTAMPNS = getattr(socket, 'SO_TIMESTAMPNS', 35)     # Linux value
TIMESPEC = struct.Struct('qq')                              # struct timespec (64-bit)


def sender(a):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    pad = b'\x00' * max(0, a.size - HDR.size)
    pps = a.rate * 1e6 / (8.0 * a.size)          # packets per second (UDP payload rate)
    gap = 1.0 / pps
    n_total = int(round(pps * a.duration))
    t0 = time.perf_counter()
    wall0 = time.time()
    sent = 0
    errors = 0
    while sent < n_total:
        target = t0 + sent * gap
        now = time.perf_counter()
        if now < target:
            dt = target - now
            if dt > 0.0005:
                time.sleep(dt - 0.0002)
            continue
        # send (catch up if late, at most 64 packets per burst)
        burst = 0
        while sent < n_total and time.perf_counter() >= t0 + sent * gap and burst < 64:
            ts = wall0 + (time.perf_counter() - t0)
            try:
                sock.sendto(HDR.pack(sent, ts, a.run_id) + pad, (a.dst, a.port))
            except OSError:
                errors += 1          # e.g. ENOBUFS; the packet counts as sent and lost
            sent += 1
            burst += 1
    elapsed = time.perf_counter() - t0
    res = {'role': 'sender', 'sent': sent, 'send_errors': errors, 'rate_mbps': a.rate,
           'size': a.size, 'pps': pps, 'gap_s': gap, 'duration_s': elapsed, 't_start': wall0}
    with open(a.out, 'w') as f:
        json.dump(res, f)


def receiver(a):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind(('0.0.0.0', a.port))
    sock.settimeout(0.2)
    kernel_ts = True
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
    except OSError:
        kernel_ts = False
    n_kernel = 0
    seqs = []
    trecv = []
    tsend = []
    t_first = None
    deadline = time.time() + a.duration + a.wait
    last_rx = None
    while True:
        now = time.time()
        if now > deadline:
            break
        if last_rx is not None and now - last_rx > a.idle and now > (t_first or now) + a.duration:
            break
        try:
            data, anc, _flags, _addr = sock.recvmsg(65535, socket.CMSG_SPACE(TIMESPEC.size))
        except socket.timeout:
            continue
        t = time.time()
        for level, ctype, cdata in anc:
            if level == socket.SOL_SOCKET and ctype == SO_TIMESTAMPNS and len(cdata) >= TIMESPEC.size:
                sec, nsec = TIMESPEC.unpack_from(cdata)
                t = sec + nsec * 1e-9
                n_kernel += 1
                break
        if len(data) < HDR.size:
            continue
        seq, ts, run_id = HDR.unpack_from(data)
        if run_id != a.run_id:
            continue
        if t_first is None:
            t_first = t
            deadline = t + a.duration + a.wait
        last_rx = t
        seqs.append(seq)
        trecv.append(t)
        tsend.append(ts)

    res = {'role': 'receiver', 'received': len(seqs)}
    if seqs:
        seen = set()
        dup = 0
        reorder = 0
        max_seq = -1
        for s in seqs:
            if s in seen:
                dup += 1
                continue
            seen.add(s)
            if s < max_seq:
                reorder += 1
            else:
                max_seq = s
        owd = [r - s for r, s in zip(trecv, tsend)]
        gaps = [trecv[i + 1] - trecv[i] for i in range(len(trecv) - 1)]
        imax = max(range(len(gaps)), key=gaps.__getitem__) if gaps else 0
        # longest run of consecutive missing sequence numbers
        uniq = sorted(seen)
        max_hole = 0
        for i in range(len(uniq) - 1):
            max_hole = max(max_hole, uniq[i + 1] - uniq[i] - 1)
        owd_sorted = sorted(owd)
        res.update({
            'unique': len(seen), 'duplicates': dup, 'reordered': reorder,
            'max_seq': max(seen), 'max_hole_pkts': max_hole,
            'max_gap_s': max(gaps) if gaps else 0.0,
            'max_gap_at_s': (trecv[imax] - trecv[0]) if gaps else 0.0,
            'owd_avg_ms': 1000 * sum(owd) / len(owd),
            'owd_p50_ms': 1000 * owd_sorted[len(owd) // 2],
            'owd_p99_ms': 1000 * owd_sorted[min(len(owd) - 1, int(0.99 * len(owd)))],
            'owd_max_ms': 1000 * owd_sorted[-1],
            't_first': trecv[0], 't_last': trecv[-1],
            'kernel_timestamps': n_kernel, 'first_send': min(tsend),
        })
        if a.disruption:
            write_disruption(a.disruption, seqs, tsend, owd, a.late_ms / 1000.0)
        if a.timeline:
            # received packets per 100 ms bin, relative to the first packet
            bins = {}
            for t in trecv:
                k = int((t - trecv[0]) / 0.1)
                bins[k] = bins.get(k, 0) + 1
            with open(a.timeline, 'w') as f:
                f.write('t_s,pkts\n')
                for k in range(0, max(bins) + 1):
                    f.write('%.1f,%d\n' % (k * 0.1, bins.get(k, 0)))
    with open(a.out, 'w') as f:
        json.dump(res, f)


def write_disruption(path, seqs, tsend, owd, late_s, bin_s=0.01):
    """Per 10-ms bin of send time: packets on time, late, lost. The send time of a lost
    packet is interpolated between the closest received sequence numbers."""
    first = {}
    for s, ts, d in zip(seqs, tsend, owd):
        if s not in first:
            first[s] = (ts, d)
    if not first:
        return
    known = sorted(first)
    t0 = first[known[0]][0]
    bins = {}

    def add(ts, kind):
        k = int((ts - t0) / bin_s)
        b = bins.setdefault(k, [0, 0, 0])
        b[kind] += 1

    for s in known:
        ts, d = first[s]
        add(ts, 1 if d > late_s else 0)
    for i in range(len(known) - 1):
        a_, b_ = known[i], known[i + 1]
        if b_ - a_ > 1:
            ta, tb = first[a_][0], first[b_][0]
            for s in range(a_ + 1, b_):
                add(ta + (tb - ta) * (s - a_) / (b_ - a_), 2)
    with open(path, 'w') as f:
        f.write('t_s,ontime,late,lost\n')
        for k in range(0, max(bins) + 1):
            o, l, x = bins.get(k, (0, 0, 0))
            f.write('%.2f,%d,%d,%d\n' % (k * bin_s, o, l, x))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='role', required=True)
    s = sub.add_parser('send')
    s.add_argument('--dst', required=True)
    s.add_argument('--port', type=int, default=PORT)
    s.add_argument('--rate', type=float, required=True, help='Mbit/s of UDP payload')
    s.add_argument('--size', type=int, default=1400, help='UDP payload bytes')
    s.add_argument('--duration', type=float, default=60)
    s.add_argument('--run-id', type=int, default=0)
    s.add_argument('--out', required=True)
    r = sub.add_parser('recv')
    r.add_argument('--port', type=int, default=PORT)
    r.add_argument('--duration', type=float, default=60)
    r.add_argument('--wait', type=float, default=10, help='extra seconds to wait')
    r.add_argument('--idle', type=float, default=3, help='stop after this idle time')
    r.add_argument('--run-id', type=int, default=0)
    r.add_argument('--out', required=True)
    r.add_argument('--timeline')
    r.add_argument('--disruption', help='per-10-ms disruption file (by send time)')
    r.add_argument('--late-ms', type=float, default=10.0,
                   help='one-way delay above which a packet counts as late')
    a = p.parse_args()
    if a.role == 'send':
        sender(a)
    else:
        receiver(a)


if __name__ == '__main__':
    sys.exit(main())
