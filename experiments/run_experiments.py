#!/usr/bin/env python3
"""
run_experiments.py - automated comparison of the SDN-based spanning tree
(DynSTPProactive and its variants, Ryu + OpenFlow 1.3) with the distributed
IEEE 802.1D STP and the IEEE 802.1w/802.1Q RSTP of Open vSwitch.

Topologies (--topo); one host per switch, port 1 of every switch is the host port:
  triangle  3 switches, links s1-s2, s3-s1, s2-s3 (code_L18)
  ring6     6 switches in a ring, s1-s2-...-s6-s1
  mesh6     6 switches, full mesh (15 links)
  ring7     7 switches in a ring, s1-s2-...-s7-s1

Traffic pair and failed link (--pair):
  fixed     h1 -> h3, failure of the inter-switch link of s1 that carries it
            (the original triangle experiment; default for --topo triangle)
  longest   before every run, the path between every pair of hosts is measured
            on the active tree (OVS port counters during a short ping); the pair
            with the longest path is used, and the link in the middle of that path
            is put down, so that the switch that sees the failure lies between
            the two hosts (default for ring6 and mesh6). The choice is checked
            again at the failure instant with the counters of the test traffic.

Failure (--failure): 'link' puts the link down; 'switch' puts every inter-switch link
of the middle switch of the traffic path down at once (needs --pair longest; results go
to results/<topo>_switch/). In mesh6 with RSTP the middle switch is the root bridge.

In every run the failure is injected after t_fail seconds (Mininet
`link sX sY down`: both interfaces go down, both switches lose carrier); the link
is restored after the run and the network re-converges before the next run.

Two traffic types:
  * ping  - ICMP echo, one probe every <interval> s   (--intervals)
  * udp   - constant-bit-rate UDP probe (udp_probe.py) (--rates, Mbit/s)

Results (appended, one row per run): <out>/ping_runs.csv, <out>/udp_runs.csv and
raw logs in <out>/raw/. <out> is results/ for the triangle and results/<topo>/
for the other topologies, unless --out is given.

Usage (inside the course VM, from this folder):
  sudo python3 run_experiments.py                                  # triangle, as before
  sudo python3 run_experiments.py --topo ring6 --modes sdnfast2 rstp stp sdn
  sudo python3 run_experiments.py --topo mesh6 --tests udp --rates 10 50 --reps 3
  sudo python3 run_experiments.py --topo triangle --pair longest --out ../results/triangle_longest

Then:  python3 analyze_results.py --results <out>
"""
import argparse
import csv
import json
import os
import re
import shlex
import signal
import socket
import subprocess
import sys
import time

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.log import setLogLevel, info
from mininet.clean import cleanup

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, 'udp_probe.py')
TOPOS = {
    'triangle': (3, [(1, 2), (3, 1), (2, 3)]),
    'ring6': (6, [(i, i % 6 + 1) for i in range(1, 7)]),
    'mesh6': (6, [(i, j) for i in range(1, 7) for j in range(i + 1, 7)]),
    'ring7': (7, [(i, i % 7 + 1) for i in range(1, 8)]),
}
# Predefined controlled scenarios (--scenario); every value can be overridden.
SCENARIOS = {
    # ring6, s1 root and s4 backup root (3 hops away). Before the failure the tree has
    # the branches s1-s6-s5-s4 and s1-s2-s3 (s3-s4 blocked); s1 fails, and the new tree
    # has the branches s4-s5-s6 and s4-s3-s2. Probes always from h2 to h6.
    'ring6-root': dict(topo='ring6', failure='switch', fail_switch='s1', src=2, dst=6,
                       bridge_priorities='s1=4096,s4=8192,s5=12288',
                       sdn_link_costs='3-4:2', expect_path='s2-s1-s6'),
}
SDN_MODES = ('sdn', 'sdnfast', 'sdnfast2', 'sdnfast3', 'sdnfast4', 'sdnfast5')


def host_ip(i):
    return '10.0.0.%d' % i
DELAY_THRESHOLD_MS = 10.0    # a reply with RTT above this value counts as "delayed"

PING_FIELDS = ['mode', 'interval_s', 'rep', 'topo', 'src', 'dst', 'path', 'failed_link', 'sent', 'received', 'lost',
               'loss_pct', 'delayed', 'rtt_avg_ms', 'rtt_p50_ms', 'rtt_max_ms',
               'outage_s', 'lost_run_s', 'buffered_pkts', 't_fail_s', 'timestamp']
UDP_FIELDS = ['mode', 'rate_mbps', 'rep', 'topo', 'src', 'dst', 'path', 'failed_link', 'sent', 'received', 'lost',
              'loss_pct', 'duplicates', 'reordered', 'outage_s', 'max_hole_pkts',
              'owd_avg_ms', 'owd_p99_ms', 'owd_max_ms', 'buffered_pkts', 't_fail_s',
              'timestamp']


# --------------------------------------------------------------------------- helpers
def sh(cmd):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, universal_newlines=True).stdout


def append_row(path, fields, row):
    """Append one row; an existing file keeps its header (older files lack the new
    columns topo/src/dst/path, which are then simply not written)."""
    new = not os.path.exists(path) or os.path.getsize(path) == 0
    if not new:
        with open(path) as f:
            fields = next(csv.reader(f))
    with open(path, 'a', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        if new:
            w.writeheader()
        w.writerow(row)


def done_keys(path, xkey):
    keys = set()
    if os.path.exists(path):
        with open(path) as f:
            for r in csv.DictReader(f):
                keys.add((r['mode'], float(r[xkey]), int(r['rep'])))
    return keys


def tx_packets(intf):
    out = sh('ovs-vsctl get Interface %s statistics:tx_packets' % intf).strip()
    try:
        return int(out)
    except ValueError:
        return 0


def all_tx_packets():
    """{interface name: tx_packets} of every switch port, read live from the datapath with
    'ovs-ofctl dump-ports' (the statistics column of the OVS database is only refreshed
    every 5 s, too slowly for a short probe). Mininet numbers the OpenFlow port of
    interface sK-ethN as N."""
    res = {}
    names = sh('ovs-vsctl list-br').split()
    for br in names:
        out = sh('ovs-ofctl -O OpenFlow13 dump-ports %s' % br)
        if 'port' not in out:
            out = sh('ovs-ofctl dump-ports %s' % br)
        port = None
        for line in out.splitlines():
            m = re.match(r'\s*port\s+"?([^:"]+)"?:', line)
            if m:
                port = m.group(1).strip()
            m = re.search(r'tx pkts=(\d+)', line)
            if m and port is not None:
                key = '%s-eth%s' % (br, port) if port.isdigit() else port
                res[key] = int(m.group(1))
                port = None
    return res


# --------------------------------------------------------------------------- topology
def build_net(mode, topo, priorities=None):
    """mode: 'sdn' / 'sdnfast' / 'sdnfast2' (Ryu controller), 'stp' (802.1D) or 'rstp'.
    Returns the network; net.sw_links lists the inter-switch links as (a, b, intf_a, intf_b)."""
    n, links = TOPOS[topo]
    if mode in SDN_MODES:
        net = Mininet(controller=RemoteController, switch=OVSKernelSwitch,
                      autoSetMacs=True, build=False)
        c0 = net.addController('c0', ip='127.0.0.1', port=6633)
        sw_opts = {'protocols': 'OpenFlow13'}
    else:
        net = Mininet(controller=None, switch=OVSKernelSwitch,
                      autoSetMacs=True, build=False)
        c0 = None
        sw_opts = {'failMode': 'standalone', 'stp': mode == 'stp'}
    s = {i: net.addSwitch('s%d' % i, **sw_opts) for i in range(1, n + 1)}
    h = {i: net.addHost('h%d' % i, ip=host_ip(i) + '/24') for i in range(1, n + 1)}
    for i in range(1, n + 1):
        net.addLink(s[i], h[i])              # added first: port 1 = host port
    for a_, b_ in links:
        net.addLink(s[a_], s[b_])
    net.build()
    if c0:
        c0.start()
        for sw in s.values():
            sw.start([c0])
    else:
        for sw in s.values():
            sw.start([])
        if mode == 'rstp':
            for sw in s.values():
                sw.cmd('ovs-vsctl set Bridge %s stp_enable=false rstp_enable=true' % sw.name)
        for name, prio in (priorities or {}).items():
            # lower value = preferred root; RSTP needs multiples of 4096
            sh('ovs-vsctl set Bridge %s other_config:stp-priority=%d other_config:rstp-priority=%d'
               % (name, prio, prio))
    net.n_hosts = n
    net.sw_links = []
    for a_, b_ in links:
        lk = net.linksBetween(s[a_], s[b_])[0]
        ia, ib = (lk.intf1, lk.intf2) if lk.intf1.node == s[a_] else (lk.intf2, lk.intf1)
        net.sw_links.append(('s%d' % a_, 's%d' % b_, ia.name, ib.name))
    return net


def flows_signature(net):
    """Proactive/broadcast rules of all switches, without counters (SDN mode)."""
    sig = []
    for sw in net.switches:
        name = sw.name
        out = sh('ovs-ofctl -O OpenFlow13 dump-flows %s' % name)
        for line in out.splitlines():
            if 'priority=5' in line or 'priority=10' in line:
                line = re.sub(r'(cookie|duration|n_packets|n_bytes|idle_age|hard_age)=[^,\s]+,?\s*', '', line)
                sig.append(name + ':' + line.strip())
    return sorted(sig)


def ping_ok(net, src, dst_ip, count=3):
    out = net.get(src).cmd('ping -c %d -i 0.2 -W 1 %s' % (count, dst_ip))
    m = re.search(r'(\d+) received', out)
    return bool(m) and int(m.group(1)) == count


def kick_hosts(net):
    """Bounce the host interfaces so that they send IPv6 RS/NA again
    (DynSTPProactive learns hosts from these ICMPv6 messages)."""
    for i in range(1, net.n_hosts + 1):
        h = net.get('h%d' % i)
        h.cmd('ip link set h%d-eth0 down; ip link set h%d-eth0 up' % (i, i))


def wait_converged(net, mode, min_wait, timeout=180):
    """Wait until all host pairs communicate and (SDN) the proactive rules are stable."""
    t0 = time.time()
    time.sleep(min_wait)
    last_sig, stable, kicked = None, 0, False
    while time.time() - t0 < timeout:
        n = net.n_hosts
        pairs = [(1, j) for j in range(2, n + 1)] + [(i, i + 1) for i in range(2, n)]
        ok = all(ping_ok(net, 'h%d' % i, host_ip(j), count=2) for i, j in pairs)
        if mode in SDN_MODES:
            sig = flows_signature(net)
            have_proactive = any('priority=5' in x for x in sig)
            if not have_proactive and not kicked and time.time() - t0 > min_wait + 8:
                info('*** no proactive rules yet: re-triggering host discovery\n')
                kick_hosts(net)
                kicked = True
            stable = stable + 1 if (ok and have_proactive and sig == last_sig) else 0
            last_sig = sig
            if stable >= 3:
                return time.time() - t0
        else:
            stable = stable + 1 if ok else 0
            if stable >= 3:
                return time.time() - t0
        time.sleep(1)
    raise RuntimeError('network did not converge within %d s (mode %s)' % (timeout, mode))


def link_deltas(net, before, after):
    """Packets sent over each inter-switch link (both directions) between two snapshots."""
    return {(a_, b_): (after.get(ia, 0) - before.get(ia, 0)) + (after.get(ib, 0) - before.get(ib, 0))
            for a_, b_, ia, ib in net.sw_links}


def order_path(links, s_src, s_dst):
    """Order a set of links into a path s_src -> ... -> s_dst; None if they do not form one."""
    adj = {}
    for a_, b_ in links:
        adj.setdefault(a_, []).append(b_)
        adj.setdefault(b_, []).append(a_)
    if s_src == s_dst:
        return [s_src] if not links else None
    if s_src not in adj or s_dst not in adj:
        return None
    path, prev, cur = [s_src], None, s_src
    while cur != s_dst:
        nxt = [x for x in adj[cur] if x != prev]
        if len(nxt) != 1:
            return None
        prev, cur = cur, nxt[0]
        path.append(cur)
    return path if len(path) == len(links) + 1 else None


def middle_link(path):
    """Link to fail on a switch path [s_a, ..., s_b]: the middle link, or for an even number
    of links the one that ends at the middle switch (so the middle switch sees the failure)."""
    k = len(path) - 1
    i = (k - 1) // 2
    return (path[i], path[i + 1])


def probe_path(net, i, j, count=30):
    """Switch path used by h_i <-> h_j, measured with a short ping and the port counters."""
    before = all_tx_packets()
    out = net.get('h%d' % i).cmd('ping -c %d -i 0.01 -W 1 %s' % (count, host_ip(j)))
    after = all_tx_packets()
    m = re.search(r'(\d+) received', out)
    if not m or int(m.group(1)) < count // 2:
        return None
    d = link_deltas(net, before, after)
    used = [l for l, v in d.items() if v >= int(m.group(1))]   # request + reply per probe
    return order_path(used, 's%d' % i, 's%d' % j)


class Choice:
    """Traffic pair, path and link (or switch) to fail for one run."""
    def __init__(self, src, dst, path, link, switch=None):
        self.src, self.dst, self.path, self.link, self.switch = src, dst, path, link, switch

    def failed(self):
        return 'switch:%s' % self.switch if self.switch else '%s-%s' % self.link

    def path_str(self):
        return '-'.join(self.path) if self.path else ''


def choose(net, a):
    """Pick the traffic pair and the link to fail before a run (see --pair)."""
    if a.src:
        p = None
        for attempt in range(3):
            p = probe_path(net, a.src, a.dst)
            if p:
                break
            time.sleep(2)
        if a.expect_path and (p is None or '-'.join(p) != a.expect_path):
            info('    WARNING: h%d->h%d path is %s, expected %s\n'
                 % (a.src, a.dst, '-'.join(p) if p else 'unknown', a.expect_path))
        if a.fail_switch and p and a.fail_switch not in p:
            info('    WARNING: the failed switch %s is not on the traffic path\n' % a.fail_switch)
        link = middle_link(p) if p and len(p) >= 2 else ('s%d' % a.src, 's%d' % a.dst)
        return Choice(a.src, a.dst, p, link, a.fail_switch)
    if a.pair == 'fixed':
        p = probe_path(net, 1, 3)
        if p and len(p) >= 2:
            return Choice(1, 3, p, (p[0], p[1]))
        # fallback: the original s1-port comparison
        b0 = all_tx_packets()
        net.get('h1').cmd('ping -c 20 -i 0.05 -W 1 %s' % host_ip(3))
        b1 = all_tx_packets()
        delta = {q: b1.get('s1-eth%d' % q, 0) - b0.get('s1-eth%d' % q, 0) for q in (2, 3)}
        link = ('s1', 's2') if delta[2] > delta[3] else ('s1', 's3')
        return Choice(1, 3, None, link)
    n = net.n_hosts
    for attempt in range(3):
        best = None
        for i in range(1, n + 1):
            for j in range(i + 1, n + 1):
                p = probe_path(net, i, j)
                if p and len(p) >= 2 and (best is None or len(p) > len(best.path)):
                    best = Choice(i, j, p, middle_link(p),
                                  p[len(p) // 2] if a.failure == 'switch' and len(p) >= 3 else None)
        if best is not None:
            return best
        info('    could not measure the host paths (attempt %d); retrying\n' % (attempt + 1))
        time.sleep(2)
    raise RuntimeError('could not measure any host-to-host path; check that '
                       '"ovs-ofctl -O OpenFlow13 dump-ports s1" works')


def live_check(net, before, ch, tag, a):
    """At the failure instant, re-derive the path of the test traffic from the counters
    accumulated since it started; if the traffic moved to another path after the probe,
    fail the corresponding link of the new path. Falls back to the probe."""
    d = link_deltas(net, before, all_tx_packets())
    top = max(d.values()) if d else 0
    if top < 20:                      # too little traffic to decide (e.g. ping -i 1)
        return ch
    used = [l for l, v in d.items() if v >= 0.5 * top]
    p = order_path(used, 's%d' % ch.src, 's%d' % ch.dst)
    if not p or len(p) < 2:
        return ch
    link = middle_link(p) if a.pair == 'longest' else (p[0], p[1])
    sw = a.fail_switch or (p[len(p) // 2] if a.failure == 'switch' and len(p) >= 3 else None)
    new = Choice(ch.src, ch.dst, p, link, sw)
    if p != ch.path:
        info('    NOTE %s: traffic path is %s, not %s as probed; failing %s\n'
             % (tag, '-'.join(p), ch.path_str(), new.failed()))
    return new


def set_failure(net, ch, state):
    """Put the chosen link, or every inter-switch link of the chosen switch, down or up.
    For a switch, all interfaces are changed with a single shell command, so that the
    links fail at practically the same instant."""
    if not ch.switch:
        net.configLinkStatus(ch.link[0], ch.link[1], state)
        return
    intfs = [x for a_, b_, ia, ib in net.sw_links if ch.switch in (a_, b_) for x in (ia, ib)]
    # one 'ip -batch' process changes every interface within a few ms (separate 'ip'
    # commands took ~50 ms each in the VM, so the failure was spread over ~100 ms)
    batch = os.path.join('/tmp', 'fail_%s_%s.ip' % (ch.switch, state))
    with open(batch, 'w') as f:
        f.write(''.join('link set dev %s %s\n' % (i, state) for i in intfs))
    sh('ip -batch %s' % batch)


# --------------------------------------------------------------------------- controller
class Controller:
    def __init__(self, cmd, log_path):
        self.cmd, self.log_path, self.proc = cmd, log_path, None

    def start(self):
        user = os.environ.get('SUDO_USER')
        cmd = self.cmd
        if user and user != 'root':
            cmd = 'sudo -u %s %s' % (user, cmd)
        self.log = open(self.log_path, 'a')
        self.proc = subprocess.Popen(cmd, shell=True, cwd=HERE, stdout=self.log,
                                     stderr=subprocess.STDOUT, preexec_fn=os.setsid)
        for _ in range(60):
            try:
                socket.create_connection(('127.0.0.1', 6633), timeout=1).close()
                return
            except OSError:
                time.sleep(0.5)
        raise RuntimeError('controller not listening on 6633; see %s' % self.log_path)

    def stop(self):
        if not self.proc:
            return
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGINT)
            self.proc.wait(timeout=10)
        except Exception:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except Exception:
                pass
        self.log.close()
        self.proc = None

    def offset(self):
        self.log.flush()
        return os.path.getsize(self.log_path)

    def buffered_since(self, off):
        """Total number of Packet-Ins flushed from the buffer since a log offset."""
        with open(self.log_path, errors='replace') as f:
            f.seek(off)
            text = f.read()
        return sum(int(x) for x in re.findall(r'Flushing packet buffer: size=(\d+)', text))


# --------------------------------------------------------------------------- tests
def parse_ping(path, n_sent, interval):
    seqs, rtts, stamps = {}, [], []
    with open(path) as f:
        for line in f:
            m = re.search(r'^\[(\d+\.\d+)\].*icmp_seq=(\d+).*time=([\d.]+) ms', line)
            if m:
                t, seq, rtt = float(m.group(1)), int(m.group(2)), float(m.group(3))
                if seq not in seqs:
                    seqs[seq] = rtt
                    rtts.append(rtt)
                    stamps.append(t)
    received = len(seqs)
    lost = n_sent - received
    longest, run = 0, 0
    for k in range(1, n_sent + 1):
        run = run + 1 if k not in seqs else 0
        longest = max(longest, run)
    stamps.sort()
    gaps = [stamps[i + 1] - stamps[i] for i in range(len(stamps) - 1)]
    # A gap longer than the whole run is a clock step in the VM (NTP), not an outage
    span = n_sent * interval
    gaps = [g for g in gaps if g <= span + 5]
    outage = max(0.0, (max(gaps) if gaps else 0.0) - interval)
    # Replies that stop and never come back (black hole) are an outage too
    tail = (n_sent - max(seqs)) * interval if seqs else span
    outage = max(outage, tail)
    srt = sorted(rtts)
    return {
        'sent': n_sent, 'received': received, 'lost': lost,
        'loss_pct': 100.0 * lost / n_sent if n_sent else 0.0,
        'delayed': sum(1 for r in rtts if r > DELAY_THRESHOLD_MS),
        'rtt_avg_ms': sum(rtts) / len(rtts) if rtts else 0.0,
        'rtt_p50_ms': srt[len(srt) // 2] if srt else 0.0,
        'rtt_max_ms': srt[-1] if srt else 0.0,
        'outage_s': outage, 'lost_run_s': longest * interval,
    }


def run_ping(net, ctl, mode, interval, rep, a):
    ch = choose(net, a)
    hs = net.get('h%d' % ch.src)
    n = int(round(a.duration / interval))
    tag = '%s_ping_i%g_r%d' % (mode, interval, rep)
    log = os.path.join(a.raw, tag + '.txt')
    off = ctl.offset() if ctl else 0
    with open(log, 'w') as f:
        before = all_tx_packets()
        p = hs.popen(['ping', '-D', '-n', '-i', str(interval), '-c', str(n), '-W', '1',
                      host_ip(ch.dst)], stdout=f, stderr=subprocess.STDOUT)
        time.sleep(a.t_fail)
        ch = live_check(net, before, ch, tag, a)
        set_failure(net, ch, 'down')
        p.wait()
    set_failure(net, ch, 'up')
    row = parse_ping(log, n, interval)
    row.update({'mode': mode, 'interval_s': interval, 'rep': rep, 'topo': a.topo,
                'src': 'h%d' % ch.src, 'dst': 'h%d' % ch.dst, 'path': ch.path_str(),
                'failed_link': ch.failed(),
                'buffered_pkts': ctl.buffered_since(off) if ctl else 0,
                't_fail_s': a.t_fail, 'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')})
    return row


def run_udp(net, ctl, mode, rate, rep, a):
    ch = choose(net, a)
    hs, hd = net.get('h%d' % ch.src), net.get('h%d' % ch.dst)
    tag = '%s_udp_r%g_rep%d' % (mode, rate, rep)
    txj, rxj = [os.path.join(a.raw, tag + s) for s in ('_tx.json', '_rx.json')]
    tl = os.path.join(a.raw, tag + '_timeline.csv')
    run_id = int(time.time()) % 100000
    off = ctl.offset() if ctl else 0
    rx = hd.popen([sys.executable, PROBE, 'recv', '--duration', str(a.duration), '--wait', '45',
                   '--idle', '3', '--run-id', str(run_id), '--out', rxj, '--timeline', tl,
                   '--disruption', tl.replace('_timeline.csv', '_disruption.csv')])
    time.sleep(1)
    before = all_tx_packets()
    tx = hs.popen([sys.executable, PROBE, 'send', '--dst', host_ip(ch.dst), '--rate', str(rate),
                   '--size', str(a.size), '--duration', str(a.duration),
                   '--run-id', str(run_id), '--out', txj])
    time.sleep(a.t_fail)
    ch = live_check(net, before, ch, tag, a)
    set_failure(net, ch, 'down')
    tx.wait()
    rx.wait()
    set_failure(net, ch, 'up')
    with open(txj) as f:
        t = json.load(f)
    with open(rxj) as f:
        r = json.load(f)
    uniq = r.get('unique', 0)
    return {'mode': mode, 'rate_mbps': rate, 'rep': rep, 'topo': a.topo,
            'src': 'h%d' % ch.src, 'dst': 'h%d' % ch.dst, 'path': ch.path_str(),
            'failed_link': ch.failed(),
            'sent': t['sent'], 'received': uniq, 'lost': t['sent'] - uniq,
            'loss_pct': 100.0 * (t['sent'] - uniq) / t['sent'] if t['sent'] else 0.0,
            'duplicates': r.get('duplicates', 0), 'reordered': r.get('reordered', 0),
            'outage_s': max(0.0, r.get('max_gap_s', 0.0) - t['gap_s'],
                            a.duration - (r.get('t_last', 0.0) - r.get('t_first', 0.0)) - 1.0
                            if uniq else a.duration),
            'max_hole_pkts': r.get('max_hole_pkts', 0),
            'owd_avg_ms': r.get('owd_avg_ms', 0.0), 'owd_p99_ms': r.get('owd_p99_ms', 0.0),
            'owd_max_ms': r.get('owd_max_ms', 0.0),
            'buffered_pkts': ctl.buffered_since(off) if ctl else 0,
            't_fail_s': a.t_fail, 'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')}


# --------------------------------------------------------------------------- main
APP_FILE = {'sdn': 'DynSTPProactive.py', 'sdnfast': 'DynSTPProactiveFast.py',
            'sdnfast2': 'DynSTPProactiveFast2.py', 'sdnfast3': 'DynSTPProactiveFast3.py',
            'sdnfast4': 'DynSTPProactiveFast4.py', 'sdnfast5': 'DynSTPProactiveFast5.py'}


CONTROLLERS = os.path.join(HERE, '..', 'controllers')


def default_ryu_cmd(mode='sdn'):
    """ryu-manager from ./ryu-manager (a wrapper, see ryu-manager.example), or from PATH,
    running the controller of the mode from ../controllers (or from this folder)."""
    local = os.path.join(HERE, 'ryu-manager')
    exe = local if os.path.exists(local) else 'ryu-manager'
    app = os.path.join(CONTROLLERS, APP_FILE[mode])
    if not os.path.exists(app):
        app = os.path.join(HERE, APP_FILE[mode])
    return '%s --observe-links %s' % (exe, os.path.abspath(app))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--modes', nargs='+', default=['sdn', 'sdnfast5', 'stp', 'rstp'], choices=['sdn', 'sdnfast', 'sdnfast2', 'sdnfast3', 'sdnfast4', 'sdnfast5', 'stp', 'rstp'])
    p.add_argument('--topo', default='triangle', choices=sorted(TOPOS),
                   help='triangle (3 switches), ring6 or mesh6 (6 switches), ring7 (7 switches)')
    p.add_argument('--pair', default=None, choices=['fixed', 'longest'],
                   help='traffic pair: fixed = h1->h3 (default for triangle), longest = the hosts '
                        'with the longest path, failing its middle link (default otherwise)')
    p.add_argument('--tests', nargs='+', default=['ping', 'udp'], choices=['ping', 'udp'])
    p.add_argument('--intervals', nargs='+', type=float, default=[1.0, 0.5, 0.2, 0.1, 0.05, 0.01])
    p.add_argument('--rates', nargs='+', type=float, default=[1, 5, 10, 25, 50])
    p.add_argument('--reps', type=int, default=5)
    p.add_argument('--duration', type=float, default=60, help='seconds of traffic per run')
    p.add_argument('--t-fail', type=float, default=5, help='link failure instant (s)')
    p.add_argument('--size', type=int, default=1400, help='UDP payload bytes')
    p.add_argument('--stp-wait', type=float, default=35, help='min. re-convergence wait for 802.1D (s)')
    p.add_argument('--ryu-cmd', default=None,
                   help='controller command for mode sdn (default: ryu-manager --observe-links DynSTPProactive.py)')
    p.add_argument('--ryu-cmd-fast', default=None,
                   help='controller command for mode sdnfast (default: ... DynSTPProactiveFast.py)')
    p.add_argument('--ryu-cmd-fast2', default=None,
                   help='controller command for mode sdnfast2 (default: ... DynSTPProactiveFast2.py)')
    p.add_argument('--ryu-cmd-fast3', default=None,
                   help='controller command for mode sdnfast3 (default: ... DynSTPProactiveFast3.py)')
    p.add_argument('--scenario', default=None, choices=sorted(SCENARIOS),
                   help='predefined controlled scenario (sets topo, failure, pair, priorities)')
    p.add_argument('--src', type=int, default=None, help='fixed source host number (with --dst)')
    p.add_argument('--dst', type=int, default=None, help='fixed destination host number')
    p.add_argument('--fail-switch', default=None, help='switch to fail with --failure switch, e.g. s1')
    p.add_argument('--bridge-priorities', default=None,
                   help='STP/RSTP bridge priorities, e.g. "s1=4096,s4=8192"')
    p.add_argument('--sdn-link-costs', default=None,
                   help='link costs for the SDN controllers\' tree, e.g. "3-4:2"')
    p.add_argument('--expect-path', default=None,
                   help='expected switch path of the probes before the failure, e.g. s2-s1-s6')
    p.add_argument('--failure', default='link', choices=['link', 'switch'],
                   help='link: the middle link of the traffic path goes down; switch: every '
                        'inter-switch link of the middle switch of the path goes down at once '
                        '(in mesh6 with RSTP this is usually the root bridge)')
    p.add_argument('--out', default=None,
                   help='results folder (default: results/ for the triangle, results/<topo>/ otherwise)')
    a = p.parse_args()
    if a.scenario:
        given = {k for k in vars(a) if any(x.lstrip('-').replace('-', '_') == k
                                             for x in sys.argv[1:] if x.startswith('--'))}
        for k, v in SCENARIOS[a.scenario].items():
            if k not in given:
                setattr(a, k, v)
        if 'pair' not in given:
            a.pair = 'longest'
    if (a.src is None) != (a.dst is None):
        sys.exit('--src and --dst go together')
    if a.fail_switch and a.failure != 'switch':
        sys.exit('--fail-switch needs --failure switch')
    a.prio = {}
    for item in (a.bridge_priorities or '').split(','):
        if item.strip():
            k, v = item.split('=')
            a.prio[k.strip()] = int(v)
    if a.pair is None:
        a.pair = 'fixed' if a.topo == 'triangle' else 'longest'
    if a.pair == 'fixed' and a.topo != 'triangle':
        sys.exit('--pair fixed is only defined for the triangle')
    if a.failure == 'switch' and a.pair != 'longest' and not a.fail_switch:
        sys.exit('--failure switch needs --pair longest or --fail-switch')
    if a.out is None:
        sub = a.scenario or (a.topo + ('_switch' if a.failure == 'switch' else ''))
        a.out = os.path.join(HERE, '..', 'results') if sub == 'triangle' \
            else os.path.join(HERE, '..', 'results', sub)
    if os.geteuid() != 0:
        sys.exit('run with sudo (Mininet needs root)')
    if a.duration < a.t_fail + 35:
        print('WARNING: duration < t_fail + 35 s: 802.1D recovery (about 30 s) may not be observed')
    a.out = os.path.abspath(a.out)
    a.raw = os.path.join(a.out, 'raw')
    os.makedirs(a.raw, exist_ok=True)
    ping_csv, udp_csv = os.path.join(a.out, 'ping_runs.csv'), os.path.join(a.out, 'udp_runs.csv')
    done_ping, done_udp = done_keys(ping_csv, 'interval_s'), done_keys(udp_csv, 'rate_mbps')
    with open(os.path.join(a.out, 'config.json'), 'w') as f:
        json.dump({k: v for k, v in vars(a).items()}, f, indent=1)
    sh('uname -a > %s/env.txt; nproc >> %s/env.txt; free -m >> %s/env.txt; '
       'ovs-vsctl --version >> %s/env.txt; mn --version >> %s/env.txt 2>&1'
       % ((a.out,) * 5))
    setLogLevel('info')

    for mode in a.modes:
        cleanup()
        cmd = {'sdn': a.ryu_cmd or default_ryu_cmd('sdn'),
               'sdnfast': a.ryu_cmd_fast or default_ryu_cmd('sdnfast'),
               'sdnfast2': a.ryu_cmd_fast2 or default_ryu_cmd('sdnfast2'),
               'sdnfast3': a.ryu_cmd_fast3 or default_ryu_cmd('sdnfast3'),
               'sdnfast4': default_ryu_cmd('sdnfast4'),
               'sdnfast5': default_ryu_cmd('sdnfast5')}.get(mode)
        if cmd and a.sdn_link_costs:
            cmd = 'env STP_LINK_COSTS=%s %s' % (a.sdn_link_costs, cmd)
        ctl = Controller(cmd, os.path.join(a.out, 'controller_%s.log' % mode)) if cmd else None
        net = None
        try:
            if ctl:
                ctl.start()
            net = build_net(mode, a.topo, a.prio)
            boot = {'sdn': 3, 'sdnfast': 3, 'sdnfast2': 3, 'sdnfast3': 3, 'sdnfast4': 3, 'sdnfast5': 3, 'stp': a.stp_wait, 'rstp': 3}[mode]
            info('*** %s: converged after %.1f s\n' % (mode, wait_converged(net, mode, boot)))
            jobs = []
            for rep in range(1, a.reps + 1):
                if 'ping' in a.tests:
                    jobs += [('ping', x, rep) for x in a.intervals if (mode, x, rep) not in done_ping]
                if 'udp' in a.tests:
                    jobs += [('udp', x, rep) for x in a.rates if (mode, x, rep) not in done_udp]
            for k, (test, x, rep) in enumerate(jobs, 1):
                info('*** [%s %s %d/%d] %s %s rep %d\n' % (a.topo, mode, k, len(jobs), test, x, rep))
                if test == 'ping':
                    row = run_ping(net, ctl, mode, x, rep, a)
                    append_row(ping_csv, PING_FIELDS, row)
                    info('    %s->%s path %s, failed %s: lost=%d outage=%.2fs rtt_max=%.1fms\n'
                         % (row['src'], row['dst'], row['path'], row['failed_link'],
                            row['lost'], row['outage_s'], row['rtt_max_ms']))
                else:
                    row = run_udp(net, ctl, mode, x, rep, a)
                    append_row(udp_csv, UDP_FIELDS, row)
                    info('    %s->%s path %s, failed %s: loss=%.2f%% outage=%.2fs owd_max=%.1fms\n'
                         % (row['src'], row['dst'], row['path'], row['failed_link'],
                            row['loss_pct'], row['outage_s'], row['owd_max_ms']))
                info('*** re-converging\n')
                wait_converged(net, mode, a.stp_wait if mode == 'stp' else 3)
        finally:
            if net:
                net.stop()
            if ctl:
                ctl.stop()
            cleanup()
    print('Done. Now run: python3 analyze_results.py --results %s' % a.out)


if __name__ == '__main__':
    main()
