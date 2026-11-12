#!/usr/bin/env python3
"""
analyze_results.py - summarises results/ping_runs.csv and results/udp_runs.csv
(produced by run_experiments.py) into the files that main.tex reads:

  results/ping_<mode>.dat, results/udp_<mode>.dat   pgfplots tables (mean and 95% CI)
  results/timeline_<mode>.csv                       UDP throughput timeline (one run)
  results/tab_ping.tex, results/tab_udp.tex         LaTeX table rows
  results/macros.tex                                \\resultstrue + numeric macros
  results/summary.md                                human-readable summary

Only the Python standard library is used.
Usage: python3 analyze_results.py [--results ../results] [--timeline-rate 10]
"""
import argparse
import csv
import math
import os
import shutil
import statistics as st
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import failwin  # noqa: E402

# Mechanisms in the paper's tables, in table order (--modes overrides it). Mode 'sdnfast5'
# (DynSTPProactiveFast5.py: event trigger, targeted make-before-break update, fast-failover
# protection) is the SDN-STP-Fast of the paper; 'sdnfast3' is the same without fast-failover
# protection. The other modes appear in summary.md only.
ALL_MODES = ['sdn', 'sdnfast', 'sdnfast2', 'sdnfast3', 'sdnfast4', 'sdnfast5', 'stp', 'rstp']
DEFAULT_MODES = ['sdn', 'sdnfast5', 'stp', 'rstp']
MODES = list(DEFAULT_MODES)
EXTRA = [m for m in ALL_MODES if m not in MODES]
LABEL = {'sdn': 'SDN-STP', 'sdnfast5': 'SDN-STP-Fast', 'sdnfast3': 'SDN-STP-Fast (no FF)',
         'stp': '802.1D STP', 'rstp': 'RSTP', 'sdnfast': 'SDN-STP-Fast v1', 'sdnfast2': 'SDN-STP-Fast v2',
         'sdnfast4': 'SDN-STP-Fast v4 (redirect and buffer)'}
# prefix of the LaTeX macros of each mode, e.g. \resFastUdpOutageFifty; --macro-prefix adds a
# scenario prefix, e.g. \resRootFastUdpOutageFifty
PREFIX = {'sdn': 'Sdn', 'sdnfast5': 'Fast', 'sdnfast3': 'NoFF', 'stp': 'Stp', 'rstp': 'Rstp',
          'sdnfast': 'FastVOne', 'sdnfast2': 'FastVTwo', 'sdnfast4': 'FastVFour'}
# two-sided 95% Student t quantiles, df = 1..30
T95 = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179,
       2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064,
       2.060, 2.056, 2.052, 2.048, 2.045, 2.042]


def ci95(xs):
    n = len(xs)
    if n < 2:
        return 0.0
    t = T95[n - 2] if n - 1 <= len(T95) else 1.96
    return t * st.stdev(xs) / math.sqrt(n)


def load(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def summarise(rows, xkey, metrics):
    """{mode: {x: {metric: (mean, ci, n)}}}"""
    out = {}
    for r in rows:
        out.setdefault(r['mode'], {}).setdefault(float(r[xkey]), []).append(r)
    res = {}
    for mode, byx in out.items():
        res[mode] = {}
        for x, rs in byx.items():
            res[mode][x] = {}
            for m in metrics:
                vals = [float(r[m]) for r in rs]
                res[mode][x][m] = (st.mean(vals), ci95(vals), len(vals))
    return res


def write_dat(path, xname, byx, metrics):
    with open(path, 'w') as f:
        cols = [xname] + [c for m in metrics for c in (m, m + '_ci')]
        f.write(' '.join(cols) + '\n')
        for x in sorted(byx):
            vals = ['%g' % x] + ['%.6g' % v for m in metrics for v in byx[x][m][:2]]
            f.write(' '.join(vals) + '\n')


def fmt(mean, ci, digits=2):
    if ci > 0:
        return '%.*f\\,$\\pm$\\,%.*f' % (digits, mean, digits, ci)
    return '%.*f' % (digits, mean)


def num(metric, v):
    """Text of a result macro: counts and delays with one decimal, the rest with two."""
    if metric in ('Lost', 'Delayed', 'Reordered', 'RttMax', 'OwdMax'):
        return '%.1f' % v
    if metric in ('Outage', 'GapRun') and v < 0.1:
        return '%.3f' % v
    return '%.2f' % v


def macro_name(*parts):
    """LaTeX macro names may contain letters only."""
    words = {'0.01': 'TenMs', '0.02': 'TwentyMs', '0.05': 'FiftyMs', '0.1': 'HundredMs',
             '0.2': 'TwoHundredMs', '0.5': 'FiveHundredMs', '1': 'One', '2': 'Two',
             '5': 'Five', '10': 'Ten', '20': 'Twenty', '25': 'TwentyFive', '50': 'Fifty',
             '75': 'SeventyFive', '100': 'Hundred'}
    out = ''
    for p in parts:
        p = str(p)
        if p in words:
            out += words[p]
        elif p.replace('.', '', 1).isdigit():
            out += 'R' + ''.join('ABCDEFGHIJ'[int(c)] if c.isdigit() else 'p' for c in p)
        else:
            digit = ['Zero','One','Two','Three','Four','Five','Six','Seven','Eight','Nine']
            p = ''.join(ch if ch.isalpha() else digit[int(ch)] if ch.isdigit() else '' for ch in p)
            out += p[:1].upper() + p[1:]
    return out


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument('--results', default=os.path.join(here, '..', 'results'))
    ap.add_argument('--timeline-rate', type=float, default=10)
    ap.add_argument('--modes', default=','.join(DEFAULT_MODES),
                    help='modes of the tables and macros, in order (default: %(default)s)')
    ap.add_argument('--macro-prefix', default='',
                    help='scenario prefix of the macros, e.g. Root -> \\resRootFastUdp...')
    a = ap.parse_args()
    MODES[:] = [m.strip() for m in a.modes.split(',') if m.strip()]
    EXTRA[:] = [m for m in ALL_MODES if m not in MODES]
    R = os.path.abspath(a.results)

    ping = load(os.path.join(R, 'ping_runs.csv'))
    udp = load(os.path.join(R, 'udp_runs.csv'))
    raw = os.path.join(R, 'raw')
    # Metrics restricted to the failure (failwin.py). The run-wide 'outage_s' (longest gap
    # anywhere in the run) also captures short pauses of the virtual machine that are
    # unrelated to the failure, so the paper uses 'int_fail_s'.
    for r in ping:
        iv = float(r['interval_s'])
        w = failwin.ping_window(os.path.join(raw, '%s_ping_i%g_r%s.txt' % (r['mode'], iv, r['rep'])),
                                iv, float(r.get('t_fail_s') or 5), int(r['sent'])) \
            if os.path.isdir(raw) and os.path.exists(os.path.join(raw, '%s_ping_i%g_r%s.txt' % (r['mode'], iv, r['rep']))) else None
        r.update(w or {'int_fail_s': r['outage_s'], 'rtt_max_win_ms': r['rtt_max_ms'], 'delayed_win': r['delayed']})
    for r in udp:
        b = os.path.join(raw, '%s_udp_r%g_rep%s' % (r['mode'], float(r['rate_mbps']), r['rep']))
        w = failwin.udp_window(b + '_tx.json', b + '_rx.json', b + '_timeline.csv', float(r.get('t_fail_s') or 5))
        r.update(w or {'int_fail_s': r['outage_s']})
    if not ping and not udp:
        raise SystemExit('no results found in %s' % R)

    pm = ['lost', 'loss_pct', 'delayed', 'rtt_max_ms', 'outage_s', 'lost_run_s', 'buffered_pkts',
          'int_fail_s', 'rtt_max_win_ms', 'delayed_win']
    um = ['loss_pct', 'lost', 'outage_s', 'owd_max_ms', 'owd_p99_ms', 'reordered',
          'duplicates', 'buffered_pkts', 'int_fail_s']
    ps = summarise(ping, 'interval_s', pm)
    us = summarise(udp, 'rate_mbps', um)

    macros = ['\\resultstrue']
    md = ['# Results summary', '',
          '(*) restricted to the failure: interruption = longest gap or loss run that starts at the',
          'failure (failwin.py); delayed probes and max RTT among the probes sent in [t_f-0.2, t_f+3] s.',
          'The longest gap in the run and the max OWD in the run also include pauses of the VM.', '']

    # ---- ping
    rows = []
    for mode in MODES + EXTRA:
        if mode not in ps:
            continue
        paper = mode in MODES
        write_dat(os.path.join(R, 'ping_%s.dat' % mode), 'interval', ps[mode], pm)
        md += ['## Ping, %s' % LABEL[mode], '',
               '| interval (s) | n | lost | loss % | delayed* | max RTT* (ms) | interruption* (s) | longest gap in run (s) |',
               '|---|---|---|---|---|---|---|---|']
        for x in sorted(ps[mode], reverse=True):
            d = ps[mode][x]
            if paper: rows.append('%s & %g & %s & %s & %s & %s \\\\' % (
                LABEL[mode], x, fmt(*d['lost'][:2], digits=1), fmt(*d['delayed_win'][:2], digits=1),
                fmt(*d['rtt_max_win_ms'][:2], digits=1), fmt(*d['int_fail_s'][:2], digits=3)))
            md.append('| %g | %d | %.1f | %.2f | %.1f | %.1f | %.3f | %.2f |' % (
                x, d['lost'][2], d['lost'][0], d['loss_pct'][0], d['delayed_win'][0],
                d['rtt_max_win_ms'][0], d['int_fail_s'][0], d['outage_s'][0]))
            for m, key in (('Lost', 'lost'), ('Outage', 'int_fail_s'), ('RttMax', 'rtt_max_win_ms'),
                           ('Delayed', 'delayed_win'), ('GapRun', 'outage_s')) if paper else ():
                macros.append('\\newcommand{\\res%s}{%s}' % (
                    macro_name(PREFIX[mode], 'Ping', m, '%g' % x), num(m, d[key][0])))
        if paper: rows.append('\\midrule')
        md.append('')
    if rows and rows[-1] == '\\midrule':
        rows.pop()
    with open(os.path.join(R, 'tab_ping.tex'), 'w') as f:
        f.write('\n'.join(rows) + '\n')

    # ---- udp
    rows = []
    for mode in MODES + EXTRA:
        if mode not in us:
            continue
        paper = mode in MODES
        write_dat(os.path.join(R, 'udp_%s.dat' % mode), 'rate', us[mode], um)
        md += ['## UDP, %s' % LABEL[mode], '',
               '| rate (Mbit/s) | n | loss % | lost | interruption* (s) | longest gap in run (s) | max OWD in run (ms) | reordered | buffered |',
               '|---|---|---|---|---|---|---|---|---|']
        for x in sorted(us[mode]):
            d = us[mode][x]
            if paper: rows.append('%s & %g & %s & %s & %s & %s \\\\' % (
                LABEL[mode], x, fmt(*d['loss_pct'][:2]), fmt(*d['lost'][:2], digits=1),
                fmt(*d['int_fail_s'][:2], digits=3), fmt(*d['reordered'][:2], digits=1)))
            md.append('| %g | %d | %.2f | %.1f | %.3f | %.2f | %.1f | %.1f | %.0f |' % (
                x, d['loss_pct'][2], d['loss_pct'][0], d['lost'][0], d['int_fail_s'][0],
                d['outage_s'][0], d['owd_max_ms'][0], d['reordered'][0], d['buffered_pkts'][0]))
            for m, key in (('LossPct', 'loss_pct'), ('Outage', 'int_fail_s'), ('GapRun', 'outage_s'),
                           ('OwdMax', 'owd_max_ms'), ('Reordered', 'reordered'),
                           ('Lost', 'lost')) if paper else ():
                macros.append('\\newcommand{\\res%s}{%s}' % (
                    macro_name(PREFIX[mode], 'Udp', m, '%g' % x), num(m, d[key][0])))
        if paper: rows.append('\\midrule')
        md.append('')
    if rows and rows[-1] == '\\midrule':
        rows.pop()
    with open(os.path.join(R, 'tab_udp.tex'), 'w') as f:
        f.write('\n'.join(rows) + '\n')

    # ---- overall per-mode figures (all ping intervals / all UDP rates)
    for mode in MODES:
        o = [float(r['int_fail_s']) for r in ping + udp if r['mode'] == mode]
        if o:
            macros.append('\\newcommand{\\res%sOutageMean}{%.2f}' % (macro_name(PREFIX[mode]), st.mean(o)))
            macros.append('\\newcommand{\\res%sOutageMax}{%.2f}' % (macro_name(PREFIX[mode]), max(o)))
        for test, sm in (('Ping', ps), ('Udp', us)):
            if mode in sm:
                means = [sm[mode][x]['int_fail_s'][0] for x in sm[mode]]
                macros.append('\\newcommand{\\res%s%sOutageBest}{%s}' % (PREFIX[mode], test, num('Outage', min(means))))
                macros.append('\\newcommand{\\res%s%sOutageWorst}{%s}' % (PREFIX[mode], test, num('Outage', max(means))))
        for test, rs in (('Ping', ping), ('Udp', udp)):
            o = [float(r['int_fail_s']) for r in rs if r['mode'] == mode]
            if o:
                macros.append('\\newcommand{\\res%s%sOutageMean}{%.2f}' % (PREFIX[mode], test, st.mean(o)))
                macros.append('\\newcommand{\\res%s%sOutageMedian}{%.2f}' % (PREFIX[mode], test, st.median(o)))
                macros.append('\\newcommand{\\res%s%sOutageMax}{%.2f}' % (PREFIX[mode], test, max(o)))
                l = [float(r['loss_pct']) for r in rs if r['mode'] == mode]
                macros.append('\\newcommand{\\res%s%sLossMean}{%.2f}' % (PREFIX[mode], test, st.mean(l)))
        n = [r for r in ping + udp if r['mode'] == mode]
        if n:
            macros.append('\\newcommand{\\res%sRuns}{%d}' % (macro_name(PREFIX[mode]), len(n)))

    # ---- UDP timeline of one run per mode (first repetition at the chosen rate)
    for mode in MODES:
        src = os.path.join(R, 'raw', '%s_udp_r%g_rep1_timeline.csv' % (mode, a.timeline_rate))
        if not os.path.exists(src):
            src = os.path.join(R, 'raw', '%s_udp_r%s_rep1_timeline.csv' % (mode, float(a.timeline_rate)))
        if os.path.exists(src):
            dst = os.path.join(R, 'timeline_%s.csv' % mode)
            shutil.copy(src, dst)
            macros.append('\\newcommand{\\hasTimeline%s}{1}' % macro_name(PREFIX[mode]))
    macros.append('\\newcommand{\\resTimelineRate}{%g}' % a.timeline_rate)

    reps = sorted({int(r['rep']) for r in ping + udp})
    macros.append('\\newcommand{\\resReps}{%d}' % (max(reps) if reps else 0))
    if a.macro_prefix:
        macros = [m.replace('\\newcommand{\\res', '\\newcommand{\\res' + a.macro_prefix)
                   .replace('\\newcommand{\\hasTimeline', '\\newcommand{\\hasTimeline' + a.macro_prefix)
                  for m in macros]
    with open(os.path.join(R, 'macros.tex'), 'w') as f:
        f.write('\n'.join(macros) + '\n')
    with open(os.path.join(R, 'summary.md'), 'w') as f:
        f.write('\n'.join(md) + '\n')
    print('\n'.join(md))
    print('Written: *.dat, tab_ping.tex, tab_udp.tex, macros.tex, summary.md in', R)


if __name__ == '__main__':
    main()
