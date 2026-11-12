"""
DynSTPProactiveFast4 - SDN-STP-Fast v4 (redirect-and-buffer).

Same as DynSTPProactiveFast3 (event-triggered, targeted make-before-break update), plus
loss protection through the controller buffer:

1. Redirect: as soon as a Port-Status reports a port down, every proactive unicast rule
   of that switch whose output is the failed port is rewritten to output to the
   controller. The packets that would be dropped at the failed port during the update
   now reach the controller and are buffered.
2. Install: the new tree's rules are sent first to every switch except the redirected
   ones.
3. Release in order: the buffered packets are sent out of the redirected switches with
   Packet-Out messages along the new path, and only then the redirected switches receive
   their new rules. Since a switch applies the messages of its connection in order, the
   buffered packets leave the switch before the packets that follow the new rules.
"""



from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.topology.api import get_switch, get_all_link
from ryu.topology import event
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv6, icmpv6, ipv4, icmp, udp
import networkx as nx
import json
import time
import signal
import os
import logging


# Optional link costs for the spanning tree, for controlled experiments, given in the
# environment, e.g. STP_LINK_COSTS="3-4:2" (link between switches 3 and 4 costs 2).
# Without the variable every link costs 1, as in the original application.
def _parse_link_costs(text):
    costs = {}
    for item in text.replace(' ', '').split(','):
        if not item:
            continue
        pair, cost = item.split(':')
        a, b = pair.split('-')
        costs[frozenset((int(a), int(b)))] = float(cost)
    return costs


LINK_COSTS = _parse_link_costs(os.environ.get('STP_LINK_COSTS', ''))


# Deduplication window for detecting repeated port failures
PORT_FAILURE_TIMEOUT = 2

# Event-triggered recomputation (SDN-STP-Fast)
TOPO_POLL_PERIOD = 1.0    # fallback polling period (s)
TRIGGER_HOLDOFF = 0.01    # wait for the Port-Status of the other end of the link (s)
APP_COOKIE = 0x5354       # 'ST': all rules of this application carry 0x5354000g
PRO_COOKIE = 0x53540010   # proactive rules (unicast paths, ARP flooding, drop rules)
RE_COOKIE = 0x53540020    # reactive rules installed by the Packet-In handler
ANY_APP_MASK = 0xffffffffffffff00   # matches both cookies above
COOKIE_MASK = 0xffffffffffffffff


def _match_key(match):
    """Cheap, hashable key of an OFPMatch (to_jsondict is far too slow per rule)."""
    return tuple(sorted((k, str(v)) for k, v in match._fields2))


def _actions_key(actions):
    """Key of an action list; this application only uses output actions."""
    return tuple(getattr(a, 'port', repr(a)) for a in actions)


class DynSTPProactiveFast4(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynSTPProactiveFast4, self).__init__(*args, **kwargs)
        self.logger.setLevel(logging.DEBUG)

        # --- Topology state (graph + entity caches) ---
        self.net = nx.DiGraph()   # Network topology graph
        self.sws = []             # Active switches [(datapath, dpid)]
        self.links = []           # Active links [(src_dpid, dst_dpid, src_port)]
        self.hosts = []           # Hosts [(mac, dpid, port)]

        # Previous snapshots (used to detect changes)
        self.sws_prev = []
        self.links_prev = []
        self.hosts_prev = []

        # --- Spanning Tree (STP) state ---
        # STP ports per switch: ports allowed by the current MST
        self.stp_ports = {}
        # Snapshot of STP ports from previous cycle to detect changes
        self.previous_stp_ports = {}

        # --- MAC learning table ---
        self.mac_to_port = {}  # {dpid: {mac: port}}

        # Proactive path installation control
        self.proactive_mode_enabled = True
        self.flow_rules_to_remove = False

        # Event trigger for the topology monitor + ports currently down
        self.topo_trigger = hub.Event()
        self.down_ports = set()        # {(dpid, port_no)}
        self.trigger_time = None       # time of the first pending trigger (for logging)
        self.installed = {}            # (dpid, priority, match) -> (dp, match, actions, actions key)
        self.collect = None            # desired rule set while a full rebuild is computed
        self.fail_dpids = set()        # switches that reported a port down since the last update
        self.redirect_dpids = set()    # switches whose rules were redirected to the controller
        self.force_rebuild = False     # set by a Port-Status: rebuild all rules (make-before-break)

        # Topology monitor (event-triggered, with periodic fallback)
        self.monitor_thread = hub.spawn(self._monitor_topology)
        self.initial_time = time.time()
        signal.signal(signal.SIGINT, self.handle_sigint)
        self.running = True

        # --- Port failure tracking ---
        # Tracks recent port-down events to avoid duplicate handling
        self.recent_port_failures = {}

        # --- Packet buffering (to survive STP re-convergence) ---
        # Why: During STP changes, packet routing may be inconsistent. Buffering
        # Packet-In events prevents drops until the new MST is applied.
        self.packet_buffer = []        # list of (seq, msg, arrival_time)
        self.buffer_enabled = False    # Enabled during STP change handling
        self.BUFFER_TIMEOUT = 0.25     # v4: buffered packets older than 250 ms are discarded
        self.BUFFER_MAX = 5000         # Max size of buffer to bound memory
        self._flushing = False         # Prevent recursion while flushing
        self.seq = 0                   # Sequence ID for FIFO ordering

    def handle_sigint(self, signum, frame):
        self.logger.info("\nCtrl+C detected! Cleaning up.")
        self.running = False
        hub.kill(self.monitor_thread)
        hub.joinall([self.monitor_thread])
        os._exit(0)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install a table-miss flow entry for all switches."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss entry: send unknown packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        """Helper function to install flow entries."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # Every rule except the table-miss entry carries APP_COOKIE, so that the
        # rules of this application can be deleted with one cookie-filtered command
        cookie = 0 if priority == 0 else (RE_COOKIE if priority == 1 else PRO_COOKIE)
        if priority in (5, 10):
            key = (datapath.id, priority, _match_key(match))
            entry = (datapath, match, actions, _actions_key(actions))
            if self.collect is not None:
                # full rebuild in progress: only record the desired rule
                self.collect[key] = entry
                return
            self.installed[key] = entry
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, cookie=cookie,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # --- Spanning Tree change detection ---
    # How STP changes are detected:
    # Compare current STP ports (self.stp_ports) with previous snapshot
    # (self.previous_stp_ports). Any added/removed ports or switches means
    # STP has re-converged.
    def detect_STP_changes(self):
        change = False
        for dpid in self.stp_ports:
            old_ports = self.previous_stp_ports.get(dpid, set())
            new_ports = self.stp_ports[dpid]

            # Ports added/removed by MST change
            added_ports = new_ports - old_ports
            removed_ports = old_ports - new_ports

            if added_ports:
                change = True
                self.logger.info(f"Switch {dpid}: Ports added to STP: {added_ports}")
            if removed_ports:
                change = True
                self.logger.info(f"Switch {dpid}: Ports removed from STP: {removed_ports}")

        # Track switches entering/leaving STP set
        old_switches = set(self.previous_stp_ports.keys())
        new_switches = set(self.stp_ports.keys())
        added_switches = new_switches - old_switches
        removed_switches = old_switches - new_switches

        if added_switches:
            change = True
            self.logger.info(f"New switches detected in STP: {added_switches}")
        if removed_switches:
            change = True
            self.logger.info(f"Switches removed from STP: {removed_switches}")

        self.logger.info(f"Current STP configuration: {self.stp_ports}")
        return change

    def _monitor_topology(self):
        """Recompute the topology when triggered by an event, or every TOPO_POLL_PERIOD s."""
        while self.running:
            try:
                self.update_topology()
            except Exception:
                # Never let an exception kill the monitor thread (that would freeze the
                # rules of the network); log it and rebuild everything at the next run.
                self.logger.exception("Topology update failed; full rebuild at the next run")
                self.force_rebuild = True
            if self.trigger_time is not None:
                t = getattr(self, '_t', {})
                ms = lambda a, b: 1000 * (t[b] - t[a]) if a in t and b in t else -1
                self.logger.info("Event-triggered recomputation done %.1f ms after the trigger "
                                 "(start +%.1f ms, topology query %.1f ms, tree %.1f ms, rules %.1f ms)",
                                 1000 * (time.time() - self.trigger_time),
                                 1000 * (t.get('start', self.trigger_time) - self.trigger_time),
                                 ms('start', 'query'), ms('query', 'tree'), ms('tree', 'rules'))
                self.trigger_time = None
            triggered = self.topo_trigger.wait(timeout=TOPO_POLL_PERIOD)
            if triggered:
                hub.sleep(TRIGGER_HOLDOFF)   # let the other end's Port-Status arrive
            self.topo_trigger.clear()

    def trigger_recompute(self, why):
        """Wake the topology monitor now."""
        if self.trigger_time is None:
            self.trigger_time = time.time()
        self.logger.info("Topology recomputation triggered: %s", why)
        self.topo_trigger.set()

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        self.trigger_recompute("link added %s:%s -> %s:%s" % (
            ev.link.src.dpid, ev.link.src.port_no, ev.link.dst.dpid, ev.link.dst.port_no))

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        self.trigger_recompute("link deleted %s:%s -> %s:%s" % (
            ev.link.src.dpid, ev.link.src.port_no, ev.link.dst.dpid, ev.link.dst.port_no))

    # Check if a switch output port is already connected to a direct link neighbor.
    # This avoids duplicate edges between non-neighbor switches.
    def check_link(self, link_in, links_list):
        for link in links_list:
            if link[0] == link_in[0] and link[2] == link_in[2]:
                return False
        return True

    def update_topology(self):
        """Recompute the topology and update any state like the spanning tree."""
        self.net.clear()
        self._t = {'start': time.time()}

        # Discover active switches
        switches = get_switch(self, None)

        # Add switches to graph
        for switch in switches:
            self.net.add_node(switch.dp.id)

        # Cache active switches as (datapath, dpid)
        self.sws = [(switch.dp, switch.dp.id) for switch in switches]

        # Discover and record links between switches
        self.links = []
        links_list = get_all_link(self)
        self._t['query'] = time.time()
        # Ignore links that touch a port reported down (the topology service may
        # still list them for a few milliseconds after the failure)
        links = [(link.src.dpid, link.dst.dpid, link.src.port_no) for link in links_list
                 if (link.src.dpid, link.src.port_no) not in self.down_ports
                 and (link.dst.dpid, link.dst.port_no) not in self.down_ports]
        # Keep a link only when LLDP has discovered both directions: after a link comes
        # back, Ryu may see one direction before the other, and a half-discovered link
        # has no port for the reverse hop (it would enter the tree but no path through it
        # could be validated).
        pairs = {(l[0], l[1]) for l in links}
        links = [l for l in links if (l[1], l[0]) in pairs]
        for link in links:
            if self.check_link(link, self.links):
                self.links.append(link)

        # Add switch-switch links into graph (directed edges with port metadata)
        for link in self.links:
            self.net.add_edge(link[0], link[1], weight=LINK_COSTS.get(frozenset((link[0], link[1])), 1), port=link[2])

        # Add host-switch links into graph
        # Hosts are learned in Packet-In handler
        for host in self.hosts:
            mac_host, dpid, port_sw = host
            # Host -> switch (virtual port 1 for host side)
            self.net.add_edge(mac_host, dpid, weight=1, port=1)
            # Switch -> host (real access port)
            self.net.add_edge(dpid, mac_host, weight=1, port=port_sw)

        # Detect topology changes by comparing current vs previous snapshots
        new_hosts = [host for host in self.hosts if host not in self.hosts_prev]
        new_links = [link for link in self.links if link not in self.links_prev]
        new_sws = [sw for sw in self.sws if sw not in self.sws_prev]

        removed_hosts = []
        if self.hosts_prev != []:
            removed_hosts = [host for host in self.hosts_prev if host not in self.hosts]
        removed_links = []
        if self.links_prev != []:
            removed_links = [link for link in self.links_prev if link not in self.links]
        removed_sws = []
        if self.sws_prev != []:
            removed_sws = [sw for sw in self.sws_prev if sw not in self.sws]

        # --- Port status failure/recovery coupling ---
        # If a switch disappeared, remove MAC learning for that DPID
        if removed_sws:
            for sw in removed_sws:
                if sw[1] in self.mac_to_port:
                    del self.mac_to_port[sw[1]]

        # If links disappeared, reflect it in internal state
        if removed_links:
            for link in removed_links:
                if link in self.links:
                    self.links.remove(link)

        # Convert directed graph to undirected for MST computation
        undirected_net = self.net.to_undirected()

        # Compute MST for STP (the set of forwarding edges)
        mst = nx.minimum_spanning_tree(undirected_net, weight='weight')
        self._t['tree'] = time.time()
        self.mst = mst

        # Snapshot current STP set for change detection
        self.previous_stp_ports = {dpid: ports.copy() for dpid, ports in self.stp_ports.items()}

        # --- Tracking switch ports belonging to STP ---
        # Translate MST edges back to per-switch port sets: for each MST edge,
        # mark the switch's egress port used by that edge as "STP-active".
        self.stp_ports = {dpid: set() for dpid in self.net.nodes()}
        for src, dst in mst.edges():
            # src -> dst port
            if dst in self.net[src] and 'port' in self.net[src][dst]:
                self.stp_ports[src].add(self.net[src][dst]['port'])
            else:
                self.logger.warning(f"Missing port info for edge {src} -> {dst}")
            # dst -> src port
            if src in self.net[dst] and 'port' in self.net[dst][src]:
                self.stp_ports[dst].add(self.net[dst][src]['port'])
            else:
                self.logger.warning(f"Missing port info for edge {dst} -> {src}")

        # --- Detect topology changes caused by STP re-convergence ---
        # Compare newly computed STP ports with previous snapshot
        STP_changes = self.detect_STP_changes()
        # v2: a port went down or up since the last rebuild -> always rebuild, even if
        # the tree computed now looks unchanged (the rules may still use the failed port)
        if self.force_rebuild:
            STP_changes = True
            self.force_rebuild = False

        # Determine if any change requires proactive re-installation of flows
        has_changes = new_hosts or new_links or new_sws or STP_changes
        if has_changes and self.proactive_mode_enabled:
            # Install flow rules proactively (only for new hosts or when STP reconfigures)
            self.logger.info("Rebuilding rules: switches=%d links=%d hosts=%d",
                             len(self.sws), len(self.links), len(self.hosts))

            self.send_all_flow_rules_proactively(removed_hosts, new_hosts, STP_changes, new_sws, new_links)
            self._t['rules'] = time.time()

            # OPTIONAL: Install drop rules for blocked ports
            # self.proactive_rule_drop()

            # --- Buffering disabled and flushed after STP stabilizes ---
            # When STP changes are detected, we turn off buffering (if it was on)
            # and flush the buffered Packet-In messages in order.
            if STP_changes:
                self.logger.info("STP changes handled: flushing and disabling buffer")
                self.buffer_enabled = False
                self.flush_packet_buffer()

            # Update previous snapshots
            self.hosts_prev = list(self.hosts)
            self.links_prev = list(self.links)
            self.sws_prev = list(self.sws)

    # Helper to list all local ports for a node in the graph
    def get_local_ports(self, graph, node):
        return [data['port'] for _, _, data in graph.edges(node, data=True) if 'port' in data]

    def proactive_rule_drop(self):
        # Visit every switch and drop traffic on ports not in STP (blocked)
        for sw in self.sws:
            datapath = sw[0]
            dpid = sw[1]

            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            stp_ports = self.stp_ports.get(dpid, set())
            all_ports = self.get_local_ports(self.net, dpid)
            blocked_ports = set(all_ports) - set(stp_ports)

            # Install drop rules for blocked ports (excluding host port 1)
            for port in blocked_ports:
                if port != 1:
                    match = parser.OFPMatch(in_port=port)
                    actions = []
                    instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    flow_mod = parser.OFPFlowMod(cookie=PRO_COOKIE, 
                        datapath=datapath,
                        priority=100,
                        match=match,
                        instructions=instructions,
                    )
                    datapath.send_msg(flow_mod)

    def proactive_flow_rule_install(self, sw, p):
        """
        Install bidirectional flow rules proactively along a path p.
        Includes unicast path (src->dst and dst->src) and ARP request flood
        restricted to STP-authorized ports.
        """
        dp = sw[0]
        dpid = sw[1]

        # First and last nodes in path are MAC addresses (hosts)
        src_mac = p[0]
        dst_mac = p[-1]

        self.mac_to_port.setdefault(dpid, {})
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        # Determine in_port/out_port for current switch based on neighbors in path
        index_current_dpid = p.index(dpid)
        prev_node = p[index_current_dpid - 1]
        next_node = p[index_current_dpid + 1]

        in_port = self.net[dpid][prev_node]['port']
        out_port = self.net[dpid][next_node]['port']

        # Forward direction (src -> dst)
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(dp, 5, match, actions)

        # Reverse direction (dst -> src)
        match = parser.OFPMatch(in_port=out_port, eth_dst=src_mac, eth_src=dst_mac)
        actions = [parser.OFPActionOutput(in_port)]
        self.add_flow(dp, 5, match, actions)

        # Restrict ARP request flood to STP-authorized ports (except in_port)
        _stp_ports = self.stp_ports.get(dpid, set())
        out_ports = [port for port in _stp_ports if port != in_port]
        actions = [parser.OFPActionOutput(port) for port in out_ports]
        match = parser.OFPMatch(in_port=in_port, eth_type=0x806, arp_op=1, eth_dst='ff:ff:ff:ff:ff:ff')
        self.add_flow(dp, 10, match, actions)

        # Manually update mac_to_port for learned MACs to avoid Packet-In reliance
        if in_port in _stp_ports:
            self.mac_to_port[dpid][src_mac] = in_port
        if out_port in _stp_ports:
            self.mac_to_port[dpid][dst_mac] = out_port

    def send_all_flow_rules_proactively(self, old, new, STP_changes, new_sws, new_links):
        """
        Remove stale flows if needed, then install proactive flow rules for
        all possible new host-to-host paths. Validates path ports against STP.
        """

        # Removed hosts: delete their rules at once (nothing replaces them)
        rebuild = False
        if self.flow_rules_to_remove and old:
            for host in old:
                host_mac, host_dpid, host_port = host
                for sw in self.sws:
                    self.remove_flows_with_mac(sw[0], host_mac)
        # v3 targeted make-before-break: on a tree, switch or link change, compute the
        # complete rule set of the new tree without sending it, then send only the
        # difference with the installed rules (apply_rule_diff).
        if STP_changes or new_sws or new_links:
            rebuild = True
            new = self.hosts
            if new_sws:
                # a (re)connected switch has an empty table
                fresh = {sw[1] for sw in new_sws}
                self.installed = {k: v for k, v in self.installed.items() if k[0] not in fresh}
            self.collect = {}

        self.flow_rules_to_remove = False

        # For each pair (existing host, new host), compute valid paths and install rules
        for host1 in self.hosts:
            for host2 in new:
                if host1 != host2:
                    if host1[0] in self.net and host2[0] in self.net:
                        if nx.has_path(self.net, host1[0], host2[0]):
                            # v2: the path between two hosts in a tree is unique, so read it
                            # from the tree instead of enumerating every simple path of the
                            # cyclic graph (Yen's algorithm took up to ~1 s in a 6-switch mesh)
                            mst = getattr(self, 'mst', None)
                            if mst is not None and host1[0] in mst and host2[0] in mst \
                                    and nx.has_path(mst, host1[0], host2[0]):
                                paths = [nx.shortest_path(mst, host1[0], host2[0])]
                            else:
                                paths = nx.shortest_simple_paths(self.net, host1[0], host2[0])

                            for path in paths:
                                path_valid = True

                                # Validate each hop respects STP-authorized ports
                                for i in range(len(path) - 1):
                                    src = path[i]
                                    dst = path[i + 1]
                                    if dst not in self.net[src] or src not in self.net[dst]:
                                        path_valid = False
                                        break
                                    out_port = self.net[src][dst].get('port')
                                    in_port = self.net[dst][src].get('port')
                                    if (out_port not in self.stp_ports.get(src, set()) or
                                        in_port not in self.stp_ports.get(dst, set())):
                                        path_valid = False
                                        break

                                if not path_valid:
                                    continue

                                # Install flows hop-by-hop along the path
                                for i in range(len(path) - 1):
                                    src_switch = path[i]
                                    for sw in self.sws:
                                        if sw[1] == src_switch:
                                            self.proactive_flow_rule_install(sw, path)
                                            self.flow_rules_to_remove = True

        if rebuild:
            desired, self.collect = self.collect, None
            self.apply_rule_diff(desired)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle Packet-In events. Buffers packets during STP changes if enabled."""
        msg = ev.msg

        # --- Packet Buffering: when and why ---
        # Buffering is enabled during STP change handling to avoid drops while
        # MST-based flows are being recalculated and installed.
        if self.buffer_enabled and not self._flushing:
            # Do not buffer LLDP/BPDU or IPv6 control traffic
            try:
                pkt_tmp = packet.Packet(msg.data)
                eth_tmp = pkt_tmp.get_protocol(ethernet.ethernet)
                if eth_tmp and (eth_tmp.ethertype == ether.ETH_TYPE_LLDP or eth_tmp.ethertype == 0x86DD):
                    return
            except Exception:
                # If parsing fails, skip buffering unknown packets
                return

            # Maintain bounded buffer size
            if len(self.packet_buffer) >= self.BUFFER_MAX:
                # Evict oldest entry
                self.packet_buffer.pop(0)

            # Store Packet-In with monotonically increasing sequence number
            self.seq += 1
            self.packet_buffer.append((self.seq, msg, time.monotonic()))
            pass  # v2: no per-packet log (it slowed the controller at high rates)
            return

        # If buffering is off, process immediately
        self._handle_packet_in_msg(msg)

    def _handle_packet_in_msg(self, msg):
        """Core Packet-In logic; used for both live and buffered messages."""
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        current_time = time.time()
        t = current_time - self.initial_time

        # Enforce STP: Drop packets arriving on blocked ports (except host port 1)
        if in_port != 1 and in_port not in self.stp_ports.get(dpid, set()):
            return

        # Parse packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        # IPv6 handling: learn hosts from RS/RA/NA ICMPv6 only
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
        if ipv6_pkt:
            icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)
            if icmpv6_pkt and (icmpv6_pkt.type_ == icmpv6.ND_ROUTER_SOLICIT or
                               icmpv6_pkt.type_ == icmpv6.ND_NEIGHBOR_ADVERT or
                               icmpv6_pkt.type_ == icmpv6.ND_ROUTER_ADVERT):
                host_mac = eth.src
                # Only learn host-like MACs
                if host_mac.startswith('00:00:00:00:00:'):
                    host_entry = (host_mac, dpid, in_port)
                    print(f"************ self.hosts: {self.hosts}, host_entry: {host_entry}")
                    if host_entry not in self.hosts:
                        self.hosts.append(host_entry)
                        print(f"{time.time()-self.initial_time:.2f}:Discovered new host: {host_mac} on switch {dpid} at port {in_port}")
            return

        # Ignore LLDP/IPv6 non-host traffic
        if eth and (eth.ethertype == ether.ETH_TYPE_LLDP or eth.ethertype == 0x86DD):
            return

        dst = eth.dst
        src = eth.src
        eth_type = eth.ethertype

        # MAC learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Forwarding decision: unicast known vs restricted flood
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = []

        # If unicast, ensure out_port is STP-authorized
        if out_port != ofproto.OFPP_FLOOD and out_port != 1 and out_port not in self.stp_ports.get(dpid, set()):
            return
        elif out_port == ofproto.OFPP_FLOOD:
            # Restricted broadcast to STP ports except incoming
            stp_ports = self.stp_ports.get(dpid, set())
            out_ports = [port for port in stp_ports if port != in_port]
            actions = [parser.OFPActionOutput(port) for port in out_ports]
        else:
            actions = [parser.OFPActionOutput(out_port)]

        # Packet-Out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        # Install a low-priority unicast flow to avoid repeated Packet-In
        if out_port != ofproto.OFPP_FLOOD and not self._flushing:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, priority=1, match=match, actions=actions)

    def flush_packet_buffer(self):
        """
        Flush buffered Packet-In events in FIFO order after STP stabilizes.
        Drops expired entries based on BUFFER_TIMEOUT.
        """
        self.logger.info("Flushing packet buffer: size=%d", len(self.packet_buffer))

        self._flushing = True
        now = time.monotonic()
        buffer_copy = list(self.packet_buffer)
        self.packet_buffer.clear()
        self.seq = 0

        # Process in sequence order (FIFO)
        buffer_copy.sort(key=lambda x: x[0])
        for (seq, msg, ts) in buffer_copy:
            # Skip expired entries
            if now - ts > self.BUFFER_TIMEOUT:
                continue
            try:
                # Re-process with stabilized STP and updated flows
                self._handle_packet_in_msg(msg)
            except Exception as e:
                self.logger.exception("Error while processing buffered packet: %s", e)

        self._flushing = False

    def _distance_to_failure(self, dpid):
        mst = getattr(self, 'mst', None)
        if not self.fail_dpids or mst is None or dpid not in mst:
            return 0
        best = 1000
        for f in self.fail_dpids:
            if f in mst:
                try:
                    best = min(best, nx.shortest_path_length(mst, dpid, f))
                except nx.NetworkXNoPath:
                    pass
        return best

    def apply_rule_diff(self, desired):
        """Make-before-break, per rule: add the new or changed rules (closest to the
        failure first), then delete the rules that are no longer needed, the reactive
        rules and any rule that outputs to a port that is down."""
        dps = {sw[1]: sw[0] for sw in self.sws}
        cur = self.installed
        adds = [k for k, v in desired.items() if k not in cur or cur[k][3] != v[3]]
        dels = [k for k in cur if k not in desired]
        def send_adds(keys):
            for k in keys:
                dp, match, actions, _ = desired[k]
                if k[0] not in dps:
                    continue
                dp = dps[k[0]]
                parser, ofproto = dp.ofproto_parser, dp.ofproto
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=k[1], cookie=PRO_COOKIE,
                                              match=match, instructions=inst))
        # v4: 1) rules of the switches that were not redirected, 2) release the buffered
        # packets along the new path, 3) rules of the redirected switches
        later = [k for k in adds if k[0] in self.redirect_dpids]
        first = [k for k in adds if k[0] not in self.redirect_dpids]
        first.sort(key=lambda k: (-self._distance_to_failure(k[0]), k[1]))
        send_adds(first)
        if self.redirect_dpids:
            self.flush_packet_buffer()
        send_adds(later)
        for k in dels:
            if k[0] not in dps:
                continue
            dp = dps[k[0]]
            parser, ofproto = dp.ofproto_parser, dp.ofproto
            dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofproto.OFPFC_DELETE_STRICT,
                                          priority=k[1], cookie=PRO_COOKIE,
                                          cookie_mask=COOKIE_MASK, out_port=ofproto.OFPP_ANY,
                                          out_group=ofproto.OFPG_ANY, match=cur[k][1]))
        for sw in self.sws:
            dp = sw[0]
            parser, ofproto = dp.ofproto_parser, dp.ofproto
            dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofproto.OFPFC_DELETE,
                                          table_id=ofproto.OFPTT_ALL, cookie=RE_COOKIE,
                                          cookie_mask=COOKIE_MASK, out_port=ofproto.OFPP_ANY,
                                          out_group=ofproto.OFPG_ANY, match=parser.OFPMatch()))
        # Safety net: no rule of this application may keep forwarding to a port that is down
        for (dpid, port_no) in list(self.down_ports):
            if dpid in dps:
                self.delete_rules_to_port(dps[dpid], port_no)
        self.installed = {k: v for k, v in desired.items() if k[0] in dps}
        for (dpid, port_no) in list(self.down_ports):
            self.installed = {k: v for k, v in self.installed.items()
                              if not (k[0] == dpid and port_no in v[3])}
        self.logger.info("Targeted update: %d rules added or changed, %d deleted, %d unchanged",
                         len(adds), len(dels), len(desired) - len(adds))
        self.fail_dpids = set()
        self.redirect_dpids = set()

    def redirect_to_controller(self, datapath, port_no):
        """Rewrite the proactive unicast rules of a switch that output to a failed port so
        that they output to the controller instead; enable buffering."""
        parser, ofproto = datapath.ofproto_parser, datapath.ofproto
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        n = 0
        for k, v in list(self.installed.items()):
            if k[0] == datapath.id and k[1] == 5 and port_no in v[3]:
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                datapath.send_msg(parser.OFPFlowMod(datapath=datapath, priority=5, cookie=PRO_COOKIE,
                                                    match=v[1], instructions=inst))
                self.installed[k] = (datapath, v[1], actions, ('CONTROLLER',))
                n += 1
        if n:
            self.buffer_enabled = True
            self.redirect_dpids.add(datapath.id)
        self.logger.info("Redirected %d rules of switch %s (port %s down) to the controller. t=%.3f",
                         n, datapath.id, port_no, time.time())

    def delete_rules_to_port(self, datapath, port_no):
        """Delete every rule of this application (both generations) that outputs to port_no."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                table_id=ofproto.OFPTT_ALL,
                                cookie=PRO_COOKIE, cookie_mask=ANY_APP_MASK,
                                out_port=port_no, out_group=ofproto.OFPG_ANY,
                                match=parser.OFPMatch())
        datapath.send_msg(mod)

    def del_flow_rules(self, datapath):
        # Request all flows from a switch
        self.request_flow_stats(datapath)

    def request_flow_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Flow stats request (all tables)
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        # Delete flows selectively (avoid default/65535 priorities)
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for stat in ev.msg.body:
            if (stat.priority == 0) or (stat.priority == 65535):
                continue

            # Rebuild match fields to delete exact flows
            match_fields = {}
            if 'in_port' in stat.match:
                match_fields['in_port'] = stat.match['in_port']
            if 'eth_src' in stat.match:
                match_fields['eth_src'] = stat.match['eth_src']
            if 'eth_dst' in stat.match:
                match_fields['eth_dst'] = stat.match['eth_dst']
            if 'eth_type' in stat.match:
                match_fields['eth_type'] = stat.match['eth_type']
            if 'ipv4_src' in stat.match:
                match_fields['ipv4_src'] = stat.match['ipv4_src']
            if 'ipv4_dst' in stat.match:
                match_fields['ipv4_dst'] = stat.match['ipv4_dst']
            if 'ip_proto' in stat.match:
                match_fields['ip_proto'] = stat.match['ip_proto']
            if 'tcp_src' in stat.match:
                match_fields['tcp_src'] = stat.match['tcp_src']
            if 'tcp_dst' in stat.match:
                match_fields['tcp_dst'] = stat.match['tcp_dst']
            if 'udp_src' in stat.match:
                match_fields['udp_src'] = stat.match['udp_src']
            if 'udp_dst' in stat.match:
                match_fields['udp_dst'] = stat.match['udp_dst']

            match = parser.OFPMatch(**match_fields)
            mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                    priority=stat.priority, match=match,
                                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
            datapath.send_msg(mod)
            self.logger.info("Deleted flow: match=%s, priority=%d", stat.match, stat.priority)

    def handle_port_failure(self, dpid, port_no):
        """
        Handle port failure by removing any retired host, flow rules and learned MACs.
        Also enables buffering so Packet-In events are retained during re-convergence.
        """
        # --- Buffering activation on port-down ---
        self.buffer_enabled = True

        removed_port = port_no
        self.logger.info("Removal of port %s on switch %s detected; topology update should be made", port_no, dpid)

        # Remove MAC bound to the failed port, if present
        mac_to_remove = None
        for mac, port in self.mac_to_port.get(dpid, {}).items():
            if port == removed_port:
                mac_to_remove = mac
                break

        # If a host was on that port, remove the host entry
        for host in self.hosts:
            host_mac, host_dpid, host_port = host
            if host_dpid == dpid and host_port == port_no:
                mac_to_remove = host_mac
                self.hosts = [h for h in self.hosts if h[1] != host_dpid or h[2] != host_port]
                self.logger.info("Removal of host with MAC  %s done", mac_to_remove)
                break

        # v2 (make-before-break): the rules of the affected switch are NOT deleted here.
        # The new tree's rules are installed first and the old generation is deleted
        # afterwards (send_all_flow_rules_proactively), so packets are not sent to the
        # controller while the new tree is being computed.

        # Clean MAC table for the failed port
        if dpid in self.mac_to_port:
            self.mac_to_port[dpid] = {mac: port for mac, port in self.mac_to_port[dpid].items() if port != port_no}
            self.logger.info("Updated mac_to_port for DPID %s after port failure, updated self.mac_to_port: %s", dpid, self.mac_to_port)

    def remove_flows_with_mac(self, datapath, mac):
        """Remove flow rules that match a specific MAC on a switch."""
        self.installed = {k: v for k, v in self.installed.items()
                          if not (k[0] == datapath.id and any(mac == v for _, v in k[2]))}
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Delete flows with eth_src=mac
        match = parser.OFPMatch(eth_src=mac)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            match=match,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY
        )
        datapath.send_msg(mod)

        # Delete flows with eth_dst=mac
        match = parser.OFPMatch(eth_dst=mac)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            match=match,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY
        )
        datapath.send_msg(mod)

        self.logger.info("Removed flow rules with MAC %s on switch %s", mac, datapath.id)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        """
        Handle port status change events.
        - Detect link/port failures (down) and recoveries (up).
        - Port-down triggers buffering and cleanup; port-up logs recovery.
        - Both trigger an immediate STP recomputation; rules are replaced make-before-break (v2).
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        port_no = msg.desc.port_no
        dpid = datapath.id
        reason = msg.reason

        current_time = time.time()

        # Evict stale failure records
        for (dpid_key, port_key), timestamp in list(self.recent_port_failures.items()):
            if current_time - timestamp > PORT_FAILURE_TIMEOUT:
                del self.recent_port_failures[(dpid_key, port_key)]

        # Decode reason and act
        if reason == ofproto.OFPPR_ADD:
            self.logger.info(f"Port {port_no} in switch {dpid} was added.")
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info(f"Port {port_no} in switch {dpid} was deleted.")
        elif reason == ofproto.OFPPR_MODIFY:
            # Determine link state
            is_port_up = not (msg.desc.state & ofproto.OFPPS_LINK_DOWN)
            if not is_port_up:
                # --- Port-down: detect link or port failure ---
                self.logger.info(f"Port {port_no} in switch {dpid} is down (link failure). t={current_time:.3f}")

                # Avoid duplicate handling for the same port-down event within timeout window
                if (dpid, port_no) in self.recent_port_failures:
                    self.logger.info(f"Duplicate port failure event for DPID={dpid}, Port={port_no}. Ignoring.")
                    return

                # Record failure timestamp and the port as down
                self.recent_port_failures[(dpid, port_no)] = current_time
                self.down_ports.add((dpid, port_no))
                self.fail_dpids.add(dpid)
                # v4: send to the controller (and buffer) what would be lost at the dead port
                self.redirect_to_controller(datapath, port_no)

                if port_no in self.stp_ports.get(dpid, set()):
                    # --- Buffering activation + local cleanup ---
                    self.handle_port_failure(dpid, port_no)
                # v2: always rebuild the rules (make-before-break), even if the port was not
                # in the tree computed last: installed rules may still point to it
                self.force_rebuild = True
                self.trigger_recompute("port %s of switch %s down" % (port_no, dpid))
            else:
                # --- Port-up: note recovery (STP will be recomputed by monitor) ---
                self.logger.info(f"Port {port_no} in switch {dpid} is UP (link restored).")
                self.down_ports.discard((dpid, port_no))
                self.recent_port_failures.pop((dpid, port_no), None)
                self.force_rebuild = True
                # The link itself comes back when LLDP rediscovers it (EventLinkAdd)
                self.trigger_recompute("port %s of switch %s up" % (port_no, dpid))
