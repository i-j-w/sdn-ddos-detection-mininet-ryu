from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.lib import hub
import math
from collections import defaultdict

class SimpleDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleDetector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.packet_count = defaultdict(int)
        self.src_ip_count = defaultdict(int)
        self.threshold = 15000
        self.entropy_threshold = 0.6
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

        self.datapaths[datapath.id] = datapath
        self.logger.info("Switch %s connected", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt:
            src = ip_pkt.src
            key = (datapath.id, src)
            self.packet_count[key] += 1
            self.src_ip_count[src] += 1

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

    def calculate_entropy(self):
        total = sum(self.src_ip_count.values())
        if total == 0:
            return 0.0

        entropy = 0.0
        for count in self.src_ip_count.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    def _monitor(self):
        while True:
            hub.sleep(5)
            self.logger.info("----- Checking -----")

            # Threshold detection
            for key, count in list(self.packet_count.items()):
                dpid, src_ip = key
                self.logger.info("Switch %s | IP %s -> %d packets", dpid, src_ip, count)
                if count > self.threshold and src_ip != "10.0.0.1":
                    self.logger.warning("*** THRESHOLD ATTACK DETECTED from %s ***", src_ip)
                    self.block_ip(dpid, src_ip)

            # Entropy detection
            entropy = self.calculate_entropy()
            self.logger.info("Current Entropy: %.4f", entropy)
            if entropy < self.entropy_threshold and sum(self.src_ip_count.values()) > 2000:
                self.logger.warning("*** LOW ENTROPY ATTACK DETECTED (Entropy=%.4f) ***", entropy)

            self.packet_count.clear()
            self.src_ip_count.clear()

    def block_ip(self, dpid, src_ip):
        datapath = self.datapaths.get(dpid)
        if not datapath:
            return

        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=[],
            idle_timeout=30
        )
        datapath.send_msg(mod)
        self.logger.info(">>> Drop rule installed for %s on switch %s", src_ip, dpid)
