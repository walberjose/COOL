# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import lldp
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types


# Generate the graph topology
import networkx as nx

# Utils
from ryu.app.LONG.long_utils import flow_creator

# Below is the library used for topo discovery
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.app.LONG.Interfaces import simple_flow_creation_interface

#long_interface import Long_Interface
import json
from webob import Response

'''
sudo PYTHONPATH=. ./bin/ryu-manager --enable-debug --observe-links --verbose  ryu/app/LONG/simple_flow_creation.py
'''

simple_flow_creation_instance_name = 'simple_switch_api_app'
url = '/simpleswitch/'

class Simple_Flow_Creation(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}
    def __init__(self, *args, **kwargs):
        super(Simple_Flow_Creation, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(simple_flow_creation_interface, {simple_flow_creation_instance_name: self})

        self.mac_to_port = {}
        self.datapaths = {}

        self.topology = nx.DiGraph()

        self.paths = {}

        # Cycle-4 topology:
        self.hosts = {'10.0.0.1': {'switch': 1, 'arp': "00:00:00:00:00:01", 'port': 1, 'router':'10.0.0.254'},
                       '10.0.0.3': {'switch': 3, 'arp': "00:00:00:00:00:03", 'port': 1, 'router':'10.0.0.254'}}

        self.ip_controller = {"10.0.0.254":'00:00:00:00:00:fe',"10.2.0.254":'00:00:00:00:00:fe'}
        self.arp_controller = '00:00:00:00:00:fe'
        self.group_id = {}

    """
        Get a port from a src node to dst node
    """

    def get_port_from_adjacent_nodes(self, src_node, dst_node):
        # print "Get port from %s to %s" % (src_node, dst_node)
        if src_node in self.hosts:
            return self.hosts[src_node]['port']
        elif dst_node in self.hosts:
            return self.hosts[dst_node]['port']
        return self.topology[src_node][dst_node]['port']


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = ofp_parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        idle_timeout=1,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    '''
    To handler log error information.
    '''
    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER,
                                             CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.debug('OFPErrorMsg received: type=0x%02x code=0x%02x '
                          'message=%s', msg.type, msg.code,
                          type(msg.data))

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        LINK_UP = 0 # definition of LINK_UP because it is not defined in ryu.ofproto.ofproto_v1_3
        msg = ev.msg  # ryu.ofproto.ofproto_v1_3_parser.OFPPortStatus
        dp = msg.datapath
        dpid = dp.id
        ofp = dp.ofproto
        reason = ""
        if msg.reason == ofp.OFPPR_ADD:
            reason = 'ADD'
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = 'MODIFY'
        else:
            reason = 'unknown'

        print 'OFPPortStatus received: reason=%s desc=%s' % (reason, msg.desc)
        self.logger.debug('OFPPortStatus received: reason=%s desc=%s',
                          reason, msg.desc)

        port = msg.desc
        if port.state == ofproto_v1_3.OFPPS_LINK_DOWN:
            print "Link down at %s datapath ID" % (dpid)
            print "Remained edges:", self.topology[dpid]
            #Edges: {2: {'port': 2}, 4: {'port': 3}}
            # Exclude the link (edge) in the graph
            failure_port = port.port_no
            for switch in self.topology[dpid]:
                print failure_port,self.topology[dpid][switch]['port']
                if failure_port == self.topology[dpid][switch]['port']:
                    # print "Found the failure port: %s, neighbor switch:%s"%(port,switch)
                    self.topology.remove_edge(dpid, switch)
                    self.topology.remove_edge(switch, dpid)  # It is a Digraph!
                    break
            #TODO: Apply here the recover method:
            #1. Find the affected flows
            #2. Calculate new rules to restore the affected flows
            #3. Install the restoration rules

        elif port.state == ofproto_v1_3.OFPPS_LIVE:
            # Live for Fast Failover Group.
            print "Link live"
        elif port.state == ofproto_v1_3.OFPPS_BLOCKED:
            print "Port is blocked!"
        elif port.state == LINK_UP:
            # Using LLDP to recover the topology information!
            # self.topology.add_edge(dpid, switch)
            # self.topology.add_edge(switch, dpid)  # It is a Digraph!
            print "Link is up!"
            # import time
            # millis = int(round(time.time() * 1000))
            # print millis


    """
        The event EventSwitchLeave will trigger the activation of get_topology_data().
    """

    @set_ev_cls(event.EventSwitchLeave)
    def _event_switch_leave_handler(self, ev):
        msg = ev.switch.to_dict()
        # Removing switches:
        dpid = int(msg['dpid'], 16)  # Convert Hex to Int
        # Exclude the switch from topology
        self.topology.remove_node(dpid)
        print self.topology
        del self.datapaths[dpid]
        print self.datapaths

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):

        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        self.logger.debug('OFPFlowRemoved received: '
                          'cookie=%d priority=%d reason=%s table_id=%d '
                          'duration_sec=%d duration_nsec=%d '
                          'idle_timeout=%d hard_timeout=%d '
                          'packet_count=%d byte_count=%d match.fields=%s',
                          msg.cookie, msg.priority, reason, msg.table_id,
                          msg.duration_sec, msg.duration_nsec,
                          msg.idle_timeout, msg.hard_timeout,
                          msg.packet_count, msg.byte_count, msg.match)

        print "Oi",dp.id, msg.match


    """
    The event EventSwitchEnter will trigger the activation of get_topology_data().
    """

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        msg = ev.switch.to_dict()
        dpid = msg['dpid']
        # switch_list = get_switch(self.topology_api_app, None)
        switch_list = get_switch(self, None)
        for switch in switch_list:
            # print switch.dp.id,"!!!!!!!!!!!!!!!!!!!!"
            if switch.dp.id not in self.datapaths:
                self.datapaths[switch.dp.id] = switch.dp

        switches = [switch.dp.id for switch in switch_list]
        links_list = get_link(self, None)
        #print links_list
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        #print links, "Links<<<<<<<<<<<<<<<<<"
        # [(2, 3, {'port': 3}), (2, 1, {'port': 2}), (3, 2, {'port': 2}), (1, 2, {'port': 2})] Links << << << << << << << << <
        for link in links:
            src, dst, port = link
            self.topology.add_edge(src, dst, port)
        #print links

    """
    Generate the set of meta instructions to a given path.
    """

    def get_instructions(self,ip_src,ip_dst, primary_path, backup_path=None,msg=None):
        print "Primary path:%s Backup path:%s"%(primary_path,backup_path)
        dict_of_inst = {}
        # if backup_path == None or len(backup_path) == 0:
        #     # print "Why?!!! :'("
        #     return dict_of_inst
        if primary_path == None:
            return dict_of_inst
        else:
            print "Primary path:", primary_path,"Backup path:",backup_path
            #Path:[1, 2, 3]
            #Instructions: {(3, 2): {'port': 2}, (2, 1): {'port': 1}}
            #Just create a single set of instructions:
            node = primary_path[0]
            in_port = 0#self.get_port_from_adjacent_nodes(ip_src, None)
            if len(primary_path) == 1:
                #Special case, where exist only one element in the primary_path
                in_port = msg.match['in_port']
                out_port = self.get_port_from_adjacent_nodes(None,ip_dst)
                return {(primary_path[0],primary_path[0]):{'in_port':in_port,'out_port':out_port}}
            for i in range(0, len(primary_path) - 1):
                if i == 0:
                    in_port = self.get_port_from_adjacent_nodes(ip_src, None)
                else:
                    in_port = self.get_port_from_adjacent_nodes(primary_path[i],primary_path[i-1])
                # print "From %s to %s on port %s" % (backup_path[num_flows], backup_path[num_flows + 1], self.topology[backup_path[num_flows]][backup_path[num_flows + 1]])
                out_port = self.topology[primary_path[i]][primary_path[i + 1]]['port']
                #print out_port,"<<<<<<<"
                dict_of_inst[primary_path[i], primary_path[i + 1]] = {'in_port':in_port,'out_port':out_port}#self.topology[primary_path[num_flows]][primary_path[num_flows + 1]]
                node = primary_path[i]
                if i+1 == len(primary_path)-1:
                    out_port = self.get_port_from_adjacent_nodes(None,ip_dst)
                    in_port = self.topology[primary_path[i+1]][primary_path[i]]['port']
                    dict_of_inst[primary_path[i+1],ip_dst] = {'in_port': in_port,
                                                                      'out_port': out_port}
            #Instructions: {(1, 2): {'port': 2}, (11, 10): {'port': 4}, (3, 1): {'port': 2}, (2, 11): {'port': 3}}
            return dict_of_inst

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            lldp_pkt = pkt.get_protocol(lldp.lldp)
            #Update the topology
            chassis = lldp_pkt.tlvs[0]
            dpid_adj = int(chassis.chassis_id[5:],16)
            self.topology.add_edge(dpid, dpid_adj, {'port': in_port})
            return

        dst = eth_pkt.dst
        src = eth_pkt.src

        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # treat arp requests:
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            print "treat arp"
            # treat arp broadcast requests:
            if arp_pkt.dst_mac == '00:00:00:00:00:00':

                # treat arp broadcast for the controller:
                if arp_pkt.dst_ip in self.ip_controller:
                    if arp_pkt.opcode == arp.ARP_REQUEST:
                        self.logger.debug("ARP type request to the controller %s.", arp_pkt.dst_ip)
                        flow_creator._handle_arp(datapath, in_port, eth_pkt, arp_pkt, self.arp_controller,
                                                    arp_pkt.dst_ip)
                        self.logger.debug("Sended ARP the controller")
                        return 0
                    elif arp_pkt.opcode == arp.ARP_REPLY:
                        # Exclude this code:
                        pass
                        # print "Server %s MAC %s is alive at %s port! "%(arp_pkt.src_ip,arp_pkt.src_mac,in_port)
                        # self.live_servers[arp_pkt.src_ip]=arp_pkt.src_mac,in_port

                elif arp_pkt.dst_ip in self.hosts:
                    # print "\n\n\n>>>>>>>>>>>Arp to ", arp_pkt.dst_ip
                    flow_creator._handle_arp(datapath, in_port, eth_pkt, arp_pkt, self.hosts[arp_pkt.dst_ip]['arp'],
                                                arp_pkt.dst_ip)
                    # packets_handler.create_l2_flow(datapath,in_port,out_port=self.hosts[arp_pkt.dst_ip]['port'])
                # treat arp for someone else:
                else:
                    print "Dont know!", arp_pkt.dst_ip
        # treat L3 packets:
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            # print "treat ipv4 in switch %s with %s input port"%(datapath.id,in_port)
            if ip_pkt.dst in self.ip_controller:
                # treat ICMP packets for the controller
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt:
                    print "Ping to controller!"
                    flow_creator._handle_icmp(datapath, in_port, eth_pkt, ip_pkt, icmp_pkt,self.arp_controller, ip_pkt.dst)
            #elif ip_pkt.dst == self.ip_controller:
            #TODO: Path Protection algorithm
            elif ip_pkt.src in self.hosts and ip_pkt.dst in self.hosts:
                # print self.topology
                sw_src = self.hosts[ip_pkt.src]['switch']
                sw_dst = self.hosts[ip_pkt.dst]['switch']
                #Simple flow creation: Ok!
                print "Buffer_id:",msg.buffer_id
                self.simple_flow_creation(ip_pkt.src, ip_pkt.dst, sw_src, sw_dst,msg)
            else:
                print "Treat other thing: %s",ip_pkt


    def simple_flow_creation(self,src_ip,dst_ip,sw_src,sw_dst,msg):
        path = list(nx.shortest_path(self.topology, sw_src,sw_dst))
        if (src_ip, dst_ip) not in self.paths:
            self.paths[(src_ip, dst_ip)] = path
        else:
            print "\n\n\nIt has already a path to the pair %s %s "%(src_ip, dst_ip)
        endpoints = {(src_ip,dst_ip): {'primary':path,'backup':None}}
        self.path_creator(endpoints=endpoints, msg=msg)


    def path_creator(self,endpoints=None, msg=None):
        if endpoints == None or endpoints == {}:
            endpoints = self.endpoints
        for endpoint_index, endpoint in enumerate(endpoints):
            # Get switches:
            src, dst = endpoint
            primary_path = endpoints[endpoint]['primary']
            backup_path = endpoints[endpoint]['backup']

            instructions = self.get_instructions(src,dst,primary_path,backup_path,msg)
            path = primary_path
            print "Instructions:",instructions


            node_before = src  # Initiate sw_before
            # Creating primary path
            for nodes in instructions:
                node,destin = nodes
                in_port = instructions[nodes]['in_port']
                out_port = instructions[nodes]['out_port']

                flow_creator.create_l3_flow_with_wildcard(self.datapaths[node], in_port, out_port=out_port,
                                            msg=msg,dst_prefix="255.255.255.255",modify_rule=False)




if __name__ == '__main__':
    pass
    # topo = Topology_discover(None, None, None)
    # links = [(2, 3, {'port': 3}), (2, 1, {'port': 2}), (3, 2, {'port': 2}), (1, 2, {'port': 2})]
    # topology = topo.topology
    # topology.add_nodes_from(switches)
