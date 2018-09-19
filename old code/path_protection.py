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

#Enable multithread in Ryu (Eventle)
from ryu.lib import hub
from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker

# Generate the graph topology
import networkx as nx

# Utils
#from ryu.app.sdnip.sdnip_utils.packets_utils import packets_handler
from ryu.app.LONG.long_utils import flow_creator
import time
from operator import attrgetter

# Below is the library used for topo discovery
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.app.LONG.long_interface import Long_Interface
import json
from webob import Response

'''
sudo PYTHONPATH=. ./bin/ryu-manager --observe-links ryu/app/LONG/long.py
'''

simple_switch_instance_name = 'simple_switch_api_app'
url = '/simpleswitch/'

class CongestionController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}
    def __init__(self, *args, **kwargs):
        super(CongestionController, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(Long_Interface, {simple_switch_instance_name: self})

        self.mac_to_port = {}
        self.datapaths = {}

        self.topology = nx.DiGraph()



        # Cycle-4 topology:
        self.hosts = {'10.0.0.1': {'switch': 1, 'arp': "00:00:00:00:00:01", 'port': 1, 'router':'10.0.0.254'},
                       '10.0.0.3': {'switch': 3, 'arp': "00:00:00:00:00:03", 'port': 1, 'router':'10.0.0.254'}}

        self.ip_controller = {"10.0.0.254":'00:00:00:00:00:fe',"10.2.0.254":'00:00:00:00:00:fe'}
        self.arp_controller = '00:00:00:00:00:fe'
        self.group_id = {}


    def creating_paths(self,endpoints=None,fine_grain=False,modify_rule=False,change_arp=True,pkt=None,primary_path=None):
        print "Primary path:", primary_path
        if endpoints == None or endpoints == {}:
            endpoints = self.endpoints
        print endpoints,"<<<<<<<<<<<Endpoints"
        for endpoint_index, endpoint in enumerate(endpoints):

            buckets = {}
            # Get switches:
            src, dst = endpoint
            group_id = self.hosts[src]['switch'] #endpoint_index + 1
            path = endpoints[endpoint]  # self.topo.find_shortest_path(switch_src, switch_dst)
            #A bug: IPs connected to the same switch! Remove it!!!
            if path[0] == path[-1]:
                continue
            print "Creating rules for %s,%s"%(src,dst)
            switch_src = self.hosts[src]['switch']
            switch_dst = self.hosts[dst]['switch']
            eth_pkt = None

            ip_pkt = ipv4.ipv4(src=src, dst=dst)
            #print path
            #print path,"Antes!",primary_path
            backup_path = self.get_instructions(primary_path,path)
            print "primary_path:",primary_path,backup_path," <-backup path!"
            #print "Instructions:", instr
            #Primary path:[1, 3, 10] Backup path:[1, 3, 1, 2, 11, 10]
            #buckets = self.get_buckets(primary_path,path)
            # for node_in_primary_path in primary_path:
            #     for node_in_backup_path in path:
            #         if node_in_primary_path == node_in_backup_path:
            #             primary_out_port = self.get_port_from_adjacent_nodes(node_in_primary_path, dst)
            #             backup_out_port = self.get_port_from_adjacent_nodes(None, dst)
            #             buckets[node_in_backup_path]=

            #print buckets,"Buckets"
            node_before = src  # Initiate sw_before
            # Creating primary path
            for index, node in enumerate(backup_path):
                dst_prefix = "255.255.255.0"
                if fine_grain:
                    dst_prefix = "255.255.255.255"
                in_port = 0
                backup_port = 0
                if index == 0:
                    in_port = self.get_port_from_adjacent_nodes(src, None)
                if index + 1 == len(backup_path):  # If it is the last datapath of the path
                    out_port = self.get_port_from_adjacent_nodes(None, dst)  # Create the fowarding rule to the host
                    # Featching the ARP address of the host's default router.
                    if change_arp:
                        eth_pkt = ethernet.ethernet(dst=self.hosts[dst]['arp'],
                                                src=self.ip_controller[self.hosts[src]['router']])
                    if pkt != None:
                        flow_creator._send_packet(self.datapaths[node], out_port, pkt)
                    #Specific to the host!
                    dst_prefix = "255.255.255.255"
                else:
                    sw_next = backup_path[index + 1]
                    if node_before == sw_next:
                        print backup_path,index,node_before,sw_next,"Found a loop!!!! \o/"
                        out_port = ofproto_v1_3.OFPP_IN_PORT
                    else:
                        print node,sw_next,"<<<<<<",primary_path,index, sw_next
                        # Primary path:[1, 4, 3, 10] Backup path:[1, 4, 3,4, 1, 2, 11, 10]
                        out_port = self.get_port_from_adjacent_nodes(node, sw_next)
                        if primary_path != None:
                            if index+1 >= len(primary_path):
                                pass
                            elif (primary_path[index]==backup_path[index]) and (primary_path[index+1] != sw_next):
                                out_port= self.get_port_from_adjacent_nodes(node, primary_path[index+1])
                                backup_port = self.get_port_from_adjacent_nodes(node, sw_next)
                                print node,"Aquiiiiiiiiiiiiiiiiiii!!!!!!\o/",out_port,backup_port

                in_port = self.get_port_from_adjacent_nodes(node, node_before)
                # print "DPID %s"%node,"Inport:%s"%in_port,"Outport:%s"%out_port,\
                #                                "Eth pkt:%s"%eth_pkt, "IP pkt: %s"%ip_pkt,"Prefix src:%s"%"255.255.255.255",\
                #                                              "Prefix dst:%s"%dst_prefix



                # print "Primary path:", sw, "Primary port:", buckets[sw]
                # print "dp:", node, " in port:", in_port, " out port:", buckets[sw], \
                #     " bucket port:", out_port, "group_id", group_id
                if group_id not in self.group_id:
                    self.group_id[group_id] = [out_port]
                else:
                    print self.group_id[group_id],"Antes"
                    if backup_port != 0:
                        self.group_id[group_id] += [backup_port]
                    print self.group_id[group_id],"Depois"

                print "Creating Group_id %s in dpid %s to output port %s backup port %s" % (group_id,node, out_port,backup_port)

                if backup_port == 0:
                    flow_creator.create_group_mod_failover_flow(self.datapaths[node], group_id,
                                                               out_port=out_port, backup_output_port=backup_port,
                                                               create_group_id=True)
                else:
                    flow_creator.create_group_mod_failover_flow(self.datapaths[node], group_id,
                                                                out_port=out_port, backup_output_port=backup_port,
                                                                create_group_id=False)
                # print "Creating in dpid %s inport %s output %s group_id %s" % (
                # self.datapaths[node], in_port, out_port, group_id)
                flow_creator.create_l3_failover_flow(self.datapaths[node], in_port, out_port=out_port,
                                                        eth_pkt=eth_pkt, ip_pkt=ip_pkt, group_id=group_id)
                print "Group ID:",self.group_id
                # If is simple creation:
                # flow_creator.create_l3_flow_with_wildcard(self.datapaths[node], in_port, out_port=out_port,
                #                                eth_pkt=eth_pkt, ip_pkt=ip_pkt,src_prefix="255.255.255.255",
                #                                              dst_prefix=dst_prefix,modify_rule=modify_rule)
                # print node_before,"Switch before"
                node_before = node

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

        # msg.desc is Instance of OFPPort
        # OFPPort(port_no=1,hw_addr='32:2b:07:c8:33:d4',name='s1-eth1',config=0,state=0,curr=2112,advertised=0,supported=0,peer=0,curr_speed=10000000,max_speed=0)

        # enum ofp_port_state
        # OFPPS_LINK_DOWN = 1 << 0  # No physical link present.
        # OFPPS_BLOCKED = 1 << 1  # Port is blocked.
        # OFPPS_LIVE = 1 << 2  # Live for Fast Failover Group


        print type(msg), msg
        print type(msg.desc)
        port = msg.desc
        if port.state == ofproto_v1_3.OFPPS_LINK_DOWN:
            print "Link down at %s" % (dpid)
            print "Edges:", self.topology[dpid]
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
                #self.simple_flow_creation(ip_pkt.src, ip_pkt.dst, sw_src, sw_dst,msg,buffer_id=msg.buffer_id)
                #Path protection:
                print 'Applying Path protection:'
                self.path_protection(ip_pkt.src, ip_pkt.dst, sw_src, sw_dst, msg)

            else:
                print "Treat other thing: %s",ip_pkt

    def failover_path_creator(self, endpoints=None, fine_grain=False, modify_rule=False, change_arp=True, msg=None,
                     primary_path=None, buffer_id=None):
        if endpoints == None or endpoints == {}:
            endpoints = self.endpoints
        for endpoint_index, endpoint in enumerate(endpoints):
            # Get switches:
            src, dst = endpoint
            primary_path = endpoints[endpoint]['primary']
            backup_path = endpoints[endpoint]['backup']
            instructions = self.get_failover_instructions(src,dst,primary_path,backup_path,msg)

            print "Instructions:",instructions

            for index,sw_src in enumerate(instructions):
                #{1: {2: {'out_port': 2, 'in_port': 1, 'backup_port': 3}},
                # 2: {3: {'out_port': 2, 'in_port': 1, 'backup_port': 1}},
                # 3: {'10.0.0.3': {'out_port': 1, 'in_port': 2}},
                # 4: {3: {'out_port': 1, 'in_port': 2}}}
                has_backup_path = False
                if 'backup_port' in instructions[sw_src]:
                    has_backup_path = True

                print ">>>>>>>",instructions[sw_src]
                primary_output_port = instructions[sw_src]['out_port']
                primary_input_port  = instructions[sw_src]['in_port']
                sw_dst              = instructions[sw_src]['forward_switch']
                backup_output_port = 0
                if has_backup_path:
                    backup_output_port  = instructions[sw_src]['backup_port']



                group_id = int(str(primary_path[0])+str(primary_path[-1]))

                #Create Group type Fast Failover
                #create_group_mod_failover_flow(datapath, group_id, out_port, backup_output_port=0,
                #                               create_group_id=False):
                if has_backup_path:
                    flow_creator.create_group_mod_failover_flow(self.datapaths[sw_src],group_id, primary_output_port,
                                                            backup_output_port,create_group_id=True)
                else:
                    flow_creator.create_group_mod_failover_flow(self.datapaths[sw_src], group_id, primary_output_port,
                                                                primary_output_port, create_group_id=False)#backup_output_port, create_group_id=True)
                #create_l3_failover_flow(datapath, in_port, out_port, ip_pkt, group_id=1, eth_pkt=None):

                #Recovering the IPv4 packet from Packet-In event
                pkt = packet.Packet(msg.data)
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                flow_creator.create_l3_failover_flow(self.datapaths[sw_src],primary_input_port, primary_output_port,
                                                     ip_pkt, group_id=group_id)
                if has_backup_path:
                    flow_creator.create_l3_failover_flow(self.datapaths[sw_src], primary_output_port,
                                                         backup_output_port,
                                                         ip_pkt, group_id=group_id)

    '''
        Get failover instructions
    '''


    def get_failover_instructions(self, ip_src, ip_dst, primary_path, backup_path=None, msg=None):
        print "Primary path:%s Backup path:%s" % (primary_path, backup_path)
        dict_of_inst = {}
        # if backup_path == None or len(backup_path) == 0:
        #     # print "Why?!!! :'("
        #     return dict_of_inst
        if primary_path == None:
            return dict_of_inst
        else:
            print "Primary path:", primary_path, "Backup path:", backup_path
            # Path:[1, 2, 3]
            # Instructions: {(3, 2): {'port': 2}, (2, 1): {'port': 1}}
            # Just create a single set of instructions:
            node = primary_path[0]
            in_port = 0  # self.get_port_from_adjacent_nodes(ip_src, None)
            if len(primary_path) == 1:
                # Special case, where exist only one element in the primary_path
                in_port = msg.match['in_port']
                out_port = self.get_port_from_adjacent_nodes(None, ip_dst)
                return {(primary_path[0], primary_path[0]): {'in_port': in_port, 'out_port': out_port}}
            # Adding primary path:
            for i in range(0, len(primary_path) - 1):
                if i == 0:
                    in_port = self.get_port_from_adjacent_nodes(ip_src, None)
                else:
                    in_port = self.get_port_from_adjacent_nodes(primary_path[i], primary_path[i - 1])
                # print "From %s to %s on port %s" % (backup_path[num_flows], backup_path[num_flows + 1], self.topology[backup_path[num_flows]][backup_path[num_flows + 1]])
                out_port = self.topology[primary_path[i]][primary_path[i + 1]]['port']
                # print out_port,"<<<<<<<"
                if primary_path[i] in backup_path:
                    index = backup_path.index(primary_path[i])
                    print primary_path[i],"Backup?",backup_path[index],backup_path[index + 1]
                    dict_of_inst[primary_path[i]] ={ 'in_port': in_port,
                                                    'out_port': out_port,
                                                    'backup_port': self.topology[backup_path[index]][backup_path[index + 1]]['port'],
                                                     'forward_switch':primary_path[i + 1],
                                                     'backup_switch':backup_path[index + 1]}
                else:
                    dict_of_inst[primary_path[i]] = {'in_port': in_port,
                                                     'out_port': out_port,
                                                     'forward_switch': primary_path[i + 1]}
                node = primary_path[i]
                if i + 1 == len(primary_path) - 1:
                    out_port = self.get_port_from_adjacent_nodes(None, ip_dst)
                    in_port = self.topology[primary_path[i + 1]][primary_path[i]]['port']
                    dict_of_inst[primary_path[i+1]] = {'in_port': in_port,
                                                     'out_port': out_port,
                                                     'forward_switch': ip_dst}
            print "Primary path>",dict_of_inst
            # Instructions: {1: {'primary': {2: {'out_port': 2, 'in_port': 1}}},
            # 2: {'primary': {3: {'out_port': 2, 'in_port': 1}}},
            # 3: {'primary': {'10.0.0.3': {'out_port': 1, 'in_port': 2}}}}
            #Adding backup path:
            for i in range(0, len(backup_path) - 1):
                if i == 0:
                    in_port = self.get_port_from_adjacent_nodes(ip_src, None)
                else:
                    in_port = self.get_port_from_adjacent_nodes(backup_path[i], backup_path[i - 1])
                # print "From %s to %s on port %s" % (backup_path[num_flows], backup_path[num_flows + 1], self.topology[backup_path[num_flows]][backup_path[num_flows + 1]])
                out_port = self.topology[backup_path[i]][backup_path[i + 1]]['port']
                # print out_port,"<<<<<<<"
                if backup_path[i] not in dict_of_inst:
                    dict_of_inst[backup_path[i]] = {'in_port': in_port,
                                                     'out_port': out_port,
                                                     'forward_switch': backup_path[i + 1]}

                # else:
                #     print "before:",dict_of_inst[backup_path[num_flows]]
                #     #{'primary': {3: {'out_port': 2, 'in_port': 1}}}
                #     dict_of_inst[backup_path[num_flows]]['backup'] ={dict_of_inst[backup_path[num_flows]], {backup_path[num_flows + 1]: {'in_port': in_port,
                #                                                       'out_port': out_port}}}
                #     print "after:", dict_of_inst[backup_path[num_flows]]
                node = backup_path[i]
                if i + 1 == len(backup_path) - 1:
                    out_port = self.get_port_from_adjacent_nodes(None, ip_dst)
                    in_port = self.topology[backup_path[i + 1]][backup_path[i]]['port']
                    if backup_path[i] not in dict_of_inst:
                        dict_of_inst[backup_path[i + 1]] = {'in_port': in_port,
                                                            'out_port': out_port,
                                                            'forward_switch': ip_dst}
                    # else:
                    #     dict_of_inst[backup_path[num_flows]]['backup'] = {ip_dst: {#'in_port': in_port,
                    #                                                                    'out_port': out_port}}

            return dict_of_inst


    def simple_flow_creation(self,src_ip,dst_ip,sw_src,sw_dst,msg,buffer_id):
        path = list(nx.shortest_path(self.topology, sw_src,sw_dst))
        # ('10.0.0.1', '10.0.0.4'): [1, 2, 11, 8, 7, 4],
        #copy_of_nxgraph = self.topology.copy()
        #copy_of_nxgraph.remove_edge(2, 11)
        #backup_path = list(nx.shortest_path(copy_of_nxgraph, 2, sw_src,sw_dst))

        # reverse_path = list(nx.shortest_path(self.topology, sw_ip_dst,sw_ip_src))
        endpoints = {(src_ip,dst_ip): {'primary':path,'backup':None}}
                     #(src_ip,dst_ip): backup_path}
        #             (ip_pkt.dst, ip_pkt.src): reverse_path}
        #print endpoints, path#, backup_path
        self.path_creator(endpoints=endpoints, fine_grain=True, change_arp=False, msg=msg,buffer_id=buffer_id)

    # def get_buckets(self, primary_path, backup_path):
    #     # Primary backup_path:[1, 3, 10] Backup backup_path:[1, 3, 1, 2, 11, 10]
    #
    #     #value_when_true if condition else value_when_false
    #     #longest_path = len(backup_path) if len(backup_path)>len(primary_path) else len(primary_path)
    #     buckets = {}
    #     #for i_primary_path,node_in_primary_path in enumerate(primary_path):
    #     for index,node_in_backup_path in enumerate(backup_path):
    #             if primary_path[index] == backup_path[index]:
    #                 if index+1 == len(primary_path):
    #                     buckets[node_in_backup_path]
    #                 else primary_path[index+1] == backup_path[index+1]:
    #                     continue
    #
    #                     buckets[node_in_backup_path] = self.get_port_from_adjacent_nodes(primary_path[i_primary_path],
    #                                                                          primary_path[i_primary_path + 1])
    #
    #                 primary_out_port = self.get_port_from_adjacent_nodes(primary_path[i_primary_path], primary_path[i_primary_path+1])
    #                 backup_out_port = self.get_port_from_adjacent_nodes(backup_path[index], backup_path[index+1])
    #                 buckets[node_in_backup_path] = [primary_out_port,backup_out_port]
    #     return buckets
    def path_creator(self,endpoints=None,fine_grain=False,modify_rule=False,change_arp=True,msg=None,primary_path=None,buffer_id=None):
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

            eth_pkt = None
            ip_pkt = ipv4.ipv4(src=src, dst=dst)

            node_before = src  # Initiate sw_before
            # Creating primary path
            for nodes in instructions:
                #Instructions: {(1, 2): {'out_port': 2, 'in_port': 1}, (2, 3): {'out_port': 2, 'in_port': 1},
                #               (3, '10.0.0.3'): {'out_port': 1, 'in_port': 2}}

                dst_prefix = "255.255.255.0"
                if fine_grain:
                    dst_prefix = "255.255.255.255"
                node,destin = nodes
                in_port = instructions[nodes]['in_port']
                out_port = instructions[nodes]['out_port']

                #Forward the packet to final destination
                # if destin in self.hosts and pkt != None:
                #     flow_creator._send_packet(self.datapaths[node], out_port, pkt)

                if msg.buffer_id == ofproto_v1_3.OFP_NO_BUFFER:
                    print "Vai dar merda!",msg.buffer_id
                    #data = msg.data
                # else:
                #     print "Esta ok!",msg.buffer_id

                flow_creator.create_l3_flow_with_wildcard(self.datapaths[node], in_port, out_port=out_port,
                                               eth_pkt=eth_pkt, ip_pkt=ip_pkt,src_prefix="255.255.255.255",
                                                             dst_prefix=dst_prefix,modify_rule=modify_rule,buffer_id=buffer_id)


    def path_protection(self,src_ip,dst_ip,sw_src,sw_dst,msg):
        path = list(nx.shortest_path(self.topology, sw_src,sw_dst))
        protected_path = path[:len(path)]
        protected_path_length = len(protected_path)
        for index,node in enumerate(protected_path):
            if index+1 == len(protected_path):
               break
            print path,protected_path
            #path:[1, 2, 3], protected:[1, 2]
            # ('10.0.0.1', '10.0.0.4'): [1, 2, 11, 8, 7, 4],
            #path: [1, 2, 11, 8, 7, 4],
            #protected_path: [1, 2, 11, 8, 7]
            copy_of_nxgraph = self.topology.copy()
            print index,"Protecting link ",path[protected_path_length-2-index],path[protected_path_length-1-index]

            copy_of_nxgraph.remove_edge(path[protected_path_length-2-index],path[protected_path_length-1-index])
            #print "Teste>", list(nx.shortest_path(copy_of_nxgraph, path[protected_path_length-2-index],path[protected_path_length-1-index]))
#            print "%d Backup paths for %s %s"%(index,path[index], path[index + 1])
#            ??????Check all paths!!!
            backup_path = list(nx.shortest_path(copy_of_nxgraph, path[protected_path_length-2-index],path[-1]))

            # reverse_path = list(nx.shortest_path(self.topology, sw_ip_dst,sw_ip_src))
            #endpoints = {(src_ip,dst_ip): backup_path}
            endpoints = {(src_ip, dst_ip): {'primary': path, 'backup': backup_path}}
                     #(src_ip,dst_ip): backup_path}
            #             (ip_pkt.dst, ip_pkt.src): reverse_path}
#            print endpoints, backup_path,"Backup path"#, backup_path
#            print "Primary path:",path
            #self.creating_paths(endpoints=endpoints, fine_grain=True, change_arp=False, pkt=None,primary_path=path)
            self.failover_path_creator(endpoints=endpoints, fine_grain=True, change_arp=False, msg=msg, primary_path=path)

if __name__ == '__main__':
    pass
    # topo = Topology_discover(None, None, None)
    # links = [(2, 3, {'port': 3}), (2, 1, {'port': 2}), (3, 2, {'port': 2}), (1, 2, {'port': 2})]
    # topology = topo.topology
    # topology.add_nodes_from(switches)
