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

# Generate the graph topology
import networkx as nx

#Manipulate IP addresses
from netaddr import *

from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import lldp
from ryu.lib.packet import packet
from ryu.lib.packet import in_proto as inet
from ryu.ofproto import ofproto_v1_3
# Below is the library used for topo discovery
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

#COOL administration
from ryu.app.COOL.Interfaces.cool_interface import COOL_Interface
from ryu.app.COOL.flow_management.flow_management import FlowManagement
from ryu.app.COOL.topology_management.topology_management import TopologyManagement
from ryu.app.COOL.domain_controller.domain_controller import Domain_Controller
from ryu.app.COOL.policy_management.policy_management import Policy_Management
# Enable multithread in Ryu (Eventle)
# Utils
# from ryu.app.sdnip.sdnip_utils.packets_utils import packets_handler

from ryu import cfg
import time
'''
sudo PYTHONPATH=. ./bin/ryu-manager --verbose  --observe-links ryu/app/COOL/cool.py
or
sudo PYTHONPATH=. ./bin/ryu-manager --wsapi-port 8081  --verbose   --observe-links ryu/app/COOL/cool.py
'''

simple_switch_instance_name = 'cool_interface'
url = '/simpleswitch/'

class COOL_Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    # DEFAULT_WSGI_HOST = '0.0.0.0'
    # DEFAULT_WSGI_PORT = 8080

    # CONF = cfg.CONF
    # CONF.register_cli_opts([
    #     cfg.StrOpt(
    #         'wsapi-host', default=DEFAULT_WSGI_HOST,
    #         help='webapp listen host (default %s)' % DEFAULT_WSGI_HOST),
    #     cfg.IntOpt(
    #         'wsapi-port', default=DEFAULT_WSGI_PORT,
    #         help='webapp listen port (default %s)' % DEFAULT_WSGI_PORT),
    # ])

    def __init__(self, *args, **kwargs):
        super(COOL_Controller, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(COOL_Interface, {simple_switch_instance_name: self})
        # self._ws_manager = wsgi.websocketmanager
        # print "WSGI:",self._ws_manager

        self.switch_bandwidth = {}

        '''Creates the policy management component'''
        self.policy_management = Policy_Management()
        '''Creates the flow management component'''
        self.flow_management = FlowManagement()
        '''Creates the topology management component'''
        self.topology_management = TopologyManagement('Monitoring...',self.flow_management.datapaths)
        #Populate the allowed set of hosts
        self.flow_management.set_hosts(self.topology_management.get_hosts())
        self.flow_management.set_networks(self.topology_management.get_networks())
        self.domain_controller = Domain_Controller(flow_management=self.flow_management,
                                                       topology_management=self.topology_management,
                                                       policy_management=self.policy_management)#self.topology_management.get_hosts())
        #self.monitor_thread = hub.spawn(self.topology_management.get_flow_stats)
        #self.monitor_thread = hub.spawn(self._monitor)

        self.flows_per_ips = {}
        time.sleep(30)

    ''' This method delegates to the Topology_Management module the capacity to process FlowStatsReply
    '''
    #OK!
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = int(ev.msg.datapath.id)
        self.domain_controller.topology_management_set_flow_stats(dpid, body)
        #self.topology_management.set_flow_stats(dpid, body)

    def get_hosts(self):
        return self.network_administation.get_hosts()

    # OK!
    @set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
    def aggregate_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = int(ev.msg.datapath.id)
        #self.flow_management.set_number_of_flows(dpid,body.flow_count)
        self.domain_controller.flow_management_set_number_of_flows(dpid,body.flow_count)
        # print "Aquiiii",,body
        # self.logger.debug('AggregateStats: packet_count=%d byte_count=%d '
        #                   'flow_count=%d',
        #                   body.packet_count, body.byte_count,
        #                   body.flow_count)

    # OK!
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

    #Ok!
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        LINK_UP = 0 # definition of LINK_UP because it is not defined in ryu.ofproto.ofproto_v1_3
        msg = ev.msg  # ryu.ofproto.ofproto_v1_3_parser.OFPPortStatus
        dp = msg.datapath
        sw_src = dp.id
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
            print "Link down at %s" % (sw_src)
            #print "Edges:", self.flow_management.topology[sw_src]
            #Edges: {2: {'port': 2}, 4: {'port': 3}}
            # Exclude the link (edge) in the graph

            failure_port = port.port_no
            for sw_dst in self.topology_management.get_topology_nodes():#self.flow_management.topology[dpid]:
                print failure_port,self.topology_management.get_output_port_from_sw_src_to_sw_dst(sw_src,sw_dst)
                if failure_port == self.topology_management.get_output_port_from_sw_src_to_sw_dst(sw_src,sw_dst):#self.flow_management.topology[dpid][switch]['port']:
                    # print "Found the failure port: %s, neighbor switch:%s"%(port,switch)
                    self.domain_controller.topology_management_link_down(sw_src, sw_dst)
                    self.domain_controller.flow_management_link_down(sw_src,sw_dst)
                    #It's working:
                    #self.topology_management.link_down(sw_dst,sw_src)
                    #self.flow_management.link_down(self.topology_management.get_topology(),sw_src,sw_dst) #<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

                    #print affected_flows,"\n\n\n\n\n"
                    #self.flow_management.topology.remove_edge(dpid, switch)
                    #self.flow_management.topology.remove_edge(switch, dpid)  # It is a Digraph!
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
            failure_port = port.port_no
            for sw_dst in self.topology_management.get_topology_nodes():  # self.flow_management.topology[dpid]:
                print failure_port, self.topology_management.get_output_port_from_sw_src_to_sw_dst(sw_src, sw_dst)
                if failure_port == self.topology_management.get_output_port_from_sw_src_to_sw_dst(sw_src,
                                                                                                  sw_dst):  # self.flow_management.topology[dpid][switch]['port']:
                    # print "Found the failure port: %s, neighbor switch:%s"%(port,switch)
                    #self.topology_management.link_down(sw_dst, sw_src)

                    self.domain_controller.topology_management_link_up(sw_src,sw_dst)
                    #self.flow_management.link_down(self.topology_management.get_topology(), sw_src,
                    #                               sw_dst)  # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                    # print affected_flows,"\n\n\n\n\n"
                    # self.flow_management.topology.remove_edge(dpid, switch)
                    # self.flow_management.topology.remove_edge(switch, dpid)  # It is a Digraph!
                    break


    """
        The event EventSwitchLeave will trigger the activation of get_topology_data().
    """
    #Ok!
    @set_ev_cls(event.EventSwitchLeave)
    def _event_switch_leave_handler(self, ev):
        msg = ev.switch.to_dict()
        # Removing switches:
        dpid = int(msg['dpid'], 16)  # Convert Hex to Int
        # Exclude the switch from topology
        self.domain_controller.topology_management_switch_down(sw_id=dpid)
        #It was working:
        #self.topology_management.remove_node(dpid)
        #del self.flow_management.datapaths[dpid]
        #self.flow_management.topology.remove_node(dpid)
        #print self.flow_management.topology
        #print self.flow_management.datapaths

    #Ok!
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


        self.domain_controller.flow_management_flow_removed(dp.id,msg.match.get('ipv4_dst'))
        #It was working:
        #self.flow_management.removed_flow(dp.id,msg.match.get('ipv4_dst'))
        #print "Oi",dp.id, msg.match,msg.match.get('ipv4_dst')

        #OFPMatch(oxm_fields={'eth_type': 2048, 'ipv4_dst': '10.0.0.100'})


    """
    The event EventSwitchEnter will trigger the activation of get_topology_data().
    """

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        msg = ev.switch.to_dict()
        dpid = msg['dpid']
        # switch_list = get_switch(self.topology_api_app, None)
        switch_list = get_switch(self, None)
        links_list = get_link(self, None)
        self.domain_controller.topology_management_switch_enter(switch_list,links_list)
        #It is working!
        # for switch in switch_list:
        #     # print switch.dp.id,"!!!!!!!!!!!!!!!!!!!!"
        #     self.domain_controller.flow_management_add_datapaths(switch.dp.id,switch.dp)
        #     # if switch.dp.id not in self.flow_management.datapaths:
        #     #     self.flow_management.datapaths[switch.dp.id] = switch.dp
        #
        # switches = [switch.dp.id for switch in switch_list]
        # links_list = get_link(self, None)
        # #print links_list
        # links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        # #print links, "Links<<<<<<<<<<<<<<<<<"
        # # [(2, 3, {'port': 3}), (2, 1, {'port': 2}), (3, 2, {'port': 2}), (1, 2, {'port': 2})] Links << << << << << << << << <
        # for link in links:
        #     src, dst, port = link
        #     self.topology_management.add_edge(src, dst, {'port': port})
        # #print links



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
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            lldp_pkt = pkt.get_protocol(lldp.lldp)
            # print dpid,in_port,lldp_pkt.tlvs[0],lldp_pkt.tlvs[1]
            #Update the topology
            chassis = lldp_pkt.tlvs[0]
            dpid_adj = int(chassis.chassis_id[5:],16)
            self.domain_controller.topology_management_add_edge(dpid, dpid_adj,in_port)
            #self.topology_management.add_edge(dpid, dpid_adj, {'port': in_port})
            #self.flow_management.topology.add_edge(dpid, dpid_adj, {'port': in_port})
            #Capture lLDP time:
            # import time
            # millis = int(round(time.time() * 1000))
            # print millis,"LLDP"
            # ignore lldp packet?
            return

        dst = eth_pkt.dst
        src = eth_pkt.src

        dpid = datapath.id
        # self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        # self.mac_to_port[dpid][src] = in_port

        # treat arp requests:
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            print "treat arp"
            self.domain_controller.flow_management_treat_arp(arp_pkt,in_port,eth_pkt,datapath)
            #self.flow_management.treat_arp(arp_pkt,in_port,eth_pkt,datapath)
        # treat L3 packets:
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            #if self.flow_management.is_a_controller_IP(ip_pkt.dst):
            if self.domain_controller.flow_management_is_a_controller_IP(ip_pkt.dst):
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt:
                    #self.flow_management.treat_icmp(pkt, in_port, eth_pkt, datapath)
                    self.domain_controller.flow_management_treat_icmp(pkt, in_port, eth_pkt, datapath)
                    print "A ping to the controller!"
                else:
                    print "SOMETHING ELSE!!!oO"
            else:
                # print "treat ipv4 in switch %s with %s input port"%(datapath.id,in_port)
                if (ip_pkt.proto == inet.IPPROTO_UDP or ip_pkt.proto == inet.IPPROTO_TCP):
                    if (ip_pkt.src not in self.flows_per_ips):
                        #self.flow_management.create_flow(ip_pkt.src,ip_pkt.dst)
                        self.domain_controller.flow_management_flow_creation(ip_pkt.src,ip_pkt.dst, msg)
                        #It was working:
                        #self.flow_management.flow_creation(self.topology_management.get_topology(),ip_pkt.src,ip_pkt.dst, msg)
                        self.flows_per_ips[ip_pkt.src] = 1
                    else:
                        print "Already have a rule for:",self.flows_per_ips[ip_pkt.src],ip_pkt.src
                    # elif self.flows_per_ips[ip_pkt.src] <3:
                    #     self.flows_per_ips[ip_pkt.src] += 1
                    #     self.flow_management.flow_creation(ip_pkt, msg)
                    #     print self.flows_per_ips,ip_pkt.src
                    #     pass
                if (ip_pkt.proto == inet.IPPROTO_ICMP):
                    self.domain_controller.flow_management_flow_creation(ip_pkt.src, ip_pkt.dst, msg)
                    #self.flow_management.flow_creation(self.topology_management.get_topology(),ip_pkt.src,ip_pkt.dst, msg)




if __name__ == '__main__':

    # topo = Topology_discover(None, None, None)
    # G = {1:{2:{'capacity':7,'total_capacity':10}},
    #      2:{3:{'capacity':3,'total_capacity':10}}
    #      #(1,3):{'rt':10}#,#sink
    #      #2:[1,3],
    #      #3:[2,4],#t
    #      #4:[1,3]
    #      }
    G = {1: [2, 4],
         2: [1, 3],
         3: [2, 4],
         4: [1, 3]}
    topo = nx.DiGraph(G)
    # for edge in G:
    #     topo.add_nodes_from(edge)#,G[edge]['rt'])
    #print nx.shortest_path(topo,1,3)
    #print topo.edge
    # max_flow,residual = nx.maximum_flow(topo,1,3)
    # print max_flow
    # print residual

# % 1. Get the board switches in the topology;
# % 2. For each switch:
# %	2.1 For each port in the switch:
# %	2.2 Check if the port is congested
# %	2.3 If port is congested:
# %		3.3.1 Take the difference between congestion threshold and the bandwidth utilization.
# %		3.3.2 Search prefixes that have minimal rate and can be changed.
# %		3.3.3. Move all of those prefixes to another board switch that can accept the new bandwidth requirement.

    congestion_window = 0
    congestion_window_threshold = 3

    def search_minimal_rate_prefixes(flow_table):
        maximum_bandwidth = 101
        num_min_bw_rule = -1
        #print flow_table,"<<"
        for rule in flow_table:
            if flow_table[rule]['rule_bandwidth'] < maximum_bandwidth:
                #Verify if the prefix in the rule has a alternative path:
                prefix = flow_table[rule]['prefix']
                alternative_dpid = bgp_table[prefix]['alternative_path']['dpid']
                alternative_port = bgp_table[prefix]['alternative_path']['switch_port']

                rule_bandwidth = flow_table[rule]['rule_bandwidth']
                alternative_bandwidth = switches[alternative_dpid][alternative_port]['bandwidth']
                alternative_switch_threshold = switches[alternative_dpid][alternative_port]['threshold']

                #Verify if the alternative path will cause the switch of the alternative path to be congested
                if alternative_bandwidth+ rule_bandwidth <= alternative_switch_threshold:
                    #If every verification is OK! then select the rule as having the potential to be changed.
                    num_min_bw_rule = rule
                    maximum_bandwidth = rule_bandwidth
        return num_min_bw_rule

    bgp_table = {'10.0.0.0/8':{'primary_path':{'dpid':1,'switch_port':1,'AS_PATH':[2,1]},'alternative_path':{'dpid':1,'switch_port':2,'AS_PATH':[2,3,1]}},
                '192.168.0.0/16':{'primary_path':{'dpid':1,'switch_port':2,'AS_PATH':[2,1]},'alternative_path':{'dpid':1,'switch_port':1,'AS_PATH':[2,3,1]}},
                '192.168.1.0/24':{'primary_path':{'dpid':1,'switch_port':2,'AS_PATH':[2,1]},'alternative_path':{'dpid':1,'switch_port':1,'AS_PATH':[2,3,1]}}}

    switches = {1:{ 1: {'max_bandwidth': 100, 'bandwidth': 2, 'threshold': 70, 'congested': 0, 'congested_threshold': 3},
                    2: {'max_bandwidth': 100, 'bandwidth':  70, 'threshold': 70, 'congested': 0, 'congested_threshold': 3}}}

    flow_table = {1:{'prefix':'10.0.0.0/8','counter':432,'rule_bandwidth':32,'output_port':1},
                  2:{'prefix':'192.168.0.0/16','counter':560,'rule_bandwidth':50,'output_port':2},
                  3:{'prefix':'192.168.1.0/24','counter':560,'rule_bandwidth':50,'output_port':2}}




    # % 1. Get the board switches in the topology;
    # % 2. For each switch:
    for switch in switches:
        # %	2.1 For each port in the switch:

        for port in switches[switch]:
            # % 2.1 Update congestion states
            if switches[switch][port]['bandwidth'] > switches[switch][port]['threshold']:
                switches[switch][port]['congested']+=1
            else:
                switches[switch][port]['congested'] = 0
            # %	2.2 Check if the port is congested
            # %	2.3 If port is congested:
            # %		3.3.1 Take the difference between congestion threshold and the bandwidth utilization.
            # %		3.3.2 Search prefixes that have minimal rate and can be changed.
            # %		3.3.3. Move all of those prefixes to another board switch that can accept the new bandwidth requirement.

            difference = switches[switch][port]['bandwidth'] - switches[switch][port]['threshold']
            rule_number = search_minimal_rate_prefixes(flow_table)
            if rule_number != -1:
                # Change the rule from switch A to B
                prefix_from_rule = flow_table[rule_number]['prefix']
                alternative_dpid = bgp_table[prefix_from_rule]['alternative_path']['dpid']
                alternative_port = bgp_table[prefix_from_rule]['alternative_path']['switch_port']
                flow_table[rule_number]['output_port'] = alternative_port
    #print switches
    print flow_table,"<<<"