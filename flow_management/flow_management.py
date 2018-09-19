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

import ryu.app.COOL.topology_management.bgp_speaker
from ryu.app.COOL.cool_utils import flow_creator
from ryu.app.COOL.flow_management import load_balancing
from ryu.app.COOL.flow_management import path_protection
from ryu.app.COOL.flow_management import protection_phase_LONG_with_VLAN
from ryu.app.COOL.flow_management.protection_phase_LONG_with_VLAN import Protection_Phase_LONG_with_VLAN
from ryu.app.COOL.flow_management.simple_flow_creation import Simple_Flow_Creation
# Import flow management strategies:
#from ryu.app.COOL.flow_management import simple_flow_creation
from ryu.app.COOL.flow_management import simple_flow_vlan
from ryu.app.COOL.flow_management import simple_routing
from ryu.base import app_manager
# Lib to manipulate TCP/IP packets
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

#Enable multithread in Ryu (Eventle)
from ryu.lib import hub

#To enable getting statistics:
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls



class FlowManagement(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    FLOW_CREATION_SIMPLE_FLOW = 1       #1. Local Restoration
    FLOW_CREATION_PATH_PROTECTION = 2 # Select cycle-3.py 2.Path Protection
    FLOW_CREATION_LOAD_BALANCING = 3
    FLOW_CREATION_SIMPLE_VLAN = 4   # 3.Local Fast Restoration
    FLOW_CREATION_PROTECTION_PHASE_LONG = 5 # 4.LONG

    #Select here the approach to flow creation
    # All strategies are ok! However, need to fix when a primary and backup paths shares common nodes!!! :-) Fix it!!!
    FLOW_CREATION_APPROACH = FLOW_CREATION_SIMPLE_FLOW#FLOW_CREATION_SIMPLE_VLAN#Ok!FLOW_CREATION_PROTECTION_PHASE_LONG#Ok!FLOW_CREATION_SIMPLE_VLAN#FLOW_CREATION_LOAD_BALANCING#Ok!:self.FLOW_CREATION_PATH_PROTECTION#Ok!:self.FLOW_CREATION_SIMPLE_FLOW #Default

    CONGESTION_THRESHOLD = 1500  # in bps
    CONGESTION_WINDOW = 3  # If 3 verifications indicate a congestion, then the link is congested.

    def __init__(self, *args, **kwargs):
        super(FlowManagement, self).__init__(*args, **kwargs)
        print "FlowManagement started! ;)"
        self.ip_controller = {"10.0.0.254": '00:00:00:00:00:fe', "10.2.0.254": '00:00:00:00:00:fe'}
        self.arp_controller = '00:00:00:00:00:fe'
        self.mac_to_port = {}
        self.group_id = {}
        self.installed_instructions = {}
        self.datapaths = {}

        #self.topology = nx.DiGraph() #Deprecated by topology_management.py
        self.datapaths = {}


        self.global_flow_table = {}

        self.hosts = {}
        self.networks = {}

        self.protection_phase_LONG_with_VLAN_instance = Protection_Phase_LONG_with_VLAN()
        self.simple_flow_creation_instance = Simple_Flow_Creation(self.global_flow_table)

        self.flow_creation_strategy = self.FLOW_CREATION_APPROACH
        #if self.flow_creation_strategy == self.FLOW_CREATION_SIMPLE_FLOW:
        self.flow_creation_engine = simple_routing.Simple_Routing_with_Load_Balancing(congestion_window=self.CONGESTION_WINDOW)

        self.congestion_monitor_thread = hub.spawn(self.congestion_monitor)
        self.number_of_flows_thread = hub.spawn(self.request_number_of_flows_installed)

        self.time_between_requests = 3

        self.number_of_flows = {}
        self.constant_number_of_flows = 2 # One to the controller and another to treat LLDP packets


    def set_number_of_flows(self, dpid, number_of_flows):
        self.number_of_flows[dpid] = number_of_flows - self.constant_number_of_flows
        total = 0
        for dpid in self.number_of_flows:
            total+=self.number_of_flows[dpid]
        #print "Total number of flows:",total,"Topology",


    def removed_flow(self, dpid, ipv4_dst):
        if dpid in self.global_flow_table:
            del self.global_flow_table[dpid][ipv4_dst]
        else:
            print "Something goes wrong! Why dpid ",dpid," does not have ",ipv4_dst,"?"


    def request_number_of_flows_installed(self):
        while True:
            for dp in self.datapaths:
                #print dp,":",self.datapaths,type(self.datapaths[dp])
                self.send_aggregate_stats_request(self.datapaths[dp])
            hub.sleep(self.time_between_requests)

    def send_aggregate_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch()
        req = ofp_parser.OFPAggregateStatsRequest(datapath, 0,
                                                  ofp.OFPTT_ALL,
                                                  ofp.OFPP_ANY,
                                                  ofp.OFPG_ANY,
                                                  cookie, cookie_mask,
                                                  match)
        datapath.send_msg(req)




    def congestion_monitor(self):
        while True:
            #print "CONGESTION MONITOR:\n\n\n\n",self.global_flow_table,"\n\n\n",self.networks,"\n\n\n\n"
            self.update_congestion_state(self.networks)
            secondsToSleep = 1  # randint(1, 2)
            hub.sleep(secondsToSleep)

    def update_congestion_state(self, networks):
        for network in self.networks:
            for next_hop in self.networks[network]['next_hop']:
                #print "Network:", network, "Next hop", next_hop, "DPID:", self.networks[network]['next_hop'][next_hop]['switch'], "Out port:", self.networks[network]['next_hop'][next_hop]['port'],"BANDWIDTH:",self.networks[network]['next_hop'][next_hop]['bandwidth']
                if (self.networks[network]['next_hop'][next_hop]['bandwidth']>self.CONGESTION_THRESHOLD):
                    self.networks[network]['next_hop'][next_hop]['congested'] += 1
                    #To keep the congestion value indication always less or equal than CONGESTION_WINDOW
                    if self.networks[network]['next_hop'][next_hop]['congested'] >= self.CONGESTION_WINDOW:
                        self.networks[network]['next_hop'][next_hop]['congested'] = self.CONGESTION_WINDOW
                        print "CONGESTED!!!",network,self.networks[network]['next_hop'][next_hop],next_hop
                else:
                    self.networks[network]['next_hop'][next_hop]['congested'] = 0



        # networks = {'10.0.2.0': {'controller_ip': "10.0.2.254", 'mask': '255.255.255.0',
        #                          'next_hop': {"10.0.2.2": {'switch': 2, 'port': 2, 'bandwidth': 0}},
        #                          'best_hop': "10.0.2.2"},
        #             '10.0.1.0': {'controller_ip': "10.0.1.254", 'mask': '255.255.255.0',
        #                          'next_hop': {"10.0.1.1": {'switch': 2, 'port': 1, 'bandwidth': 0}},
        #                          'best_hop': "10.0.1.1"},
        #             '172.16.0.0': {'controller_ip': "10.0.1.254", 'mask': '255.255.255.0',
        #                            'next_hop': {"10.0.1.1": {'switch': 2, 'port': 1, 'bandwidth': 0},
        #                                         "10.0.2.2": {'switch': 2, 'port': 2, 'bandwidth': 0}},
        #                            'best_hop': "10.0.1.1"}}
        pass #TODO
        #self.global_flow_table:
        #  {(2, '192.168.2.5', '172.16.0.3'): {'group_id': 0, 'instructions': {(2, 2): {'out_port': 1, 'in_port': 3}}},
        #  (2, '192.168.2.4', '172.16.0.3'): {'group_id': 0, 'instructions': {(2, 2): {'out_port': 1, 'in_port': 4}}},
        #  (2, '172.16.0.3', '192.168.2.5'): {'group_id': 0, 'instructions': {(2, 2): {'out_port': 3, 'in_port': 2}}},
        #  (2, '172.16.0.3', '192.168.2.4'): {'group_id': 0, 'instructions': {(2, 2): {'out_port': 4, 'in_port': 2}}}}


    def treat_arp(self,arp_pkt,in_port,eth_pkt,datapath):
        flow_creator.treat_arp(arp_pkt,in_port,eth_pkt,datapath,self.hosts)


    def treat_icmp(self,pkt,in_port,eth_pkt,datapath):
        flow_creator.treat_icmp(pkt,in_port,eth_pkt,datapath,self.hosts)

    def get_installed_instructions(self):
        return self.installed_instructions

    '''
    Treat when a link goes down!
    '''

    def link_down(self,topology, sw_src, sw_dst):
        #print "Deleting ", sw_src, sw_dst, " from the network!\n\n\n\n\n"
        # try:
        #     #Because the code uses bidirectional graph, it is required to remove both direction of link edges.
        #     self.topology.remove_edge(sw_src, sw_dst)
        #     self.topology.remove_edge(sw_dst, sw_src)
        # except:
        #     print "Cannot remove ",sw_src, sw_dst
        #self.topology.remove_edge(destination_node, source_node)
        # Find the affected flows
        print "Find the affected flows"
        #print "Global flow table ", self.global_flow_table
        local_global_flow_table = self.global_flow_table.copy()
        for ip_dst in local_global_flow_table[sw_src]:
            ip_src = local_global_flow_table[sw_src][ip_dst]['ip_src']
            self.flow_creation(topology, ip_src, ip_dst, msg=None, primary_path=None)
        else:
            if True:
                return
        # {1: {'10.0.0.5': {'in_port': 1, 'out_port': 4, 'ip_src': '10.0.0.1', 'match': '10.0.0.5',
        #                   'instructions': {(1, 2): {'out_port': 4, 'in_port': 1},
        #                                    (3, '10.0.0.5'): {'out_port': 2, 'in_port': 4}, 'primary_path': [1, 2, 3],
        #                                    (2, 3): {'out_port': 2, 'in_port': 1}, 'backup_path': None}},
        #      '10.0.0.4': {'in_port': 1, 'out_port': 4, 'ip_src': '10.0.0.1', 'match': '10.0.0.4',
        #                   'instructions': {(1, 2): {'out_port': 4, 'in_port': 1}, 'primary_path': [1, 2, 3],
        #                                    (3, '10.0.0.4'): {'out_port': 1, 'in_port': 4},
        #                                    (2, 3): {'out_port': 2, 'in_port': 1}, 'backup_path': None}},
        #      '10.0.0.6': {'in_port': 1, 'out_port': 4, 'ip_src': '10.0.0.1', 'match': '10.0.0.6',
        #                   'instructions': {(1, 2): {'out_port': 4, 'in_port': 1}, 'primary_path': [1, 2, 3],
        #                                    (2, 3): {'out_port': 2, 'in_port': 1},
        #                                    (3, '10.0.0.6'): {'out_port': 3, 'in_port': 4}, 'backup_path': None}},
        #      '10.0.0.1': {'in_port': 4, 'out_port': 1, 'ip_src': '10.0.0.4', 'match': '10.0.0.1',
        #                   'instructions': {'primary_path': [3, 2, 1], (3, 2): {'out_port': 4, 'in_port': 1},
        #                                    (1, '10.0.0.1'): {'out_port': 1, 'in_port': 4},
        #                                    (2, 1): {'out_port': 1, 'in_port': 2}, 'backup_path': None}},
        #      '10.0.0.3': {'in_port': 4, 'out_port': 3, 'ip_src': '10.0.0.4', 'match': '10.0.0.3',
        #                   'instructions': {'primary_path': [3, 2, 1], (3, 2): {'out_port': 4, 'in_port': 1},
        #                                    (1, '10.0.0.3'): {'out_port': 3, 'in_port': 4},
        #                                    (2, 1): {'out_port': 1, 'in_port': 2}, 'backup_path': None}},
        #      '10.0.0.2': {'in_port': 4, 'out_port': 2, 'ip_src': '10.0.0.4', 'match': '10.0.0.2',
        #                   'instructions': {'primary_path': [3, 2, 1], (3, 2): {'out_port': 4, 'in_port': 1},
        #                                    'backup_path': None, (2, 1): {'out_port': 1, 'in_port': 2},
        #                                    (1, '10.0.0.2'): {'out_port': 2, 'in_port': 4}}}}, 2: {
        #     '10.0.0.5': {'in_port': 1, 'out_port': 2, 'ip_src': '10.0.0.1', 'match': '10.0.0.5',
        #                  'instructions': {(1, 2): {'out_port': 4, 'in_port': 1},
        #                                   (3, '10.0.0.5'): {'out_port': 2, 'in_port': 4}, 'primary_path': [1, 2, 3],
        #                                   (2, 3): {'out_port': 2, 'in_port': 1}, 'backup_path': None}},
        #     '10.0.0.4': {'in_port': 1, 'out_port': 2, 'ip_src': '10.0.0.1', 'match': '10.0.0.4',
        #                  'instructions': {(1, 2): {'out_port': 4, 'in_port': 1}, 'primary_path': [1, 2, 3],
        #                                   (3, '10.0.0.4'): {'out_port': 1, 'in_port': 4},
        #                                   (2, 3): {'out_port': 2, 'in_port': 1}, 'backup_path': None}},
        #     '10.0.0.6': {'in_port': 1, 'out_port': 2, 'ip_src': '10.0.0.1', 'match': '10.0.0.6',
        #                  'instructions': {(1, 2): {'out_port': 4, 'in_port': 1}, 'primary_path': [1, 2, 3],
        #                                   (2, 3): {'out_port': 2, 'in_port': 1},
        #                                   (3, '10.0.0.6'): {'out_port': 3, 'in_port': 4}, 'backup_path': None}},
        #     '10.0.0.1': {'in_port': 2, 'out_port': 1, 'ip_src': '10.0.0.4', 'match': '10.0.0.1',
        #                  'instructions': {'primary_path': [3, 2, 1], (3, 2): {'out_port': 4, 'in_port': 1},
        #                                   (1, '10.0.0.1'): {'out_port': 1, 'in_port': 4},
        #                                   (2, 1): {'out_port': 1, 'in_port': 2}, 'backup_path': None}},
        #     '10.0.0.3': {'in_port': 2, 'out_port': 1, 'ip_src': '10.0.0.4', 'match': '10.0.0.3',
        #                  'instructions': {'primary_path': [3, 2, 1], (3, 2): {'out_port': 4, 'in_port': 1},
        #                                   (1, '10.0.0.3'): {'out_port': 3, 'in_port': 4},
        #                                   (2, 1): {'out_port': 1, 'in_port': 2}, 'backup_path': None}},
        #     '10.0.0.2': {'in_port': 2, 'out_port': 1, 'ip_src': '10.0.0.4', 'match': '10.0.0.2',
        #                  'instructions': {'primary_path': [3, 2, 1], (3, 2): {'out_port': 4, 'in_port': 1},
        #                                   'backup_path': None, (2, 1): {'out_port': 1, 'in_port': 2},
        #                                   (1, '10.0.0.2'): {'out_port': 2, 'in_port': 4}}}}, 3: {
        #     '10.0.0.5': {'in_port': 4, 'out_port': 2, 'ip_src': '10.0.0.1', 'match': '10.0.0.5',
        #                  'instructions': {(1, 2): {'out_port': 4, 'in_port': 1},
        #                                   (3, '10.0.0.5'): {'out_port': 2, 'in_port': 4}, 'primary_path': [1, 2, 3],
        #                                   (2, 3): {'out_port': 2, 'in_port': 1}, 'backup_path': None}},
        #     '10.0.0.4': {'in_port': 4, 'out_port': 1, 'ip_src': '10.0.0.1', 'match': '10.0.0.4',
        #                  'instructions': {(1, 2): {'out_port': 4, 'in_port': 1}, 'primary_path': [1, 2, 3],
        #                                   (3, '10.0.0.4'): {'out_port': 1, 'in_port': 4},
        #                                   (2, 3): {'out_port': 2, 'in_port': 1}, 'backup_path': None}},
        #     '10.0.0.6': {'in_port': 4, 'out_port': 3, 'ip_src': '10.0.0.1', 'match': '10.0.0.6',
        #                  'instructions': {(1, 2): {'out_port': 4, 'in_port': 1}, 'primary_path': [1, 2, 3],
        #                                   (2, 3): {'out_port': 2, 'in_port': 1},
        #                                   (3, '10.0.0.6'): {'out_port': 3, 'in_port': 4}, 'backup_path': None}},
        #     '10.0.0.1': {'in_port': 1, 'out_port': 4, 'ip_src': '10.0.0.4', 'match': '10.0.0.1',
        #                  'instructions': {'primary_path': [3, 2, 1], (3, 2): {'out_port': 4, 'in_port': 1},
        #                                   (1, '10.0.0.1'): {'out_port': 1, 'in_port': 4},
        #                                   (2, 1): {'out_port': 1, 'in_port': 2}, 'backup_path': None}},
        #     '10.0.0.3': {'in_port': 1, 'out_port': 4, 'ip_src': '10.0.0.4', 'match': '10.0.0.3',
        #                  'instructions': {'primary_path': [3, 2, 1], (3, 2): {'out_port': 4, 'in_port': 1},
        #                                   (1, '10.0.0.3'): {'out_port': 3, 'in_port': 4},
        #                                   (2, 1): {'out_port': 1, 'in_port': 2}, 'backup_path': None}},
        #     '10.0.0.2': {'in_port': 1, 'out_port': 4, 'ip_src': '10.0.0.4', 'match': '10.0.0.2',
        #                  'instructions': {'primary_path': [3, 2, 1], (3, 2): {'out_port': 4, 'in_port': 1},
        #                                   'backup_path': None, (2, 1): {'out_port': 1, 'in_port': 2},
        #                                   (1, '10.0.0.2'): {'out_port': 2, 'in_port': 4}}}}}

        # affected_flows = {}
        # for key in local_global_flow_table:
        #     dpid, ip_pkt_src, ip_pkt_dst = key
        #     #Instructions:
        #     # 1: {'backup_switch': 4, 'forward_switch': 2, 'out_port': 4, 'in_port': 1, 'backup_port': 5},
        #     # 2: {'forward_switch': 3, 'out_port': 2, 'in_port': 1},
        #     # 3: {'forward_switch': '10.0.0.4', 'out_port': 1, 'in_port': 2},
        #     # 4: {'forward_switch': 3, 'out_port': 1, 'in_port': 2}, 'backup_path': [1, 4, 3], 'primary_path': [1, 2, 3]}
        #     primary_path = local_global_flow_table[key]['instructions']['primary_path']
        #     if sw_src in primary_path and sw_dst in primary_path:
        #         #Regenerate flows:
        #         try:
        #             first_sw = primary_path.index(sw_src)
        #             second_sw = primary_path.index(sw_dst)
        #             if first_sw> second_sw:
        #                 tmp = sw_src
        #                 sw_src = sw_dst
        #                 sw_dst = tmp
        #             affected_flows[key] = primary_path
        #
        #             # # Create new flows for primary_path
        #             # if self.flow_creation_strategy == self.FLOW_CREATION_SIMPLE_FLOW:
        #             #     # Simple flow creation: Ok!
        #             #     #print "Simple flow recreation...", 'for',ip_pkt_src, ip_pkt_dst, sw_src, sw_dst,
        #             #     #Add new paths...
        #             #     self.simple_flow_creation_instance.simple_flow_creation(self.topology, self.datapaths, self.hosts,
        #             #                                               self.global_flow_table,
        #             #                                               ip_pkt_src, ip_pkt_dst,
        #             #                                               None, None, modify_rule=False)
        #             #     #...modify the old paths to the new ones.
        #             #     # simple_flow_creation.simple_flow_creation(self.topology, self.datapaths, self.hosts,
        #             #     #                                           self.global_flow_table,
        #             #     #                                           ip_pkt_src, ip_pkt_dst, sw_src, sw_dst,
        #             #     #                                           None,None,modify_rule=True)
        #             # # Create vlans inside the SDN network
        #             # elif self.flow_creation_strategy == self.FLOW_CREATION_SIMPLE_VLAN:
        #             #     # Simple flow creation: Ok!
        #             #     # print "Simple flow recreation...", 'for',ip_pkt_src, ip_pkt_dst, sw_src, sw_dst,
        #             #     # Add new paths...
        #             #     simple_flow_vlan.simple_flow_vlan(self.topology, self.datapaths, self.hosts,
        #             #                                               self.global_flow_table,
        #             #                                               ip_pkt_src, ip_pkt_dst, sw_src, sw_dst,
        #             #                                               None, None, modify_rule=False)
        #             #
        #             # elif self.flow_creation_strategy == self.FLOW_CREATION_PATH_PROTECTION:
        #             #     # Path protection:
        #             #     #print 'Applying Path protection:'
        #             #     path_protection.path_protection(self.topology, self.datapaths, self.hosts,
        #             #                                     self.global_flow_table,
        #             #                                     ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, None,add_rules=True)
        #             #     path_protection.path_protection(self.topology, self.datapaths, self.hosts,
        #             #                                     self.global_flow_table,
        #             #                                     ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, None, add_rules=False)
        #             #     #self.path_protection(ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, msg=None, add_rules=False)
        #             #     # self.simple_flow_creation(ip_src, ip_dst, source_node, destination_node, msg=None,
        #             #     #                           buffer_id=None)
        #             # elif self.flow_creation_strategy == self.FLOW_CREATION_PROTECTION_PHASE_LONG:
        #             #     # Path protection:
        #             #     #print 'Applying Path protection:'
        #             #     self.protection_phase_LONG_with_VLAN_instance.protection_phase_LONG(self.topology, self.datapaths, self.hosts,
        #             #                                     self.global_flow_table,
        #             #                                     ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, None,add_rules=True)
        #             #     self.protection_phase_LONG_with_VLAN_instance.protection_phase_LONG(self.topology, self.datapaths, self.hosts,
        #             #                                     self.global_flow_table,
        #             #                                     ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, None, add_rules=False)
        #             #     #self.path_protection(ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, msg=None, add_rules=False)
        #             #     # self.simple_flow_creation(ip_src, ip_dst, source_node, destination_node, msg=None,
        #             #     #                           buffer_id=None)
        #             # elif self.flow_creation_strategy == self.FLOW_CREATION_LOAD_BALANCING:
        #             #     # Load Balacing Application: Ok!
        #             #     #print 'Applying Load Balancing:'
        #             #     load_balancing.load_balancing(self.topology, self.datapaths, self.hosts, self.global_flow_table,
        #             #                                   ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, msg=None)
        #             #     #self.load_balancing(ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, msg=None)
        #
        #         except Exception as e:
        #             print e
        #             print "Not in primary path ", primary_path, " switches ", sw_src, sw_dst
        #
        #     print "DEU CERTO?!!!", primary_path
        # else:
        #     print "Global flow table ",self.global_flow_table
        # return affected_flows


    def is_a_controller_IP(self,ip_address):
        if ip_address in self.hosts['controller']:
            return True
        else:
            return False


    def set_hosts(self,hosts):
        self.hosts = hosts

    def set_networks(self,networks):
        self.networks = networks

    def get_global_flow_table(self):
        return self.global_flow_table

    def is_in_network_learned(self, ip_address):
        for network in self.networks:
            #print self.networks[network],"<<<<<<<<<<<",network
            network_mask = self.networks[network]['mask']
            #print ip_address,network_mask,"KKKKK",type(ip_address),type(network_mask)
            #print network,ip_address,IPNetwork(ip_address +'/'+ network_mask),IPNetwork(network+'/'+ network_mask)
            if IPNetwork(str(ip_address) +'/'+ str(network_mask)) == IPNetwork(str(network)+'/'+ str(network_mask)):
                print "TRUE"
                return True
        return False


    def flow_creation(self,topology,ip_pkt_src,ip_pkt_dst,msg=None,primary_path=None):
        print "AQUI:",primary_path,ip_pkt_src,ip_pkt_dst,self.hosts,"\n\n\n\n"
        #Check if is an inside flow!
        if ip_pkt_src in self.hosts and ip_pkt_dst in self.hosts:
        # Call flow creation processing in flow management
            if ip_pkt_dst in self.hosts:
                # ip_pkt = pkt.get_protocol(ipv4.ipv4)
                # print self.topology
                sw_src = self.hosts[ip_pkt_src]['switch']
                sw_dst = self.hosts[ip_pkt_dst]['switch']
                if self.flow_creation_strategy == self.FLOW_CREATION_SIMPLE_FLOW:
                    # Simple flow creation: Ok!
                    # self.simple_flow_creation(ip_pkt_src, ip_pkt_dst, sw_src, sw_dst,msg,buffer_id=msg.buffer_id)
                    self.simple_flow_creation_instance.simple_flow_creation(topology, self.datapaths, self.hosts,
                                                              self.global_flow_table,
                                                              ip_pkt_src, ip_pkt_dst,
                                                              msg=msg, modify_rule=False,primary_path=primary_path)
                # Create vlans inside the SDN network
                elif self.flow_creation_strategy == self.FLOW_CREATION_SIMPLE_VLAN:
                    # Simple flow creation: Ok!
                    print "Simple flow recreation...", 'for',ip_pkt_src, ip_pkt_dst, sw_src, sw_dst,
                    # Add new paths...
                    simple_flow_vlan.simple_flow_vlan(topology, self.datapaths, self.hosts,
                                                      self.global_flow_table,
                                                      ip_pkt_src, ip_pkt_dst, sw_src, sw_dst,
                                                      msg, modify_rule=False)
                elif self.flow_creation_strategy == self.FLOW_CREATION_PATH_PROTECTION:
                    # Path protection:
                    #print 'Applying Path protection:'
                    path_protection.path_protection(topology, self.datapaths, self.hosts, self.global_flow_table,
                                                    ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, msg)
                elif self.flow_creation_strategy == self.FLOW_CREATION_PROTECTION_PHASE_LONG:
                    # Path protection:
                    print 'Applying Protection Phase of LONG:'
                    self.protection_phase_LONG_with_VLAN_instance.protection_phase_LONG(topology, self.datapaths, self.hosts, self.global_flow_table,
                                                    ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, msg)
                elif self.flow_creation_strategy == self.FLOW_CREATION_LOAD_BALANCING:
                    # Load Balacing Application: Ok!
                    #print 'Applying Load Balancing:'
                    load_balancing.load_balancing(topology, self.datapaths, self.hosts, self.global_flow_table,
                                                  ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, msg)
        # Check if the destination is outside of the network
        elif self.is_in_network_learned(ip_pkt_dst):
            #print "\n\n\n To other network %s \n\n\n" % (ip_pkt.dst)
            #print "Packets to other networks from the OpenFlow network"
            self.flow_creation_engine.routing_to_other_networks(topology, self.datapaths, self.hosts,
                                                                self.global_flow_table,self.networks,msg)
        # Check if the packets goes to the OpenFlow network
        elif self.is_in_network_learned(ip_pkt_src) and ip_pkt_dst in self.hosts:
            #print "Packets from other networks to the OpenFlow network"
            self.flow_creation_engine.routing_from_other_networks(topology, self.datapaths, self.hosts,
                                                                  self.global_flow_table,self.networks,msg)
        else:
            print "Treat other thing: %s", ip_pkt_src, ip_pkt_dst
            return

if __name__ == '__main__':
    pass
    # topo = Topology_discover(None, None, None)
    # links = [(2, 3, {'port': 3}), (2, 1, {'port': 2}), (3, 2, {'port': 2}), (1, 2, {'port': 2})]
    # topology = topo.topology
    # topology.add_nodes_from(switches)
