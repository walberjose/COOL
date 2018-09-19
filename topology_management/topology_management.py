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

from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,HANDSHAKE_DISPATCHER
from ryu.controller import ofp_event
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3


#Enable the BGP module
from ryu.app.COOL.topology_management import bgp_speaker

#Enable multithread in Ryu (Eventle)
from ryu.lib import hub

from random import randint
import time

# Generate the graph topology
import networkx as nx

#Manipulate IP addresses
from netaddr import *

class TopologyManagement(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #_CONTEXTS = {'bgp': bgp_speaker.BGP_Speaker}
    # To enable the bgp speaker
    ENABLE_BGP_SPEAKER = False #TODO Something in BGP Speaker is messing up with port 8080

    def __init__(self, parameter, datapaths,*args, **kwargs):
        super(TopologyManagement, self).__init__(*args, **kwargs)
        self.flows_stats = {}
        self.datapaths = datapaths
        self.prefix_bandwidth = {}
        self.topology = nx.DiGraph()
        self.networks = self.populate_networks() #Change this to use cool-topology.py
        #self.networks = self.populate_paper_topoology() # Uses paper-incoming-topology.py
        self.hosts = self.populate_hosts() # Allow hosts and controller to be reachable!
        self.hosts = self.populate_paper_hosts()  # Uses paper-incoming-topology.py

        #It works:
        self.networks = self.populate_paper_networks_LONG()  # Uses paper: long-example-topology.py
        self.hosts = self.populate_paper_hosts_LONG() # Uses paper: long-example-topology.py

        #Cool-topology.py
        self.networks = self.populate_paper_networks_COOL()
        self.hosts = self.populate_paper_hosts_COOL()  # Uses paper: cool-topology.py

        self.bgp_speaker = None
        #self.monitor_thread = hub.spawn(self.get_flow_stats)

    def enable_BGP_Speaker(self):
        if not self.ENABLE_BGP_SPEAKER:
            self.bgp_speaker = bgp_speaker.BGP_Speaker(self.hosts, self.networks)
        self.ENABLE_BGP_SPEAKER = True

    def get_hosts(self):
        return self.hosts

    def get_networks(self):
        return self.networks

    def get_prefix_bandwidth(self):
        return self.prefix_bandwidth

    def get_topology_nodes(self):
        return self.topology

    def get_output_port_from_sw_src_to_sw_dst(self,sw_src,sw_dst):
        #print self.topology,"\n\n\n"
        if self.topology.has_edge(sw_src,sw_dst):
            return self.topology[sw_src][sw_dst]['port']
        else:
            return None

    def remove_node(self,sw_id):
        self.topology.remove_node(sw_id)

    def add_edge(self,sw_src,sw_dst,port):
        self.topology.add_edge(sw_src,sw_dst,port)

    def get_topology(self):
        return self.topology.copy()

    def get_flow_stats(self):
        while True:
            self.bgp_speaker.update_networks_from_rib()
            #print "Monitoring->",self.datapaths,self.flows_stats
            secondsToSleep = 1  # randint(1, 2)
            # print "Vou dormir por %s segundos!!!" % secondsToSleep
            for datapath in self.datapaths:
                self._request_stats(self.datapaths[datapath])
            #print "\n\n\nPrefix learned:\n\n\n", self.bgp_speaker.prefix_learned
            hub.sleep(secondsToSleep)

    def set_flow_stats(self,dpid,body):
        if dpid in self.datapaths:
            self.flows_stats[dpid] = body
            self.treat_body(dpid,body)

    def extract_attributes_from_stats_reply(self, stat):
        #in_port = stat.match['in_port']
        match = stat.match
        out_port = stat.instructions[0].actions[-1].port
        #return in_port,match,out_port
        return match, out_port

    '''
    Receives the body of FlowStats from a switch (dpid) and generate the object self.prefix_bandwidth
    '''

    def treat_body(self,dpid,body):
        #print "BODY",type(body),body
# BODY <type 'list'> [OFPFlowStats(byte_count=0,cookie=0,duration_nsec=627000000,duration_sec=25,flags=0,hard_timeout=0,idle_timeout=0,instructions=[OFPInstructionActions(actions=[OFPActionOutput(len=16,max_len=65535,port=4294967293,type=0)],len=24,type=4)],length=96,match=OFPMatch(oxm_fields={'eth_dst': '01:80:c2:00:00:0e', 'eth_type': 35020}),packet_count=0,priority=65535,table_id=0),
# OFPFlowStats(byte_count=16562,cookie=0,duration_nsec=997000000,duration_sec=168,flags=1,hard_timeout=3600,idle_timeout=30,instructions=[OFPInstructionActions(actions=[OFPActionSetField(eth_dst='00:00:00:00:00:02'), OFPActionSetField(eth_src='00:10:00:01:00:fe'), OFPActionOutput(len=16,max_len=65509,port=2,type=0)],len=56,type=4)],length=136,match=OFPMatch(oxm_fields={'eth_type': 2048, 'ipv4_dst': ('172.16.0.0', '255.255.255.0'), 'in_port': 3}),packet_count=169,priority=32768,table_id=0),
# OFPFlowStats(byte_count=7546,cookie=0,duration_nsec=549000000,duration_sec=76,flags=1,hard_timeout=3600,idle_timeout=30,instructions=[OFPInstructionActions(actions=[OFPActionSetField(eth_dst='00:00:00:00:00:01'), OFPActionSetField(eth_src='00:10:00:01:00:fe'), OFPActionOutput(len=16,max_len=65509,port=1,type=0)],len=56,type=4)],length=136,match=OFPMatch(oxm_fields={'eth_type': 2048, 'ipv4_dst': ('172.16.0.0', '255.255.255.0'), 'in_port': 4}),packet_count=77,priority=32768,table_id=0),
# OFPFlowStats(byte_count=16562,cookie=0,duration_nsec=990000000,duration_sec=168,flags=1,hard_timeout=3600,idle_timeout=30,instructions=[OFPInstructionActions(actions=[OFPActionSetField(eth_dst='00:00:00:00:00:05'), OFPActionSetField(eth_src='01:92:01:68:02:fe'), OFPActionOutput(len=16,max_len=65509,port=3,type=0)],len=56,type=4)],length=136,match=OFPMatch(oxm_fields={'eth_type': 2048, 'ipv4_dst': '192.168.2.5', 'in_port': 2}),packet_count=169,priority=32768,table_id=0),
# OFPFlowStats(byte_count=7546,cookie=0,duration_nsec=543000000,duration_sec=76,flags=1,hard_timeout=3600,idle_timeout=30,instructions=[OFPInstructionActions(actions=[OFPActionSetField(eth_dst='00:00:00:00:00:04'), OFPActionSetField(eth_src='01:92:01:68:02:fe'), OFPActionOutput(len=16,max_len=65509,port=4,type=0)],len=56,type=4)],length=136,match=OFPMatch(oxm_fields={'eth_type': 2048, 'ipv4_dst': '192.168.2.4', 'in_port': 2}),packet_count=77,priority=32768,table_id=0),
        # OFPFlowStats(byte_count=1442,cookie=0,duration_nsec=630000000,duration_sec=25,flags=0,hard_timeout=0,idle_timeout=0,instructions=[OFPInstructionActions(actions=[OFPActionOutput(len=16,max_len=65535,port=4294967293,type=0)],len=24,type=4)],length=80,match=OFPMatch(oxm_fields={}),packet_count=21,priority=0,table_id=0)]

        if dpid not in self.prefix_bandwidth:
            self.prefix_bandwidth[dpid]={}
        #print "\n\n\n\n"
        #self.prefix_bandwidth['time'] = time.time() # In milliseconds!!!
        for index,stat in enumerate(body):  # sorted([flow for flow in body], #if flow.priority == 1],
            # key=lambda flow: (flow.match['in_port'],
            #                   flow.match['ipv4_dst'])):
            #[OFPFlowStats(byte_count=9480,cookie=0,duration_nsec=870000000,duration_sec=21,flags=0,hard_timeout=0,idle_timeout=0,instructions=[OFPInstructionActions(actions=[OFPActionOutput(len=16,max_len=65535,port=4294967293,type=0)],len=24,type=4)],length=96,match=OFPMatch(oxm_fields={'eth_dst': '01:80:c2:00:00:0e', 'eth_type': 35020}),packet_count=158,priority=65535,table_id=0), OFPFlowStats(byte_count=980,cookie=0,duration_nsec=403000000,duration_sec=14,flags=1,hard_timeout=3600,idle_timeout=60,instructions=[OFPInstructionActions(actions=[OFPActionGroup(group_id=30494165,len=8,type=22)],len=16,type=4)],length=88,match=OFPMatch(oxm_fields={'eth_type': 2048, 'ipv4_dst': '10.0.0.4'}),packet_count=10,priority=32768,table_id=0), OFPFlowStats(byte_count=882,cookie=0,duration_nsec=395000000,duration_sec=13,flags=1,hard_timeout=3600,idle_timeout=60,instructions=[OFPInstructionActions(actions=[OFPActionGroup(group_id=86241685,len=8,type=22)],len=16,type=4)],length=88,match=OFPMatch(oxm_fields={'eth_type': 2048, 'ipv4_dst': '10.0.0.1'}),packet_count=9,priority=32768,table_id=0), OFPFlowStats(byte_count=480,cookie=0,duration_nsec=874000000,duration_sec=21,flags=0,hard_timeout=0,idle_timeout=0,instructions=[OFPInstructionActions(actions=[OFPActionOutput(len=16,max_len=65535,port=4294967293,type=0)],len=24,type=4)],length=80,match=OFPMatch(oxm_fields={}),packet_count=7,priority=0,table_id=0)]
            # if 'in_port' not in stat.match or 'ipv4_dst' not in stat.match:
            #      continue
            #print stat,"<<<<<<<<<<<<" #.match,"<<<<<<<<<<<"

            #print stat,"STAT?<<<",index
            try:
                (network, mask) = stat.match['ipv4_dst']
                if (network, mask) not in self.prefix_bandwidth[dpid]:
                    self.prefix_bandwidth[dpid][(network, mask)] = {}
                #print network, mask,"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<",index
                if (network, mask) in self.prefix_bandwidth[dpid]:
                    match, out_port = self.extract_attributes_from_stats_reply(stat)
                    network, mask = stat.match['ipv4_dst']

                    try:
                        if out_port not in self.prefix_bandwidth[dpid][(network, mask)]:
                            self.prefix_bandwidth[dpid][(network, mask)][out_port] = {}

                        if 'bytes_count' not in self.prefix_bandwidth[dpid][(network, mask)][out_port]:
                            self.prefix_bandwidth[dpid][(network, mask)][out_port]['bytes_count'] = []
                        previous_count = self.prefix_bandwidth[dpid][(network, mask)][out_port]['bytes_count']
                        current_count = stat.byte_count
                        previous_count.append(current_count)
                        # if 'time' not in self.prefix_bandwidth[dpid][stat.match['ipv4_dst']][out_port]:
                        #     self.prefix_bandwidth[dpid][stat.match['ipv4_dst']][out_port]['time'] = 0
                        # previous_time = self.prefix_bandwidth[dpid][stat.match['ipv4_dst']][out_port]['time']
                        #
                        # print "\n\ncurrent_count: ", current_count, "previous_count: ", previous_count, "previous_time: ", previous_time, 'current time', time.time()
                        # print "IPv4 dst:",network,mask,"DPID:",dpid,"PORT:",out_port,stat.match['ipv4_dst'],"BANDWIDTH: %.4f bps \n"%(((current_count-previous_count)/(time.time()-previous_time))*8)
                        # self.prefix_bandwidth[dpid][stat.match['ipv4_dst']][out_port] = {'bytes_count': stat.byte_count,
                        #                                                'time': time.time(), 'bandwidth': (current_count-previous_count)/(time.time()-previous_time)*8}
                    except Exception as e:
                        #print e
                        pass
                #else:
                #    self.prefix_bandwidth[dpid][stat.match['ipv4_dst']][out_port]={'bytes_count':stat.byte_count,'time':time.time(),'bandwidth':0}

            except:
                #print "This rule does not contain IPv4"
                pass
            # print stat.instructions, "<<<<<<<<<<<"
            #in_port, match, out_port = self.extract_attributes_from_stats_reply(stat)
            #print "DPID:",dpid,in_port,match,out_port,"IIIIIIIIIIIIIIIII"

            # self.logger.info('%016x %8x %17s %8x %8d %8d',
            #                  ev.msg.datapath.id,
            #                  stat.match['in_port'], stat.match['ipv4_dst'],
            #                  out_port,  # Have two actions one for change MAC and other to forward the packet.
            #                  stat.packet_count, stat.byte_count)

        #print "\n\n\n\n\n\nAQUIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII1\n\n\n\n\n\n"
        for dpid in self.prefix_bandwidth:
            #print "\n\n\n\n\n\nAQUIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII2\n\n\n\n\n\n"
            for (network, mask) in self.prefix_bandwidth[dpid]:
                #print "\n\n\n\n\n\nAQUIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII3\n\n\n\n\n\n"
                #print self.prefix_bandwidth,self.prefix_bandwidth[dpid]
                for port in self.prefix_bandwidth[dpid][(network, mask)]:
                    #print "\n\n\n\n\n\nAQUIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII4\n\n\n\n\n\n",self.prefix_bandwidth
                    current_count = 0
                    for value in self.prefix_bandwidth[dpid][(network, mask)][port]['bytes_count']:
                        current_count += value
                    #print "\n\n\n\n\n\nAQUIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII\n\n\n\n\n\n"
                    if 'previous_count' not in self.prefix_bandwidth[dpid][(network, mask)][port]:
                        self.prefix_bandwidth[dpid][(network, mask)][port]['previous_count'] = current_count
                        if 'previous_time' not in self.prefix_bandwidth[dpid][(network, mask)][port]:
                            self.prefix_bandwidth[dpid][(network, mask)][port]['previous_time'] = time.time() # In milliseconds!!!
                            continue

                    for next_hop in self.networks[network]['next_hop']:
                        #print "Network:",network,"Next hop",next_hop,"DPID:",dpid,"Out port:",port
                        if ((self.networks[network]['next_hop'][next_hop]['switch'] == dpid) and
                                (self.networks[network]['next_hop'][next_hop]['port'] == port)):
                            previous_count = self.prefix_bandwidth[dpid][(network, mask)][port]['previous_count']
                            previous_time = self.prefix_bandwidth[dpid][(network, mask)][port]['previous_time']
                            current_time = time.time()
                            self.networks[network]['next_hop'][next_hop]['bandwidth'] = ((current_count - previous_count) / (
                                current_time - previous_time)) * 8

                            self.prefix_bandwidth[dpid][(network, mask)][port]['previous_count'] = current_count
                            self.prefix_bandwidth[dpid][(network, mask)][port]['bytes_count'] = []
                            self.prefix_bandwidth[dpid][(network, mask)][port]['previous_time'] = current_time
                            #print "\n\n\n\n\n\n"
                            #print "Current_count",current_count,"Previous_count",previous_count,"Current_time",current_time,"Previous_time",previous_time
                            #print "IPv4 dst:", network, mask, "DPID:", dpid, "PORT:", port,"BANDWIDTH: %.4f bps\n"%(((current_count - previous_count) / (
                            #    current_time - previous_time)) * 8)
                            #print "\n\n\n\n\n\n"
                            # print network, self.networks[network],"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@22",out_port,dpid

            # if 'time' not in self.prefix_bandwidth[dpid][stat.match['ipv4_dst']][out_port]:
            #     self.prefix_bandwidth[dpid][stat.match['ipv4_dst']][out_port]['time'] = 0
            # previous_time = self.prefix_bandwidth[dpid][stat.match['ipv4_dst']][out_port]['time']


            # print stat,"WTF?!"
            #print self.prefix_bandwidth,"\n\n"
            #print self.networks,"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<|||||||||||||||||||||||||||||"
            pass
            #print "ERROOOOOOOOOOOOOOOOOOOOOOOOO!!!!!!!!!!!!"
            # print [flow for flow in body]
            # key = lambda flow: (flow.match['in_port'],flow.match['ipv4_dst'])
            # print key
            # print "_flow_stats_reply_handler", ev.msg.body


    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        print 'send stats request: %016x', datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        # req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        # datapath.send_msg(req)

    '''
        Treat when a link goes up!
    '''

    def up_down(self, sw_src, sw_dst):
        self.topology.add_edge(sw_src, sw_dst)

    '''
        Treat when a link goes down!
    '''

    def link_down(self, sw_src, sw_dst):
        # print "Deleting ", sw_src, sw_dst, " from the network!\n\n\n\n\n"
        try:
            # Because the code uses bidirectional graph, it is required to remove both direction of link edges.
            self.topology.remove_edge(sw_src, sw_dst)
            self.topology.remove_edge(sw_dst, sw_src)
        except:
            print "Cannot remove ", sw_src, sw_dst
        # self.topology.remove_edge(destination_node, source_node)
        # Find the affected flows
        # print "Find the affected flows"
        # print "Global flow table ", self.global_flow_table
        # local_global_flow_table = self.global_flow_table.copy()
        # for key in local_global_flow_table:
        #     dpid, ip_pkt_src, ip_pkt_dst = key
        #     # Instructions:
        #     # 1: {'backup_switch': 4, 'forward_switch': 2, 'out_port': 4, 'in_port': 1, 'backup_port': 5},
        #     # 2: {'forward_switch': 3, 'out_port': 2, 'in_port': 1},
        #     # 3: {'forward_switch': '10.0.0.4', 'out_port': 1, 'in_port': 2},
        #     # 4: {'forward_switch': 3, 'out_port': 1, 'in_port': 2}, 'backup_path': [1, 4, 3], 'primary_path': [1, 2, 3]}
        #     primary_path = local_global_flow_table[key]['instructions']['primary_path']
        #     if sw_src in primary_path and sw_dst in primary_path:
        #         # Regenerate flows:
        #         try:
        #             first_sw = primary_path.index(sw_src)
        #             second_sw = primary_path.index(sw_dst)
        #             if first_sw > second_sw:
        #                 tmp = sw_src
        #                 sw_src = sw_dst
        #                 sw_dst = tmp
        #
        #             # Create new flows for primary_path
        #             if self.flow_creation_strategy == self.FLOW_CREATION_SIMPLE_FLOW:
        #                 # Simple flow creation: Ok!
        #                 # print "Simple flow recreation...", 'for',ip_pkt_src, ip_pkt_dst, sw_src, sw_dst,
        #                 # Add new paths...
        #                 self.simple_flow_creation_instance.simple_flow_creation(self.topology, self.datapaths,
        #                                                                         self.hosts,
        #                                                                         self.global_flow_table,
        #                                                                         ip_pkt_src, ip_pkt_dst,
        #                                                                         None, None, modify_rule=False)
        #                 # ...modify the old paths to the new ones.
        #                 # simple_flow_creation.simple_flow_creation(self.topology, self.datapaths, self.hosts,
        #                 #                                           self.global_flow_table,
        #                 #                                           ip_pkt_src, ip_pkt_dst, sw_src, sw_dst,
        #                 #                                           None,None,modify_rule=True)
        #             # Create vlans inside the SDN network
        #             elif self.flow_creation_strategy == self.FLOW_CREATION_SIMPLE_VLAN:
        #                 # Simple flow creation: Ok!
        #                 # print "Simple flow recreation...", 'for',ip_pkt_src, ip_pkt_dst, sw_src, sw_dst,
        #                 # Add new paths...
        #                 simple_flow_vlan.simple_flow_vlan(self.topology, self.datapaths, self.hosts,
        #                                                   self.global_flow_table,
        #                                                   ip_pkt_src, ip_pkt_dst, sw_src, sw_dst,
        #                                                   None, None, modify_rule=False)
        #
        #             elif self.flow_creation_strategy == self.FLOW_CREATION_PATH_PROTECTION:
        #                 # Path protection:
        #                 # print 'Applying Path protection:'
        #                 path_protection.path_protection(self.topology, self.datapaths, self.hosts,
        #                                                 self.global_flow_table,
        #                                                 ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, None, add_rules=True)
        #                 path_protection.path_protection(self.topology, self.datapaths, self.hosts,
        #                                                 self.global_flow_table,
        #                                                 ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, None, add_rules=False)
        #                 # self.path_protection(ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, msg=None, add_rules=False)
        #                 # self.simple_flow_creation(ip_src, ip_dst, source_node, destination_node, msg=None,
        #                 #                           buffer_id=None)
        #             elif self.flow_creation_strategy == self.FLOW_CREATION_PROTECTION_PHASE_LONG:
        #                 # Path protection:
        #                 # print 'Applying Path protection:'
        #                 self.protection_phase_LONG_with_VLAN_instance.protection_phase_LONG(self.topology,
        #                                                                                     self.datapaths, self.hosts,
        #                                                                                     self.global_flow_table,
        #                                                                                     ip_pkt_src, ip_pkt_dst,
        #                                                                                     sw_src, sw_dst, None,
        #                                                                                     add_rules=True)
        #                 self.protection_phase_LONG_with_VLAN_instance.protection_phase_LONG(self.topology,
        #                                                                                     self.datapaths, self.hosts,
        #                                                                                     self.global_flow_table,
        #                                                                                     ip_pkt_src, ip_pkt_dst,
        #                                                                                     sw_src, sw_dst, None,
        #                                                                                     add_rules=False)
        #                 # self.path_protection(ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, msg=None, add_rules=False)
        #                 # self.simple_flow_creation(ip_src, ip_dst, source_node, destination_node, msg=None,
        #                 #                           buffer_id=None)
        #             elif self.flow_creation_strategy == self.FLOW_CREATION_LOAD_BALANCING:
        #                 # Load Balacing Application: Ok!
        #                 # print 'Applying Load Balancing:'
        #                 load_balancing.load_balancing(self.topology, self.datapaths, self.hosts, self.global_flow_table,
        #                                               ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, msg=None)
        #                 # self.load_balancing(ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, msg=None)
        #
        #         except Exception as e:
        #             print e
        #             print "Not in primary path ", primary_path, " switches ", sw_src, sw_dst
        #
        #     print "DEU CERTO?!!!", primary_path
        # else:
        #     print "Global flow table ", self.global_flow_table

    def populate_hosts(self):

        #Cool-topology:
        # hosts = {'10.0.0.1': {'switch': 1, 'arp': "00:00:00:00:00:01", 'port': 1, 'router':'10.0.0.254'},
        #               '10.0.0.2': {'switch': 1, 'arp': "00:00:00:00:00:02", 'port': 2, 'router': '10.0.0.254'},
        #               '10.0.0.3': {'switch': 1, 'arp': "00:00:00:00:00:03", 'port': 3, 'router': '10.0.0.254'},
        #               '10.0.0.4': {'switch': 1, 'arp': "00:00:00:00:00:04", 'port': 4, 'router': '10.0.0.254'},
        #               '10.0.0.5': {'switch': 1, 'arp': "00:00:00:00:00:05", 'port': 5, 'router': '10.0.0.254'},
        #               '10.2.0.9': {'switch': 2, 'arp': "00:00:00:00:00:09", 'port': 1, 'router':'10.2.0.254'}}
        # endpoints = {('10.0.0.1', '10.2.0.9'): [1,3,2],
        #                   ('10.2.0.9', '10.0.0.1'): [2,3,1],
        #                   ('10.0.0.2', '10.2.0.9'): [1,2],
        #                   ('10.2.0.9', '10.0.0.2'): [2,1],
        #                   ('10.0.0.3', '10.2.0.9'): [1,2],
        #                   ('10.2.0.9', '10.0.0.3'): [2,1],
        #                   ('10.0.0.4', '10.2.0.9'): [1,2],
        #                   ('10.2.0.9', '10.0.0.4'): [2,1],
        #                   ('10.0.0.5', '10.2.0.9'): [1,2],
        #                   ('10.2.0.9', '10.0.0.5'): [2,1]}

        # Cycle-4-Monitor topology:
        # $ sudo python ryu/app/COOL/mininet_topo/cycle-4-Monitor.py
        # hosts = {  '10.0.0.1': {'switch': 1, 'arp': "00:00:00:00:00:01", 'port': 1},
        #                 '10.0.0.2': {'switch': 1, 'arp': "00:00:00:00:00:02", 'port': 2},
        #                 '10.0.0.3': {'switch': 1, 'arp': "00:00:00:00:00:03", 'port': 3},
        #                 '10.0.0.4': {'switch': 1, 'arp': "00:00:00:00:00:04", 'port': 4},
        #                 '10.0.0.5': {'switch': 1, 'arp': "00:00:00:00:00:05", 'port': 5},
        #                 '10.0.0.6': {'switch': 1, 'arp': "00:00:00:00:00:06", 'port': 6},
        #                 '10.0.0.7': {'switch': 1, 'arp': "00:00:00:00:00:07", 'port': 7},
        #                 '10.0.0.8': {'switch': 1, 'arp': "00:00:00:00:00:08", 'port': 8},
        #                 '10.0.0.9': {'switch': 1, 'arp': "00:00:00:00:00:09", 'port': 9},
        #                 '10.0.0.10': {'switch': 1, 'arp': "00:00:00:00:00:0A", 'port': 10},
        #
        #                 '10.0.0.11': {'switch': 1, 'arp': "00:00:00:00:01:01", 'port': 11},
        #                 '10.0.0.12': {'switch': 1, 'arp': "00:00:00:00:01:02", 'port': 12},
        #                 '10.0.0.13': {'switch': 1, 'arp': "00:00:00:00:01:03", 'port': 13},
        #                 '10.0.0.14': {'switch': 1, 'arp': "00:00:00:00:01:04", 'port': 14},
        #                 '10.0.0.15': {'switch': 1, 'arp': "00:00:00:00:01:05", 'port': 15},
        #                 '10.0.0.16': {'switch': 1, 'arp': "00:00:00:00:01:06", 'port': 16},
        #                 '10.0.0.17': {'switch': 1, 'arp': "00:00:00:00:01:07", 'port': 17},
        #                 '10.0.0.18': {'switch': 1, 'arp': "00:00:00:00:01:08", 'port': 18},
        #                 '10.0.0.19': {'switch': 1, 'arp': "00:00:00:00:01:09", 'port': 19},
        #                 '10.0.0.20': {'switch': 1, 'arp': "00:00:00:00:01:0A", 'port': 20},
        #
        #                 '10.0.0.21': {'switch': 1, 'arp': "00:00:00:00:02:01", 'port': 21},
        #                 '10.0.0.22': {'switch': 1, 'arp': "00:00:00:00:02:02", 'port': 22},
        #                 '10.0.0.23': {'switch': 1, 'arp': "00:00:00:00:02:03", 'port': 23},
        #                 '10.0.0.24': {'switch': 1, 'arp': "00:00:00:00:02:04", 'port': 24},
        #                 '10.0.0.25': {'switch': 1, 'arp': "00:00:00:00:02:05", 'port': 25},
        #                 '10.0.0.26': {'switch': 1, 'arp': "00:00:00:00:02:06", 'port': 26},
        #                 '10.0.0.27': {'switch': 1, 'arp': "00:00:00:00:02:07", 'port': 27},
        #                 '10.0.0.28': {'switch': 1, 'arp': "00:00:00:00:02:08", 'port': 28},
        #                 '10.0.0.29': {'switch': 1, 'arp': "00:00:00:00:02:09", 'port': 29},
        #                 '10.0.0.30': {'switch': 1, 'arp': "00:00:00:00:02:0A", 'port': 30},
        #
        #                 '10.0.0.31': {'switch': 1, 'arp': "00:00:00:00:03:01", 'port': 31},
        #                 '10.0.0.32': {'switch': 1, 'arp': "00:00:00:00:03:02", 'port': 32},
        #                 '10.0.0.33': {'switch': 1, 'arp': "00:00:00:00:03:03", 'port': 33},
        #                 '10.0.0.34': {'switch': 1, 'arp': "00:00:00:00:03:04", 'port': 34},
        #                 '10.0.0.35': {'switch': 1, 'arp': "00:00:00:00:03:05", 'port': 35},
        #                 '10.0.0.36': {'switch': 1, 'arp': "00:00:00:00:03:06", 'port': 36},
        #                 '10.0.0.37': {'switch': 1, 'arp': "00:00:00:00:03:07", 'port': 37},
        #                 '10.0.0.38': {'switch': 1, 'arp': "00:00:00:00:03:08", 'port': 38},
        #                 '10.0.0.39': {'switch': 1, 'arp': "00:00:00:00:03:09", 'port': 39},
        #                 '10.0.0.40': {'switch': 1, 'arp': "00:00:00:00:03:0A", 'port': 40},
        #
        #                 '10.0.0.41': {'switch': 1, 'arp': "00:00:00:00:04:01", 'port': 41},
        #                 '10.0.0.42': {'switch': 1, 'arp': "00:00:00:00:04:02", 'port': 42},
        #                 '10.0.0.43': {'switch': 1, 'arp': "00:00:00:00:04:03", 'port': 43},
        #                 '10.0.0.44': {'switch': 1, 'arp': "00:00:00:00:04:04", 'port': 44},
        #                 '10.0.0.45': {'switch': 1, 'arp': "00:00:00:00:04:05", 'port': 45},
        #                 '10.0.0.46': {'switch': 1, 'arp': "00:00:00:00:04:06", 'port': 46},
        #                 '10.0.0.47': {'switch': 1, 'arp': "00:00:00:00:04:07", 'port': 47},
        #                 '10.0.0.48': {'switch': 1, 'arp': "00:00:00:00:04:08", 'port': 48},
        #                 '10.0.0.49': {'switch': 1, 'arp': "00:00:00:00:04:09", 'port': 49},
        #                 '10.0.0.50': {'switch': 1, 'arp': "00:00:00:00:04:0A", 'port': 50},
        #
        #                 '10.0.0.100': {'switch': 3, 'arp': "00:00:00:00:00:FE", 'port': 1}}

        # Cycle-4 topology:
        # $ sudo python ryu/app/COOL/mininet_topo/cycle-4.py
        # hosts = {'10.0.0.1': {'switch': 1, 'arp': "00:00:00:00:00:01", 'port': 1},
        #               '10.0.0.2': {'switch': 1, 'arp': "00:00:00:00:00:02", 'port': 2},
        #               '10.0.0.3': {'switch': 1, 'arp': "00:00:00:00:00:03", 'port': 3},
        #               '10.0.0.4': {'switch': 3, 'arp': "00:00:00:00:00:04", 'port': 1}}

        # Cycle-3 topology: (FLOW_CREATION_PATH_PROTECTION)
        # $ sudo python ryu/app/COOL/mininet_topo/cycle-3.py
        # hosts = {'10.0.0.1': {'switch': 1, 'arp': "00:00:00:00:00:01", 'port': 1},
        #               '10.0.0.2': {'switch': 2, 'arp': "00:00:00:00:00:02", 'port': 1}}
        # simple_linear_2links with 3 hosts:
        hosts = {'10.0.0.1': {'switch': 1, 'arp': "00:00:00:00:00:01", 'port': 1},
                      '10.0.0.2': {'switch': 2, 'arp': "00:00:00:00:00:02", 'port': 1},
                      '10.0.0.3': {'switch': 2, 'arp': "00:00:00:00:00:03", 'port': 2}}

        # Abilene topology with 11 hosts to h2:
        #self.weight_distribution = [0, 0, 1, 2]
        #self.outbound_selection = 0

        # hosts = {'10.0.0.1': {'switch': 1, 'arp': "00:00:00:00:00:01", 'port': 1, 'router': '10.0.0.254'},
        #               '10.0.0.4': {'switch': 4, 'arp': "00:00:00:00:00:04", 'port': 1, 'router': '10.0.0.254'},
        #               '10.0.0.5': {'switch': 5, 'arp': "00:00:00:00:00:05", 'port': 1, 'router': '10.0.0.254'},
        #               '10.0.0.10': {'switch': 10, 'arp': "00:00:00:00:00:0A", 'port': 1, 'router': '10.0.0.254'}
        #               }

        # endpoints = {('10.0.0.1', '10.0.0.2'): [1, 3, 2],
        #                   ('10.0.0.2', '10.0.0.1'): [2, 3, 1],
        #                   ('10.0.0.2', '10.0.0.10'):[2, 5, 1],
        #                   ('10.0.0.2', '10.0.0.11'):[2, 3, 1],
        #                   ('10.0.0.2', '10.0.0.12'):[2, 5, 4, 1],
        #                   ('10.0.0.2', '10.0.0.13'):[2, 5, 4, 1]}

        # Cool-topology.py:
        # hosts = {'192.168.2.4': {'switch': 2, 'arp': "00:00:00:00:00:04", 'port': 4,'controller':"192.168.2.254"},
        #          '192.168.2.5': {'switch': 2, 'arp': "00:00:00:00:00:05", 'port': 3,'controller':"192.168.2.254"},
        #          '192.168.2.6': {'switch': 2, 'arp': "00:00:00:00:00:06", 'port': 5,'controller':"192.168.2.254"}
        #          #'192.168.2.254': {'switch': 2, 'arp': "00:00:00:00:00:07", 'port': 6,'controller':"192.168.2.254"},
        #          #'10.0.254.': {'switch': 2, 'arp': "00:00:00:00:00:07", 'port': 6,'controller':"192.168.2.254"}
        #          # '192.168.2.254': {'switch': 2, 'arp': "00:00:00:00:00:07", 'port': 6, 'controller': "192.168.2.254"},
        #          # '192.168.2.254': {'switch': 2, 'arp': "00:00:00:00:00:07", 'port': 6, 'controller': "192.168.2.254"},
        #          }


        # Single topology:

        #Adding the controller information (valid IP and ARP) to the list of hosts
        hosts['controller'] = {"10.0.1.254": {'arp': '00:10:00:01:00:fe'},
                               "10.0.2.254": {'arp': '00:10:00:02:00:fe'},
                               "192.168.2.254": {'arp': '00:10:00:02:00:fe'},
                               "10.0.254.254": {'arp': '00:10:00:02:00:fe'}}
        hosts['neighbors'] = {  '10.0.1.1': {'controller_ip':'10.0.1.254','switch': 2, 'arp': "00:00:00:00:00:01", 'port': 1},
                                '10.0.2.2': {'controller_ip':'10.0.2.254','switch': 2, 'arp': "00:00:00:00:00:02", 'port': 2},
                                '10.0.254.1': {'switch': 2, 'arp': "00:00:00:00:00:07", 'port': 6}}

        return hosts

    def populate_networks(self):
        networks = {'10.0.2.0': {'controller_ip':"10.0.2.254",'mask': '255.255.255.0',
                                    'next_hop': {"10.0.2.2": {'switch': 2, 'port': 2,'bandwidth': 0,'congested':0}},'best_hop':"10.0.2.2"},
                    '10.0.1.0': {'controller_ip':"10.0.1.254",'mask': '255.255.255.0',
                                    'next_hop': {"10.0.1.1": {'switch': 2, 'port': 1,'bandwidth': 0,'congested':0}},'best_hop':"10.0.1.1"},
                    # '172.16.0.0': {'controller_ip':"10.0.1.254",'mask': '255.255.255.0',
                    #                 'next_hop': {"10.0.1.1": {'switch': 2, 'port': 1,'bandwidth': 0,'congested':0},
                    #                              "10.0.2.2": {'switch': 2, 'port': 2,'bandwidth': 0,'congested':0}},
                    #                              'best_hop': "10.0.1.1"},
                    '10.0.254.0': {'controller_ip':"10.0.254.254",'mask': '255.255.255.0',
                                    'next_hop': {"10.0.254.1": {'switch': 2, 'port': 6,'bandwidth': 0,'congested':0}},'best_hop':"10.0.254.1"}
                    }
        return networks

    def populate_paper_hosts(self):
        hosts = {}
        # paper-incoming-topology.py:
        num_of_required_hosts = 50
        for i in range(1,num_of_required_hosts+1):
            mac = EUI(i)
            mac.dialect = mac_unix
            hosts['192.168.2.'+str(i)] = { 'switch':2,'arp': str(mac),'port':i, 'controller': "192.168.2.254"}



        # Adding the controller information (valid IP and ARP) to the list of hosts
        hosts['controller'] = {"10.0.1.254": {'arp': '00:10:00:01:00:fe'},
                               "10.0.2.254": {'arp': '00:10:00:02:00:fe'},
                               "192.168.2.254": {'arp': '00:10:00:02:00:fe'},
                               "10.0.254.254": {'arp': '00:10:00:02:00:fe'}}
        hosts['neighbors'] = {
            '10.0.1.1': {'controller_ip': '10.0.1.254', 'switch': 2, 'arp': "00:00:00:00:00:F1", 'port': num_of_required_hosts+1},
            '10.0.2.2': {'controller_ip': '10.0.2.254', 'switch': 2, 'arp': "00:00:00:00:00:F2", 'port': num_of_required_hosts+2},
            '10.0.254.1': {'switch': 2, 'arp': "00:00:00:00:00:F7", 'port': num_of_required_hosts+3}}

        return hosts


    def populate_paper_topoology(self):
        networks = {'10.0.2.0': {'controller_ip':"10.0.2.254",'mask': '255.255.255.0',
                                    'next_hop': {"10.0.2.2": {'switch': 2, 'port': 52,'bandwidth': 0,'congested':0}},'best_hop':"10.0.2.2"},
                    '10.0.1.0': {'controller_ip':"10.0.1.254",'mask': '255.255.255.0',
                                    'next_hop': {"10.0.1.1": {'switch': 2, 'port': 51,'bandwidth': 0,'congested':0}},'best_hop':"10.0.1.1"},
                    '172.16.0.0': {'controller_ip':"10.0.1.254",'mask': '255.255.255.0',
                                    'next_hop': {"10.0.1.1": {'switch': 2, 'port': 51,'bandwidth': 0,'congested':0},
                                                 "10.0.2.2": {'switch': 2, 'port': 52,'bandwidth': 0,'congested':0}},
                                                 'best_hop': "10.0.1.1"},
                    '10.0.254.0': {'controller_ip':"10.0.254.254",'mask': '255.255.255.0',
                                    'next_hop': {"10.0.254.1": {'switch': 2, 'port': 53,'bandwidth': 0,'congested':0}},'best_hop':"10.0.254.1"}
                    }
        return networks

#####################################################################NEW:

    def populate_paper_hosts_LONG(self):
        hosts = {}
        # paper-incoming-topology.py:
        num_of_required_hosts = 50
        for i in range(1, num_of_required_hosts + 1):
            mac = EUI(i)
            mac.dialect = mac_unix
            hosts['10.0.0.' + str(i)] = {'switch': 1, 'arp': str(mac), 'port': i, 'controller': "10.0.0.254"}
            # if i <= 3:
            #     hosts['10.0.0.' + str(i)] = {'switch': 1, 'arp': str(mac), 'port': i, 'controller': "10.0.0.254"}
            # else:
            #     hosts['10.0.0.' + str(i)] = {'switch': 3, 'arp': str(mac), 'port': i-3, 'controller': "10.0.0.254"}

        hosts['10.0.0.100'] = {'switch': 3, 'arp': 'FE:00:00:00:00:FE', 'port': 1, 'controller': "10.0.0.254"}
        #final_host = self.addHost('h100', ip='10.0.0.100/24', mac='FE:00:00:00:00:FE')
        # Adding the controller information (valid IP and ARP) to the list of hosts
        hosts['controller'] = {"10.0.0.254": {'arp': '00:10:00:01:00:fe'}}
        hosts['neighbors'] = {}

        return hosts

    def populate_paper_networks_LONG(self):
        # TOPO: long-example-topology.py

        networks = {'10.0.0.1': {'controller_ip':"10.0.0.254",'mask': '255.255.255.0',
                                    'next_hop': {"0.0.0.0": {'switch': 1, 'port': 1,'bandwidth': 0,'congested':0}},'best_hop':"0.0.0.0"},
                    '10.0.0.2': {'controller_ip':"10.0.0.254",'mask': '255.255.255.0',
                                    'next_hop': {"0.0.0.0": {'switch': 1, 'port': 2,'bandwidth': 0,'congested':0}},'best_hop':"0.0.0.0"},
                    '10.0.0.3': {'controller_ip':"10.0.0.254",'mask': '255.255.255.0',
                                    'next_hop': {"0.0.0.0": {'switch': 1, 'port': 3,'bandwidth': 0,'congested':0}},'best_hop':"0.0.0.0"},
                    '10.0.0.4': {'controller_ip':"10.0.0.254",'mask': '255.255.255.0',
                                    'next_hop': {"0.0.0.0": {'switch': 3, 'port': 1,'bandwidth': 0,'congested':0}},'best_hop':"0.0.0.0"},
                    '10.0.0.5': {'controller_ip':"10.0.0.254",'mask': '255.255.255.0',
                                    'next_hop': {"0.0.0.0": {'switch': 3, 'port': 2,'bandwidth': 0,'congested':0}},'best_hop':"0.0.0.0"},
                    '10.0.0.6': {'controller_ip':"10.0.0.254",'mask': '255.255.255.0',
                                    'next_hop': {"0.0.0.0": {'switch': 3, 'port': 3,'bandwidth': 0,'congested':0}},'best_hop':"0.0.0.0"}
                    }
        return networks

#####################################################################Cool-Topology.py:

    def populate_paper_hosts_COOL(self):
        hosts = {}
        # paper-incoming-topology.py:
        num_of_required_hosts = 6
        for i in range(1, num_of_required_hosts + 1):
            mac = EUI(i)
            mac.dialect = mac_unix
            #hosts['10.0.0.' + str(i)] = {'switch': 1, 'arp': str(mac), 'port': i, 'controller': "10.0.0.254"}
            if i <= 3:
                 hosts['10.0.0.' + str(i)] = {'switch': 1, 'arp': str(mac), 'port': i, 'controller': "10.0.0.254"}
            else:
                 hosts['10.0.0.' + str(i)] = {'switch': 3, 'arp': str(mac), 'port': i-3, 'controller': "10.0.0.254"}

        #hosts['10.0.0.100'] = {'switch': 3, 'arp': 'FE:00:00:00:00:FE', 'port': 1, 'controller': "10.0.0.254"}
        #final_host = self.addHost('h100', ip='10.0.0.100/24', mac='FE:00:00:00:00:FE')
        # Adding the controller information (valid IP and ARP) to the list of hosts
        hosts['controller'] = {"10.0.0.254": {'arp': '00:10:00:01:00:fe'}}
        hosts['neighbors'] = {}

        return hosts

    def populate_paper_networks_COOL(self):
        # TOPO: long-example-topology.py

        networks = {'10.0.0.1': {'controller_ip':"10.0.0.254",'mask': '255.255.255.0',
                                    'next_hop': {"0.0.0.0": {'switch': 1, 'port': 1,'bandwidth': 0,'congested':0}},'best_hop':"0.0.0.0"},
                    '10.0.0.2': {'controller_ip':"10.0.0.254",'mask': '255.255.255.0',
                                    'next_hop': {"0.0.0.0": {'switch': 1, 'port': 2,'bandwidth': 0,'congested':0}},'best_hop':"0.0.0.0"},
                    '10.0.0.3': {'controller_ip':"10.0.0.254",'mask': '255.255.255.0',
                                    'next_hop': {"0.0.0.0": {'switch': 1, 'port': 3,'bandwidth': 0,'congested':0}},'best_hop':"0.0.0.0"},
                    '10.0.0.4': {'controller_ip':"10.0.0.254",'mask': '255.255.255.0',
                                    'next_hop': {"0.0.0.0": {'switch': 3, 'port': 1,'bandwidth': 0,'congested':0}},'best_hop':"0.0.0.0"},
                    '10.0.0.5': {'controller_ip':"10.0.0.254",'mask': '255.255.255.0',
                                    'next_hop': {"0.0.0.0": {'switch': 3, 'port': 2,'bandwidth': 0,'congested':0}},'best_hop':"0.0.0.0"},
                    '10.0.0.6': {'controller_ip':"10.0.0.254",'mask': '255.255.255.0',
                                    'next_hop': {"0.0.0.0": {'switch': 3, 'port': 3,'bandwidth': 0,'congested':0}},'best_hop':"0.0.0.0"}
                    }
        return networks