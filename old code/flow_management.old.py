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

import ryu.app.COOL.topology_management.bgp_speaker
from ryu.app.COOL.cool_utils import flow_creator
# Import flow management strategies:
from ryu.app.COOL.flow_management import simple_flow_creation
from ryu.base import app_manager
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
# Lib to manipulate TCP/IP packets
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3


class FlowManagement(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    FLOW_CREATION_SIMPLE_FLOW = 1
    FLOW_CREATION_PATH_PROTECTION = 2
    FLOW_CREATION_LOAD_BALANCING = 3

    #To enable the bgp speaker
    ENABLE_BGP_SPEAKER = False#True

    def __init__(self, *args, **kwargs):
        super(FlowManagement, self).__init__(*args, **kwargs)
        print "FlowManagement started! ;)"
        self.ip_controller = {"10.0.0.254": '00:00:00:00:00:fe', "10.2.0.254": '00:00:00:00:00:fe'}
        self.arp_controller = '00:00:00:00:00:fe'
        self.group_id = {}
        self.installed_instructions = {}
        self.datapaths = {}

        #Cool-topology:
        # self.hosts = {'10.0.0.1': {'switch': 1, 'arp': "00:00:00:00:00:01", 'port': 1, 'router':'10.0.0.254'},
        #               '10.0.0.2': {'switch': 1, 'arp': "00:00:00:00:00:02", 'port': 2, 'router': '10.0.0.254'},
        #               '10.0.0.3': {'switch': 1, 'arp': "00:00:00:00:00:03", 'port': 3, 'router': '10.0.0.254'},
        #               '10.0.0.4': {'switch': 1, 'arp': "00:00:00:00:00:04", 'port': 4, 'router': '10.0.0.254'},
        #               '10.0.0.5': {'switch': 1, 'arp': "00:00:00:00:00:05", 'port': 5, 'router': '10.0.0.254'},
        #               '10.2.0.9': {'switch': 2, 'arp': "00:00:00:00:00:09", 'port': 1, 'router':'10.2.0.254'}}
        # self.endpoints = {('10.0.0.1', '10.2.0.9'): [1,3,2],
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
        # self.hosts = {  '10.0.0.1': {'switch': 1, 'arp': "00:00:00:00:00:01", 'port': 1},
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
        self.hosts = {'10.0.0.1': {'switch': 1, 'arp': "00:00:00:00:00:01", 'port': 1, 'router':'10.0.0.254'},
                      '10.0.0.2': {'switch': 1, 'arp': "00:00:00:00:00:02", 'port': 2, 'router': '10.0.0.254'},
                       '10.0.0.3': {'switch': 1, 'arp': "00:00:00:00:00:03", 'port': 3, 'router':'10.0.0.254'},
                       '10.0.0.4': {'switch': 3, 'arp': "00:00:00:00:00:04", 'port': 1, 'router':'10.0.0.254'}}

        # Cycle-3 topology:
        # $ sudo python ryu/app/COOL/mininet_topo/cycle-4.py
        self.hosts = {'10.0.0.1': {'switch': 1, 'arp': "00:00:00:00:00:01", 'port': 1},
                      '10.0.0.2': {'switch': 2, 'arp': "00:00:00:00:00:02", 'port': 1}}
        # simple_linear_2links with 3 hosts:
        # self.hosts = {'10.0.0.1': {'switch': 1, 'arp': "00:00:00:00:00:01", 'port': 1},
        #               '10.0.0.2': {'switch': 2, 'arp': "00:00:00:00:00:02", 'port': 1},
        #               '10.0.0.3': {'switch': 2, 'arp': "00:00:00:00:00:03", 'port': 2}}

        # Abilene topology with 11 hosts to h2:
        #self.weight_distribution = [0, 0, 1, 2]
        #self.outbound_selection = 0

        # self.hosts = {'10.0.0.1': {'switch': 1, 'arp': "00:00:00:00:00:01", 'port': 1, 'router': '10.0.0.254'},
        #               '10.0.0.4': {'switch': 4, 'arp': "00:00:00:00:00:04", 'port': 1, 'router': '10.0.0.254'},
        #               '10.0.0.5': {'switch': 5, 'arp': "00:00:00:00:00:05", 'port': 1, 'router': '10.0.0.254'},
        #               '10.0.0.10': {'switch': 10, 'arp': "00:00:00:00:00:0A", 'port': 1, 'router': '10.0.0.254'}
        #               }

        # self.endpoints = {('10.0.0.1', '10.0.0.2'): [1, 3, 2],
        #                   ('10.0.0.2', '10.0.0.1'): [2, 3, 1],
        #                   ('10.0.0.2', '10.0.0.10'):[2, 5, 1],
        #                   ('10.0.0.2', '10.0.0.11'):[2, 3, 1],
        #                   ('10.0.0.2', '10.0.0.12'):[2, 5, 4, 1],
        #                   ('10.0.0.2', '10.0.0.13'):[2, 5, 4, 1]}

        self.topology = nx.DiGraph()
        self.datapaths = {}


        self.global_flow_table = {}

        #All strategies are ok! However, just for one direction!!! :-) Fix it!!!

        self.flow_creation_strategy = self.FLOW_CREATION_SIMPLE_FLOW#Ok!:self.FLOW_CREATION_LOAD_BALANCING #Ok!:self.FLOW_CREATION_SIMPLE_FLOW #Default
        if self.ENABLE_BGP_SPEAKER:
            self.bgp_speaker = ryu.app.COOL.topology_management.bgp_speaker.BGP_Speaker()


    def get_global_flow_table(self):
        return self.global_flow_table


    def flow_creation(self,ip_pkt_src,ip_pkt_dst,msg):
        #ip_pkt = pkt.get_protocol(ipv4.ipv4)
        # print self.topology
        sw_src = self.hosts[ip_pkt_src]['switch']
        sw_dst = self.hosts[ip_pkt_dst]['switch']
        if self.flow_creation_strategy == self.FLOW_CREATION_SIMPLE_FLOW:
            # Simple flow creation: Ok!
            print self.topology, "<<<<<<<<<<<<<<<<<<<<<<<<<<<TOPOLOGY!!!!!!"
            # self.simple_flow_creation(ip_pkt_src, ip_pkt_dst, sw_src, sw_dst,msg,buffer_id=msg.buffer_id)
            simple_flow_creation.simple_flow_creation(self.topology,self.datapaths,self.hosts,
                                                      ip_pkt_src, ip_pkt_dst, sw_src, sw_dst,
                                                      msg,buffer_id=msg.buffer_id)

        elif self.flow_creation_strategy == self.FLOW_CREATION_PATH_PROTECTION:
            #TODO:Verify!
            # Path protection:
            print 'Applying Path protection:'
            self.path_protection(ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, msg)
        elif self.flow_creation_strategy == self.FLOW_CREATION_LOAD_BALANCING:
            # Load Balacing Application: Ok!
            print 'Applying Load Balancing:'
            self.load_balancing(ip_pkt_src, ip_pkt_dst, sw_src, sw_dst, msg)

    def treat_arp(self,arp_pkt,in_port,eth_pkt,datapath):
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

    def treat_icmp(self,pkt,in_port,eth_pkt,datapath):
        # treat ICMP packets for the controller
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if icmp_pkt:
            print "Ping to controller!"
            flow_creator._handle_icmp(datapath, in_port, eth_pkt, ip_pkt, icmp_pkt, self.arp_controller, ip_pkt.dst)



    def load_balancing(self,src_ip,dst_ip,sw_src,sw_dst,msg):
        path = list(nx.shortest_path(self.topology, sw_src,sw_dst))
        protected_path = path[:len(path)]
        protected_path_length = len(protected_path)
        #print protected_path,"<<<<<<<<"
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

    def path_protection(self, src_ip, dst_ip, sw_src, sw_dst, msg,add_rules=True):
        path = list(nx.shortest_path(self.topology, sw_src, sw_dst))
        protected_path = path[:len(path)]
        protected_path_length = len(protected_path)
        for index, node in enumerate(protected_path):
            if index + 1 == len(protected_path):
                break
            print path, protected_path
            # path:[1, 2, 3], protected:[1, 2]
            # ('10.0.0.1', '10.0.0.4'): [1, 2, 11, 8, 7, 4],
            # path: [1, 2, 11, 8, 7, 4],
            # protected_path: [1, 2, 11, 8, 7]
            copy_of_nxgraph = self.topology.copy()
            print index, "Protecting link ", path[protected_path_length - 2 - index], path[
                protected_path_length - 1 - index]

            #Verify if there is a backup path available:
            backup_path = None
            try:
                copy_of_nxgraph.remove_edge(path[protected_path_length - 2 - index],
                                        path[protected_path_length - 1 - index])
                # print "Teste>", list(nx.shortest_path(copy_of_nxgraph, path[protected_path_length-2-index],path[protected_path_length-1-index]))
                #            print "%d Backup paths for %s %s"%(index,path[index], path[index + 1])
                #            ??????Check all paths!!!
                backup_path = list(nx.shortest_path(copy_of_nxgraph, path[protected_path_length - 2 - index], path[-1]))


            except:
                print "Something is wrong!"

            # reverse_path = list(nx.shortest_path(self.topology, sw_ip_dst,sw_ip_src))
            # endpoints = {(src_ip,dst_ip): backup_path}
            endpoints = {(src_ip, dst_ip): {'primary': path, 'backup': backup_path}}
            # (src_ip,dst_ip): backup_path}
            #             (ip_pkt.dst, ip_pkt.src): reverse_path}
            #            print endpoints, backup_path,"Backup path"#, backup_path
            #            print "Primary path:",path
            # self.creating_paths(endpoints=endpoints, fine_grain=True, change_arp=False, pkt=None,primary_path=path)
            print "Endpoints:", endpoints
            self.failover_path_creator(endpoints=endpoints, fine_grain=True, change_arp=False, msg=msg,
                                       primary_path=path,add_rules=add_rules)

    '''
    Create the load balancing path
    '''

    def load_balancing_path_creator(self, endpoints=None, fine_grain=False, modify_rule=False, change_arp=True, msg=None,
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
            self.lb_install_instructions(instructions, endpoint, msg)



    '''
    Create the failover path
    '''

    def failover_path_creator(self, endpoints=None, fine_grain=False, modify_rule=False, change_arp=True, msg=None,
                     primary_path=None, buffer_id=None,add_rules=True):

        if endpoints == None or endpoints == {}:
            endpoints = self.endpoints
        for endpoint_index, endpoint in enumerate(endpoints):
            # Get switches:
            src, dst = endpoint
            primary_path = endpoints[endpoint]['primary']
            backup_path = endpoints[endpoint]['backup']
            if msg == None:
                in_port = 0
                print "Getting failover instructions without msg"
                instructions = self.get_failover_instructions(src, dst, primary_path, backup_path,in_port)
            else:
                print "Getting failover instructions with msg"
                instructions = self.get_failover_instructions(src,dst,primary_path,backup_path,in_port = msg.match['in_port'])

            print "Instructions:",instructions
            self.install_instructions(instructions, endpoint, msg,add_rules)



    '''
        Get failover instructions
    '''


    def get_failover_instructions(self, ip_src, ip_dst, primary_path, backup_path=None, in_port=None):
        print "Primary path:%s Backup path:%s" % (primary_path, backup_path)
        dict_of_inst = {}
        # if backup_path == None or len(backup_path) == 0:
        #     # print "Why?!!! :'("
        #     return dict_of_inst
        if primary_path == None:
            print "Instructions without primary path?! oO"
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
                #in_port = msg.match['in_port']
                out_port = self.get_port_from_adjacent_nodes(None, ip_dst)
                return {(primary_path[0], primary_path[0]): {'in_port': in_port, 'out_port': out_port}}
            # Adding primary path:
            print "Adding primary path:"
            for i in range(0, len(primary_path) - 1):
                print "Iteration ",i
                if i == 0:
                    in_port = self.get_port_from_adjacent_nodes(ip_src, None)
                else:
                    in_port = self.get_port_from_adjacent_nodes(primary_path[i], primary_path[i - 1])
                # print "From %s to %s on port %s" % (backup_path[num_flows], backup_path[num_flows + 1], self.topology[backup_path[num_flows]][backup_path[num_flows + 1]])
                out_port = self.topology[primary_path[i]][primary_path[i + 1]]['port']
                print out_port,"<<<<<<<"
                if backup_path != None:
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
            dict_of_inst['primary_path']=primary_path
            # Instructions: {1: {'primary': {2: {'out_port': 2, 'in_port': 1}}},
            # 2: {'primary': {3: {'out_port': 2, 'in_port': 1}}},
            # 3: {'primary': {'10.0.0.3': {'out_port': 1, 'in_port': 2}}}}

            if backup_path == None:
                return dict_of_inst
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

            dict_of_inst['backup_path'] = backup_path
            return dict_of_inst

    """
        Generate the set of meta instructions to a given path.
    """

    def get_instructions(self, ip_src, ip_dst, primary_path, backup_path=None, msg=None):
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
            for i in range(0, len(primary_path) - 1):
                if i == 0:
                    in_port = self.get_port_from_adjacent_nodes(ip_src, None)
                else:
                    in_port = self.get_port_from_adjacent_nodes(primary_path[i], primary_path[i - 1])
                # print "From %s to %s on port %s" % (backup_path[num_flows], backup_path[num_flows + 1], self.topology[backup_path[num_flows]][backup_path[num_flows + 1]])
                out_port = self.topology[primary_path[i]][primary_path[i + 1]]['port']
                # print out_port,"<<<<<<<"
                dict_of_inst[primary_path[i], primary_path[i + 1]] = {'in_port': in_port,
                                                                      'out_port': out_port}  # self.topology[primary_path[num_flows]][primary_path[num_flows + 1]]
                node = primary_path[i]
                if i + 1 == len(primary_path) - 1:
                    out_port = self.get_port_from_adjacent_nodes(None, ip_dst)
                    in_port = self.topology[primary_path[i + 1]][primary_path[i]]['port']
                    dict_of_inst[primary_path[i + 1], ip_dst] = {'in_port': in_port,
                                                                 'out_port': out_port}
            # Instructions: {(1, 2): {'port': 2}, (11, 10): {'port': 4}, (3, 1): {'port': 2}, (2, 11): {'port': 3}}
            return dict_of_inst

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


    def creating_paths(self,endpoints=None,fine_grain=False,modify_rule=False,change_arp=True,pkt=None,primary_path=None):
        print "Primary path:", primary_path
        # if endpoints == None or endpoints == {}:
        #     endpoints = self.endpoints
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

    '''
        Apply the instructions in the data plane elements.
    '''

    def lb_install_instructions(self, instructions, endpoint, msg):

        print "Instructions:", instructions
        src, dst = endpoint
        group_id = 0
        for index, sw_src in enumerate(instructions):
            # {1: {2: {'out_port': 2, 'in_port': 1, 'backup_port': 3}},
            # 2: {3: {'out_port': 2, 'in_port': 1, 'backup_port': 1}},
            # 3: {'10.0.0.3': {'out_port': 1, 'in_port': 2}},
            # 4: {3: {'out_port': 1, 'in_port': 2}}}
            has_backup_path = False
            if 'backup_port' in instructions[sw_src]:
                has_backup_path = True

            print "ID:", sw_src, ">>>>>>>", instructions[sw_src]
            primary_output_port = instructions[sw_src]['out_port']
            primary_input_port = instructions[sw_src]['in_port']
            sw_dst = instructions[sw_src]['forward_switch']
            backup_output_port = 0
            if has_backup_path:
                backup_output_port = instructions[sw_src]['backup_port']

            group_id = hash(str(src) + str(dst)) % (10 ** 8)
            print "Hash: ", group_id, " from:", src, dst
            # group_id = int(str(self.counter)+str(primary_path[0])+str(primary_path[-1]))

            # Create Group type Fast Failover
            # create_group_mod_failover_flow(datapath, group_id, out_port, backup_output_port=0,
            #                               create_group_id=False):
            if has_backup_path:
                flow_creator.create_group_mod_select_flow(self.datapaths[sw_src], group_id,
                                                          primary_output_port, backup_output_port, create_group_id=True)
            else:
                flow_creator.create_group_mod_select_flow(self.datapaths[sw_src], group_id, primary_output_port,
                                                          create_group_id=True)
            # else:
            #     flow_creator.create_group_mod_failover_flow(self.datapaths[sw_src], group_id, primary_output_port,
            #                                                 primary_output_port, create_group_id=False)#backup_output_port, create_group_id=True)
            # create_l3_failover_flow(datapath, in_port, out_port, ip_pkt, group_id=1, eth_pkt=None):

            # Recovering the IPv4 packet from Packet-In event

            pkt = packet.Packet(msg.data)
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if has_backup_path:
                flow_creator.create_lb_select_flow(self.datapaths[sw_src], primary_output_port,
                                                   backup_output_port,
                                                   ip_pkt, group_id=group_id, msg=msg)
            else:
                flow_creator.create_lb_select_flow(self.datapaths[sw_src], primary_input_port, primary_output_port,
                                                   ip_pkt, group_id=group_id, msg=msg)

        self.installed_instructions[endpoint] = {'instructions': instructions, 'group_id': group_id}

    '''
    Apply the instructions in the data plane elements.
    '''

    def install_instructions(self, instructions,endpoint, msg,add_rules=True):

        print "Instructions:", instructions
        primary_path = instructions['primary_path']
        src, dst = endpoint
        group_id = 0
        for index, sw_src in enumerate(instructions):
            # {1: {2: {'out_port': 2, 'in_port': 1, 'backup_port': 3}},
            # 2: {3: {'out_port': 2, 'in_port': 1, 'backup_port': 1}},
            # 3: {'10.0.0.3': {'out_port': 1, 'in_port': 2}},
            # 4: {3: {'out_port': 1, 'in_port': 2}}}
            has_backup_path = False
            if 'backup_port' in instructions[sw_src]:
                has_backup_path = True

            print "ID:", sw_src, ">>>>>>>", instructions[sw_src]

            #Used to avoid using the strings as dpid. #TODO:FIX ME!!!
            if sw_src == 'primary_path' or sw_src == 'backup_path':
                #File "/home/walber/Dropbox/SDN - Controllers/ryu/ryu/app/COOL/flow_management.py", line 675, in install_instructions
                # primary_output_port = instructions[sw_src]['out_port']
                # TypeError: list indices must be integers, not str
                continue
            primary_output_port = instructions[sw_src]['out_port']
            primary_input_port = instructions[sw_src]['in_port']
            sw_dst = instructions[sw_src]['forward_switch']
            backup_output_port = 0
            if has_backup_path:
                backup_output_port = instructions[sw_src]['backup_port']

            group_id = hash(str(primary_path[0])+str(src) + str(dst)+str(primary_path[0])) % (10 ** 8)
            avoid_override_rule = False
            if endpoint in self.installed_instructions:
                if group_id == self.installed_instructions[endpoint]['group_id']:
                    print "SOMETHING GOES WRONG ##############################"
                else:
                    avoid_override_rule = True
                    print primary_path[0],str(src),str(dst),"It will be override!!!!!!!!!!!\n\n\n\n"

            print "Hash: ", group_id, " from:", src, dst

            if self.flow_creation_strategy ==  self.FLOW_CREATION_LOAD_BALANCING:
                flow_creator.create_group_mod_select_flow(self.datapaths[sw_src], group_id, primary_output_port,
                                                        backup_output_port, create_group_id=add_rules)
            elif self.flow_creation_strategy ==  self.FLOW_CREATION_PATH_PROTECTION:
                if avoid_override_rule:
                    flow_creator.create_group_mod_failover_flow(self.datapaths[sw_src], group_id, primary_output_port,
                                                        backup_output_port, create_group_id=avoid_override_rule)
                else:
                    flow_creator.create_group_mod_failover_flow(self.datapaths[sw_src], group_id, primary_output_port,
                                                                backup_output_port, create_group_id=add_rules)
            else:
                print "DEU ERRROOOOOOOOOOOOOOOOOOOOOO!!!!!!!!!!!"

            # Recovering the IPv4 packet from Packet-In event
            pkt = packet.Packet(msg.data)
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            dpid = msg.datapath.id
            #print "\n\n\n\n",self.global_flow_table
            self.global_flow_table[dpid,ip_pkt.src,ip_pkt.dst] = {'instructions':instructions,'group_id':group_id}
            #print "\n\n\n\n", self.global_flow_table

            flow_creator.create_l3_failover_flow(self.datapaths[sw_src], primary_input_port, primary_output_port,
                                                 ip_pkt, group_id=group_id)
            if has_backup_path:
                flow_creator.create_l3_failover_flow(self.datapaths[sw_src], primary_output_port,
                                                     backup_output_port,
                                                     ip_pkt, group_id=group_id)

        self.installed_instructions[endpoint] = {'instructions':instructions,'group_id':group_id}

    def get_installed_instructions(self):
        return self.installed_instructions

    def simple_flow_creation(self,src_ip,dst_ip,sw_src,sw_dst,msg,buffer_id):
        print "Simple flow creation..."
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

        #Reconstruct the affected flows

    '''
    Treat when a link goes down!
    '''

    def link_down(self, source_node, destination_node):
        print "Deleting ", source_node, destination_node, " from the network!"
        self.topology.remove_edge(source_node, destination_node)
        #self.topology.remove_edge(destination_node, source_node)
        # Find the affected flows
        for key in self.global_flow_table:
            dpid, ip_src, ip_dst = key
            #Instructions:
            # 1: {'backup_switch': 4, 'forward_switch': 2, 'out_port': 4, 'in_port': 1, 'backup_port': 5},
            # 2: {'forward_switch': 3, 'out_port': 2, 'in_port': 1},
            # 3: {'forward_switch': '10.0.0.4', 'out_port': 1, 'in_port': 2},
            # 4: {'forward_switch': 3, 'out_port': 1, 'in_port': 2}, 'backup_path': [1, 4, 3], 'primary_path': [1, 2, 3]}
            primary_path = self.global_flow_table[key]['instructions']['primary_path']
            if source_node in primary_path and destination_node in primary_path:
                #Regenerate flows:
                try:
                    # Create new flows for primary_path
                    if self.flow_creation_strategy == self.FLOW_CREATION_SIMPLE_FLOW:
                        # Simple flow creation: Ok!
                        self.simple_flow_creation(ip_src, ip_dst, source_node, destination_node, msg=None, buffer_id=None)
                    elif self.flow_creation_strategy == self.FLOW_CREATION_PATH_PROTECTION:
                        # Path protection:
                        print 'Applying Path protection:'
                        self.path_protection(ip_src, ip_dst, source_node, destination_node, msg=None,add_rules=False)
                        # self.simple_flow_creation(ip_src, ip_dst, source_node, destination_node, msg=None,
                        #                           buffer_id=None)
                    elif self.flow_creation_strategy == self.FLOW_CREATION_LOAD_BALANCING:
                        # Load Balacing Application: Ok!
                        print 'Applying Load Balancing:'
                        self.load_balancing(ip_src, ip_dst, source_node, destination_node, msg=None)

                except:
                    print "Not in primary path ", primary_path, " switches ", source_node, destination_node

            print "DEU CERTO?!!!", primary_path

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
                # else:
                #     print "Esta ok!",msg.buffer_id
                print "Creating new flow    >>>>>>>"

                # def create_l3_flow_with_wildcard(datapath, in_port, out_port, ip_pkt_src, ip_pkt_dst, msg,
                #                                  modify_rule=False):
                flow_creator.create_l3_flow_with_wildcard(self.datapaths[node], in_port, out_port=out_port,
                                                          ip_pkt_src=src, ip_pkt_dst=dst,msg=msg,
                                                          priority= 50000,
                                                          modify_rule=False)

if __name__ == '__main__':
    pass
    # topo = Topology_discover(None, None, None)
    # links = [(2, 3, {'port': 3}), (2, 1, {'port': 2}), (3, 2, {'port': 2}), (1, 2, {'port': 2})]
    # topology = topo.topology
    # topology.add_nodes_from(switches)
