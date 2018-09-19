# COOL utils:
from ryu.app.COOL.cool_utils import flow_creator

# Generate the graph topology
import networkx as nx

#Manipulate IP addresses
from netaddr import *

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
#from ryu.app.COOL.flow_management import flow_management

import random
from ryu.lib.packet import ipv4

class Simple_Routing_with_Load_Balancing():
    strategies = ["bgp",#0
                  "random",#1
                  "round-robin",#2
                  "bandwidth_utilization"]#3
    def __init__(self,congestion_window=3):
        self.strategy = self.strategies[0]  # Set the strategy to be used.
        self.valid_next_hop = {}
        self.congestion_window = congestion_window
        #print topology, datapaths, hosts,global_flow_table, networks,"LLLLLLLLLLLLLLL\n\n\n\n\n\n"

    def _pick_next_hop (self, network, possible_next_hops, best_next_hop):
        #network: 172.16.0.0
        #possible_next_hops: {'10.0.1.1': {'switch': 2, 'bandwidth': 0, 'port': 1, 'congested': 0}, '10.0.2.2': {'switch': 2, 'bandwidth': 0, 'port': 2, 'congested': 0}}
        #best_next_hop: 10.0.1.1
        print network, possible_next_hops, best_next_hop
        """
        Pick a next hop for a (hopefully) new connection
        """
        #Store the state of the network
        if network not in self.valid_next_hop:
            self.valid_next_hop[network] = []
            for next_hop in possible_next_hops:
                self.valid_next_hop[network].append(next_hop)

        #TODO:Check if the list of next_hops suffers a changing.
        #print "\n\n\n\n", "Valid next hops to before ", network, ":", self.valid_next_hop[network], "\n\n\n\n"
        #list_valid_next_hop = []
        for next_hop in possible_next_hops:
            if self.strategy == self.strategies[3]:
                #print "\n\n\nAQUIIIIII",self.valid_next_hop[network][next_hop],self.congestion_window
                if possible_next_hops[next_hop]['congested'] < self.congestion_window:
                    self.valid_next_hop[network].append(next_hop)
            else:
                pass
                # Used by other strategies:
                #list_valid_next_hop.append(next_hop)
                #self.valid_next_hop[network].append(next_hop)

        #print "\n\n\n\n","Valid next hops to ",network,":",self.valid_next_hop[network],"\n\n\n\n"
        #172.16.0.0 : ['10.0.1.1', '10.0.2.2']

        if self.strategy == self.strategies[3]:  # Bandwidth Utilization
            #Searching for a next hop that is not congested
            if len(self.valid_next_hop[network]) == 0:
                return best_next_hop
            else:
                for next_hop in possible_next_hops:
                    if possible_next_hops[next_hop]['congested'] < self.congestion_window:
                        #print "\n\n\n\n\n\n\n\n\n\nPICKED ", next_hop, " TO ", network, " BEST NEXT HOP", best_next_hop, "\n\n\n\n\n\n\n\n\n\n"
                        #Apply load balancing:
                        next_hop = self.valid_next_hop[network].pop(0)
                        self.valid_next_hop[network].append(next_hop)
                        return next_hop
                    #Next hop is congested!
                    next_hop = self.valid_next_hop[network].pop(0)
                    self.valid_next_hop[network].append(next_hop)
                #All valid next hop addresses are congested! O_O
                #print "All valid next hop addresses are congested! O_O"
                return best_next_hop

        if self.strategy == self.strategies[2]: # Round-robin
            # for server in  self.valid_next_hop:
            #     print server
            #next_hop = list_valid_next_hop.pop(0)
            next_hop = self.valid_next_hop[network].pop(0)
            #print "\n\n\n\n\nROUND-ROBIN\n\n\n\n\nPICKED ",next_hop," TO ", network," BEST NEXT HOP", best_next_hop,"\n\n\n\n\n\n\n\n\n\n"
            #list_valid_next_hop.append(next_hop)
            #self.valid_next_hop[network]= list_valid_next_hop#.append(next_hop)
            self.valid_next_hop[network].append(next_hop)
            return next_hop
        elif self.strategy == self.strategies[1]:# Random pick.
            return random.choice(self.valid_next_hop[network])
        elif self.strategy == self.strategies[0]:# BGP pick it up.
            return best_next_hop


    def routing_to_other_networks(self,topology, datapaths, hosts,global_flow_table, networks,msg):
        #print topology, datapaths, hosts, global_flow_table, networks,ip_pkt,msg, "LLLLLLLLLLLLLLL\n\n\n\n\n\n"
        #topology, datapaths, hosts, global_flow_table, networks,
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]
        arp_dst = eth_pkt.dst
        arp_src = eth_pkt.src
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
        # self.mac_to_port.setdefault(dpid, {})
        # self.mac_to_port[dpid][arp_src] = in_port

        #print "\n\n\n To other network %s \n\n\n" % (ip_pkt.dst)
        # TODO:
        #Verify if the source of the other network is a neighbor
        sw_src = self.search_the_switch_source(hosts, networks, ip_pkt.src)
        network = self.where_network_to_forward(hosts, networks,ip_pkt.dst)
        network_mask = networks[network]['mask']
        best_next_hop = self._pick_next_hop(network,networks[network]['next_hop'],networks[network]['best_hop'])
        sw_dst = networks[network]['next_hop'][best_next_hop]['switch']
        forward_port = networks[network]['next_hop'][best_next_hop]['port']
        next_hop_ip = best_next_hop
        next_hop_arp = hosts['neighbors'][next_hop_ip]['arp']
        controller_ip = networks[network]['controller_ip']
        controller_arp = hosts['controller'][controller_ip]['arp']
        # TODO: check if ARP resolution is working from different neighbors networks.

        routing_instructions = {sw_dst: {'old_arp_src': arp_src, 'old_arp_dst': arp_dst, 'forward_port': forward_port,
                                         'new_arp_src': controller_arp, 'new_arp_dst': next_hop_arp,
                                         'network': network, 'mask': network_mask}}
        #print routing_instructions,"Routing instructions"
        self.simple_routing(topology, datapaths, hosts,global_flow_table, networks,ip_pkt.src, ip_pkt.dst, sw_src, sw_dst,
                                      msg, routing_instructions, buffer_id=msg.buffer_id, modify_rule=False)
        #print "Tudo certo!"


    def routing_from_other_networks(self,topology, datapaths, hosts,global_flow_table,networks,msg):
        print "Packets from other network to a host inside the OpenFlow network."
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]
        arp_dst = eth_pkt.dst
        arp_src = eth_pkt.src
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
        # self.mac_to_port.setdefault(dpid, {})
        # self.mac_to_port[dpid][arp_src] = in_port

        #print "\n\n\n From other network %s to %s \n\n\n" % (ip_pkt.src,ip_pkt.dst)
        # TODO:
        # sw_src = self.hosts[ip_pkt.src]['switch']
        network = self.where_network_to_forward(hosts, networks,ip_pkt.dst)
        if network in hosts:
            sw_src = dpid
            sw_dst = hosts[ip_pkt.dst]['switch']
            forward_port = hosts[ip_pkt.dst]['port']
            controller = hosts[ip_pkt.dst]['controller']
            controller_arp = hosts['controller'][controller]['arp']
            next_hop_arp = hosts[ip_pkt.dst]['arp']
            #Because it is a host, then /32
            network_mask = "255.255.255.255"
            routing_instructions = {
                sw_dst: {'old_arp_src': arp_src, 'old_arp_dst': arp_dst, 'forward_port': forward_port,
                         'new_arp_src': controller_arp, 'new_arp_dst': next_hop_arp,
                         'network': network, 'mask': network_mask}}
            #print "Routing inst", routing_instructions

            self.simple_routing(topology, datapaths, hosts, global_flow_table, networks, ip_pkt.src, ip_pkt.dst, sw_src,
                                sw_dst,
                                msg, routing_instructions, buffer_id=msg.buffer_id, modify_rule=False)

        elif network in networks:

            network_mask = networks[network]['mask']  # "255.255.255.255"

            # networks = {'10.0.2.0': {'controller_ip': "10.0.2.254", 'mask': '255.255.255.0',
            #                          'next_hop': {"10.0.2.2": {'switch': 2, 'port': 2}}, 'best_hop': "10.0.2.2"},
            #             '10.0.1.0': {'controller_ip': "10.0.1.254", 'mask': '255.255.255.0',
            #                          'next_hop': {"10.0.1.1": {'switch': 2, 'port': 1}}, 'best_hop': "10.0.1.1"},
            #             '172.16.0.0': {'controller_ip': "10.0.1.254", 'mask': '255.255.255.0',
            #                            'next_hop': {"10.0.1.1": {'switch': 2, 'port': 1},
            #                                         "10.0.2.2": {'switch': 2, 'port': 2},
            #                                         'best_hop': "10.0.1.1"}}}
            best_next_hop = networks[network]['best_hop']
            #sw_dst = networks[network]['next_hop'][best_next_hop]['switch']
            #forward_port = networks[network]['next_hop'][best_next_hop]['port']
            #next_hop_ip = best_next_hop

            sw_dst = networks[network]['next_hop'][best_next_hop]['switch']
            forward_port = hosts[ip_pkt.dst]['port']

            sw_src = hosts[ip_pkt.dst]['switch']
            next_hop_ip = ip_pkt.dst  # self.networks[network]['next_hop']
            next_hop_arp = hosts[ip_pkt.dst]['arp']  # self.hosts['neighbors'][next_hop_ip]['arp']
            controller_ip = networks[network]['controller_ip']
            controller_arp = hosts['controller'][controller_ip]['arp']
            # TODO: check if ARP resolution is working from different neighbors networks.

            routing_instructions = {
                sw_dst: {'old_arp_src': arp_src, 'old_arp_dst': arp_dst, 'forward_port': forward_port,
                         'new_arp_src': controller_arp, 'new_arp_dst': next_hop_arp,
                         'network': network, 'mask': network_mask}}
            #print "Routing inst",routing_instructions
            self.simple_routing(topology, datapaths, hosts,global_flow_table,networks,ip_pkt.src, ip_pkt.dst, sw_src, sw_dst,
                                          msg, routing_instructions, buffer_id=msg.buffer_id, modify_rule=False)

        else:
            "ERROR: I don't know what to do with this packet!"



    def simple_routing(self,topology, datapaths, hosts,global_flow_table, networks,
                       src_ip, dst_ip, sw_src, sw_dst, msg, routing_inst, buffer_id, modify_rule):
        #print "Simple flow creation...", topology,datapaths
        #Define here how to create the path
        #Path between switches:
        #path = list(nx.shortest_path(topology, sw_src, sw_dst))
        #Path between hosts:
        path = list(nx.shortest_path(topology, sw_src,sw_dst))
        #print "PATH:",path
        # ('10.0.0.1', '10.0.0.4'): [1, 2, 11, 8, 7, 4],
        # copy_of_nxgraph = self.topology.copy()
        # copy_of_nxgraph.remove_edge(2, 11)
        # backup_path = list(nx.shortest_path(copy_of_nxgraph, 2, sw_src,sw_dst))

        # reverse_path = list(nx.shortest_path(self.topology, sw_ip_dst,sw_ip_src))
        endpoints = {(src_ip, dst_ip): {'primary': path, 'backup': None}}
        # (src_ip,dst_ip): backup_path}
        #             (ip_pkt.dst, ip_pkt.src): reverse_path}
        #print endpoints, path#, backup_path
        self.simple_routing_creator(topology, datapaths, hosts,global_flow_table, networks,
                                    routing_inst, endpoints=endpoints, fine_grain=True, modify_rule= modify_rule,
                     change_arp=False, msg=msg, buffer_id=buffer_id)

        # Reconstruct the affected flows

    def simple_routing_creator(self,topology, datapaths, hosts,global_flow_table, networks,
                               routing_inst, endpoints=None,fine_grain=False,modify_rule=False,change_arp=True,
                               msg=None,primary_path=None,buffer_id=None):
        # if endpoints == None or endpoints == {}:
        #     endpoints = self.endpoints
        for endpoint_index, endpoint in enumerate(endpoints):
            # Get switches:
            src, dst = endpoint
            #print endpoint,"Endpoint"
            primary_path = endpoints[endpoint]['primary']
            backup_path = endpoints[endpoint]['backup']


            instructions = self.get_instructions(topology, hosts,networks, src,dst,primary_path,backup_path,msg)
            last_node_in_path = primary_path[-1]
            #print "Instructions:",instructions


            add_rule = False
            # Creating primary path
            for nodes in instructions:
                #Ignoring 'primary_path' and 'backup_paths' keys.
                if isinstance(nodes,(str,unicode)):
                    continue

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
                #print "Creating new flow    >>>>>>>"



                # def create_l3_flow_with_wildcard(datapath, in_port, out_port, ip_pkt_src, ip_pkt_dst, msg,
                #                                  modify_rule=False):
                if last_node_in_path != node:
                    flow_creator.create_l3_flow_with_wildcard(datapaths[node], in_port, out_port=out_port,
                                                          ip_pkt_src=src, ip_pkt_dst=dst, msg=msg,
                                                          #priority=50000,
                                                          modify_rule=modify_rule)
                else:
                    # routing_instructions = {
                    #     sw_dst: {'old_arp_src': arp_src, 'old_arp_dst': arp_dst, 'forward_port': forward_port,
                    #              'new_arp_src': controller_arp, 'new_arp_dst': next_hop_arp,
                    #              'network': network, 'mask': network_mask}}
                    out_port = routing_inst[node]['forward_port']
                    set_arp_dst = routing_inst[node]['new_arp_dst']
                    set_arp_src = routing_inst[node]['new_arp_src']
                    network = routing_inst[node]['network']
                    network_mask = routing_inst[node]['mask']
                    flow_creator.create_routing_with_wildcard(datapaths[node], in_port, out_port=out_port,
                                                              set_arp_dst=set_arp_dst,set_arp_src=set_arp_src,
                                                              network=network,network_mask=network_mask,
                                                              msg=msg,#priority= 50000,
                                                              modify_rule=modify_rule)

                global_flow_table[node, src, dst] = {'instructions': instructions, 'group_id': 0}

    def search_the_switch_source(self,hosts,networks,ip_pkt_src):
        if ip_pkt_src in hosts:
            return hosts[ip_pkt_src]['switch']
        else:
            network = self.where_network_to_forward( hosts, networks, ip_pkt_src)
            best_next_hop = networks[network]['best_hop']
            return networks[network]['next_hop'][best_next_hop]['switch']


    def is_in_network_learned(self, networks, ip_address):
        for network in networks:
            network_mask = networks[network]['mask']
            #print network,ip_address,IPNetwork(ip_address +'/'+ network_mask),IPNetwork(network+'/'+ network_mask)
            if IPNetwork(str(ip_address) + '/' + str(network_mask)) == IPNetwork(str(network) + '/' + str(network_mask)):
                #print "TRUE"
                return True
        return False

    def where_network_to_forward(self,hosts, networks, ip_address):
        # Verify internal networks:
        if ip_address in hosts:
             return ip_address

        #Verify external networks:
        for network in networks:
            network_mask = networks[network]['mask']
            #print network,ip_address,IPNetwork(ip_address +'/'+ network_mask),IPNetwork(network+'/'+ network_mask)
            if IPNetwork(str(ip_address) +'/'+ str(network_mask)) == IPNetwork(str(network)+'/'+ str(network_mask)):
                return network

        print "I dont know!!!!", ip_address, networks,hosts
        return "0.0.0.0"
    """
        Get a port from a src node to dst node
    """

    def get_port_from_adjacent_nodes(self, topology, hosts,networks, src_node, dst_node):
        # print "Get port from %s to %s" % (src_node, dst_node)
        if src_node in hosts:
            return hosts[src_node]['port']
        elif dst_node in hosts:
            return hosts[dst_node]['port']
        elif self.is_in_network_learned(networks,dst_node):
            # networks = {'10.0.2.0': {'controller_ip': "10.0.2.254", 'mask': '255.255.255.0',
            #                          'next_hop': {"10.0.2.2": {'switch': 2, 'port': 2}}, 'best_hop': "10.0.2.2"},
            #             '10.0.1.0': {'controller_ip': "10.0.1.254", 'mask': '255.255.255.0',
            #                          'next_hop': {"10.0.1.1": {'switch': 2, 'port': 1}}, 'best_hop': "10.0.1.1"},
            #             '172.16.0.0': {'controller_ip': "10.0.1.254", 'mask': '255.255.255.0',
            #                            'next_hop': {"10.0.1.1": {'switch': 2, 'port': 1},
            #                                         "10.0.2.2": {'switch': 2, 'port': 2},
            #                                         'best_hop': "10.0.1.1"}}}

            learned_network = self.where_network_to_forward(hosts, networks,dst_node)
            #print src_node, dst_node, "<<<<<<<<<<",learned_network,"||||||||||||",networks[learned_network]
            best_next_hop = networks[learned_network]['best_hop']
            forward_port = networks[learned_network]['next_hop'][best_next_hop]['port']
            return forward_port
        try:
            return topology[src_node][dst_node]['port']
        except:
            return None


    """
        Generate the set of meta instructions to a given path.
    """

    def get_instructions(self,topology, hosts, networks,ip_src, ip_dst, primary_path, backup_path=None, msg=None):
        #print "Primary path:%s Backup path:%s" % (primary_path, backup_path)
        dict_of_inst = {}
        # if backup_path == None or len(backup_path) == 0:
        #     # print "Why?!!! :'("
        #     return dict_of_inst
        if primary_path == None:
            return dict_of_inst
        else:
            #print "Primary path:", primary_path, "Backup path:", backup_path
            # Path:[1, 2, 3]
            # Instructions: {(3, 2): {'port': 2}, (2, 1): {'port': 1}}
            # Just create a single set of instructions:
            node = primary_path[0]
            in_port = 0  # self.get_port_from_adjacent_nodes(ip_src, None)
            if len(primary_path) == 1:
                # Special case, where exist only one element in the primary_path
                in_port = msg.match['in_port']
                out_port = self.get_port_from_adjacent_nodes(topology, hosts,networks,None, ip_dst)
                return {(primary_path[0], primary_path[0]): {'in_port': in_port, 'out_port': out_port}}
            for i in range(0, len(primary_path) - 1):
                if i == 0:
                    in_port = self.get_port_from_adjacent_nodes(topology, hosts,networks,ip_src, None)
                else:
                    in_port = self.get_port_from_adjacent_nodes(topology, hosts,networks,primary_path[i], primary_path[i - 1])
                # print "From %s to %s on port %s" % (backup_path[num_flows], backup_path[num_flows + 1], self.topology[backup_path[num_flows]][backup_path[num_flows + 1]])
                out_port = topology[primary_path[i]][primary_path[i + 1]]['port']
                # print out_port,"<<<<<<<"
                dict_of_inst[primary_path[i], primary_path[i + 1]] = {'in_port': in_port,
                                                                      'out_port': out_port}  # self.topology[primary_path[num_flows]][primary_path[num_flows + 1]]
                node = primary_path[i]
                if i + 1 == len(primary_path) - 1:
                    #Last node:
                    out_port = self.get_port_from_adjacent_nodes(topology, hosts,networks,None, ip_dst)
                    in_port = topology[primary_path[i + 1]][primary_path[i]]['port']
                    dict_of_inst[primary_path[i + 1], ip_dst] = {'in_port': in_port,
                                                                 'out_port': out_port}

            dict_of_inst['primary_path'] = primary_path
            dict_of_inst['backup_path'] = backup_path
            # Instructions: {(1, 2): {'port': 2}, (11, 10): {'port': 4}, (3, 1): {'port': 2}, (2, 11): {'port': 3}}
            return dict_of_inst