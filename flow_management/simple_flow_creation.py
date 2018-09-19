# COOL utils:
from ryu.app.COOL.cool_utils import flow_creator

# Generate the graph topology
import networkx as nx
#Enable multithread in Ryu (Eventle)
from ryu.lib import hub
from random import randint
import time


class Simple_Flow_Creation():

    def __init__(self,global_table={}):
        self.flows = global_table
        #self.monitor_of_flows_thread = hub.spawn(self.monitor_of_flows_thread)
        #print "AUIIIIIIIIIIIIII\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"


    def monitor_of_flows_thread(self):
        secondsToSleep = 1
        while True:
            # print "Vou dormir por %s segundos!!!" % secondsToSleep
            for flow_id in self.flows:
                print 'Flow:',flow_id,self.flows[flow_id]
            else:
                print "Printed the flows created!!!"
            #print "\n\n\nPrefix learned:\n\n\n", self.bgp_speaker.prefix_learned
            hub.sleep(secondsToSleep)


    def simple_flow_creation(self,topology, datapaths, hosts,global_flow_table, src_ip, dst_ip, msg=None, modify_rule=None,primary_path=None):
        print "Simple flow creation...", topology,datapaths
        #Define here how to create the path
        #Path between switches:
        #path = list(nx.shortest_path(topology, sw_src, sw_dst))
        #Path between hosts:
        if primary_path == None:
            primary_path = list(nx.shortest_path(topology, hosts[src_ip]['switch'],hosts[dst_ip]['switch']))

        print "PATH:",primary_path
        # ('10.0.0.1', '10.0.0.4'): [1, 2, 11, 8, 7, 4],
        # copy_of_nxgraph = self.topology.copy()
        # copy_of_nxgraph.remove_edge(2, 11)
        # backup_path = list(nx.shortest_path(copy_of_nxgraph, 2, sw_src,sw_dst))

        # reverse_path = list(nx.shortest_path(self.topology, sw_ip_dst,sw_ip_src))
        endpoints = {(src_ip, dst_ip): {'primary': primary_path, 'backup': None}}
        # (src_ip,dst_ip): backup_path}
        #             (ip_pkt.dst, ip_pkt.src): reverse_path}
        # print endpoints, path#, backup_path
        self.simple_path_creator(topology, datapaths, hosts,global_flow_table, endpoints=endpoints, fine_grain=True, modify_rule= modify_rule,
                     change_arp=False, msg=msg)

        # Reconstruct the affected flows

    def simple_path_creator(self,topology, datapaths, hosts, global_flow_table, endpoints=None,fine_grain=False,modify_rule=False,change_arp=True,msg=None,primary_path=None,buffer_id=None):
        # if endpoints == None or endpoints == {}:
        #     endpoints = self.endpoints
        for endpoint_index, endpoint in enumerate(endpoints):
            # Get switches:
            src, dst = endpoint
            primary_path = endpoints[endpoint]['primary']
            backup_path = endpoints[endpoint]['backup']

            instructions = self.get_instructions(topology, hosts,src,dst,primary_path,backup_path,msg)
            path = primary_path
            print "Instructions:",instructions


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
                print "Creating new flow    >>>>>>>"



                # def create_l3_flow_with_wildcard(datapath, in_port, out_port, ip_pkt_src, ip_pkt_dst, msg,
                #                                  modify_rule=False):
                flow_creator.create_l3_flow_with_wildcard(datapaths[node], in_port, out_port=out_port,
                                                          ip_pkt_src=src, ip_pkt_dst=dst,msg=msg,
                                                          priority= 50000,
                                                          modify_rule=modify_rule)

                #global_flow_table[node, src, dst] = {'instructions': instructions, 'group_id': 0}
                if node not in global_flow_table:
                    global_flow_table[node] = {dst:{'match':dst,'ip_src':src,'in_port': in_port, 'out_port': out_port,'instructions': instructions}}
                else:
                    global_flow_table[node][dst] = {'match':dst,'ip_src':src,'in_port': in_port, 'out_port': out_port,'instructions': instructions}

    """
        Get a port from a src node to dst node
    """

    def get_port_from_adjacent_nodes(self,topology, hosts, src_node, dst_node):
        # print "Get port from %s to %s" % (src_node, dst_node)
        if src_node in hosts:
            return hosts[src_node]['port']
        elif dst_node in hosts:
            return hosts[dst_node]['port']
        return topology[src_node][dst_node]['port']


    """
        Generate the set of meta instructions to a given path.
    """

    def get_instructions(self,topology, hosts,ip_src, ip_dst, primary_path, backup_path=None, msg=None):
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
                out_port = self.get_port_from_adjacent_nodes(topology, hosts,None, ip_dst)
                return {(primary_path[0], primary_path[0]): {'in_port': in_port, 'out_port': out_port}}
            for i in range(0, len(primary_path) - 1):
                if i == 0:
                    in_port = self.get_port_from_adjacent_nodes(topology, hosts,ip_src, None)
                else:
                    in_port = self.get_port_from_adjacent_nodes(topology, hosts,primary_path[i], primary_path[i - 1])
                # print "From %s to %s on port %s" % (backup_path[num_flows], backup_path[num_flows + 1], self.topology[backup_path[num_flows]][backup_path[num_flows + 1]])
                out_port = topology[primary_path[i]][primary_path[i + 1]]['port']
                # print out_port,"<<<<<<<"
                dict_of_inst[primary_path[i], primary_path[i + 1]] = {'in_port': in_port,
                                                                      'out_port': out_port}  # self.topology[primary_path[num_flows]][primary_path[num_flows + 1]]
                node = primary_path[i]
                if i + 1 == len(primary_path) - 1:
                    #Last node:
                    out_port = self.get_port_from_adjacent_nodes(topology, hosts,None, ip_dst)
                    in_port = topology[primary_path[i + 1]][primary_path[i]]['port']
                    dict_of_inst[primary_path[i + 1], ip_dst] = {'in_port': in_port,
                                                                 'out_port': out_port}

            dict_of_inst['primary_path'] = primary_path
            dict_of_inst['backup_path'] = backup_path
            # Instructions: {(1, 2): {'port': 2}, (11, 10): {'port': 4}, (3, 1): {'port': 2}, (2, 11): {'port': 3}}
            return dict_of_inst