# COOL utils:
from ryu.app.COOL.cool_utils import flow_creator

# Generate the graph topology
import networkx as nx

'''
The idea of this flow creation strategy is use VLAN tags inside the path and use fine-grain matches on the edge of the path
'''

def simple_flow_vlan(topology, datapaths, hosts,global_flow_table, src_ip, dst_ip, sw_src, sw_dst, msg, modify_rule):
    print "Simple flow creation with VLAN...", topology,datapaths
    #Define here how to create the path
    #Path between switches:
    #path = list(nx.shortest_path(topology, sw_src, sw_dst))
    #Path between hosts:
    path = list(nx.shortest_path(topology, hosts[src_ip]['switch'],hosts[dst_ip]['switch']))
    print "PATH:",path
    # ('10.0.0.1', '10.0.0.4'): [1, 2, 11, 8, 7, 4],
    # copy_of_nxgraph = self.topology.copy()
    # copy_of_nxgraph.remove_edge(2, 11)
    # backup_path = list(nx.shortest_path(copy_of_nxgraph, 2, sw_src,sw_dst))

    # reverse_path = list(nx.shortest_path(self.topology, sw_ip_dst,sw_ip_src))
    endpoints = {(src_ip, dst_ip): {'primary': path, 'backup': None}}
    # (src_ip,dst_ip): backup_path}
    #             (ip_pkt.dst, ip_pkt.src): reverse_path}
    # print endpoints, path#, backup_path
    simple_vlan_path_creator(topology, datapaths, hosts,global_flow_table, endpoints=endpoints, fine_grain=True, modify_rule= modify_rule,
                 change_arp=False, msg=msg)

    # Reconstruct the affected flows

def simple_vlan_path_creator(topology, datapaths, hosts, global_flow_table, endpoints=None,fine_grain=False,modify_rule=False,change_arp=True,msg=None,primary_path=None):
    # if endpoints == None or endpoints == {}:
    #     endpoints = self.endpoints
    for endpoint_index, endpoint in enumerate(endpoints):
        # Get switches:
        src, dst = endpoint
        primary_path = endpoints[endpoint]['primary']
        backup_path = endpoints[endpoint]['backup']

        #Extract path information
        sw_header = primary_path[0]
        sw_tail = primary_path[-1]
        vlan_tag = sw_tail # This will be a bug if the number of switches will be bigger than the number of VLAN tags

        instructions = get_instructions(topology, hosts, src, dst, primary_path, backup_path, msg)
        path = primary_path
        print "Instructions:", instructions

        #Avoid unavailability between hosts connected in the same switch.
        if sw_header == sw_tail:  # The hosts are connected with the switch.
            switch_node = (sw_header,sw_tail)
            in_port = instructions[switch_node]['in_port']
            out_port = instructions[switch_node]['out_port']
            flow_creator.create_simple_l3_flow(datapaths[sw_header], in_port, out_port=out_port,
                                               ip_pkt_src=src, ip_pkt_dst=dst, msg=msg,
                                               priority=50000,
                                               modify_rule=modify_rule)
            return # Avoid the installation of multiple rules for the same flow.


        add_rule = False

        # Creating primary path
        for nodes in instructions:
            #Ignoring 'primary_path', 'backup_paths' and 'vlan' keys.
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
            flow_creator.create_l2_vlan_flow(datapaths[node], sw_header,sw_tail,  vlan_tag, in_port, out_port=out_port,
                                                      ip_pkt_src=src, ip_pkt_dst=dst,msg=msg,
                                                      priority= 50000,
                                                      modify_rule=modify_rule)

            global_flow_table[node, src, dst] = {'instructions': instructions, 'group_id': 0}

"""
    Get a port from a src node to dst node
"""

def get_port_from_adjacent_nodes(topology, hosts, src_node, dst_node):
    # print "Get port from %s to %s" % (src_node, dst_node)
    if src_node in hosts:
        return hosts[src_node]['port']
    elif dst_node in hosts:
        return hosts[dst_node]['port']
    return topology[src_node][dst_node]['port']


"""
    Generate the set of meta instructions to a given path.
"""

def get_instructions(topology, hosts,ip_src, ip_dst, primary_path, backup_path=None, msg=None):

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
            out_port = get_port_from_adjacent_nodes(topology, hosts,None, ip_dst)
            return {(primary_path[0], primary_path[0]): {'in_port': in_port, 'out_port': out_port}}
        for i in range(0, len(primary_path) - 1):
            if i == 0:
                in_port = get_port_from_adjacent_nodes(topology, hosts,ip_src, None)
            else:
                in_port = get_port_from_adjacent_nodes(topology, hosts,primary_path[i], primary_path[i - 1])
            # print "From %s to %s on port %s" % (backup_path[num_flows], backup_path[num_flows + 1], self.topology[backup_path[num_flows]][backup_path[num_flows + 1]])
            out_port = topology[primary_path[i]][primary_path[i + 1]]['port']
            # print out_port,"<<<<<<<"
            dict_of_inst[primary_path[i], primary_path[i + 1]] = {'in_port': in_port,
                                                                  'out_port': out_port}  # self.topology[primary_path[num_flows]][primary_path[num_flows + 1]]
            node = primary_path[i]
            if i + 1 == len(primary_path) - 1:
                #Last node:
                out_port = get_port_from_adjacent_nodes(topology, hosts,None, ip_dst)
                in_port = topology[primary_path[i + 1]][primary_path[i]]['port']
                dict_of_inst[primary_path[i + 1], ip_dst] = {'in_port': in_port,
                                                             'out_port': out_port}

        dict_of_inst['primary_path'] = primary_path
        dict_of_inst['backup_path'] = backup_path
        # Instructions: {(1, 2): {'port': 2}, (11, 10): {'port': 4}, (3, 1): {'port': 2}, (2, 11): {'port': 3}}
        return dict_of_inst