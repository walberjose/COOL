# Lib to manipulate TCP/IP packets
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4

'''
It is only working for cycle-3.py. Debug to discover what the hell is going on!
'''

# COOL utils:
from ryu.app.COOL.cool_utils import flow_creator

# Generate the graph topology
import networkx as nx

#def path_protection(topology, datapaths, hosts,global_flow_table, src_ip, dst_ip, sw_src, sw_dst, msg, add_rules=True):
def load_balancing(topology, datapaths, hosts,global_flow_table,src_ip,dst_ip,sw_src,sw_dst,msg):
    # Define here how to create the path
    # Path between switches:
    # path = list(nx.shortest_path(topology, sw_src, sw_dst))
    # Path between hosts:
    path = list(nx.shortest_path(topology, hosts[src_ip]['switch'], hosts[dst_ip]['switch']))

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
        copy_of_nxgraph = topology.copy()
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
        failover_path_creator(topology, datapaths, hosts,global_flow_table,endpoints=endpoints, fine_grain=True, change_arp=False, msg=msg, primary_path=path)

'''
Create the failover path
'''

def failover_path_creator(topology, datapaths, hosts,global_flow_table, endpoints=None, fine_grain=False, modify_rule=False, change_arp=True, msg=None,
                 primary_path=None, buffer_id=None,add_rules=True):

    # if endpoints == None or endpoints == {}:
    #     endpoints = self.endpoints
    for endpoint_index, endpoint in enumerate(endpoints):
        # Get switches:
        src, dst = endpoint
        primary_path = endpoints[endpoint]['primary']
        backup_path = endpoints[endpoint]['backup']
        if msg == None:
            in_port = 0
            print "Getting failover instructions without msg"
            instructions = get_failover_instructions(topology, datapaths, hosts,global_flow_table,
                                                          src, dst, primary_path, backup_path,in_port)
        else:
            print "Getting failover instructions with msg"
            instructions = get_failover_instructions(topology, datapaths, hosts,global_flow_table,
                                                          src,dst,primary_path,backup_path,in_port = msg.match['in_port'])

        print "Instructions:",instructions
        install_instructions(topology, datapaths, hosts,global_flow_table,
                                  instructions, endpoint, msg,add_rules)

'''
    Get failover instructions
'''
def get_failover_instructions(topology, datapaths, hosts,global_flow_table, ip_src, ip_dst, primary_path, backup_path=None, in_port=None):
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
            out_port = get_port_from_adjacent_nodes(topology, hosts,None, ip_dst)
            return {(primary_path[0], primary_path[0]): {'in_port': in_port, 'out_port': out_port}}
        # Adding primary path:
        print "Adding primary path:"
        for i in range(0, len(primary_path) - 1):
            print "Iteration ",i
            if i == 0:
                in_port = get_port_from_adjacent_nodes(topology, hosts,ip_src, None)
            else:
                in_port = get_port_from_adjacent_nodes(topology, hosts,primary_path[i], primary_path[i - 1])
            # print "From %s to %s on port %s" % (backup_path[num_flows], backup_path[num_flows + 1], self.topology[backup_path[num_flows]][backup_path[num_flows + 1]])
            out_port = topology[primary_path[i]][primary_path[i + 1]]['port']
            print out_port,"<<<<<<<"
            if backup_path != None:
                if primary_path[i] in backup_path:
                    index = backup_path.index(primary_path[i])
                    print primary_path[i],"Backup?",backup_path[index],backup_path[index + 1]
                    dict_of_inst[primary_path[i]] ={ 'in_port': in_port,
                                                    'out_port': out_port,
                                                    'backup_port': topology[backup_path[index]][backup_path[index + 1]]['port'],
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
                out_port = get_port_from_adjacent_nodes(topology, hosts,None, ip_dst)
                in_port = topology[primary_path[i + 1]][primary_path[i]]['port']
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
                in_port = get_port_from_adjacent_nodes(topology, hosts,ip_src, None)
            else:
                in_port = get_port_from_adjacent_nodes(topology, hosts,backup_path[i], backup_path[i - 1])
            # print "From %s to %s on port %s" % (backup_path[num_flows], backup_path[num_flows + 1], self.topology[backup_path[num_flows]][backup_path[num_flows + 1]])
            out_port = topology[backup_path[i]][backup_path[i + 1]]['port']
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
                out_port = get_port_from_adjacent_nodes(topology, hosts,None, ip_dst)
                in_port = topology[backup_path[i + 1]][backup_path[i]]['port']
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
    Get a port from a src node to dst node
"""

def get_port_from_adjacent_nodes(topology, hosts, src_node, dst_node):
    # print "Get port from %s to %s" % (src_node, dst_node)
    if src_node in hosts:
        return hosts[src_node]['port']
    elif dst_node in hosts:
        return hosts[dst_node]['port']
    return topology[src_node][dst_node]['port']

'''
Apply the instructions in the data plane elements.
'''

def install_instructions(topology, datapaths, hosts,global_flow_table, instructions,endpoint, msg,add_rules=True):

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

        import hashlib
        group_id = hash(str(primary_path[0])+str(src) + str(dst)+str(primary_path[0])) % (10 ** 8)
        avoid_override_rule = False

        print "Hash: ", group_id, " from:", src, dst

        flow_creator.create_group_mod_select_flow(datapaths[sw_src], group_id, primary_output_port,
                                                    backup_output_port, create_group_id=add_rules)

        # Recovering the IPv4 packet from Packet-In event
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        dpid = msg.datapath.id
        #print "\n\n\n\n",self.global_flow_table
        global_flow_table[dpid, ip_pkt.src, ip_pkt.dst] = {'instructions': instructions, 'group_id': group_id}
        #print "\n\n\n\n", self.global_flow_table

        flow_creator.create_l3_failover_flow(datapaths[sw_src], primary_input_port, primary_output_port,
                                             ip_pkt,msg=msg, group_id=group_id)
        if has_backup_path:
            flow_creator.create_l3_failover_flow(datapaths[sw_src], primary_output_port,
                                                 backup_output_port,
                                                 ip_pkt, group_id=group_id)

        global_flow_table[sw_src, src, dst] = {'instructions': instructions, 'group_id': group_id}