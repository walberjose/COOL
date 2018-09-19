# Lib to manipulate TCP/IP packets
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types

'''
It is only working for cycle-3.py. Debug to discover what the hell is going on!
'''

# COOL utils:
from ryu.app.COOL.cool_utils import flow_creator

# Generate the graph topology
import networkx as nx

class Protection_Phase_LONG_with_VLAN():

    def __init__(self):
        self.group_set_IDs = {} #group_id=30159066,type=ff,bucket=watch_port:2,actions=output:2,output:2
                                #self.group_set_IDs[watch_port,output,]


    def protection_phase_LONG(self, topology, datapaths, hosts,global_flow_table, src_ip, dst_ip, sw_src, sw_dst, msg, add_rules=True):
        # Define here how to create the path
        # Path between switches:
        # path = list(nx.shortest_path(topology, sw_src, sw_dst))
        # Path between hosts:
        path = list(nx.shortest_path(topology, hosts[src_ip]['switch'], hosts[dst_ip]['switch']))
        protected_path = path[:len(path)]
        print path,protected_path
        protected_path_length = len(protected_path)
        #for index, node in enumerate(protected_path):
        # if index + 1 == len(protected_path):
        #     print "Parou"
        #     break
        print path, protected_path
        # path:[1, 2, 3], protected:[1, 2]
        # ('10.0.0.1', '10.0.0.4'): [1, 2, 11, 8, 7, 4],
        # path: [1, 2, 11, 8, 7, 4],
        # protected_path: [1, 2, 11, 8, 7]
        copy_of_nxgraph = topology.copy()
        print "Protecting link ", path[protected_path_length - 2], path[protected_path_length - 1]

        # Verify if there is a backup path available:
        backup_path = None
        try:
            copy_of_nxgraph.remove_edge(path[protected_path_length - 2 ], # ante-penultimo
                                        path[protected_path_length - 1 ]) # ultimo switch
            # print "Teste>", list(nx.shortest_path(copy_of_nxgraph, path[protected_path_length-2-index],path[protected_path_length-1-index]))
            #            print "%d Backup paths for %s %s"%(index,path[index], path[index + 1])
            #            ??????Check all paths!!!
            backup_path = list(nx.shortest_path(copy_of_nxgraph, path[protected_path_length - 2], path[-1]))
        except:
            print "Something seems to be going wrong!"

        # reverse_path = list(nx.shortest_path(self.topology, sw_ip_dst,sw_ip_src))
        # endpoints = {(src_ip,dst_ip): backup_path}
        endpoints = {(src_ip, dst_ip): {'primary': path, 'backup': backup_path}}
        # (src_ip,dst_ip): backup_path}
        #             (ip_pkt.dst, ip_pkt.src): reverse_path}
        #            print endpoints, backup_path,"Backup path"#, backup_path
        #            print "Primary path:",path
        # self.creating_paths(endpoints=endpoints, fine_grain=True, change_arp=False, pkt=None,primary_path=path)
        print "Endpoints:", endpoints
        self.protection_phase_LONG_creator(topology, datapaths, hosts,global_flow_table,endpoints=endpoints, fine_grain=True, change_arp=False, msg=msg,
                                   primary_path=path, add_rules=add_rules)



    '''
    Create the failover path
    '''
    def protection_phase_LONG_creator(self,topology, datapaths, hosts,global_flow_table, endpoints=None, fine_grain=False, modify_rule=False, change_arp=True, msg=None,
                     primary_path=None, buffer_id=None,add_rules=True):

        instructions = None
        if endpoints == None or endpoints == {}:
            endpoints = endpoints
        for endpoint_index, endpoint in enumerate(endpoints):
            # Get switches:
            src, dst = endpoint
            primary_path = endpoints[endpoint]['primary']
            backup_path = endpoints[endpoint]['backup']
            protected_path_length = 0
            if backup_path != None:
                protected_path_length = len(backup_path)

            #Instructions for the primary path:
            if msg == None:
                in_port = 0
                print "Getting failover instructions without msg"
                instructions = self.get_primary_path_instructions(topology, datapaths, hosts, global_flow_table, src, dst,
                                                             primary_path, backup_path, in_port)
            else:
                print "Getting failover instructions with msg"
                instructions = self.get_primary_path_instructions(topology, datapaths, hosts, global_flow_table, src, dst,
                                                             primary_path, backup_path, in_port=msg.match['in_port'])

            #print "\n\n\n\n\n\n\nPrimary Instructions:", instructions
            # Instructions: {'primary_path': [1, 2, 3],
            #                1: {'has_failover_path': False, 'vlan': 3, 'forward_switch': 2, 'out_port': 4, 'in_port': 1},
            #                2: {'has_failover_path': False, 'vlan': 3, 'forward_switch': 3, 'out_port': 2, 'in_port': 1},
            #                3: {'has_failover_path': False, 'vlan': 3, 'forward_switch': '10.0.0.4', 'out_port': 1,
            #                    'in_port': 4}}

            # Protect each link belong to the
            if protected_path_length != 0:
                for index, node in enumerate(backup_path):
                    sw_source_link = backup_path[protected_path_length - 2 - index]
                    sw_destination_link  = backup_path[protected_path_length - 1 - index]
                    #print "Protecting link ", path[protected_path_length - 2 - index], path[protected_path_length - 1 - index]

                    # Protect every link in the backup path!!!>D

                    if msg == None:
                        in_port = 0
                        print "Getting failover instructions without msg"
                        instructions = self.get_backup_path_instructions(topology, datapaths, hosts, instructions,global_flow_table,src, dst, primary_path, backup_path,in_port)
                    else:
                        print "Getting failover instructions with msg"
                        instructions = self.get_backup_path_instructions(topology, datapaths, hosts,instructions,global_flow_table,src,dst,primary_path,backup_path,in_port = msg.match['in_port'])

             #       print "Instructions:",instructions


            #print "Aquiiiiiiiiiiiii\n\n\n\n\n",endpoint_index,"Instructions:",instructions
            # Instructions: {1: {'has_failover_path': True, 'failover_in_port': 4, 'backup_switch': 4, 'failover_out_port': 5,
            #                    'vlan_tag_failover': 503},
            #                2: {'has_failover_path': True, 'failover_in_port': 1, 'backup_switch': 1, 'failover_out_port': 1,
            #                    'vlan_tag_failover': 503},
            #                3: {'has_failover_path': True, 'failover_in_port': 5, 'backup_switch': 3, 'failover_out_port': 1,
            #                    'vlan_tag_failover': 503},
            #                4: {'has_failover_path': True, 'failover_in_port': 1, 'backup_switch': 5, 'failover_out_port': 2,
            #                    'vlan_tag_failover': 503},
            #                5: {'has_failover_path': True, 'failover_in_port': 1, 'backup_switch': 6, 'failover_out_port': 2,
            #                    'vlan_tag_failover': 503},
            #                6: {'has_failover_path': True, 'failover_in_port': 1, 'backup_switch': 3, 'failover_out_port': 2,
            #                    'vlan_tag_failover': 503}, 'backup_path': [2, 1, 4, 5, 6, 3]}

            self.install_instructions(topology, datapaths, hosts,global_flow_table,instructions, endpoint, msg,add_rules)

    '''
        Get failover instructions
    '''
    def get_backup_path_instructions(self,topology, datapaths, hosts,instructions,global_flow_table, ip_src, ip_dst, primary_path, backup_path=None, in_port=None):
        #print "Primary path:%s Backup path:%s" % (primary_path, backup_path)
        # Extract path information
        sw_header_primary_path = primary_path[0]
        sw_tail_primary_path = primary_path[-1]
        vlan_tag = sw_tail_primary_path  # This will be a bug if the number of switches will be bigger than the number of VLAN tags
        JUMP_TAG = 500  # To avoid a hit in the tags used for primary and backup paths.
        vlan_tag_failover = sw_tail_primary_path + JUMP_TAG

        dict_of_inst = instructions
        # if backup_path == None or len(backup_path) == 0:
        #     # print "Why?!!! :'("
        #     return dict_of_inst
        if primary_path == None:
            print "Instructions without primary path?! oO"
            return dict_of_inst
        else:
            if backup_path == None:
                return dict_of_inst
            #Adding backup path:
            for i in range(0, len(backup_path) - 1):
                #print "Switch in backup path:",backup_path[i]
                # {'primary_path': [1, 2, 3], 1: {'vlan': 3, 'forward_switch': 2, 'out_port': 4, 'in_port': 1},
                #  2: {'vlan': 3, 'forward_switch': 3, 'out_port': 2, 'in_port': 1},
                #  3: {'vlan': 3, 'forward_switch': '10.0.0.4', 'out_port': 1, 'in_port': 4}}

                if i == 0:
                    in_port = self.get_port_from_adjacent_nodes(topology, hosts,ip_src, None)
                else:
                    in_port = self.get_port_from_adjacent_nodes(topology, hosts,backup_path[i], backup_path[i - 1])
                # print "From %s to %s on port %s" % (backup_path[num_flows], backup_path[num_flows + 1], self.topology[backup_path[num_flows]][backup_path[num_flows + 1]])
                out_port = topology[backup_path[i]][backup_path[i + 1]]['port']
                # print out_port,"<<<<<<<"
                if backup_path[i] not in dict_of_inst:
                    #print (backup_path[i] not in dict_of_inst),backup_path[i], dict_of_inst,"OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOLL"
                    dict_of_inst[backup_path[i]] = { 'failover_in_port': in_port,
                                                     'failover_out_port': out_port,
                                                     'backup_switch': backup_path[i + 1],
                                                     'vlan_tag_failover': vlan_tag_failover,
                                                     'has_failover_path':True
                                                    }
                else:
                    #print dict_of_inst[backup_path[i]],"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n\n\n\n\n\nLLLLLLLLLLLLLLLLLLLLLLLL"
                    dict_of_inst[backup_path[i]]['failover_in_port'] = in_port
                    dict_of_inst[backup_path[i]]['failover_out_port']= out_port
                    dict_of_inst[backup_path[i]]['backup_switch']= backup_path[i + 1]
                    dict_of_inst[backup_path[i]]['vlan_tag_failover']= vlan_tag_failover
                    dict_of_inst[backup_path[i]]['has_failover_path']=True

                #The tail of the backup path:
                index_of_the_last_switch_in_the_backup_path = i + 1
                if index_of_the_last_switch_in_the_backup_path == len(backup_path) - 1:
                    #print "Last switch in the backup path!!!",backup_path[index_of_the_last_switch_in_the_backup_path]
                    out_port = self.get_port_from_adjacent_nodes(topology, hosts,None, ip_dst)
                    in_port = topology[backup_path[index_of_the_last_switch_in_the_backup_path]][backup_path[i]]['port']
                    if backup_path[index_of_the_last_switch_in_the_backup_path] not in dict_of_inst:
                        dict_of_inst[backup_path[index_of_the_last_switch_in_the_backup_path]] = {'failover_in_port': in_port,
                                                        'failover_out_port': out_port,
                                                        'backup_switch': backup_path[index_of_the_last_switch_in_the_backup_path],
                                                        'vlan_tag_failover': vlan_tag_failover,
                                                        'has_failover_path': True
                                                        }
                    else:
                        dict_of_inst[backup_path[index_of_the_last_switch_in_the_backup_path]]['failover_in_port'] = in_port
                        dict_of_inst[backup_path[index_of_the_last_switch_in_the_backup_path]]['failover_out_port'] = out_port
                        dict_of_inst[backup_path[index_of_the_last_switch_in_the_backup_path]]['backup_switch'] = backup_path[index_of_the_last_switch_in_the_backup_path]
                        dict_of_inst[backup_path[index_of_the_last_switch_in_the_backup_path]]['vlan_tag_failover'] = vlan_tag_failover
                        dict_of_inst[backup_path[index_of_the_last_switch_in_the_backup_path]]['has_failover_path'] = True

                        # else:
                    #     dict_of_inst[backup_path[num_flows]]['backup'] = {ip_dst: {#'in_port': in_port,
                    #                                                                    'out_port': out_port}}

            dict_of_inst['backup_path'] = backup_path
            #print "\n\n\n\n\nDepois:", dict_of_inst
            return dict_of_inst

    '''
        Get primary path instructions:
    '''


    def get_primary_path_instructions(self,topology, datapaths, hosts,global_flow_table, ip_src, ip_dst, primary_path, backup_path=None, in_port=None):
        #print "Primary path:%s Backup path:%s" % (primary_path, backup_path)
        # Extract path information
        sw_header_primary_path = primary_path[0]
        sw_tail_primary_path = primary_path[-1]
        vlan_tag = sw_tail_primary_path  # This will be a bug if the number of switches will be bigger than the number of VLAN tags
        JUMP_TAG = 500  # To avoid a hit in the tags used for primary and backup paths.
        vlan_tag_failover = sw_tail_primary_path + JUMP_TAG

        dict_of_inst = {}
        # if backup_path == None or len(backup_path) == 0:
        #     # print "Why?!!! :'("
        #     return dict_of_inst
        if primary_path == None:
            print "Instructions without primary path?! oO"
            return dict_of_inst
        else:
            #print "Primary path:", primary_path, "Backup path:", backup_path
            # Path:[1, 2, 3]
            # Instructions: {(3, 2): {'port': 2}, (2, 1): {'port': 1}}
            # Just create a single set of instructions:
            node = primary_path[0]
            in_port = self.get_port_from_adjacent_nodes(topology, hosts, ip_src, None) #???
            if len(primary_path) == 1:
                # Special case, where exist only one element in the primary_path
                #in_port = msg.match['in_port']
                out_port = self.get_port_from_adjacent_nodes(topology, hosts,None, ip_dst)
                dict_of_inst['primary_path'] = primary_path

                dict_of_inst[primary_path[0]] = {'forward_switch': primary_path[0],
                                                     'in_port': in_port, 'out_port': out_port,
                                                 'has_failover_path':False}
                return dict_of_inst
            # Adding primary path:
            #print "Adding primary path:"
            for i in range(0, len(primary_path) - 1):
                #print "Iteration ",i
                if i == 0:
                    in_port = self.get_port_from_adjacent_nodes(topology, hosts,ip_src, None)
                else:
                    in_port = self.get_port_from_adjacent_nodes(topology, hosts,primary_path[i], primary_path[i - 1])
                # print "From %s to %s on port %s" % (backup_path[num_flows], backup_path[num_flows + 1], self.topology[backup_path[num_flows]][backup_path[num_flows + 1]])
                out_port = topology[primary_path[i]][primary_path[i + 1]]['port']
                #print out_port,"<<<<<<<"
    #            if backup_path != None:
    #                 if primary_path[i] in backup_path:
    #                     index = backup_path.index(primary_path[i])
    #                     print primary_path[i],"Backup?",backup_path[index],backup_path[index + 1]
    #                     dict_of_inst[primary_path[i]] ={ 'in_port': in_port,
    #                                                     'out_port': out_port,
    #                                                     'backup_port': topology[backup_path[index]][backup_path[index + 1]]['port'],
    #                                                      'forward_switch':primary_path[i + 1],
    #                                                      'backup_switch':backup_path[index + 1]}
    #                 else:
                dict_of_inst[primary_path[i]] = {'in_port': in_port,
                                                 'out_port': out_port,
                                                 'forward_switch': primary_path[i + 1],
                                                 'vlan':vlan_tag,
                                                 'has_failover_path':False}
                #Without backup path:
                # else:
                #     dict_of_inst[primary_path[i]] = {'in_port': in_port,
                #                                      'out_port': out_port,
                #                                      'forward_switch': primary_path[i + 1]}
                node = primary_path[i]
                if i + 1 == len(primary_path) - 1:
                    out_port = self.get_port_from_adjacent_nodes(topology, hosts,None, ip_dst)
                    in_port = topology[primary_path[i + 1]][primary_path[i]]['port']
                    dict_of_inst[primary_path[i+1]] = { 'in_port': in_port,
                                                        'out_port': out_port,
                                                        'forward_switch': ip_dst,
                                                        'vlan':vlan_tag,
                                                        'has_failover_path':False}
            #print "Primary path>",dict_of_inst
            dict_of_inst['primary_path']=primary_path
            # {1: {'has_failover_path': False, 'vlan': 3, 'forward_switch': 2, 'out_port': 4, 'in_port': 1},
            #  2: {'has_failover_path': False, 'vlan': 3, 'forward_switch': 3, 'out_port': 2, 'in_port': 1},
            #  3: {'has_failover_path': False, 'vlan': 3, 'forward_switch': '10.0.0.4', 'out_port': 1, 'in_port': 4}}
            return dict_of_inst



    """
        Get a port from a src node to dst node
    """

    def get_port_from_adjacent_nodes(self, topology, hosts, src_node, dst_node):
        # print "Get port from %s to %s" % (src_node, dst_node)
        if src_node in hosts:
            return hosts[src_node]['port']
        elif dst_node in hosts:
            return hosts[dst_node]['port']
        return topology[src_node][dst_node]['port']

    '''
    Apply the instructions in the data plane elements.
    '''

    def install_instructions(self,topology, datapaths, hosts,global_flow_table, instructions,endpoint, msg,add_rules=True):

        #print "Instructions:", instructions
        # Instructions: {
        #     1: {'has_failover_path': True, 'vlan': 3, 'out_port': 4, 'failover_in_port': 4, 'vlan_tag_failover': 503,
        #         'forward_switch': 2, 'failover_out_port': 5, 'backup_switch': 4, 'in_port': 1},
        #     2: {'has_failover_path': True, 'vlan': 3, 'out_port': 2, 'failover_in_port': 1, 'vlan_tag_failover': 503,
        #         'forward_switch': 3, 'failover_out_port': 1, 'backup_switch': 1, 'in_port': 1},
        #     3: {'has_failover_path': True, 'vlan': 3, 'out_port': 1, 'failover_in_port': 5, 'vlan_tag_failover': 503,
        #         'forward_switch': '10.0.0.4', 'failover_out_port': 1, 'backup_switch': 3, 'in_port': 4},
        #     4: {'has_failover_path': True, 'failover_in_port': 1, 'backup_switch': 5, 'failover_out_port': 2,
        #         'vlan_tag_failover': 503},
        #     5: {'has_failover_path': True, 'failover_in_port': 1, 'backup_switch': 6, 'failover_out_port': 2,
        #         'vlan_tag_failover': 503},
        #     6: {'has_failover_path': True, 'failover_in_port': 1, 'backup_switch': 3, 'failover_out_port': 2,
        #         'vlan_tag_failover': 503}, 'backup_path': [2, 1, 4, 5, 6, 3], 'primary_path': [1, 2, 3]}

        primary_path = instructions['primary_path']
        backup_path = None
        if 'backup_path' in instructions:
            backup_path = instructions['backup_path']
        src, dst = endpoint
        group_id = 0

        # Extract path information
        sw_header_primary_path = primary_path[0]
        sw_tail_primary_path = primary_path[-1]
        vlan_tag = sw_tail_primary_path  # This will be a bug if the number of switches will be bigger than the number of VLAN tags
        JUMP_TAG = 500      # To avoid a hit in the tags used for primary and backup paths.
        #vlan_tag_failover = sw_tail_primary_path+ JUMP_TAG

        for index, sw_src in enumerate(instructions):
            # {1: {2: {'out_port': 2, 'in_port': 1, 'backup_port': 3}},
            # 2: {3: {'out_port': 2, 'in_port': 1, 'backup_port': 1}},
            # 3: {'10.0.0.3': {'out_port': 1, 'in_port': 2}},
            # 4: {3: {'out_port': 1, 'in_port': 2}}}


            # Avoid unavailability between hosts connected in the same switch.
            if len(instructions.keys()) == 1:  # The hosts are connected with the switch.
                switch_node = (sw_header_primary_path, sw_tail_primary_path)
                in_port = instructions[switch_node]['in_port']
                out_port = instructions[switch_node]['out_port']
                flow_creator.create_simple_l3_flow(datapaths[sw_header_primary_path], in_port, out_port=out_port,
                                                   ip_pkt_src=src, ip_pkt_dst=dst, msg=msg,
                                                   priority=50000,
                                                   modify_rule=add_rules)
                return  # Avoid the installation of multiple rules for the same flow.
            #print "ID:", sw_src, ">>>>>>>", instructions[sw_src]
            #Used to avoid using the strings as dpid. #TODO:FIX ME!!!
            if sw_src == 'primary_path' or sw_src == 'backup_path':
                #File "/home/walber/Dropbox/SDN - Controllers/ryu/ryu/app/COOL/flow_management.py", line 675, in install_instructions
                # primary_output_port = instructions[sw_src]['out_port']
                # TypeError: list indices must be integers, not str
                continue
            #     1: {'has_failover_path': True, 'vlan': 3, 'out_port': 4, 'failover_in_port': 4, 'vlan_tag_failover': 503,
            #         'forward_switch': 2, 'failover_out_port': 5, 'backup_switch': 4, 'in_port': 1},

            # Verify if those optional fields are in instructions dictionary:
            has_backup_path = None
            if 'has_failover_path' in instructions[sw_src]:
                has_backup_path = instructions[sw_src]['has_failover_path']

            failover_in_port = None
            backup_switch = None
            failover_out_port = None
            vlan_tag_failover = None
            if has_backup_path:
                failover_in_port = instructions[sw_src]['failover_in_port']
                backup_switch = instructions[sw_src]['backup_switch']
                failover_out_port = instructions[sw_src]['failover_out_port']
                vlan_tag_failover = instructions[sw_src]['vlan_tag_failover']

            vlan_tag = None
            if 'vlan' in instructions[sw_src]:
                vlan_tag = instructions[sw_src]['vlan']

            primary_output_port = None
            if 'out_port' in instructions[sw_src]:
                primary_output_port = instructions[sw_src]['out_port']

            primary_input_port = None
            if 'in_port' in instructions[sw_src]:
                primary_input_port = instructions[sw_src]['in_port']

            forward_switch = None
            if 'forward_switch' in instructions[sw_src]:
                forward_switch = instructions[sw_src]['forward_switch']

            primary_path_actions = []
            backup_path_actions = []

            primary_path = instructions['primary_path']
            backup_path = None
            sw_backup_head = None
            sw_backup_tail = None
            if 'backup_path' in instructions:
                backup_path = instructions['backup_path']
                sw_backup_head = backup_path[0]
                sw_backup_tail = backup_path[-1]

            sw_primary_head = primary_path[0]
            sw_primary_tail = primary_path[-1]



            datapath = datapaths[sw_src]
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            backup_output_port = 0

            # vlan_tag = sw_tail_primary_path  # This will be a bug if the number of switches will be bigger than the number of VLAN tags
            # JUMP_TAG = 500  # To avoid a hit in the tags used for primary and backup paths.
            # vlan_tag_failover = sw_tail_primary_path + JUMP_TAG

            if has_backup_path:
                backup_output_port = instructions[sw_src]['failover_out_port']

            import hashlib
            group_id = hash(str(primary_path[0])+str(src) + str(dst)+str(primary_path[-1])) % (10 ** 8)

            #group_id = hash( str(dst) + str(primary_path[-1])) % (10 ** 8)
            #group_id = hash(str(primary_path[0])+str(src) + str(dst)) % (10 ** 8)

            avoid_override_rule = False

            # if endpoint in global_flow_table[sw_src, src, dst]:
            #     if group_id == self.installed_instructions[endpoint]['group_id']:
            #         print "SOMETHING GOES WRONG ##############################"
            #     else:
            #         avoid_override_rule = True
            #         print primary_path[0],str(src),str(dst),"It will be override!!!!!!!!!!!\n\n\n\n"

            print "Hash: ", group_id, " from:", src, dst
            seeking_group_id = 59028827
            if sw_src == 2:
                print "OIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIJJJJJJJJJJJJJJJJJ"

            # if node == primary header:
            if sw_src == sw_primary_head:
                if seeking_group_id == group_id:
                    print "1AQUIIIIIIIIIIIIIIIIIiii\n\n\n\n\n\n\nKKKKKKKKKKKKKKKKKKKKKKKKK"
                if not has_backup_path:
                # if node == primary tail:
                #if sw_src == sw_primary_tail:
                    # Match1: primary_in_port -> Action1
                    primary_match = ofp_parser.OFPMatch(in_port=primary_input_port,
                                                        eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_dst=(dst, "255.255.255.255"))

                    # Action1: watch: out_port -> Forward to forward_switch
                    primary_path_actions = [ofp_parser.OFPActionOutput(primary_output_port)]
                    failover_actions = None
                    #watch port, action, out port
                    flow_creator.create_a_group_action_instruction(datapath, primary_path_actions, failover_actions,
                                                               primary_output_port,failover_out_port,
                                                               group_id, modify_rule=False)
                    flow_creator.create_a_group_match_instruction(datapath, msg, primary_match,
                                                                  primary_output_port,
                                                              group_id, modify_rule=False)


                    #OK!
                    continue
                elif sw_src == sw_backup_tail:
                #Primary Head and Backup Tail
                # elif node == failover tail:
                    # Match1: primary_in_port -> Action1
                    primary_match = ofp_parser.OFPMatch(in_port=primary_input_port)
                    # Action1: watch: out_port -> Forward to forward_switch
                    primary_path_actions = [ofp_parser.OFPActionOutput(primary_output_port)]
                    failover_actions = None
                    flow_creator.create_a_group_action_instruction(datapath, primary_path_actions, failover_actions,
                                                                   primary_output_port,failover_out_port,
                                                                   group_id, modify_rule=False)
                    flow_creator.create_a_group_match_instruction(datapath, msg, primary_match,
                                                                  primary_output_port,
                                                                  group_id, modify_rule=False)
                    print "1.AQUIIIIIIIIIIIIIIIIIIIiiiiiiiiiiiiiiiiiiiiIIIIIIIII", sw_src, primary_input_port, primary_output_port
                    continue
                    #Not tested!
                elif sw_src == sw_backup_head:
                #Primary Head and Backup Head
                # elif node == failover header:
                    # Match1:#1. Based on IP dst -> Action 1
                    primary_match = ofp_parser.OFPMatch(in_port=primary_input_port,
                                                        eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_dst=(dst, "255.255.255.255"))

                    primary_path_actions = [ofp_parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                                            ofp_parser.OFPActionSetField(vlan_vid=(0x1000 | vlan_tag)),
                                            ofp_parser.OFPActionOutput(primary_output_port)]
                    failover_actions = [#ofp_parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                                            ofp_parser.OFPActionSetField(vlan_vid=(0x1000 | vlan_tag_failover)),
                                            ofp_parser.OFPActionOutput(primary_output_port)]
                    # Action1:   watch: out_port -> Push primary vlan| Forward to forward_switch,
                    #       watch: failover_out_port -> Push vlan_tag_failover | failover_out_port
                    flow_creator.create_a_group_action_instruction(datapath, primary_path_actions, failover_actions,
                                                                   primary_output_port,failover_out_port,
                                                                   group_id, modify_rule=False)
                    flow_creator.create_a_group_match_instruction(datapath, msg, primary_match,
                                                                  primary_output_port,
                                                                  group_id, modify_rule=False)
                    print "2.AQUIIIIIIIIIIIIIIIIIIIiiiiiiiiiiiiiiiiiiiiIIIIIIIII", sw_src, primary_input_port, primary_output_port
                    continue
                    # Not tested!
                else:
                #Primary Head and Backup Forward
                # else:
                    # Match1: #1. Based on IP dst -> Action 1
                    match1 = ofp_parser.OFPMatch(in_port=primary_input_port, eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_dst=(dst, "255.255.255.255"))

                    # Match2: vlan_tag_failover -> Action 2
                    match2 = ofp_parser.OFPMatch(vlan_vid=(0x1000 | vlan_tag_failover))
                    # Action1: watch: out_port -> Push primary vlan| Forward to forward_switch
                    actions1 = [ofp_parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                                        ofp_parser.OFPActionSetField(vlan_vid=(0x1000 | vlan_tag)),
                                        ofp_parser.OFPActionOutput(primary_output_port)]
                    # Action2: watch: failover_out_port -> failover_out_port | out port: failover_out_port
                    actions2 = [ofp_parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                                        ofp_parser.OFPActionSetField(vlan_vid=(0x1000 | vlan_tag_failover))]#
                                        #ofp_parser.OFPActionOutput(failover_out_port)]
                    if primary_input_port == failover_out_port:
                        actions2.append(ofp_parser.OFPActionOutput(ofp.OFPP_IN_PORT))
                        failover_out_port = ofp.OFPP_IN_PORT
                    else:
                        actions2.append(ofp_parser.OFPActionOutput(failover_out_port))

                    failover_actions = []
                    if primary_input_port == failover_out_port:
                        failover_actions.append(ofp_parser.OFPActionOutput(ofp.OFPP_IN_PORT))
                        failover_out_port = ofp.OFPP_IN_PORT
                    else:
                        failover_actions.append(ofp_parser.OFPActionOutput(failover_out_port))

                    print "3.AQUIIIIIIIIIIIIIIIIIIIiiiiiiiiiiiiiiiiiiiiIIIIIIIII", sw_src, primary_input_port, primary_output_port
                    flow_creator.create_a_group_action_instruction(datapath, actions1,actions2,
                                                                   primary_output_port, failover_out_port,
                                                                   group_id, modify_rule=False)
                    flow_creator.create_a_group_match_instruction(datapath, msg, match1,
                                                                  primary_output_port,
                                                                  group_id, modify_rule=False)

                    flow_creator.create_a_group_action_instruction(datapath, failover_actions, None,
                                                                   failover_out_port, failover_out_port,
                                                                   group_id+1, modify_rule=False)
                    flow_creator.create_a_group_match_instruction(datapath, msg, match2,                                                               failover_out_port,
                                                                  group_id+1, modify_rule=False)

                    continue

            # elif node == primary tail:
            elif sw_src == sw_primary_tail:
                if seeking_group_id == group_id:
                    print "2AQUIIIIIIIIIIIIIIIIIiii\n\n\n\n\n\n\nKKKKKKKKKKKKKKKKKKKKKKKKK"
                # if node == failover tail:
                if sw_src == sw_backup_tail:
                    # Match1: vlan tag -> Action 1
                    #print "VLAN TAG:",vlan_tag
                    match1 = ofp_parser.OFPMatch(vlan_vid=(0x1000 | vlan_tag),eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_dst=(dst, "255.255.255.255"))
                    #print "ANTES>", instructions[sw_src]['out_port'],primary_output_port
                    primary_output_port = instructions[sw_src]['out_port']
                    # Action1.   watch: out_port -> Pop primary vlan| Forward to forward_switch,
                    actions1 = [ofp_parser.OFPActionPopVlan(),
                                ofp_parser.OFPActionOutput(primary_output_port)]#,
                                #ofp_parser.OFPActionGroup(group_id)]
                    # Match2: vlan tag failover -> Action 2
                    match2 = ofp_parser.OFPMatch(vlan_vid=(0x1000 | vlan_tag_failover),eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_dst=(dst, "255.255.255.255"))
                    # Action2.   watch: failover_out_port -> Pop failover vlan| Forward to forward_switch,
                    actions2 = [ofp_parser.OFPActionPopVlan(),
                                ofp_parser.OFPActionOutput(failover_out_port)]


                    flow_creator.create_a_group_action_instruction(datapath, actions1, actions2,
                                                                   primary_output_port, failover_out_port,
                                                                   group_id, modify_rule=False)
                    flow_creator.create_a_group_match_instruction(datapath, msg, match1,
                                                                  primary_output_port,
                                                                  group_id, modify_rule=False)
                    flow_creator.create_a_group_match_instruction(datapath, msg, match2,
                                                                  primary_output_port,
                                                                  group_id, modify_rule=False)
                    continue
                #else:
                else:
                    # Print ERROR!
                    print "\n\n\n\n\nERRRRRRRRRRROOOOOOOOOOOOOOOOOOOOOOOOO!!!!!!!!\n\n\n\n\n"
                    continue

            # else: # Primary forward
            else:
                if seeking_group_id == group_id:
                    print "3AQUIIIIIIIIIIIIIIIIIiii\n\n\n\n\n\n\nKKKKKKKKKKKKKKKKKKKKKKKKK"
                #Primary Forward
                #If not in the primary path, then it is in failover path
                key = sw_src, primary_output_port, failover_out_port
                print group_id, "<<<"
                if key not in self.group_set_IDs:
                    self.group_set_IDs[key] = group_id
                else:
                    print "Reducing group_id rules!\n\n\n\n\n\n\n"
                    group_id = self.group_set_IDs[key]

                if sw_src not in primary_path:
                    if seeking_group_id == group_id:
                        print "4AQUIIIIIIIIIIIIIIIIIiii\n\n\n\n\n\n\nKKKKKKKKKKKKKKKKKKKKKKKKK"
                    if sw_src == sw_backup_head:
                        if seeking_group_id == group_id:
                            print "5AQUIIIIIIIIIIIIIIIIIiii\n\n\n\n\n\n\nKKKKKKKKKKKKKKKKKKKKKKKKK"
                        primary_match = ofp_parser.OFPMatch(vlan_vid=(0x1000 | vlan_tag))

                        primary_path_actions = [ofp_parser.OFPActionOutput(primary_output_port)]
                        failover_actions = []
                        if primary_input_port == failover_out_port:
                            failover_actions.append(ofp_parser.OFPActionOutput(ofp.OFPP_IN_PORT))
                            flow_creator.create_a_group_action_instruction(datapath, primary_path_actions, failover_actions,
                                                                           primary_output_port, ofp.OFPP_IN_PORT,
                                                                           group_id, modify_rule=False)
                        else:
                            failover_actions.append(ofp_parser.OFPActionOutput(failover_out_port))
                            flow_creator.create_a_group_action_instruction(datapath, primary_path_actions, failover_actions,
                                                                           primary_output_port, failover_out_port,
                                                                           group_id, modify_rule=False)


                        flow_creator.create_a_group_match_instruction(datapath, msg, primary_match,
                                                                      primary_output_port,
                                                                      group_id, modify_rule=False)

                    else:
                    #Primary Forward and Backup Forward
                        if seeking_group_id == group_id:
                            print "6AQUIIIIIIIIIIIIIIIIIiii\n\n\n\n\n\n\nKKKKKKKKKKKKKKKKKKKKKKKKK",failover_in_port, failover_out_port
                        match1 = ofp_parser.OFPMatch(vlan_vid=(0x1000 | vlan_tag_failover))
                        actions1 = [ofp_parser.OFPActionOutput(failover_out_port)]
                        actions2 = None
                        if primary_input_port == failover_out_port:
                            actions1.append(ofp_parser.OFPActionOutput(ofp.OFPP_IN_PORT))
                            flow_creator.create_a_group_action_instruction(datapath, actions1, actions2,
                                                                           failover_out_port, None,
                                                                           group_id, modify_rule=False)
                            flow_creator.create_a_group_match_instruction(datapath, msg, match1,
                                                                          ofp.OFPP_IN_PORT,
                                                                          group_id, modify_rule=False)
                        else:
                            actions1.append(ofp_parser.OFPActionOutput(failover_out_port))
                            flow_creator.create_a_group_action_instruction(datapath, actions1, actions2,
                                                                           failover_out_port, None,
                                                                           group_id, modify_rule=False)
                            flow_creator.create_a_group_match_instruction(datapath, msg, match1,
                                                                          failover_out_port,
                                                                          group_id, modify_rule=False)

                else:
                    if seeking_group_id == group_id:
                        print "7AQUIIIIIIIIIIIIIIIIIiii\n\n\n\n\n\n\nKKKKKKKKKKKKKKKKKKKKKKKKK"
                    #Primary Forward and Backup Forward
                    print sw_src, "Primary PATH \n\n\n\n\n\n", primary_output_port, failover_out_port, group_id
                    # Match1: vlan tag -> Action 1
                    match1 = ofp_parser.OFPMatch(vlan_vid=(0x1000 | vlan_tag))
                    # Action1.   watch: out_port -> Forward to forward_switch,
                    #       watch: failover_out_port, Action: Set vlan_tag_failover and Forward: failover_out_port
                    actions1 = [ofp_parser.OFPActionOutput(primary_output_port)]
                    actions2 = None
                    if has_backup_path:
                        actions2 = [  # ofp_parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                            ofp_parser.OFPActionSetField(vlan_vid=(0x1000 | vlan_tag_failover))]
                        if primary_input_port == failover_out_port:
                            actions2.append(ofp_parser.OFPActionOutput(ofp.OFPP_IN_PORT))
                        else:
                            actions2.append(ofp_parser.OFPActionOutput(failover_out_port))
                    flow_creator.create_a_group_action_instruction(datapath, actions1, actions2,
                                                                   primary_output_port,failover_out_port,
                                                                   group_id, modify_rule=False)
                    flow_creator.create_a_group_match_instruction(datapath, msg, match1,
                                                                  primary_output_port,
                                                                  group_id, modify_rule=False)


        ###############################################################################################################

            # print "Flow group:",datapaths[sw_src], group_id, primary_output_port,backup_output_port
            # # Instructions: {1: {'backup_switch': 4, 'forward_switch': 2, 'out_port': 4, 'in_port': 1, 'backup_port': 5},
            #
            # flow_creator.create_group_mod_failover_flow_with_vlan(datapaths,sw_src,instructions,group_id, create_group_id=True)
            #
            # # flow_creator.create_group_mod_failover_flow(self.datapaths[sw_src], group_id, primary_output_port,
            # #                                                     backup_output_port, create_group_id=add_rules)
            #
            # # Recovering the IPv4 packet from Packet-In event
            # pkt = packet.Packet(msg.data)
            # ip_pkt = pkt.get_protocol(ipv4.ipv4)
            # dpid = msg.datapath.id
            # #print "\n\n\n\n",self.global_flow_table
            # global_flow_table[dpid,ip_pkt.src,ip_pkt.dst] = {'instructions':instructions,'group_id':group_id}
            # #print "\n\n\n\n", self.global_flow_table
            #
            # print "Flow creation:",datapaths[sw_src], primary_input_port, primary_output_port,ip_pkt, group_id
            #
            #
            # flow_creator.create_l3_failover_flow_with_VLAN(datapaths,sw_src,instructions,group_id,msg = msg)
            #
            # if has_backup_path:
            #     primary_path = instructions['primary_path']
            #     backup_path = instructions['backup_path']
            #
            #     sw_primary_head = primary_path[0]
            #     sw_primary_tail = primary_path[-1]
            #
            #     sw_backup_head = backup_path[0]
            #     sw_backup_tail = backup_path[-1]
            #
            #     failover_in_port = instructions[sw_src]['failover_in_port']
            #     failover_out_port = instructions[sw_src]['failover_out_port']
            #
            #     vlan_tag_failover = instructions[sw_src]['vlan_tag_failover']
            #
            #     flow_creator.create_failover_vlan_flow(datapaths[sw_src], sw_backup_head, sw_backup_tail, vlan_tag_failover, failover_in_port, out_port=failover_out_port,
            #                                      ip_pkt_src=src, ip_pkt_dst=dst, msg=msg,
            #                                      priority=50000,
            #                                      modify_rule=False)
            #     flow_creator.create_l3_failover_flow_with_VLAN(datapaths, sw_src, instructions, group_id, msg=msg)

            global_flow_table[sw_src, src, dst] = {'instructions':instructions,'group_id':group_id}


if __name__ == '__main__':
    instructions= {
        1: {'has_failover_path': True, 'vlan': 3, 'out_port': 4, 'failover_in_port': 4, 'vlan_tag_failover': 503,
            'forward_switch': 2, 'failover_out_port': 5, 'backup_switch': 4, 'in_port': 1},
        2: {'has_failover_path': True, 'vlan': 3, 'out_port': 2, 'failover_in_port': 1, 'vlan_tag_failover': 503,
            'forward_switch': 3, 'failover_out_port': 1, 'backup_switch': 1, 'in_port': 1},
        3: {'has_failover_path': True, 'vlan': 3, 'out_port': 1, 'failover_in_port': 5, 'vlan_tag_failover': 503,
            'forward_switch': '10.0.0.4', 'failover_out_port': 1, 'backup_switch': 3, 'in_port': 4},
        4: {'has_failover_path': True, 'failover_in_port': 1, 'backup_switch': 5, 'failover_out_port': 2,
            'vlan_tag_failover': 503},
        5: {'has_failover_path': True, 'failover_in_port': 1, 'backup_switch': 6, 'failover_out_port': 2,
            'vlan_tag_failover': 503},
        6: {'has_failover_path': True, 'failover_in_port': 1, 'backup_switch': 3, 'failover_out_port': 2,
            'vlan_tag_failover': 503}, 'backup_path': [2, 1, 4, 5, 6, 3], 'primary_path': [1, 2, 3]}

    #TODO Goal: extract match and actions for each switch!!!




    #   PH  PF  PT  BH  BF  BT  #Result
    #   0   0   0   0   0   0   False
    #   0   0   0   0   0   1   False
    #   0   0   0   0   1   0   False
    #   0   0   0   0   1   1   True
    #   0   0   0   1   0   0
    #   0   0   0   1   0   1
    #   0   0   0   1   1   0
    #   0   0   0   1   1   1
    #   0   0   1   0   0   0
    #   0   0   1   0   0   1
    #   0   0   1   0   1   0
    #   0   0   1   0   1   1
    #   0   0   1   1   0   0
    #   0   0   1   1   0   1
    #   0   0   1   1   1   0
    #   0   0   1   1   1   1
    #   0   1   0   0   0   0
    #   0   1   0   0   0   1
    #   0   1   0   0   1   0
    #   0   1   0   0   1   1
    #   0   1   0   1   0   0
    #   0   1   0   1   0   1
    #   0   1   0   1   1   0
    #   0   1   0   1   1   1
    #   0   1   1   0   0   0
    #   0   1   1   0   0   1
    #   0   1   1   0   1   0
    #   0   1   1   0   1   1
    #   0   1   1   1   0   0
    #   0   1   1   1   0   1
    #   0   1   1   1   1   0
    #   0   1   1   1   1   1
    #   1   0   0   0   0   0
    #   1   0   0   0   0   1
    #   1   0   0   0   1   0
    #   1   0   0   0   1   1
    #   1   0   0   1   0   0
    #   1   0   0   1   0   1
    #   1   0   0   1   1   0
    #   1   0   0   1   1   1
    #   1   0   1   0   0   0
    #   1   0   1   0   0   1
    #   1   0   1   0   1   0
    #   1   0   1   0   1   1
    #   1   0   1   1   0   0
    #   1   0   1   1   0   1
    #   1   0   1   1   1   0
    #   1   0   1   1   1   1
    #   1   1   0   0   0   0
    #   1   1   0   0   0   1
    #   1   1   0   0   1   0
    #   1   1   0   0   1   1
    #   1   1   0   1   0   0
    #   1   1   0   1   0   1
    #   1   1   0   1   1   0
    #   1   1   0   1   1   1
    #   1   1   1   0   0   0
    #   1   1   1   0   0   1
    #   1   1   1   0   1   0
    #   1   1   1   0   1   1
    #   1   1   1   1   0   0
    #   1   1   1   1   0   1
    #   1   1   1   1   1   0
    #   1   1   1   1   1   1


    for sw_src in instructions:
        has_backup_path = instructions[sw_src]['has_failover_path']
        failover_in_port = instructions[sw_src]['failover_in_port']
        backup_switch = instructions[sw_src]['backup_switch']
        failover_out_port = instructions[sw_src]['failover_out_port']

        primary_output_port = instructions[sw_src]['out_port']
        primary_input_port = instructions[sw_src]['in_port']
        forward_switch = instructions[sw_src]['forward_switch']
        vlan_tag = instructions[sw_src]['vlan']
        vlan_tag_failover = instructions[sw_src]['vlan_tag_failover']

        primary_path_actions = None
        backup_path_actions = None

        primary_path = instructions['primary_path']
        backup_path = instructions['backup_path']

        sw_primary_header = primary_path[0]
        sw_primary_tail = primary_path[-1]

        sw_backup_head = backup_path[0]
        sw_backup_tail = backup_path[-1]


        match = {}

        if sw_src == sw_primary_header:
            if sw_src == sw_primary_tail:
                match[sw_src] = 0
        # if node == primary header:
            #if node == primary tail:
                # Match1: primary_in_port -> Action1
                # Action1: watch: out_port -> Forward to forward_switch
            #elif node == failover tail:
                # Match1: primary_in_port -> Action1
                # Action1: watch: out_port -> Forward to forward_switch
            #elif node == failover header:
                # Match1:#1. Based on IP dst -> Action 1
                # Action1:   watch: out_port -> Push primary vlan| Forward to forward_switch,
                #       watch: failover_out_port -> Push vlan_tag_failover | failover_out_port
            #else:
                # Match1: #1. Based on IP dst -> Action 1
                # Match2: vlan_tag_failover -> Action 2
                # Action1: watch: out_port -> Push primary vlan| Forward to forward_switch
                # Action2: watch: failover_out_port -> failover_out_port

        #elif node == primary tail:
            #if node == failover tail:
                # Match1: vlan tag -> Action 1
                # Action1.   watch: out_port -> Pop primary vlan| Forward to forward_switch,
                # Match2: vlan tag failover -> Action 2
                # Action2.   watch: failover_out_port -> Pop failover vlan| Forward to forward_switch,

        #else: # Primary forward
            # Match1: vlan tag -> Action 1
            # Action1.   watch: out_port -> Forward to forward_switch,
            #       watch: failover_out_port, Action: Set vlan_tag_failover and Forward: failover_out_port





    dict_of_inst = instructions
    primary_path = [1, 2, 3]
    backup_path =  [2,1,4,5,6,3]
    protected_path_length = len(backup_path)