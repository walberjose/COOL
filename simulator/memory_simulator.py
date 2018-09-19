import networkx as nx
import random
import numpy
import math

def confidence_interval_with_95(list):
    mean = numpy.mean(list)
    interval = 1.96 * numpy.std(list) / math.sqrt(len(list)) #95%
    return mean,interval

def select_number_of_paths(paths,size):
    import random
    new_l = []
    for i in range(0,size):
        if len(paths)>=1:
            e = random.randint(0,len(paths)-1)
            #print e,len(paths),"<<<?"
            new_l.append(paths[e])
            del paths[e]
    return new_l

'''
Utility function:
'''
def contains(listA, listB):
    '''
    :param small: a list 
    :param big: another list
    :return: False, if the small list is not in the big list, otherwise, the index of the common items in those lists.
    Example:
    #contains([1,2],[1,2,3])
    (0, 2)
    #contains([1,4],[1,2,3])
    False
    #contains([2,3],[1,2,3])
    (1, 3)
    #contains([1,2,3],[2,3])
    False
    '''
    small, big = [],[]
    if len(listA) < len(listB):
        small = listA
        big = listB
    else:
        big = listA
        small = listB

    for i in xrange(len(big)-len(small)+1):
        for j in xrange(len(small)):
            if big[i+j] != small[j]:
                break
        else:
            return i, i+len(small)
    return False


def simple_flow_creation(graph,paths,flows_per_path=1, default_rules=2):
    number_of_rules = 0
    for path in paths:
        number_of_rules+=(flows_per_path*len(path))
    return number_of_rules+default_rules*len(graph.nodes())


def path_protection(graph,paths,flows_per_path=1,default_rules=2):
    number_of_rules = 0
    for path in paths:
        for index,node in enumerate(path):
            if node == path[-1]:
                break
            #for next_node in path[1:]:
            next_node = path[index+1]
            copy = graph.copy()
            backup_path = []
            try:
                copy.remove_edge(node, next_node)
                backup_path = nx.shortest_path(copy,node,path[-1])
            except:
                #If you want, I can count the number of unavailable backup paths here ;)
                pass
            #print node, next_node, "<<", backup_path
            number_of_rules+=len(backup_path)*flows_per_path
        number_of_rules += len(path)*flows_per_path
    return number_of_rules + default_rules * len(graph.nodes())

def local_restoration(graph,paths,failure_src_node, failure_dst_node,flows_per_path=1, default_rules=2):
    used_nodes = []
    number_of_rules = 0
    #print "\nFailure links:",failure_src_node,failure_dst_node
    for path in paths:
        # print "\nPath:",path
        #print "Is ",failure_dst_node, "in ", graph.neighbors(failure_src_node),"?"
        # print (failure_src_node in path)
        # print (failure_dst_node in path)
        #Is not the failure links neighbors?
        if (failure_dst_node not in graph.neighbors(failure_src_node)):
            # print "It is!"
            continue
        #Is not the failure links in the path?
        if failure_src_node not in path or failure_dst_node not in path:
            # print "It is!"
            #print "Path does not have failure links:",path
            number_of_rules += len(path) * flows_per_path
            continue
        #Where is the failure?
        copy = graph.copy()
        primary_path = []
        backup_path = []
        try:
            copy.remove_edge(failure_src_node,failure_dst_node)
            primary_path = nx.shortest_path(copy, path[0], failure_src_node)
            backup_path = nx.shortest_path(copy, failure_src_node, path[-1])
        except:
            # If you want, I can count the number of unavailable backup paths here ;)
            pass
        #print primary_path,"<<", backup_path
        number_of_rules += (len(primary_path)+len(backup_path)-1) * flows_per_path

    return number_of_rules + default_rules * len(graph.nodes())

def path_restoration(graph,paths,failure_src_node, failure_dst_node,flows_per_path=1, default_rules=2):
    used_nodes = []
    number_of_rules = 0
    for path in paths:
        #Where is the failure?
        copy = graph.copy()
        backup_path = []
        for node in path:
            try:
                copy.remove_edge(failure_src_node,failure_dst_node)
                backup_path = nx.shortest_path(copy, path[0], path[-1])
            except:
                # If you want, I can count the number of unavailable backup paths here ;)
                pass
            #print "<<", backup_path
            number_of_rules += len(backup_path) * flows_per_path

    return number_of_rules + default_rules * len(graph.nodes())

def local_fast_restoration(graph,paths,default_rules=2):
    flows_per_path = 1 #Always will be one!
    list_of_backup_paths = []
    number_of_rules = 0
    for path in paths:
        for index,node in enumerate(path):
            if node == path[-1]:
                break
            #for next_node in path[1:]:
            next_node = path[index+1]
            copy = graph.copy()
            backup_path = []
            try:
                copy.remove_edge(node, next_node)
                backup_path = nx.shortest_path(copy,node,path[-1])
            except:
                #If you want, I can count the number of unavailable backup paths here ;)
                pass
            #print node, next_node, "<<", backup_path

            contains_backup_rule = False
            changed_places = False
            first_index_backup = 0
            remain_backup_path_length = 0
            for bck_path in list_of_backup_paths:
                # Find which list is longer than the other
                small = []
                big = []
                if len(backup_path) > len(bck_path):
                    small = bck_path
                    big = backup_path
                    changed_places = True
                else:
                    big = bck_path
                    small = backup_path

                if contains(small,big) == False:
                    continue
                else:
                    (first_index_backup,last_index_backup) = contains(small,big)
                    if first_index_backup != 0:
                        remain_backup_path_length = first_index_backup
                    contains_backup_rule = True
                    break

            if contains_backup_rule == True:
                if changed_places == True:
                    #print "Remain", remain_backup_path_length
                    number_of_rules += remain_backup_path_length +2* flows_per_path
                    continue
                else:
                    #Do not count the backup path because it has already a flow for it.
                    pass
            else:
                number_of_rules += len(backup_path) * flows_per_path
                list_of_backup_paths.append(backup_path)

        #number_of_rules += len(path)*flows_per_path
    return number_of_rules + default_rules * len(graph.nodes())

def all_connected_with_tunnels(graph, paths, flows_per_path, default_rules=0):
    number_of_rules = 0
    tunnels = []
    for path in paths:
        for tunnel in paths:
            if path == tunnel:
                continue
            if contains(tunnel,path) == False:
                #print tunnels,"@@@",tunnel,path
                tunnels.append(tunnel)
            else:
                start,end = contains(tunnel, path)
                new_tunnel = []
                if len(tunnel)>len(path):
                    number_of_rules += len(tunnel[0:start])+len(tunnel[end:-1])
                    new_tunnel = tunnel[0:start]+tunnel[end:-1]
                else:
                    number_of_rules += len(path[0:start]) + len(path[end:-1])
                    new_tunnel = path[0:start] + path[end:-1]
                if new_tunnel not in tunnels:
                    #print "Tem algo",new_tunnel,tunnels
                    tunnels.append(new_tunnel)

            #print len(tunnels),tunnels,path
        #number_of_rules+=flows_per_path
    #print tunnels,"<<<"
    return number_of_rules+len(paths)*flows_per_path

def long_protect_phase_without_backup(graph, paths, flows_per_path, default_rules=0):
    number_of_rules = 0
    tunnels = []
    for path in paths:
        number_of_rules+=len(path)+2*flows_per_path
    return number_of_rules


def long_protect_phase(graph, paths, flows_per_path, default_rules=0):
    number_of_rules = 0
    dict = {}
    for path in paths:
        src = path[0]
        dst = path[-1]
        dict[src, dst] = {'primary': path}  # len(path)+2*flows_per_path
    for path in paths:
        src = path[0]
        dst = path[-1]
        if (src,dst) not in dict:
            dict[src,dst] = {'primary':path}#len(path)+2*flows_per_path
        copy = graph.copy()
        for index,node in enumerate(path):
            if index + 1 == len(path):
                break
            failure_src_node = path[index]
            failure_dst_node = path[index+1]
            backup_path = []
            try:
                copy.remove_edge(failure_src_node,failure_dst_node)
                backup_path = nx.shortest_path(copy, failure_src_node, dst)
                #print failure_src_node,failure_dst_node,"Backup path:",backup_path
            except:
                continue
                # If you want, I can count the number of unavailable backup paths here ;)
                pass
            if (failure_src_node, dst) in dict:
                #print (failure_src_node, dst),path,"----",nx.shortest_path(graph, failure_src_node, dst)
                dict[failure_src_node, dst] = {'primary':nx.shortest_path(graph, failure_src_node, dst),
                                               'backup':backup_path}#len(backup_path)}# + 2 * flows_per_path}
            else:
                #print src,dst,path,backup_path
                dict[failure_src_node, dst] = {'primary': path,
                                               'backup': backup_path}  # len(backup_path)}# + 2 * flows_per_path}
                #print "Novo",(failure_src_node, dst),backup_path#,"DIC:",dict[failure_src_node, dst]
                #print dict[failure_src_node, dst]['backup'],"<<<"

    for path in dict:
        #print path,"Primary:",dict[path]['primary'],"\t\t",dict[path]['backup']
        number_of_rules += len(dict[path]['primary'])+len(dict[path]['backup'])+flows_per_path*2

    #print dict
    return number_of_rules+default_rules
#(1, 4): {'backup': [1, 2, 3, 4], 'primary': [1, 4]}

def long(graph,paths,failure_src_node,failure_dst_node, default_rules=0):
    used_nodes = []
    used_paths = []
    number_of_rules = 0
    for path in paths:
        copy = graph.copy()
        primary_path = []
        try:
            copy.remove_edge(failure_src_node, failure_dst_node)
            primary_path = nx.shortest_path(copy, path[0], path[-1])
        except:
            # If you want, I can count the number of unavailable backup paths here ;)
            pass
        #Check if there is already a path calculated to the backup path
        if primary_path not in used_paths:
            used_paths.append(primary_path)
            #print primary_path,"<<<"
            if len(primary_path)>1:
                number_of_rules += len(primary_path)-2+2*flows_per_path
            else:
                number_of_rules += len(primary_path)*flows_per_path
        else:
            number_of_rules += 2*flows_per_path #The number of rules in the board of the paths

        # Calculate the number of used nodes:
        for node in primary_path:
            if node not in used_nodes:
                used_nodes.append(node)
    return number_of_rules + default_rules * len(used_nodes)


# p = [[1,4,3],[1,4]]
# p = [[1,4],[3,1,4]]
# p = [[2,5,1,4,3],[1,4]]
#p = [[1,4,3],[1,4]]
# print contains(p[0],p[1])
# p = [[1,4],[2,5,1,4,3]]
# print contains(p[0],p[1])
#G = {1: [2], 2: [1,3], 3: [2,4,6],4: [3,5],5:[4,6],6:[5,1]}

#Simple linear topology
#G = {1: [2], 2: [1]}
# paths = [[1,2]]
#4-cycle topology
# G = {1: {2: {'capacity': 1}, 4: {'capacity': 1}},
#      2: {1: {'capacity': 1}, 3: {'capacity': 1}},
#      3: {2: {'capacity': 1}, 4: {'capacity': 1}},
#      4: {1: {'capacity': 1}, 3: {'capacity': 1}}}

#Article topology
# G = {1: [2, 6],
#      2: [1,3],
#      3: [2,4],
#      4: [3,5],
#      5: [4,6],
#      6: [5,1]}

#4-cycle topology
# G = {1: [2, 4],
#      2: [1,3],
#      3: [2,4],
#      4: [1,3]}

#Google Topology
#G = {1:[2,4,6],2:[1,3],3:[2,5],4:[1,5,8,7],5:[3,6,4],6:[1,5,7,8],7:[4,6,8,9],8:[6,4,7,10],9:[7,10,12,11],10:[8,9,11,12],11:[9,10],12:[9,10]}
#Abilene topology
G = {1: [2,3],2: [1,3,4],3: [1,2,6],4: [2,5],5: [4,6,7],6:[3,5,8],7:[5,8,11],8:[6,7,9],9:[8,10],10:[9,11],11:[10,7]}
topology = nx.DiGraph(G)

#paths = [[1,2,3],[1,4,3]]
paths = []
for node_src in topology.nodes():
    for node_dst in topology.nodes():
        if node_src == node_dst:
            continue
        # print node_src,node_dst
        path = nx.shortest_path(topology,node_src, node_dst)
        # print path
        paths.append(path)


failure_src_node=2
failure_dst_node=3
flows_per_path=10
default_rules=0

simple_flow_creation_list = []
path_protection_list = []
long_protect_phase_list = []

l = []
print len(paths)
print "#Number of flows, Simple Flow Creation(Path length), Path Protection(Path length), LONG protection phase(Path length)"
for num_flows in range(10, len(paths),15):
    #print num_flows,"<<<",len(paths)

    for i in range(0,1):
        new_paths = select_number_of_paths(paths[:], num_flows)
        l.append(num_flows)
        simple_flow_creation_list.append(simple_flow_creation(topology,new_paths,flows_per_path=flows_per_path, default_rules=default_rules))
        path_protection_list.append(path_protection(topology, new_paths, flows_per_path=flows_per_path, default_rules=default_rules))
        long_protect_phase_list.append(long_protect_phase(topology, new_paths, flows_per_path=flows_per_path, default_rules=0))
    #print numpy.mean(l),"<<"
    mean_simple,error_simple = confidence_interval_with_95(simple_flow_creation_list)
    mean_pp, error_pp = confidence_interval_with_95(path_protection_list)
    mean_long, error_long = confidence_interval_with_95(long_protect_phase_list)
    print "%.d %.2f %.2f %.2f %.2f %.2f %.2f"%(num_flows*flows_per_path,mean_simple,error_simple,mean_pp, error_pp,mean_long, error_long)

#Used for Google topology
#flows_per_path=10
# print "#Number of flows, Simple Flow Creation(Path length), Path Protection(Path length), LONG protection phase(Path length)"
# for num_flows in range(10, len(paths), 15):
#     # print num_flows,"<<<",len(paths)
#
#     for i in range(0, 300):
#         new_paths = select_number_of_paths(paths[:], num_flows)
#         l.append(num_flows)
#         simple_flow_creation_list.append(
#             simple_flow_creation(topology, new_paths, flows_per_path=flows_per_path, default_rules=default_rules))
#         path_protection_list.append(
#             path_protection(topology, new_paths, flows_per_path=flows_per_path, default_rules=default_rules))
#         long_protect_phase_list.append(
#             long_protect_phase(topology, new_paths, flows_per_path=flows_per_path, default_rules=0))
#     # print numpy.mean(l),"<<"
#     mean_simple, error_simple = confidence_interval_with_95(simple_flow_creation_list)
#     mean_pp, error_pp = confidence_interval_with_95(path_protection_list)
#     mean_long, error_long = confidence_interval_with_95(long_protect_phase_list)
#     print "%.d %.2f %.2f %.2f %.2f %.2f %.2f" % (
#     num_flows * flows_per_path, mean_simple, error_simple, mean_pp, error_pp, mean_long, error_long)


        # print "Total number of flows:",number_of_flows
    # print "Number of rules for simple flow creation:",simple_flow_creation(topology,new_paths,flows_per_path=flows_per_path, default_rules=default_rules)
    # print "Number of rules for Path Protection:",path_protection(topology,new_paths,flows_per_path=flows_per_path, default_rules=default_rules)
    # print "Number of rules for all connected with tunnels:",all_connected_with_tunnels(topology, new_paths, flows_per_path=flows_per_path, default_rules=0)
    # print "Number of rules for Long protection phase (without backup):",long_protect_phase_without_backup(topology, new_paths, flows_per_path=flows_per_path, default_rules=0)
    # print "Number of rules for Long protection phase (with backup):",long_protect_phase(topology, new_paths, flows_per_path=flows_per_path, default_rules=0)

# print "Number of rules for Local Restoration:",local_restoration(topology,paths,failure_src_node=failure_src_node,
#                                                                 failure_dst_node=failure_dst_node,flows_per_path=flows_per_path, default_rules=default_rules)
# print "Number of rules for Path Restoration:",path_restoration(topology,paths,failure_src_node=failure_src_node,
#                                                                 failure_dst_node=failure_dst_node,flows_per_path=flows_per_path, default_rules=default_rules)
# print "Number of rules for Local Fast Restoration:",local_fast_restoration(topology,paths, default_rules=default_rules)
# print "Number of rules for LONG:",long(topology,paths,failure_src_node=failure_src_node,
#                                        failure_dst_node=failure_dst_node, default_rules=default_rules)


# topology.add_node(1,{'demand':2})
# topology.add_node(3,{'demand':-2})
#print proactive_rule_number(topology,0)
# for node in topology.nodes(data=True):
#     print node
# print nx.network_simplex(topology)
#G = nx.scale_free_graph(5)
#print G.edges()



#print nx.shortest_path(G,1,9)

#print proactive_rule_number(topology,0)
