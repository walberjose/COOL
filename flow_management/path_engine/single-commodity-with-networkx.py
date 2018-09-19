'''
Example taked from Network-Routing-Algorithms-Protocols-and-Architectures-Reviewed.pdf

'''

import networkx as nx
from networkx.algorithms.flow import shortest_augmenting_path
import matplotlib.pyplot as plt

#Linar programming API:
import pulp

# A Three-Node Illustration
# FIGURE 4.1

G = nx.DiGraph()

#Demand:
h = 10
G.add_node(1,demand= -h)
G.add_node(2,demand= 2*h)
G.add_node(3,demand= -h)

G.add_edge(1,2,weight=1,capacity=10)
G.add_edge(2,1,weight=1,capacity=10)
G.add_edge(1,3,weight=1,capacity=10)
G.add_edge(3,1,weight=1,capacity=10)
G.add_edge(2,3,weight=1,capacity=10)
G.add_edge(3,2,weight=1,capacity=10)

flowCost, flowDict = nx.capacity_scaling(G)
print flowCost



# # Variables:
# # m -> metric (or cost) of the path
# # p -> demand in each path
# # h -> the total demand volume
# # c -> capacity limit
#
# # Objective funciton: m12*p12+m132*p132
#
# # Variables
# # p12+p132 == h # Total demand volume is the sum of demands on paths
# # p12 <= c12    # Demand on path 12 must be less or equal of the capacity of the path
# # p132 <= c132  #       ||      ||      ||      ||
# # p12 <= 0      # The variable cannot take negative demand
# # p132 <= 0     # The variable cannot take negative demand
#
# # Assuming capacity limit is the same on all links
# # c12 = c132 = c
#
# #Define a LP problem
# model = pulp.LpProblem("A Three-Node Illustration", pulp.LpMinimize)
#
#
#
# h = pulp.LpVariable('h',lowBound = 0, cat = 'Integer')
#
# # Instance 1:
# c12 = c132 = c = 10
#
#
# #paths = nx.algorithms.connectivity.edge_connectivity(G, 1, 2, flow_func=shortest_augmenting_path)
# #print(G,G.nodes())
# #print(paths)
#
# # If the unit cost is based on a unit flow per link:
# source = 1
# target = 2
# paths = nx.all_simple_paths(G,source=source,target=target)
# cost = []
# flows = {}
# #Define the variables
# #p12 = pulp.LpVariable('p12',lowBound = 0, cat = 'Integer') # A cabinet can not be buy in parts, so is an 'Integer' variable.
# #p132 = pulp.LpVariable('p132',lowBound = 0, cat = 'Integer')
# for path in paths:
#     flow = {}
#     flow['flow_variable'] = pulp.LpVariable(str(path),lowBound = 0, cat = 'Integer')
#     flow['cost'] = len(path)-1 #Exclude the source node
#     flows[str(path)] = flow
#
# # print flows
# # print [flows[flow]['flow_variable'] for flow in flows]
# # print [ flows[flow]['cost'] for flow in flows]
# # print [ flows[flow]['cost']*flows[flow]['flow_variable'] for flow in flows]
# # print cost
# #m12 =  1     # One flow per path
# #m132 = 2    # Two flows per path
#
# # Maximum demand volume
# for demand in range(1,21):
#     model += h == demand#10
#     #model += h >= 0
#
#     # Sum of all demand
#     model += sum([flows[flow]['flow_variable'] for flow in flows]) == h
# #    model += p12+p132 == h
#     for flow in flows:
#         variable = flows[flow]['flow_variable']
#         model += variable <= c
#         model += variable >= 0
#     # model += p132 <= c132
#     # model += p12 >= 0
#     # model += p132 >= 0
#
#     #Objective function
#     model += sum([ flows[flow]['cost']*flows[flow]['flow_variable'] for flow in flows] ),"M"# m12*p12 +m132*p132),'M' #M -> metric (cost)
#
#     model.solve()
#     print(pulp.LpStatus[model.status])
#
#     for variable in model.variables():
#         print("{} = {}".format(variable.name, variable.varValue))
#
#     print(pulp.value(model.objective))
# #print()
#
# #print(G.nodes())
# #print(nx.maximum_flow_value(G,1,6,'weight'))
# #print(nx.shortest_path(G,1,6,'weight'))
#
# #nx.draw(G)
# #plt.savefig("simple_path.png") # save as png
# #plt.show() # display
#
