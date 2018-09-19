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

G.add_edge(1,2,weight=10)
G.add_edge(1,3,weight=10)
G.add_edge(2,3,weight=10)

# Variables:
# m -> metric (or cost) of the path
# p -> demand in each path
# h -> the total demand volume
# c -> capacity limit

# Objective funciton: m12*p12+m132*p132

# Variables
# p12+p132 == h # Total demand volume is the sum of demands on paths
# p12 <= c12    # Demand on path 12 must be less or equal of the capacity of the path
# p132 <= c132  #       ||      ||      ||      ||
# p12 <= 0      # The variable cannot take negative demand
# p132 <= 0     # The variable cannot take negative demand

# Assuming capacity limit is the same on all links
# c12 = c132 = c

#Define a LP problem
model = pulp.LpProblem("A Three-Node Illustration", pulp.LpMinimize)

#Define the variables
p12 = pulp.LpVariable('p12',lowBound = 0, cat = 'Integer') # A cabinet can not be buy in parts, so is an 'Integer' variable.
p132 = pulp.LpVariable('p132',lowBound = 0, cat = 'Integer')

h = pulp.LpVariable('h',lowBound = 0, cat = 'Integer')

# Instance 1:
c12 = c132 = c = 10


#paths = nx.algorithms.connectivity.edge_connectivity(G, 1, 2, flow_func=shortest_augmenting_path)
#print(G,G.nodes())
#print(paths)

# If the unit cost is based on a unit flow per link:
m12 =  1     # One flow per path
m132 = 2    # Two flows per path

# Maximum demand volume
for demand in range(1,21):
    model += h == demand#10
    #model += h >= 0

    model += p12+p132 == h
    model += p12 <= c12
    model += p132 <= c132
    model += p12 >= 0
    model += p132 >= 0

    #Objective function
    model += m12*p12 +m132*p132,'M' #M -> metric (cost)

    model.solve()
    print(pulp.LpStatus[model.status])

    for variable in model.variables():
        print("{} = {}".format(variable.name, variable.varValue))

    print(pulp.value(model.objective))
#print()

#print(G.nodes())
#print(nx.maximum_flow_value(G,1,6,'weight'))
#print(nx.shortest_path(G,1,6,'weight'))

#nx.draw(G)
#plt.savefig("simple_path.png") # save as png
#plt.show() # display

# if __name__ == '__main__':
#     print 'sdfjk'