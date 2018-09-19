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

print G.nodes(),G.edge

nx.node_d

nx.algorithms.connectivity.disjoint_paths.node_disjoint_paths

