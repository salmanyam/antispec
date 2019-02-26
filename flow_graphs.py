import angr
import monkeyhex
import networkx as nx
import matplotlib.pyplot as plt

proj = angr.Project('CADET_00001', auto_load_libs=False)

print(proj.arch)

cfg = proj.analyses.CFG()

G = cfg.graph

#print(G.nodes())

print('Total nodes =', len(G.nodes()))

print('Total edges =', len(G.edges()))

print(proj.entry)
entry_node = cfg.get_any_node(proj.entry)
print(entry_node)

nx.draw(G)
#plt.draw()
plt.show()

d = proj.analyses.DFG()

bbl_addr, dfg = d.dfgs.popitem()

#print(bbl_addr)
#print(dfg.in_edges())

#G2 = dfg.graph
#print(dfg.nodes())

nx.draw(dfg)
#plt.draw()
plt.show()

