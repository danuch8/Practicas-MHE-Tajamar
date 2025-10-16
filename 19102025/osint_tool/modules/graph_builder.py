import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Use non-GUI backend suitable for servers/threads
import matplotlib.pyplot as plt

class GraphBuilder:
    def __init__(self, results: dict):
        self.results = results

    def build(self, outfile: str = "graph.png"):
        G = nx.Graph()
        for key in self.results:
            G.add_node(key)
        for key, val in self.results.items():
            if isinstance(val, dict):
                for subk in val:
                    G.add_edge(key, subk)
        plt.figure(figsize=(8, 6))
        nx.draw(G, with_labels=True, node_size=800, font_size=8)
        plt.savefig(outfile)
        plt.close()
        return outfile
