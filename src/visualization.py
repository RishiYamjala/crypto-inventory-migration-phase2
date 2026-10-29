"""Figures for architecture and benchmark interpretation."""
from pathlib import Path
import matplotlib.pyplot as plt
import networkx as nx
from qiskit.visualization import circuit_drawer


def make_figures(processors, logical, compiled, rows, output_dir='results/figures'):
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    for key, proc in processors.items():
        g = nx.Graph(); g.add_nodes_from(range(proc['num_qubits'])); g.add_edges_from(proc['coupling_map'])
        plt.figure(figsize=(5,4)); pos = nx.spring_layout(g, seed=42); nx.draw_networkx(g, pos=pos, with_labels=True, node_color='#9ecae1', node_size=900, edge_color='#3182bd')
        plt.title(f"{proc['name']} coupling graph\nParticipant-defined research topology")
        plt.axis('off'); plt.tight_layout(); plt.savefig(out/f'{key}_graph.png', dpi=160); plt.close()
    circuit_drawer(logical, output='mpl', filename=str(out/'logical_vs_transpiled.png'), style={'backgroundcolor':'white'})
    names = [r['processor'] for r in rows]; p = [r['success_probability'] for r in rows]; e = [r['std_error'] for r in rows]
    chart_colors = ['#756bb1', '#31a354', '#e6550d'][:len(rows)]
    plt.figure(figsize=(max(6, 2.2 * len(rows)),4)); plt.bar(names,p,yerr=e,capsize=5,color=chart_colors); plt.ylabel('P(measuring 101)'); plt.ylim(0,1); plt.title('Noisy benchmark performance'); plt.tight_layout(); plt.savefig(out/'AB_performance.png',dpi=160); plt.close()
    metrics = ['depth','two_qubit_gates','swap_estimate']; x=list(range(len(metrics))); width=.8 / len(rows)
    plt.figure(figsize=(8,4))
    for index, row in enumerate(rows):
        offsets = [value + (index - (len(rows)-1)/2) * width for value in x]
        plt.bar(offsets,[row[m] for m in metrics],width,label=row['processor'],color=chart_colors[index])
    plt.xticks(x,metrics); plt.ylabel('Measured / estimated value'); plt.title('Architecture trade-offs'); plt.legend(); plt.tight_layout(); plt.savefig(out/'architecture_tradeoffs.png',dpi=160); plt.close()
