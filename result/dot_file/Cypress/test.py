import networkx as nx
import matplotlib.pyplot as plt

# 创建 Mealy 自动机的有向图
machine = nx.MultiDiGraph()

# 添加状态
states = ['A', 'B', 'C']
machine.add_nodes_from(states)

# 添加带有输入输出对的转换
transitions = [('A', 'B', {'input': '0', 'output': '0'}),
               ('A', 'C', {'input': '1', 'output': '1'}),
               ('B', 'A', {'input': '0', 'output': '1'}),
               ('B', 'C', {'input': '1', 'output': '0'}),
               ('C', 'B', {'input': '0', 'output': '1'}),
               ('C', 'A', {'input': '1', 'output': '0'})]

machine.add_edges_from(transitions)

# 绘制 Mealy 自动机
pos = nx.spring_layout(machine)
nx.draw(machine, pos, with_labels=True, node_color='lightblue', font_weight='bold')

# 为输入输出对添加边标签
edge_labels = {(u, v): f"{d['input']}/{d['output']}" for u, v, d in machine.edges(data=True)}
nx.draw_networkx_edge_labels(machine, pos, edge_labels=edge_labels)

# 保存为 PDF 文件
plt.savefig("mealy_machine.pdf", format="pdf")
plt.show()
