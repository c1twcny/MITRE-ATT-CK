# MITRE-ATT-CK
Graph linking Actor, Tactic, Techniques, Mitigation and Data Source

Main Neo4j Cypher file: 
1. mitre_graph_v1.2.cypher

Node files:
1. threatActor.csv
2. threatTactic.csv
3. threatTechnique.csv
4. mitigations.csv
5. datasource.scv

Edge files:
1. tt_edge.csv: (Tactic)-(Technique)
2. mt_edge.csv: (Mitigation)-(Technique)
3. gt_edge.csv: (Actor)-(Technique)
4. dt_edge.csv: (DataSource)-(Technique)

/python folder contains several files that perform data scraping on MITRE website (work-in-progress) 
