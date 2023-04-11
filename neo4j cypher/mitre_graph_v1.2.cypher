//Prod-v1.2: (Mitigation)-(Tactic)-(Technique)-(Actor)-(DataSource) graph
//Lesson: Use 'UNION' for the best performance
//
LOAD CSV WITH HEADERS FROM 'file:///threatTactic.csv' AS tactics
MERGE (:Tactics {id:tactics.id, name:tactics.name, description:tactics.description})

UNION

LOAD CSV WITH HEADERS FROM 'file:///threatTechnique.csv' AS techniques
MERGE (:Technique {id:techniques.id, sudid:techniques.sub_id, name:techniques.name, description:techniques.description})

UNION

LOAD CSV WITH HEADERS from 'file:///mitigations.csv' AS mitigations
MERGE (:Mitigation {id:mitigations.id, name:mitigations.name, description:mitigations.description})

UNION

LOAD CSV WITH HEADERS FROM 'file:///threatActor.csv' AS actors
MERGE (:Actor {id:actors.id, name:actors.name, country:actors.country, associatedGroup:actors.associatedGroup})

UNION

LOAD CSV WITH HEADERS FROM 'file:///datasource.csv' AS datasource
MERGE (:DataSource {id:datasource.id, name:datasource.name, description:datasource.description})

UNION

LOAD CSV WITH HEADERS FROM 'file:///tt_edge.csv' AS tt_edges
MATCH (s:Tactics {id:tt_edges.tactic})
MATCH (d:Technique {id:tt_edges.technique})
MERGE (s)-[:CONTAIN]->(d)

UNION

LOAD CSV WITH HEADERS FROM 'file:///mt_edge.csv' AS mt_edges
MATCH (s1:Mitigation {id:mt_edges.mitigation})
MATCH (d1:Technique {id:mt_edges.technique})
MERGE (s1)-[:MITIGATE]->(d1)

UNION

LOAD CSV WITH HEADERS FROM 'file:///gt_edge.csv' AS gt_edge
MATCH (s2:Actor {id:gt_edge.group})
MATCH (d2:Technique {id:gt_edge.technique})
MERGE (s2)-[:DEPLOY]->(d2)

UNION

LOAD CSV WITH HEADERS FROM 'file:///dt_edge.csv' AS dt_edge
MATCH (s3:DataSource {id:dt_edge.data_source})
MATCH (d3:Technique {id:dt_edge.technique})
MERGE (s3)-[:DETECT]->(d3)