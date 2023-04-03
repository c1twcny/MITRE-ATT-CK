//Create (Actor)-(Technique)-(Tactic) graph using MITRE data sets
//
//First: Create Country->Actor->AssociatedGroup
//
WITH 'file:///threatActor.csv' as threat_actor
LOAD CSV WITH HEADERS FROM threat_actor AS row
MERGE (:Actor {id:row.id, name:row.name, country:row.country, associatedGroup:row.associatedGroup})

//Create Links
WITH *
OPTIONAL MATCH (p:Actor)
//WHERE p.country IS NOT NULL AND p.associatedGroup IS NOT NULL
WHERE p.country IS NOT NULL AND p.associatedGroup<>'0'
UNWIND SPLIT(p.associatedGroup,',') AS group0
WITH *, p, p.country AS country, TRIM(group0) AS group1
MERGE (c:Country {country:country})
MERGE (ag:AssociatedGroup {name:group1})
MERGE (p)-[:IS_ASSOCIATED_WITH]->(ag)
MERGE (c)-[:SUPPORT]->(p)

UNION

//Second: Load Tactic-Technique Mapping data
WITH 'file:///threatTacticTechniqueMapping.csv' AS tactic
LOAD CSV WITH HEADERS FROM tactic AS row
MERGE (:TTMapping {id:row.id, name:row.name, techniqueID:row.techniqueID})
WITH *
MATCH (n0:TTMapping)
WITH *, collect(DISTINCT n0.name) AS group0, collect(DISTINCT n0.techniqueID) AS group1
MERGE (a:Tactic {name:group0})
MERGE (b:Technique {name:group1})
MERGE (b)-[:PERFORM]->(a)

UNION

//Third: Load Technique data
WITH 'file:///threatTechnique.csv' as threat_technique
LOAD CSV WITH HEADERS FROM threat_technique AS row
MERGE (:Technique {id:row.id, subid:row.sub_id, name:row.name})

UNION

//Forth: Using UNION to merge multiple MATCH statements together
MATCH (a:Country {country: 'china'}), (b:Actor {name: 'admin@338'}), (c:Technique)
WHERE any(x IN c.name WHERE x IN ['T1087', 'T1059', 'T1203','T1083', 'T1036', 'T1069', 'T1566', 'T1082', 'T1016', 'T1049', 'T1007', 'T1204'])
WITH b, c, a
MERGE (b)-[:EMPLOY]->(c)
MERGE (a)-[:SUPPORT]->(b)

UNION 

MATCH (a1:Country {country: 'russia'}), (b1:Actor {name: 'APT29'}), (c1:Technique)
WHERE any(y IN c1.name WHERE y IN ['T1548', 'T1087', 'T1098', 'T1583', 'T1595', 'T1071', 'T1560', 'T1547', 'T1110', 'T1059', 'T1586', 'T1584', 'T1136', 'T1555', 'T1213', 'T1005', 'T1001', 'T1074', 'T1140', 'T1587', 'T1484', 'T1482', 'T1568', 'T1114', 'T1573', 'T1546', 'T1048', 'T1190', 'T1203', 'T1068', 'T1133', 'T1083', 'T1606', 'T1589', 'T1562', 'T1070', 'T1105', 'T1036', 'T1556', 'T1621', 'T1095', 'T1027', 'T1588', 'T1003', 'T1069', 'T1566', 'T1057', 'T1090', 'T1021', 'T1018','T1053', 'T1505', 'T1649', 'T1558', 'T1539', 'T1553', 'T1195', 'T1218', 'T1082', 'T1016', 'T1199', 'T1552', 'T1550', 'T1204', 'T1078', 'T1102', 'T1047'])
WITH b1, c1, a1
MERGE (b1)-[:EMPLOY]->(c1)
MERGE (a1)-[:SUPPORT]->(b1)

UNION

MATCH (a2:Country {country: "northKorean"}), (b2:Actor {name: 'Andariel'}), (c2:Technique)
WHERE any(y2 IN c2.name WHERE y2 IN ['T1005', 'T1189', 'T1203', 'T1592', 'T1590', 'T1105', 'T1027', 'T1588', 'T1566', 'T1057','T1049', 'T1204'])
WITH b2, c2, a2
MERGE (b2)-[:EMPLOY]->(c2)
MERGE (a2)-[:SUPPORT]->(b2)

UNION

MATCH (a3:Country {country: 'iran'}), (b3:Actor {name: 'APT39'}), (c3:Technique)
WHERE any(y3 IN c3.name WHERE y3 IN ['T1071', 'T1560', 'T1197', 'T1547', 'T1110', 'T1115', 'T1059', 'T1136', 'T1555', 'T1005', 'T1074', 'T1140', 'T1546', 'T1041', 'T1190', 'T1083', 'T1070', 'T1105', 'T1056', 'T1036', 'T1046', 'T1135', 'T1027', 'T1588', 'T1003', 'T1566', 'T1090', 'T1012', 'T1021', 'T1018', 'T1053', 'T1113', 'T1505', 'T1553', 'T1033', 'T1569', 'T1204', 'T1078', 'T1102'])
WITH b3, c3, a3
MERGE (b3)-[:EMPLOY]->(c3)
MERGE (a3)-[:SUPPORT]->(b3)

UNION

MATCH (a4:Country {country: 'china'}), (b4:Actor {name: 'ZIRCONIUM'}), (c4:Technique)
WHERE any(y4 IN c4.name WHERE y4 IN ['T1583','T1547','T1059','T1555', 'T1140','T1573','T1041','T1567','T1068','T1105','T1036','T1027','T1566','T1598','T1012','T1218','T1082','T1016','T1033','T1124','T1204','T1102'])
WITH b4, c4, a4
MERGE (b4)-[:EMPLOY]->(c4)
MERGE (a4)-[:SUPPORT]->(b4)

UNION

MATCH (a5:Country {country: 'russia'}), (b5:Actor {name: 'APT28'}), (c5:Technique)
WHERE any(y5 IN c5.name WHERE y5 IN ['T1134','T1098','T1583','T1595','T1071','T1560','T1119','T1547','T1037','T1110','T1059','T1092','T1586','T1213','T1005','T1039','T1025','T1001','T1074','T1030','T1140','T1189','T1114','T1573','T1546','T1048','T1567','T1190','T1203','T1211','T1068','T1210','T1133','T1083','T1589','T1564','T1070','T1105','T1056','T1559','T1036','T1498','T1040','T1027','T1588','T1137','T1003','T1120','T1566','T1598','T1542','T1057','T1090','T1021','T1091','T1014','T1113','T1505','T1528','T1218','T1221','T1199','T1550','T1204','T1078','T1102'])
WITH b5, c5, a5
MERGE (b5)-[:EMPLOY]->(c5)
MERGE (a5)-[:SUPPORT]->(b5)

UNION

MATCH (a6:Country {country: '0'}), (b6:Actor {name: 'Cobalt Group'}), (c6:Technique)
WHERE any(y6 IN c6.name WHERE y6 IN ['T1548','T1071','T1547','T1037','T1059','T1543','T1573','T1203','T1068','T1070','T1105','T1559','T1046','T1027','T1588','T1566','T1055','T1572','T1219','T1021','T1053','T1518','T1195','T1218','T1204','T1220'])
WITH b6, c6, a6
MERGE (b6)-[:EMPLOY]->(c6)
MERGE (a6)-[:SUPPORT]->(b6)


UNION

MATCH (a7:Country {country: 'china'}), (b6:Actor {name: 'APT1'}), (c7:Technique)
WHERE any(y7 IN c7.name WHERE y7 IN ['T1087','T1583','T1560','T1119','T1059','T1584','T1005','T1114','T1585','T1036','T1135','T1588','T1003','T1566','T1057','T1021','T1016','T1049','T1007','T1550'])
WITH b7, c7, a7
MERGE (b7)-[:EMPLOY]->(c7)
MERGE (a7)-[:SUPPORT]->(b7)

UNION

MATCH (a8:Country {country: 'china'}), (b8:Actor {name: 'APT12'}), (c8:Technique)
WHERE any(y8 IN c8.name WHERE y8 IN ['T1568','T1203','T1566','T1204','T1102'])
WITH b8, c8, a8
MERGE (b8)-[:EMPLOY]->(c8)
MERGE (a8)-[:SUPPORT]->(b8)

UNION

MATCH (a9:Country {country: 'china'}), (b9:Actor {name: 'APT16'}), (c9:Technique)
WHERE any(y9 IN c9.name WHERE y9 IN ['T1584'])
WITH b9, c9, a9
MERGE (b9)-[:EMPLOY]->(c9)
MERGE (a9)-[:SUPPORT]->(b9)

UNION

MATCH (a10:Country {country: 'china'}), (b10:Actor {name: 'APT17'}), (c10:Technique)
WHERE any(y10 IN c10.name WHERE y10 IN ['T1583','T1585'])
WITH b10, c10, a10
MERGE (b10)-[:EMPLOY]->(c10)
MERGE (a10)-[:SUPPORT]->(b10)

UNION

MATCH (a11:Country {country: '0'}), (b11:Actor {name: 'APT18'}), (c11:Technique)
WHERE any(y11 IN c11.name WHERE y11 IN ['T1071','T1547','T1059','T1133','T1083','T1070','T1105','T1027','T1053','T1082','T1078'])
WITH b11, c11, a11
MERGE (b11)-[:EMPLOY]->(c11)
MERGE (a11)-[:SUPPORT]->(b11)

UNION

MATCH (a12:Country {country: 'china'}), (b12:Actor {name: 'APT19'}), (c12:Technique)
WHERE any(y12 IN c12.name WHERE y12 IN ['T1071','T1547','T1059','T1543','T1132','T1140','T1189','T1564','T1574','T1112','T1027','T1588','T1218','T1082','T1016','T1033','T1204'])
WITH b12, c12, a12
MERGE (b12)-[:EMPLOY]->(c12)
MERGE (a12)-[:SUPPORT]->(b12)

UNION

MATCH (a13:Country {country: 'china'}), (b13:Actor {name: 'APT3'}), (c13:Technique)
WHERE any(y13 IN c13.name WHERE y13 IN ['T1087','T1098','T1560','T1547','T1110','T1059','T1136','T1543','T1555','T1005','T1074','T1546','T1041','T1203','T1083','T1564','T1574','T1070','T1105','T1056','T1104','T1095','T1027','T1003','T1069','T1566','T1057','T1090','T1021','T1018','T1053','T1218','T1082','T1016','T1049','T1033','T1552','T1204','T1078'])
WITH b13, c13, a13
MERGE (b13)-[:EMPLOY]->(c13)
MERGE (a13)-[:SUPPORT]->(b13)

UNION

MATCH (a14:Country {country: 'china'}), (b14:Actor {name: 'APT30'}), (c14:Technique)
WHERE any(y14 IN c14.name WHERE y14 IN ['T1566','T1204'])
WITH b14, c14, a14
MERGE (b14)-[:EMPLOY]->(c14)
MERGE (a14)-[:SUPPORT]->(b14)

UNION

MATCH (a15:Country {country: 'vietnam'}), (b15:Actor {name: 'APT32'}), (c15:Technique)
WHERE any(y15 IN c15.name WHERE y15 IN ['T1087','T1583','T1071','T1560','T1547','T1059','T1543','T1189','T1585','T1048','T1041','T1203','T1068','T1083','T1222','T1589','T1564','T1574','T1070','T1105','T1056','T1036','T1112','T1046','T1135','T1571','T1027','T1588','T1137','T1003','T1566','T1598','T1055','T1012','T1021','T1018','T1053','T1505','T1072','T1608','T1218','T1082','T1016','T1049','T1033','T1216','T1569','T1552','T1550','T1204','T1078','T1102','T1047'])
WITH b15, c15, a15
MERGE (b15)-[:EMPLOY]->(c15)
MERGE (a15)-[:SUPPORT]->(b15)

UNION

MATCH (a16:Country {country: 'iran'}), (b16:Actor {name: 'APT33'}), (c16:Technique)
WHERE any(y16 IN c16.name WHERE y16 IN ['T1071','T1560','T1547','T1110','T1059','T1555','T1132','T1573','T1546','T1048','T1203','T1068','T1105','T1040','T1571','T1027','T1588','T1003','T1566','T1053','T1552','T1204','T1078','T0852','T0856'])
WITH b16, c16, a16
MERGE (b16)-[:EMPLOY]->(c16)
MERGE (a16)-[:SUPPORT]->(b16)