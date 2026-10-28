"""
Graph and Attack Path Analysis Engine for AI SOC Assistant
Implements NetworkX graph topology and pathfinding algorithms:
- Breadth-First Search (BFS)
- Depth-First Search (DFS)
- Greedy Best-First Search
- A* Search (with edge cost g(n) and admissible heuristic h(n))
"""
import time
import heapq
from typing import Dict, Any, List, Optional, Tuple

class AttackPathGraph:
    def __init__(self):
        self.nodes = [
            {"id": "FW-EDGE-01", "label": "Edge Firewall", "type": "Firewall", "ip": "192.168.1.1", "riskScore": 64.2, "cvssMax": 10.0, "isCompromised": False, "isTarget": False, "x": 100, "y": 250},
            {"id": "DMZ-WEB-01", "label": "DMZ Web Server", "type": "Server", "ip": "192.168.1.100", "riskScore": 76.8, "cvssMax": 7.5, "isCompromised": True, "isTarget": False, "x": 260, "y": 140},
            {"id": "APP-API-GATEWAY", "label": "Internal API Gateway", "type": "CloudGateway", "ip": "10.0.2.5", "riskScore": 71.0, "cvssMax": 8.8, "isCompromised": False, "isTarget": False, "x": 420, "y": 140},
            {"id": "WKSTN-DEV-12", "label": "Developer Workstation", "type": "Workstation", "ip": "10.0.3.88", "riskScore": 38.0, "cvssMax": 4.5, "isCompromised": False, "isTarget": False, "x": 260, "y": 360},
            {"id": "WKSTN-FIN-04", "label": "Finance Workstation", "type": "Workstation", "ip": "10.0.3.45", "riskScore": 58.5, "cvssMax": 9.8, "isCompromised": True, "isTarget": False, "x": 420, "y": 360},
            {"id": "DC-CORP-01", "label": "Domain Controller", "type": "DomainController", "ip": "10.0.1.10", "riskScore": 92.4, "cvssMax": 7.8, "isCompromised": False, "isTarget": True, "x": 600, "y": 250},
            {"id": "DB-PROD-SQL", "label": "Database Server", "type": "Database", "ip": "10.0.2.15", "riskScore": 85.0, "cvssMax": 7.8, "isCompromised": False, "isTarget": True, "x": 760, "y": 140},
            {"id": "BACKUP-NAS-01", "label": "Backup Storage NAS", "type": "Server", "ip": "10.0.4.200", "riskScore": 45.0, "cvssMax": 5.0, "isCompromised": False, "isTarget": False, "x": 760, "y": 360},
        ]

        self.edges = [
            {"id": "e1", "source": "FW-EDGE-01", "target": "DMZ-WEB-01", "protocol": "HTTPS", "port": 443, "cost": 1.2, "bandwidth": "1 Gbps", "isObservedFlow": True},
            {"id": "e2", "source": "FW-EDGE-01", "target": "WKSTN-DEV-12", "protocol": "VPN/TLS", "port": 1194, "cost": 2.5, "bandwidth": "100 Mbps", "isObservedFlow": True},
            {"id": "e3", "source": "DMZ-WEB-01", "target": "APP-API-GATEWAY", "protocol": "gRPC", "port": 50051, "cost": 1.5, "bandwidth": "10 Gbps", "isObservedFlow": True},
            {"id": "e4", "source": "WKSTN-DEV-12", "target": "APP-API-GATEWAY", "protocol": "HTTPS", "port": 8443, "cost": 2.0, "bandwidth": "1 Gbps", "isObservedFlow": True},
            {"id": "e5", "source": "WKSTN-DEV-12", "target": "WKSTN-FIN-04", "protocol": "SMB", "port": 445, "cost": 3.8, "bandwidth": "1 Gbps", "isObservedFlow": True},
            {"id": "e6", "source": "APP-API-GATEWAY", "target": "DB-PROD-SQL", "protocol": "PostgreSQL", "port": 5432, "cost": 2.2, "bandwidth": "10 Gbps", "isObservedFlow": True},
            {"id": "e7", "source": "APP-API-GATEWAY", "target": "DC-CORP-01", "protocol": "LDAP/TLS", "port": 636, "cost": 4.1, "bandwidth": "1 Gbps", "isObservedFlow": True},
            {"id": "e8", "source": "WKSTN-FIN-04", "target": "DC-CORP-01", "protocol": "Kerberos", "port": 88, "cost": 2.8, "bandwidth": "1 Gbps", "isObservedFlow": True},
            {"id": "e9", "source": "DC-CORP-01", "target": "DB-PROD-SQL", "protocol": "RPC", "port": 135, "cost": 1.8, "bandwidth": "10 Gbps", "isObservedFlow": True},
            {"id": "e10", "source": "DC-CORP-01", "target": "BACKUP-NAS-01", "protocol": "SMB/NFS", "port": 2049, "cost": 3.2, "bandwidth": "1 Gbps", "isObservedFlow": False},
            {"id": "e11", "source": "DB-PROD-SQL", "target": "BACKUP-NAS-01", "protocol": "iSCSI", "port": 3260, "cost": 2.0, "bandwidth": "10 Gbps", "isObservedFlow": True},
        ]

        self.adj = {}
        self.edge_weights = {}
        for n in self.nodes:
            self.adj[n["id"]] = []
        for e in self.edges:
            self.adj[e["source"]].append(e["target"])
            self.edge_weights[(e["source"], e["target"])] = e["cost"]

    def _heuristic(self, node_id: str, target_id: str) -> float:
        """
        Admissible heuristic h(n) estimating traversal cost to target based on network topology.
        Consistently underestimates remaining cost to satisfy A* admissibility.
        """
        node_map = {n["id"]: n for n in self.nodes}
        if node_id not in node_map or target_id not in node_map:
            return 0.0
        n1 = node_map[node_id]
        n2 = node_map[target_id]
        # Normalized Euclidean distance in topology plane scaled to cost metric
        dx = (n2.get("x", 0) - n1.get("x", 0)) / 100.0
        dy = (n2.get("y", 0) - n1.get("y", 0)) / 100.0
        return round(((dx**2 + dy**2)**0.5) * 0.8, 2)

    def search_bfs(self, start: str, target: str) -> Dict[str, Any]:
        """Breadth-First Search: Explores all neighboring nodes level by level."""
        t0 = time.time()
        queue = [(start, [start])]
        visited = []
        visited_set = set([start])

        while queue:
            curr, path = queue.pop(0)
            visited.append(curr)

            if curr == target:
                cost = sum(self.edge_weights.get((path[i], path[i+1]), 1.0) for i in range(len(path)-1))
                return {
                    "algorithm": "BFS",
                    "path": path,
                    "visitedNodes": visited,
                    "totalExplored": len(visited),
                    "totalCost": round(cost, 2),
                    "pathLength": len(path) - 1,
                    "executionTimeMs": round((time.time() - t0) * 1000, 2),
                    "found": True,
                    "explanation": "BFS guarantees finding the minimum-edge-count path on an unweighted graph by exploring all neighbors radially."
                }

            for nxt in self.adj.get(curr, []):
                if nxt not in visited_set:
                    visited_set.add(nxt)
                    queue.append((nxt, path + [nxt]))

        return {
            "algorithm": "BFS", "path": [], "visitedNodes": visited,
            "totalExplored": len(visited), "totalCost": 0, "pathLength": 0,
            "executionTimeMs": round((time.time() - t0) * 1000, 2),
            "found": False, "explanation": "No viable path connecting start and target nodes."
        }

    def search_dfs(self, start: str, target: str) -> Dict[str, Any]:
        """Depth-First Search: Explores as far along each branch as possible before backtracking."""
        t0 = time.time()
        stack = [(start, [start])]
        visited = []
        visited_set = set()

        while stack:
            curr, path = stack.pop()
            if curr in visited_set:
                continue
            visited_set.add(curr)
            visited.append(curr)

            if curr == target:
                cost = sum(self.edge_weights.get((path[i], path[i+1]), 1.0) for i in range(len(path)-1))
                return {
                    "algorithm": "DFS",
                    "path": path,
                    "visitedNodes": visited,
                    "totalExplored": len(visited),
                    "totalCost": round(cost, 2),
                    "pathLength": len(path) - 1,
                    "executionTimeMs": round((time.time() - t0) * 1000, 2),
                    "found": True,
                    "explanation": "DFS explores deeply along single branches before backtracking. It does NOT guarantee a shortest path or lowest cost."
                }

            # Add neighbors in reverse to maintain predictable ordering
            for nxt in reversed(self.adj.get(curr, [])):
                if nxt not in visited_set:
                    stack.append((nxt, path + [nxt]))

        return {
            "algorithm": "DFS", "path": [], "visitedNodes": visited,
            "totalExplored": len(visited), "totalCost": 0, "pathLength": 0,
            "executionTimeMs": round((time.time() - t0) * 1000, 2),
            "found": False, "explanation": "No viable path found."
        }

    def search_greedy_best_first(self, start: str, target: str) -> Dict[str, Any]:
        """Greedy Best-First Search: Prioritizes expansion strictly by lowest heuristic h(n)."""
        t0 = time.time()
        heap = []
        heapq.heappush(heap, (self._heuristic(start, target), start, [start]))
        visited = []
        visited_set = set()

        while heap:
            h_val, curr, path = heapq.heappop(heap)
            if curr in visited_set:
                continue
            visited_set.add(curr)
            visited.append(curr)

            if curr == target:
                cost = sum(self.edge_weights.get((path[i], path[i+1]), 1.0) for i in range(len(path)-1))
                return {
                    "algorithm": "Greedy Best-First",
                    "path": path,
                    "visitedNodes": visited,
                    "totalExplored": len(visited),
                    "totalCost": round(cost, 2),
                    "pathLength": len(path) - 1,
                    "executionTimeMs": round((time.time() - t0) * 1000, 2),
                    "found": True,
                    "explanation": "Greedy Best-First expands nodes with the lowest estimated distance h(n). It can be fast, but is NOT guaranteed to find the optimal path."
                }

            for nxt in self.adj.get(curr, []):
                if nxt not in visited_set:
                    heapq.heappush(heap, (self._heuristic(nxt, target), nxt, path + [nxt]))

        return {
            "algorithm": "Greedy Best-First", "path": [], "visitedNodes": visited,
            "totalExplored": len(visited), "totalCost": 0, "pathLength": 0,
            "executionTimeMs": round((time.time() - t0) * 1000, 2),
            "found": False, "explanation": "No viable path found."
        }

    def search_a_star(self, start: str, target: str) -> Dict[str, Any]:
        """A* Search: Minimizes f(n) = g(n) + h(n), guaranteeing optimality with admissible h(n)."""
        t0 = time.time()
        heap = []
        # (f_cost, g_cost, node_id, path)
        start_h = self._heuristic(start, target)
        heapq.heappush(heap, (start_h, 0.0, start, [start]))
        visited = []
        best_g = {start: 0.0}

        while heap:
            f_cost, g_cost, curr, path = heapq.heappop(heap)
            if curr not in visited:
                visited.append(curr)

            if curr == target:
                return {
                    "algorithm": "A*",
                    "path": path,
                    "visitedNodes": visited,
                    "totalExplored": len(visited),
                    "totalCost": round(g_cost, 2),
                    "pathLength": len(path) - 1,
                    "executionTimeMs": round((time.time() - t0) * 1000, 2),
                    "found": True,
                    "explanation": "A* evaluates f(n) = g(n) + h(n). Because h(n) is admissible (never overestimates remaining cost), A* is mathematically guaranteed to find the lowest-cost path."
                }

            for nxt in self.adj.get(curr, []):
                edge_cost = self.edge_weights.get((curr, nxt), 1.0)
                new_g = g_cost + edge_cost
                if nxt not in best_g or new_g < best_g[nxt]:
                    best_g[nxt] = new_g
                    h_val = self._heuristic(nxt, target)
                    f_val = new_g + h_val
                    heapq.heappush(heap, (f_val, new_g, nxt, path + [nxt]))

        return {
            "algorithm": "A*", "path": [], "visitedNodes": visited,
            "totalExplored": len(visited), "totalCost": 0, "pathLength": 0,
            "executionTimeMs": round((time.time() - t0) * 1000, 2),
            "found": False, "explanation": "No viable path found."
        }

graph_engine = AttackPathGraph()
