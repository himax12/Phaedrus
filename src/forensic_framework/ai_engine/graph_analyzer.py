"""
Graph-based attack path analysis using NetworkX.

Converts log data into a provenance graph where:
- Nodes: Users, IPs, Files, Processes
- Edges: Actions (EXECUTE, READ, CONNECT, LOGIN, etc.)

Provides:
- Attack path reconstruction
- Lateral movement detection
- Subgraph extraction for investigation
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import networkx as nx


class NodeType(str, Enum):
    """Types of nodes in the provenance graph."""

    USER = "user"
    IP = "ip"
    HOST = "host"
    FILE = "file"
    PROCESS = "process"
    SERVICE = "service"


class EdgeType(str, Enum):
    """Types of edges (actions) in the provenance graph."""

    CONNECT = "connect"
    LOGIN = "login"
    EXECUTE = "execute"
    READ = "read"
    WRITE = "write"
    MODIFY = "modify"
    DELETE = "delete"
    SPAWN = "spawn"
    ACCESS = "access"


@dataclass
class GraphNode:
    """A node in the provenance graph."""

    id: str
    type: NodeType
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0


@dataclass
class GraphEdge:
    """An edge in the provenance graph."""

    source: str
    target: str
    type: EdgeType
    timestamp: datetime | None = None
    log_id: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    """A detected attack path."""

    nodes: list[str]
    edges: list[tuple[str, str]]
    risk_score: float
    description: str
    entry_point: str | None = None
    target: str | None = None


class GraphAnalyzer:
    """
    NetworkX-based graph analyzer for attack path reconstruction.

    Usage:
        analyzer = GraphAnalyzer()
        analyzer.add_node("user:admin", NodeType.USER, "Admin User")
        analyzer.add_edge("user:admin", "host:server1", EdgeType.LOGIN)
        paths = analyzer.find_attack_paths("ip:malicious", "file:sensitive")
    """

    def __init__(self):
        """Initialize the graph analyzer."""
        self.graph = nx.DiGraph()
        self._node_data: dict[str, GraphNode] = {}
        self._high_risk_patterns: list[list[EdgeType]] = [
            # Suspicious patterns
            [EdgeType.LOGIN, EdgeType.EXECUTE, EdgeType.MODIFY],
            [EdgeType.CONNECT, EdgeType.LOGIN, EdgeType.READ],
            [EdgeType.EXECUTE, EdgeType.SPAWN, EdgeType.CONNECT],
        ]

    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        label: str,
        properties: dict[str, Any] | None = None,
        risk_score: float = 0.0,
    ) -> None:
        """
        Add a node to the graph.

        Args:
            node_id: Unique identifier (e.g., "user:admin", "ip:192.168.1.1")
            node_type: Type of node
            label: Human-readable label
            properties: Additional properties
            risk_score: Initial risk score (0-1)
        """
        node = GraphNode(
            id=node_id,
            type=node_type,
            label=label,
            properties=properties or {},
            risk_score=risk_score,
        )
        self._node_data[node_id] = node
        self.graph.add_node(
            node_id,
            type=node_type.value,
            label=label,
            risk_score=risk_score,
            **node.properties,
        )

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: EdgeType,
        timestamp: datetime | None = None,
        log_id: str | None = None,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """
        Add an edge (action) to the graph.

        Args:
            source: Source node ID
            target: Target node ID
            edge_type: Type of action
            timestamp: When the action occurred
            log_id: Reference to source log
            properties: Additional properties
        """
        # Auto-create nodes if they don't exist
        if source not in self.graph:
            self.add_node(source, self._infer_type(source), source)
        if target not in self.graph:
            self.add_node(target, self._infer_type(target), target)

        self.graph.add_edge(
            source,
            target,
            type=edge_type.value,
            timestamp=timestamp.isoformat() if timestamp else None,
            log_id=log_id,
            **(properties or {}),
        )

    def _infer_type(self, node_id: str) -> NodeType:
        """Infer node type from ID prefix."""
        if node_id.startswith("user:"):
            return NodeType.USER
        elif node_id.startswith("ip:"):
            return NodeType.IP
        elif node_id.startswith("host:"):
            return NodeType.HOST
        elif node_id.startswith("file:"):
            return NodeType.FILE
        elif node_id.startswith("process:"):
            return NodeType.PROCESS
        elif node_id.startswith("service:"):
            return NodeType.SERVICE
        return NodeType.HOST

    def find_paths(
        self,
        source: str,
        target: str,
        max_length: int = 10,
    ) -> list[list[str]]:
        """
        Find all simple paths between two nodes.

        Args:
            source: Source node ID
            target: Target node ID
            max_length: Maximum path length

        Returns:
            List of paths (each path is a list of node IDs)
        """
        if source not in self.graph or target not in self.graph:
            return []

        try:
            paths = list(nx.all_simple_paths(
                self.graph, source, target, cutoff=max_length
            ))
            return paths
        except nx.NetworkXNoPath:
            return []

    def find_attack_paths(
        self,
        source: str | None = None,
        target: str | None = None,
        min_risk_score: float = 0.5,
    ) -> list[AttackPath]:
        """
        Find potential attack paths in the graph.

        Args:
            source: Optional source node (entry point)
            target: Optional target node (goal)
            min_risk_score: Minimum risk score to include

        Returns:
            List of AttackPath objects sorted by risk
        """
        attack_paths: list[AttackPath] = []

        # If source and target specified, find direct paths
        if source and target:
            paths = self.find_paths(source, target)
            for path in paths:
                risk = self._calculate_path_risk(path)
                if risk >= min_risk_score:
                    attack_paths.append(AttackPath(
                        nodes=path,
                        edges=list(zip(path[:-1], path[1:])),
                        risk_score=risk,
                        description=self._describe_path(path),
                        entry_point=source,
                        target=target,
                    ))
        else:
            # Find all suspicious paths
            high_risk_nodes = [
                n for n, d in self.graph.nodes(data=True)
                if d.get("risk_score", 0) >= min_risk_score
            ]

            for node in high_risk_nodes:
                # Find paths TO high-risk nodes
                for other in self.graph.nodes():
                    if other != node:
                        paths = self.find_paths(other, node, max_length=5)
                        for path in paths:
                            risk = self._calculate_path_risk(path)
                            if risk >= min_risk_score:
                                attack_paths.append(AttackPath(
                                    nodes=path,
                                    edges=list(zip(path[:-1], path[1:])),
                                    risk_score=risk,
                                    description=self._describe_path(path),
                                    entry_point=path[0],
                                    target=path[-1],
                                ))

        # Sort by risk score descending
        attack_paths.sort(key=lambda p: p.risk_score, reverse=True)
        return attack_paths

    def _calculate_path_risk(self, path: list[str]) -> float:
        """Calculate risk score for a path."""
        if len(path) < 2:
            return 0.0

        risk = 0.0

        # Factor 1: Node risk scores
        for node in path:
            node_data = self.graph.nodes.get(node, {})
            risk += node_data.get("risk_score", 0)

        # Factor 2: Edge types
        edge_types = []
        for i in range(len(path) - 1):
            edge_data = self.graph.edges.get((path[i], path[i + 1]), {})
            edge_type_str = edge_data.get("type", "")
            try:
                edge_types.append(EdgeType(edge_type_str))
            except ValueError:
                pass

        # Check for high-risk patterns
        for pattern in self._high_risk_patterns:
            if self._pattern_matches(edge_types, pattern):
                risk += 0.3

        # Factor 3: Path length (longer paths = more lateral movement)
        if len(path) > 3:
            risk += 0.1 * (len(path) - 3)

        # Factor 4: Cross-type transitions
        types_in_path = [self.graph.nodes.get(n, {}).get("type") for n in path]
        unique_types = len(set(types_in_path))
        if unique_types > 2:
            risk += 0.2

        return min(risk, 1.0)

    def _pattern_matches(
        self,
        edge_types: list[EdgeType],
        pattern: list[EdgeType],
    ) -> bool:
        """Check if edge type sequence contains a pattern."""
        if len(edge_types) < len(pattern):
            return False

        for i in range(len(edge_types) - len(pattern) + 1):
            if edge_types[i:i + len(pattern)] == pattern:
                return True
        return False

    def _describe_path(self, path: list[str]) -> str:
        """Generate human-readable description of a path."""
        if len(path) < 2:
            return "Empty path"

        descriptions = []
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]
            edge_data = self.graph.edges.get((source, target), {})
            edge_type = edge_data.get("type", "connected to")

            src_label = self.graph.nodes.get(source, {}).get("label", source)
            tgt_label = self.graph.nodes.get(target, {}).get("label", target)

            descriptions.append(f"{src_label} --[{edge_type}]--> {tgt_label}")

        return " | ".join(descriptions)

    def get_neighborhood(
        self,
        node: str,
        radius: int = 2,
    ) -> nx.DiGraph:
        """
        Get subgraph around a node.

        Args:
            node: Center node ID
            radius: Number of hops to include

        Returns:
            Subgraph containing the neighborhood
        """
        if node not in self.graph:
            return nx.DiGraph()

        # Get nodes within radius
        nodes_in_radius = {node}
        current_frontier = {node}

        for _ in range(radius):
            next_frontier = set()
            for n in current_frontier:
                next_frontier.update(self.graph.predecessors(n))
                next_frontier.update(self.graph.successors(n))
            nodes_in_radius.update(next_frontier)
            current_frontier = next_frontier

        return self.graph.subgraph(nodes_in_radius).copy()

    def backward_trace(
        self,
        target: str,
        max_depth: int = 10,
    ) -> list[str]:
        """
        Trace backwards from a target node to find entry points.

        Args:
            target: Target node to trace from
            max_depth: Maximum trace depth

        Returns:
            List of potential entry point nodes
        """
        if target not in self.graph:
            return []

        entry_points = []
        visited = set()

        def dfs(node: str, depth: int):
            if depth > max_depth or node in visited:
                return
            visited.add(node)

            predecessors = list(self.graph.predecessors(node))
            if not predecessors:
                # This is an entry point
                entry_points.append(node)
            else:
                for pred in predecessors:
                    dfs(pred, depth + 1)

        dfs(target, 0)
        return entry_points

    def get_stats(self) -> dict[str, Any]:
        """Get graph statistics."""
        return {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "node_types": dict(
                nx.get_node_attributes(self.graph, "type")
            ),
            "connected_components": nx.number_weakly_connected_components(self.graph),
        }

    def to_json(self) -> dict[str, Any]:
        """Export graph to JSON-serializable format."""
        return {
            "nodes": [
                {"id": n, **d}
                for n, d in self.graph.nodes(data=True)
            ],
            "edges": [
                {"source": u, "target": v, **d}
                for u, v, d in self.graph.edges(data=True)
            ],
        }


def main():
    """Demo graph analyzer functionality."""
    print("Graph Analyzer Demo\n")

    analyzer = GraphAnalyzer()

    # Build a sample attack scenario
    print("Building provenance graph for attack scenario...")

    # Add nodes
    analyzer.add_node("ip:203.0.113.50", NodeType.IP, "External IP", risk_score=0.8)
    analyzer.add_node("user:admin", NodeType.USER, "Admin Account", risk_score=0.3)
    analyzer.add_node("host:webserver", NodeType.HOST, "Web Server")
    analyzer.add_node("host:dbserver", NodeType.HOST, "Database Server", risk_score=0.2)
    analyzer.add_node("process:shell", NodeType.PROCESS, "Bash Shell", risk_score=0.5)
    analyzer.add_node("file:passwd", NodeType.FILE, "/etc/passwd", risk_score=0.9)
    analyzer.add_node("file:config", NodeType.FILE, "config.yaml", risk_score=0.7)

    # Add edges (attack chain)
    analyzer.add_edge("ip:203.0.113.50", "host:webserver", EdgeType.CONNECT)
    analyzer.add_edge("host:webserver", "user:admin", EdgeType.LOGIN)
    analyzer.add_edge("user:admin", "process:shell", EdgeType.EXECUTE)
    analyzer.add_edge("process:shell", "file:passwd", EdgeType.READ)
    analyzer.add_edge("process:shell", "host:dbserver", EdgeType.CONNECT)
    analyzer.add_edge("host:dbserver", "file:config", EdgeType.MODIFY)

    print(f"  Nodes: {analyzer.graph.number_of_nodes()}")
    print(f"  Edges: {analyzer.graph.number_of_edges()}")

    # Find attack paths
    print("\nFinding attack paths...")
    paths = analyzer.find_attack_paths(min_risk_score=0.3)

    for i, path in enumerate(paths[:5]):
        print(f"\n  Path {i + 1} (Risk: {path.risk_score:.2f}):")
        print(f"    Entry: {path.entry_point}")
        print(f"    Target: {path.target}")
        print(f"    Description: {path.description}")

    # Backward trace
    print("\nBackward trace from file:passwd...")
    entry_points = analyzer.backward_trace("file:passwd")
    print(f"  Entry points: {entry_points}")

    # Get neighborhood
    print("\nNeighborhood of process:shell (radius=1):")
    subgraph = analyzer.get_neighborhood("process:shell", radius=1)
    print(f"  Nodes: {list(subgraph.nodes())}")


if __name__ == "__main__":
    main()
