"""Dependency security graph (structure, reachability and blast-radius metrics).

See :mod:`app.graph.engine` for the graph model, metric definitions and the security rationale.
"""

from app.graph.engine import (
    EDGE_DEPENDS_ON,
    EDGE_VULNERABLE_TO,
    NODE_PACKAGE,
    NODE_PROJECT,
    NODE_VULNERABILITY,
    GraphAnalysis,
    build_graph,
    severity_band,
    subgraph,
)

__all__ = [
    "EDGE_DEPENDS_ON",
    "EDGE_VULNERABLE_TO",
    "NODE_PACKAGE",
    "NODE_PROJECT",
    "NODE_VULNERABILITY",
    "GraphAnalysis",
    "build_graph",
    "severity_band",
    "subgraph",
]
