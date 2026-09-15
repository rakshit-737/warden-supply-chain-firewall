"""Dependency security graph: structure, reachability and blast-radius metrics for a project.

The engine turns a :class:`~app.sbom.models.ProjectInventory` (plus optional per-component risk
scores, policy decisions, vulnerabilities and findings) into a directed graph and computes
metrics for the questions a reviewer asks about a risky dependency: how deep it sits, what
pulls it in, how much of the project a compromise of it could reach, and whether a whole
sub-tree enters the project only through it.

Graph model
-----------
* one ``project`` node (the inventory ``root_ref``), one ``package`` node per component and, when
  ``vulns_by_ref`` is supplied, one ``vulnerability`` node per distinct advisory id
  (node id ``"vuln:<advisory id>"`` so it cannot collide with a purl-style ``bom_ref``);
* ``depends_on`` edges ``parent -> child`` from the inventory, plus an implicit
  ``project -> component`` edge for every component marked ``direct`` that has no explicit root
  edge (a direct dependency is, by definition, depended on by the project);
* ``vulnerable_to`` edges ``package -> vulnerability``.

Structural metrics (depth, dominators, betweenness, reachability) are computed on the dependency
graph (project + packages); vulnerability nodes never change a package's metrics.

Metric definitions (over the *emitted*, possibly truncated, graph)
------------------------------------------------------------------
Let ``P`` be the set of package nodes and ``D`` the project's direct dependencies.

* ``depth`` — shortest path length from the project root; ``None`` when unreachable.
* ``direct`` — the project root has an edge to the package (explicit, or implied by
  ``Component.direct``).
* ``dependents`` — number of package parents (the project root is reported through ``direct``).
* ``transitive_dependents`` / ``transitive_dependencies`` — package ancestors / descendants.
* ``blast_radius`` — ``transitive_dependents / max(1, |P| - 1)`` in ``[0, 1]``: the fraction of the
  *other* packages that transitively depend on the node.
* ``direct_exposure`` — fraction of ``D`` whose closure (the direct dependency itself plus its
  descendants) contains the node; ``0.0`` when the project has no direct dependencies.
* ``dominated`` — number of root-reachable packages every root path to which passes through the
  node (dominator-tree sub-tree size minus the node itself, from
  :func:`networkx.immediate_dominators`, which is correct on cyclic graphs). Unreachable packages
  are never counted and have ``dominated == 0``. ``is_single_point`` is ``dominated >= 2``.
* ``betweenness`` — normalised shortest-path betweenness on the dependency graph; exact up to
  :data:`EXACT_BETWEENNESS_MAX_NODES` nodes, above that an estimate from
  :data:`BETWEENNESS_SAMPLE_SIZE` source nodes drawn with the fixed :data:`BETWEENNESS_SEED`, so
  identical inputs always give identical values.
* ``subtree_max_risk`` — maximum risk over the node and its descendants (``None`` if none known).

For a vulnerability node the same keys keep their meaning in the combined graph: its
``dependents`` are the affected packages, ``transitive_dependents`` are the affected packages plus
their ancestors, ``blast_radius`` divides that by ``max(1, |P|)``, ``direct_exposure`` is the
fraction of direct dependencies whose closure contains an affected package, and ``depth`` is one
more than the shallowest reachable affected package. Keys without meaning for a node type (e.g.
``dominated`` for the project or a vulnerability) are ``None``.

These are structural signals for prioritisation. They do not show that vulnerable code is
reachable at runtime, and the graph is only as complete as the inventory (an inventory without
resolved transitive edges yields a shallow graph).

Security and robustness rationale
---------------------------------
Manifests and lock files are attacker-influenced (a pull request can edit them), so the
inventory is handled as hostile input:

* **Bounded work and output** — at most ``max_nodes`` nodes are emitted (the project root, then
  direct dependencies, then breadth-first order, then unreachable components; vulnerability nodes
  use any remaining budget). Ancestor/descendant sets are propagated once per strongly connected
  component as integer bitsets rather than one traversal per node, and betweenness is sampled on
  large graphs, so graphs at the ``MAX_GRAPH_NODES`` limit stay tractable.
* **Malformed data never raises** — edges naming unknown components, self-dependencies, edges into
  the project root, duplicate components, invalid vulnerability entries and non-numeric risk
  values are skipped (or merged) and reported in a bounded ``warnings`` list.
* **No secret or control-character leakage** — the graph is persisted, returned by the API and
  rendered, so identifiers and free text pass through :func:`app.core.redaction.sanitize_text`
  (control/bidi characters escaped, high-confidence secret patterns redacted, lengths bounded).
  Ordinary purl ``bom_ref`` values are unchanged by this.
* **Deterministic** — nodes are inserted and emitted in sorted order, BFS visits children in
  sorted order, duplicate-edge specifiers are merged as a sorted set, and sampling uses a fixed
  seed.
* **No network, no package code** — pure computation over in-memory data.
"""

from __future__ import annotations

import copy
import math
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from app.core.config import settings
from app.core.redaction import sanitize_text
from app.sbom.models import ProjectInventory

NODE_PROJECT = "project"
NODE_PACKAGE = "package"
NODE_VULNERABILITY = "vulnerability"
EDGE_DEPENDS_ON = "depends_on"
EDGE_VULNERABLE_TO = "vulnerable_to"

#: Non-direct packages with risk at or above this value are listed in ``high_risk_transitive``.
HIGH_RISK_THRESHOLD = 60
#: Length of the ranked lists in the metrics (single points, most depended upon).
TOP_N = 10
#: Betweenness is exact up to this many dependency nodes (project + packages).
EXACT_BETWEENNESS_MAX_NODES = 500
#: Number of source nodes sampled for betweenness above the exact threshold.
BETWEENNESS_SAMPLE_SIZE = 256
#: Fixed seed so sampled betweenness is reproducible for identical inputs.
BETWEENNESS_SEED = 7919
VULNERABILITY_ID_PREFIX = "vuln:"
#: Upper bound on the hop radius :func:`subgraph` explores.
MAX_SUBGRAPH_DEPTH = 10

_MAX_WARNINGS = 50
_MAX_REF_LEN = 512
_MAX_NAME_LEN = 214
_MAX_VERSION_LEN = 64
_MAX_SPECIFIER_LEN = 200
_MAX_VULN_ID_LEN = 128
_MAX_DECISION_LEN = 32
_MAX_INTRODUCED_VIA = 10
_DIGITS = 6

_TYPE_RANK = {NODE_PROJECT: 0, NODE_PACKAGE: 1, NODE_VULNERABILITY: 2}
_VULN_SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_DIRECTIONS = ("both", "dependencies", "dependents")


# ---------------------------------------------------------------------------------------------- result


@dataclass
class GraphAnalysis:
    """The emitted graph: sorted node and edge dicts plus graph-level metrics."""

    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    metrics: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    _index: dict[str, dict[str, Any]] = field(default_factory=dict, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._index = {n["id"]: n for n in self.nodes}

    def node(self, node_id: str) -> dict[str, Any] | None:
        return self._index.get(node_id)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe ``{nodes, edges, metrics}`` (a deep copy; mutating it never alters this object)."""
        return copy.deepcopy({"nodes": self.nodes, "edges": self.edges, "metrics": self.metrics})


# ---------------------------------------------------------------------------------------------- helpers


def severity_band(score: float | None) -> str | None:
    """Warden severity band for a 0-100 risk score (the risk engine's thresholds)."""
    if score is None:
        return None
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def _cvss_severity(score: float | None) -> str:
    """CVSS v3 qualitative rating; ``unknown`` when no positive score is available."""
    if score is None or score <= 0:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class _Warnings:
    """Bounded warning collector: hostile input cannot grow the output without limit."""

    def __init__(self, limit: int = _MAX_WARNINGS) -> None:
        self._limit = limit
        self._items: list[str] = []
        self._suppressed = 0

    def add(self, message: str) -> None:
        if len(self._items) < self._limit:
            self._items.append(sanitize_text(message, max_len=400))
        else:
            self._suppressed += 1

    def result(self) -> list[str]:
        out = list(self._items)
        if self._suppressed:
            out.append(f"{self._suppressed} further warning(s) suppressed")
        return out


def _clean_ref(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return sanitize_text(value, max_len=_MAX_REF_LEN)


def _clean_text(value: object, max_len: int) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return sanitize_text(value.strip(), max_len=max_len)


def _describe(value: object) -> str:
    if isinstance(value, str):
        return repr(sanitize_text(value, max_len=120))
    return f"<{type(value).__name__}>"


def _coerce_risk(value: object) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    number = min(100.0, max(0.0, number))
    return int(number) if number.is_integer() else round(number, 2)


def _coerce_cvss(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return round(min(10.0, max(0.0, number)), 1)


def _count(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, (list, tuple, set, frozenset)):
        return len(value)
    return 0


def _lookup(mapping: Mapping[str, Any] | None, refs: Iterable[str]) -> Any:
    if not mapping:
        return None
    for ref in refs:
        if ref in mapping:
            return mapping[ref]
    return None


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(min(1.0, max(0.0, numerator / denominator)), _DIGITS)


def _merged_specifier(values: Iterable[str]) -> str | None:
    joined = ",".join(sorted(values))
    return sanitize_text(joined, max_len=_MAX_SPECIFIER_LEN) if joined else None


def _validate_max_nodes(max_nodes: int | None) -> int:
    limit = settings.MAX_GRAPH_NODES if max_nodes is None else max_nodes
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("max_nodes must be a positive integer")
    return limit


# ---------------------------------------------------------------------------------------------- ingestion


@dataclass
class _Component:
    id: str
    refs: list[str]  # raw references that resolve to this node (keys for the *_by_ref maps)
    name: str
    version: str | None
    direct: bool
    specifier: str | None


@dataclass
class _Vulnerability:
    advisory_id: str
    node_id: str
    severities: set[str] = field(default_factory=set)
    cvss_score: float | None = None
    kev: bool = False
    affected: set[str] = field(default_factory=set)

    def merge(self, entry: Mapping[str, Any]) -> None:
        severity = entry.get("severity")
        if isinstance(severity, str) and severity.strip().lower() in _VULN_SEVERITY_RANK:
            self.severities.add(severity.strip().lower())
        cvss = _coerce_cvss(entry.get("cvss_score"))
        if cvss is not None and (self.cvss_score is None or cvss > self.cvss_score):
            self.cvss_score = cvss
        self.kev = self.kev or entry.get("kev") is True

    @property
    def severity(self) -> str:
        """Worst explicitly reported severity, else the CVSS rating, else ``unknown``."""
        known = [s for s in self.severities if s != "unknown"]
        if known:
            return max(known, key=_VULN_SEVERITY_RANK.__getitem__)
        return _cvss_severity(self.cvss_score)


def _ingest_components(
    inventory: ProjectInventory, root_raw: object, root_id: str, warnings: _Warnings
) -> tuple[dict[str, _Component], dict[str, str]]:
    components: dict[str, _Component] = {}
    ref_map: dict[str, str] = {}
    for comp in getattr(inventory, "components", None) or ():
        raw = getattr(comp, "bom_ref", None)
        node_id = _clean_ref(raw)
        if node_id is None:
            warnings.add(f"component with invalid bom_ref {_describe(raw)} ignored")
            continue
        if raw == root_raw or node_id == root_id:
            warnings.add(f"component {node_id!r} reuses the project root reference; ignored")
            continue
        direct = getattr(comp, "direct", False) is True
        existing = components.get(node_id)
        if existing is not None:
            warnings.add(f"duplicate component {node_id!r} merged")
            existing.direct = existing.direct or direct
            if raw not in ref_map:
                existing.refs.append(raw)
                ref_map[raw] = node_id
            continue
        components[node_id] = _Component(
            id=node_id,
            refs=[raw],
            name=_clean_text(getattr(comp, "name", None), _MAX_NAME_LEN) or node_id,
            version=_clean_text(getattr(comp, "version", None), _MAX_VERSION_LEN),
            direct=direct,
            specifier=_clean_text(getattr(comp, "specifier", None), _MAX_SPECIFIER_LEN),
        )
        ref_map[raw] = node_id
    return components, ref_map


def _ingest_edges(
    inventory: ProjectInventory,
    root_raw: object,
    root_id: str,
    ref_map: Mapping[str, str],
    warnings: _Warnings,
) -> dict[tuple[str, str], set[str]]:
    def resolve(raw: object) -> str | None:
        if not isinstance(raw, str):
            return None
        if raw == root_raw:
            return root_id
        return ref_map.get(raw)

    specs: dict[tuple[str, str], set[str]] = {}
    for edge in getattr(inventory, "edges", None) or ():
        parent_raw, child_raw = getattr(edge, "parent", None), getattr(edge, "child", None)
        parent, child = resolve(parent_raw), resolve(child_raw)
        label = f"{_describe(parent_raw)} -> {_describe(child_raw)}"
        if parent is None or child is None:
            unknown = " and ".join(name for name, ref in (("parent", parent), ("child", child)) if ref is None)
            warnings.add(f"dependency edge {label} ignored: unknown {unknown}")
            continue
        if child == root_id:
            warnings.add(f"dependency edge {label} ignored: edges into the project root are not allowed")
            continue
        if parent == child:
            warnings.add(f"dependency edge {label} ignored: self-dependency")
            continue
        bucket = specs.setdefault((parent, child), set())
        specifier = _clean_text(getattr(edge, "specifier", None), _MAX_SPECIFIER_LEN)
        if specifier:
            bucket.add(specifier)
    return specs


def _add_implicit_direct_edges(
    root_id: str, components: Mapping[str, _Component], specs: dict[tuple[str, str], set[str]]
) -> None:
    for node_id in sorted(components):
        comp = components[node_id]
        if comp.direct and (root_id, node_id) not in specs:
            specs[(root_id, node_id)] = {comp.specifier} if comp.specifier else set()


def _priority_order(root_id: str, components: Mapping[str, _Component], specs: Iterable[tuple[str, str]]) -> list[str]:
    """Packages ordered for truncation: BFS from the root (children sorted), then unreachable (sorted)."""
    children: dict[str, list[str]] = defaultdict(list)
    for parent, child in specs:
        children[parent].append(child)
    for kids in children.values():
        kids.sort()
    seen = {root_id}
    order: list[str] = []
    queue = deque([root_id])
    while queue:
        current = queue.popleft()
        for child in children.get(current, ()):
            if child not in seen:
                seen.add(child)
                order.append(child)
                queue.append(child)
    order.extend(sorted(set(components) - seen))
    return order


def _package_vulnerability_entries(
    package: _Component, vulns_by_ref: Mapping[str, Any], warnings: _Warnings
) -> dict[str, list[Mapping[str, Any]]]:
    entries: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for ref in package.refs:
        raw_entries = vulns_by_ref.get(ref)
        if raw_entries is None:
            continue
        if isinstance(raw_entries, (str, bytes, Mapping)) or not isinstance(raw_entries, Iterable):
            warnings.add(f"vulnerabilities for {package.id!r} ignored: expected a list of objects")
            continue
        for entry in raw_entries:
            advisory = _clean_text(entry.get("id"), _MAX_VULN_ID_LEN) if isinstance(entry, Mapping) else None
            if advisory is None:
                warnings.add(f"vulnerability entry for {package.id!r} without a valid id ignored")
                continue
            entries[advisory].append(entry)
    return entries


def _ingest_vulnerabilities(
    vulns_by_ref: Mapping[str, Any] | None,
    priority: list[str],
    components: Mapping[str, _Component],
    ref_map: Mapping[str, str],
    root_id: str,
    warnings: _Warnings,
) -> tuple[dict[str, list[str]], list[_Vulnerability]]:
    """Advisory ids per package, and merged vulnerability records in first-seen priority order."""
    ids_by_package: dict[str, list[str]] = {}
    records: dict[str, _Vulnerability] = {}
    if not vulns_by_ref:
        return ids_by_package, []
    for key in vulns_by_ref:
        if not isinstance(key, str) or key not in ref_map:
            warnings.add(f"vulnerabilities for unknown component {_describe(key)} ignored")
    for package_id in priority:
        entries = _package_vulnerability_entries(components[package_id], vulns_by_ref, warnings)
        if not entries:
            continue
        ids_by_package[package_id] = sorted(entries)
        for advisory in sorted(entries):
            record = records.get(advisory)
            if record is None:
                record = records[advisory] = _Vulnerability(advisory, VULNERABILITY_ID_PREFIX + advisory)
            for entry in entries[advisory]:
                record.merge(entry)
            record.affected.add(package_id)
    emitted: list[_Vulnerability] = []
    for record in records.values():
        if record.node_id in components or record.node_id == root_id:
            warnings.add(f"vulnerability node {record.node_id!r} collides with a component reference; node omitted")
        else:
            emitted.append(record)
    return ids_by_package, emitted


# ---------------------------------------------------------------------------------------------- analysis


class _Reachability:
    """Ancestor / descendant sets for every dependency node, as integer bitsets.

    Strongly connected components are condensed into a DAG and closures are propagated once in
    topological order, instead of one graph traversal per node. A member of a cyclic component
    reaches, and is reached by, every other member of that component.
    """

    def __init__(self, graph: nx.DiGraph) -> None:
        self.order: list[str] = list(graph.nodes)
        self.bit = {node: 1 << i for i, node in enumerate(self.order)}
        condensed = nx.condensation(graph)
        self.component_of: dict[str, int] = condensed.graph["mapping"]
        self.members: dict[int, set[str]] = {c: data["members"] for c, data in condensed.nodes(data=True)}
        self.member_bits: dict[int, int] = {}
        for comp, members in self.members.items():
            bits = 0
            for member in members:
                bits |= self.bit[member]
            self.member_bits[comp] = bits
        self.cyclic = {comp for comp, members in self.members.items() if len(members) > 1}
        self.topological = list(nx.topological_sort(condensed))
        self.successors = {comp: list(condensed.successors(comp)) for comp in condensed}
        self._descendants: dict[int, int] = {}
        for comp in reversed(self.topological):
            bits = 0
            for succ in self.successors[comp]:
                bits |= self.member_bits[succ] | self._descendants[succ]
            self._descendants[comp] = bits
        self._ancestors: dict[int, int] = {}
        for comp in self.topological:
            bits = 0
            for pred in condensed.predecessors(comp):
                bits |= self.member_bits[pred] | self._ancestors[pred]
            self._ancestors[comp] = bits

    def _cycle_bits(self, comp: int) -> int:
        return self.member_bits[comp] if comp in self.cyclic else 0

    def descendants(self, node: str) -> int:
        comp = self.component_of[node]
        return (self._descendants[comp] | self._cycle_bits(comp)) & ~self.bit[node]

    def ancestors(self, node: str) -> int:
        comp = self.component_of[node]
        return (self._ancestors[comp] | self._cycle_bits(comp)) & ~self.bit[node]

    def subtree_max(self, values: Mapping[str, int | float | None]) -> dict[str, int | float | None]:
        """Max of ``values`` over each node and its descendants (``None`` when nothing is known)."""
        per_comp: dict[int, int | float | None] = {}
        for comp in reversed(self.topological):
            known = [values[m] for m in self.members[comp] if values.get(m) is not None]
            known.extend(per_comp[s] for s in self.successors[comp] if per_comp[s] is not None)
            per_comp[comp] = max(known) if known else None
        return {node: per_comp[self.component_of[node]] for node in self.order}


def _dominated_counts(graph: nx.DiGraph, root_id: str, reachable: Iterable[str]) -> dict[str, int]:
    """Dominator-tree sub-tree sizes (excluding the node itself) for root-reachable packages."""
    reach_graph = graph.subgraph(reachable).copy()
    idom = nx.immediate_dominators(reach_graph, root_id)
    idom.pop(root_id, None)  # networkx releases before 3.5 map start -> start
    children: dict[str, list[str]] = defaultdict(list)
    for node, parent in idom.items():
        children[parent].append(node)
    order = [root_id]
    index = 0
    while index < len(order):
        order.extend(children.get(order[index], ()))
        index += 1
    size: dict[str, int] = {}
    for node in reversed(order):
        size[node] = 1 + sum(size[child] for child in children.get(node, ()))
    return {node: size[node] - 1 for node in order if node != root_id}


def _betweenness(graph: nx.DiGraph) -> tuple[dict[str, float], str, int | None]:
    count = graph.number_of_nodes()
    if count <= EXACT_BETWEENNESS_MAX_NODES:
        return nx.betweenness_centrality(graph, normalized=True), "exact", None
    sample = min(count, BETWEENNESS_SAMPLE_SIZE)
    values = nx.betweenness_centrality(graph, k=sample, normalized=True, seed=BETWEENNESS_SEED)
    return values, "sampled", sample


def _node_sort_key(node: Mapping[str, Any]) -> tuple[int, str]:
    return _TYPE_RANK.get(str(node.get("type")), len(_TYPE_RANK)), str(node.get("id"))


def _edge_sort_key(edge: Mapping[str, Any]) -> tuple[str, str, str]:
    return str(edge.get("source")), str(edge.get("target")), str(edge.get("type"))


def _base_node(node_id: str, node_type: str, name: str, version: str | None) -> dict[str, Any]:
    return {
        "id": node_id,
        "type": node_type,
        "name": name,
        "version": version,
        "direct": False,
        "depth": None,
        "risk": None,
        "severity": None,
        "decision": None,
        "dependents": 0,
        "transitive_dependents": 0,
        "transitive_dependencies": 0,
        "blast_radius": None,
        "direct_exposure": None,
        "dominated": None,
        "is_single_point": False,
        "betweenness": None,
        "vulnerability_ids": [],
        "findings_count": None,
        "subtree_max_risk": None,
    }


@dataclass
class _Context:
    """Everything the node builders need, computed once per graph."""

    graph: nx.DiGraph
    root_id: str
    reach: _Reachability
    depth: dict[str, int]
    risk: dict[str, int | float | None]
    subtree_max: dict[str, int | float | None]
    betweenness: dict[str, float]
    direct_ids: list[str]
    direct_bits: int
    package_count: int

    def closure_bits(self, node_id: str) -> int:
        """The node plus its package ancestors: everything whose closure contains the node."""
        return (self.reach.ancestors(node_id) | self.reach.bit[node_id]) & ~self.reach.bit[self.root_id]

    def annotate(
        self, node: dict[str, Any], refs: list[str], decisions: Mapping | None, findings: Mapping | None
    ) -> None:
        node_id = node["id"]
        score = self.risk.get(node_id)
        node.update(
            depth=self.depth.get(node_id),
            risk=score,
            severity=severity_band(score),
            decision=_clean_text(_lookup(decisions, refs), _MAX_DECISION_LEN),
            betweenness=round(min(1.0, max(0.0, self.betweenness.get(node_id, 0.0))), _DIGITS),
            findings_count=_count(_lookup(findings, refs)),
            subtree_max_risk=self.subtree_max.get(node_id),
        )


def _package_node(ctx: _Context, comp: _Component, dominated: int, vulnerability_ids: list[str]) -> dict[str, Any]:
    node = _base_node(comp.id, NODE_PACKAGE, comp.name, comp.version)
    dependents_total = (ctx.reach.ancestors(comp.id) & ~ctx.reach.bit[ctx.root_id]).bit_count()
    node.update(
        direct=ctx.graph.has_edge(ctx.root_id, comp.id),
        dependents=sum(1 for parent in ctx.graph.predecessors(comp.id) if parent != ctx.root_id),
        transitive_dependents=dependents_total,
        transitive_dependencies=ctx.reach.descendants(comp.id).bit_count(),
        blast_radius=_ratio(dependents_total, max(1, ctx.package_count - 1)),
        direct_exposure=_ratio((ctx.closure_bits(comp.id) & ctx.direct_bits).bit_count(), len(ctx.direct_ids)),
        dominated=dominated,
        is_single_point=dominated >= 2,
        vulnerability_ids=list(vulnerability_ids),
    )
    return node


def _vulnerability_node(ctx: _Context, record: _Vulnerability, affected: list[str]) -> dict[str, Any]:
    node = _base_node(record.node_id, NODE_VULNERABILITY, record.advisory_id, None)
    exposed = 0
    for package_id in affected:
        exposed |= ctx.closure_bits(package_id)
    reachable_depths = [ctx.depth[p] for p in affected if p in ctx.depth]
    node.update(
        depth=min(reachable_depths) + 1 if reachable_depths else None,
        severity=record.severity,
        dependents=len(affected),
        transitive_dependents=exposed.bit_count(),
        blast_radius=_ratio(exposed.bit_count(), max(1, ctx.package_count)),
        direct_exposure=_ratio((exposed & ctx.direct_bits).bit_count(), len(ctx.direct_ids)),
        vulnerability_ids=[record.advisory_id],
        cvss_score=record.cvss_score,
        kev=record.kev,
    )
    return node


def _summary(node: Mapping[str, Any], *keys: str) -> dict[str, Any]:
    return {key: copy.deepcopy(node[key]) for key in ("id", "name", "version", *keys)}


def _metrics(
    ctx: _Context,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    packages: list[dict[str, Any]],
) -> dict[str, Any]:
    depths = [n["depth"] for n in packages if n["depth"] is not None]
    single_points = sorted((n for n in packages if n["is_single_point"]), key=lambda n: (-n["dominated"], n["id"]))
    depended = sorted((n for n in packages if n["transitive_dependents"] > 0),
                      key=lambda n: (-n["transitive_dependents"], n["id"]))
    high_risk = sorted(
        (n for n in packages if not n["direct"] and n["risk"] is not None and n["risk"] >= HIGH_RISK_THRESHOLD),
        key=lambda n: (-n["risk"], n["id"]),
    )
    high_risk_items = []
    for node in high_risk:
        closure = ctx.closure_bits(node["id"])
        via = [d for d in ctx.direct_ids if closure & ctx.reach.bit[d]][:_MAX_INTRODUCED_VIA]
        high_risk_items.append({**_summary(node, "risk", "severity", "depth", "decision"), "introduced_via": via})
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "package_count": len(packages),
        "vulnerability_count": sum(1 for n in nodes if n["type"] == NODE_VULNERABILITY),
        "dependency_edge_count": ctx.graph.number_of_edges(),
        "max_depth": max(depths, default=0),
        "direct_count": len(ctx.direct_ids),
        # Partition of packages: direct (depth 1) + transitive (reachable, depth >= 2) + unreachable.
        "transitive_count": sum(1 for d in depths if d >= 2),
        "unreachable_count": len(packages) - len(depths),
        "has_cycles": bool(ctx.reach.cyclic),
        "cyclic_group_count": len(ctx.reach.cyclic),
        "single_points": [_summary(n, "dominated", "blast_radius", "risk") for n in single_points[:TOP_N]],
        "high_risk_transitive": high_risk_items,
        "most_depended_upon": [
            _summary(n, "transitive_dependents", "dependents", "blast_radius") for n in depended[:TOP_N]
        ],
    }


def _truncation_note(limit: int, emitted: int, dropped_packages: int, dropped_vulns: int) -> str:
    return (
        f"Graph truncated to {emitted} node(s) (max_nodes={limit}): kept the project root, its direct dependencies, "
        f"then dependencies in breadth-first order and finally unreachable components; omitted {dropped_packages} "
        f"package node(s) and {dropped_vulns} vulnerability node(s). Metrics describe the retained graph only; "
        "retained packages still list all of their vulnerability ids."
    )


def build_graph(
    inventory: ProjectInventory,
    *,
    risk_by_ref: Mapping[str, Any] | None = None,
    decision_by_ref: Mapping[str, Any] | None = None,
    vulns_by_ref: Mapping[str, Any] | None = None,
    findings_by_ref: Mapping[str, Any] | None = None,
    max_nodes: int | None = None,
) -> GraphAnalysis:
    """Build the dependency security graph for ``inventory``.

    ``risk_by_ref`` maps bom_ref -> 0-100 risk score, ``decision_by_ref`` -> policy decision string,
    ``vulns_by_ref`` -> list of vulnerability dicts (``id`` required; ``severity``, ``cvss_score`` and
    ``kev`` optional) and ``findings_by_ref`` -> list of findings (only the count is used). The
    project ``root_ref`` may also be a key of the risk/decision/findings maps. ``max_nodes``
    defaults to ``settings.MAX_GRAPH_NODES``; a non-positive value raises ``ValueError``. Malformed
    inventory data is skipped and reported in ``warnings`` rather than raised.
    """
    limit = _validate_max_nodes(max_nodes)
    warnings = _Warnings()
    root_raw = getattr(inventory, "root_ref", None)
    root_id = _clean_ref(root_raw)
    if root_id is None:
        warnings.add("inventory root_ref is missing or invalid; using 'project'")
        root_id = "project"
    root_refs = [root_raw] if isinstance(root_raw, str) else []

    components, ref_map = _ingest_components(inventory, root_raw, root_id, warnings)
    specs = _ingest_edges(inventory, root_raw, root_id, ref_map, warnings)
    _add_implicit_direct_edges(root_id, components, specs)
    priority = _priority_order(root_id, components, specs)
    kept = set(priority[: limit - 1])

    graph = nx.DiGraph()
    graph.add_node(root_id)
    graph.add_nodes_from(sorted(kept))
    graph.add_edges_from(sorted(pair for pair in specs if pair[0] in graph and pair[1] in graph))

    ids_by_package, vulnerabilities = _ingest_vulnerabilities(
        vulns_by_ref, priority, components, ref_map, root_id, warnings
    )
    candidates = [record for record in vulnerabilities if record.affected & kept]
    emitted_vulns = candidates[: max(0, limit - graph.number_of_nodes())]

    reach = _Reachability(graph)
    risk = {root_id: _coerce_risk(_lookup(risk_by_ref, root_refs))}
    risk.update({pid: _coerce_risk(_lookup(risk_by_ref, components[pid].refs)) for pid in kept})
    direct_ids = sorted(graph.successors(root_id))
    direct_bits = 0
    for node_id in direct_ids:
        direct_bits |= reach.bit[node_id]
    depth = nx.single_source_shortest_path_length(graph, root_id)
    betweenness, betweenness_method, sample_size = _betweenness(graph)
    ctx = _Context(
        graph=graph, root_id=root_id, reach=reach, depth=depth, risk=risk, subtree_max=reach.subtree_max(risk),
        betweenness=betweenness, direct_ids=direct_ids, direct_bits=direct_bits, package_count=len(kept),
    )
    dominated = _dominated_counts(graph, root_id, depth)

    project_name = _clean_text(getattr(inventory, "project_name", None), _MAX_NAME_LEN) or root_id
    root_node = _base_node(root_id, NODE_PROJECT, project_name, None)
    ctx.annotate(root_node, root_refs, decision_by_ref, findings_by_ref)
    root_node["transitive_dependencies"] = reach.descendants(root_id).bit_count()

    packages = []
    for package_id in sorted(kept):
        comp = components[package_id]
        node = _package_node(ctx, comp, dominated.get(package_id, 0), ids_by_package.get(package_id, []))
        ctx.annotate(node, comp.refs, decision_by_ref, findings_by_ref)
        packages.append(node)

    edges = [
        {"source": src, "target": dst, "type": EDGE_DEPENDS_ON, "specifier": _merged_specifier(specs[(src, dst)])}
        for src, dst in graph.edges
    ]
    vulnerability_nodes = []
    for record in emitted_vulns:
        affected = sorted(record.affected & kept)
        vulnerability_nodes.append(_vulnerability_node(ctx, record, affected))
        edges.extend(
            {"source": pid, "target": record.node_id, "type": EDGE_VULNERABLE_TO, "specifier": None} for pid in affected
        )

    nodes = sorted([root_node, *packages, *vulnerability_nodes], key=_node_sort_key)
    edges.sort(key=_edge_sort_key)
    warning_list = warnings.result()
    dropped_packages = len(components) - len(kept)
    dropped_vulns = len(vulnerabilities) - len(emitted_vulns)
    truncated = dropped_packages > 0 or dropped_vulns > 0
    metrics = _metrics(ctx, nodes, edges, packages)
    metrics.update(
        betweenness_method=betweenness_method,
        betweenness_sample_size=sample_size,
        truncated=truncated,
        truncation_note=_truncation_note(limit, len(nodes), dropped_packages, dropped_vulns) if truncated else None,
        warnings=list(warning_list),
    )
    return GraphAnalysis(nodes=nodes, edges=edges, metrics=metrics, warnings=warning_list)


# ---------------------------------------------------------------------------------------------- drill-down


def subgraph(
    graph: Mapping[str, Any] | GraphAnalysis,
    node_id: str,
    depth: int = 2,
    *,
    direction: str = "both",
) -> dict[str, Any]:
    """Neighbourhood of ``node_id`` within ``depth`` hops, for UI drill-down.

    ``graph`` is a :class:`GraphAnalysis` or its ``to_dict()`` output (for example as loaded from
    the database). ``direction`` is ``both`` (default), ``dependencies`` (follow outgoing edges:
    what the node depends on and its vulnerabilities) or ``dependents`` (incoming edges). The
    radius is capped at :data:`MAX_SUBGRAPH_DEPTH`. Each returned node is a copy carrying an extra
    ``distance`` (hops from the centre). Malformed node/edge entries are skipped. Raises
    ``KeyError`` when the node is not in the graph and ``ValueError`` for an invalid depth or
    direction.
    """
    if isinstance(graph, GraphAnalysis):
        raw_nodes, raw_edges = graph.nodes, graph.edges
    elif isinstance(graph, Mapping):
        raw_nodes, raw_edges = graph.get("nodes"), graph.get("edges")
    else:
        raise TypeError("graph must be a GraphAnalysis or a mapping with 'nodes' and 'edges'")
    if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
        raise ValueError("depth must be a non-negative integer")
    if direction not in _DIRECTIONS:
        raise ValueError(f"direction must be one of {', '.join(_DIRECTIONS)}")
    radius = min(depth, MAX_SUBGRAPH_DEPTH)

    by_id: dict[str, Mapping[str, Any]] = {}
    for node in raw_nodes if isinstance(raw_nodes, list) else ():
        if isinstance(node, Mapping) and isinstance(node.get("id"), str):
            by_id.setdefault(node["id"], node)
    if node_id not in by_id:
        raise KeyError(node_id)
    edges = [
        e for e in (raw_edges if isinstance(raw_edges, list) else ())
        if isinstance(e, Mapping) and e.get("source") in by_id and e.get("target") in by_id
    ]
    neighbours: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        if direction in ("both", "dependencies"):
            neighbours[edge["source"]].add(edge["target"])
        if direction in ("both", "dependents"):
            neighbours[edge["target"]].add(edge["source"])

    distance = {node_id: 0}
    frontier = [node_id]
    for hop in range(1, radius + 1):
        next_frontier = []
        for current in frontier:
            for neighbour in sorted(neighbours.get(current, ())):
                if neighbour not in distance:
                    distance[neighbour] = hop
                    next_frontier.append(neighbour)
        if not next_frontier:
            break
        frontier = next_frontier

    nodes_out = [{**copy.deepcopy(dict(by_id[nid])), "distance": hops} for nid, hops in distance.items()]
    edges_out = [copy.deepcopy(dict(e)) for e in edges if e["source"] in distance and e["target"] in distance]
    return {
        "center": node_id,
        "depth": radius,
        "direction": direction,
        "nodes": sorted(nodes_out, key=_node_sort_key),
        "edges": sorted(edges_out, key=_edge_sort_key),
    }
