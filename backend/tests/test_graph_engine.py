"""Dependency graph engine tests.

Inventories are built directly from ``app.sbom.models`` dataclasses (no manifest parsers), and
expected metrics are computed by hand for small graphs (diamond, chain, star, cycle, unreachable
components). Hypothesis property tests then check invariants and compare every per-node metric
against brute-force oracles written independently with plain networkx traversals.
"""

from __future__ import annotations

import json
import random

import networkx as nx
import pytest
from hypothesis import HealthCheck, given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st

from app.graph import engine
from app.graph.engine import GraphAnalysis, build_graph, severity_band, subgraph
from app.sbom.models import Component, DependencyEdge, ProjectInventory

ROOT = "project:demo"


def ref(name: str) -> str:
    return f"pkg:pypi/{name}@1.0"


def make_inventory(
    edges: list[tuple[str, str]] | list[tuple[str, str, str | None]],
    *,
    names: list[str] | None = None,
    direct: set[str] | None = None,
) -> ProjectInventory:
    """Short names in, inventory out. ``root`` is the project; root children are marked direct."""
    all_names = set(names or ())
    for edge in edges:
        all_names.update(edge[:2])
    all_names.discard("root")
    direct_names = set(direct or ()) | {e[1] for e in edges if e[0] == "root"}
    components = [
        Component(bom_ref=ref(n), name=n, normalized_name=n, version="1.0", purl=ref(n), direct=n in direct_names)
        for n in sorted(all_names)
    ]
    dep_edges = [
        DependencyEdge(
            parent=ROOT if e[0] == "root" else ref(e[0]), child=ref(e[1]), specifier=e[2] if len(e) > 2 else None
        )
        for e in edges
    ]
    return ProjectInventory(project_name="demo", root_ref=ROOT, components=components, edges=dep_edges)


def node(result: GraphAnalysis, name: str) -> dict:
    found = result.node(ROOT if name == "root" else ref(name))
    assert found is not None, name
    return found


def depends_on(result: GraphAnalysis) -> set[tuple[str, str]]:
    return {(e["source"], e["target"]) for e in result.edges if e["type"] == "depends_on"}


# Diamond with a tail: root -> a, root -> b, a -> c, b -> c, c -> d, c -> e
DIAMOND = [("root", "a"), ("root", "b"), ("a", "c"), ("b", "c"), ("c", "d"), ("c", "e")]


# ------------------------------------------------------------------------------------------ hand-computed


def test_diamond_metrics_hand_computed():
    result = build_graph(make_inventory(DIAMOND))
    expected = {
        # name: (depth, dependents, transitive_dependents, transitive_dependencies, blast, exposure, dominated)
        "a": (1, 0, 0, 3, 0.0, 0.5, 0),
        "b": (1, 0, 0, 3, 0.0, 0.5, 0),
        "c": (2, 2, 2, 2, 0.5, 1.0, 2),
        "d": (3, 1, 3, 0, 0.75, 1.0, 0),
        "e": (3, 1, 3, 0, 0.75, 1.0, 0),
    }
    for name, (depth, deps, tdeps, tdeps_down, blast, exposure, dominated) in expected.items():
        n = node(result, name)
        assert n["type"] == "package"
        assert n["depth"] == depth, name
        assert n["dependents"] == deps, name
        assert n["transitive_dependents"] == tdeps, name
        assert n["transitive_dependencies"] == tdeps_down, name
        assert n["blast_radius"] == pytest.approx(blast), name
        assert n["direct_exposure"] == pytest.approx(exposure), name
        assert n["dominated"] == dominated, name
        assert n["is_single_point"] is (dominated >= 2), name
    assert node(result, "a")["direct"] and node(result, "b")["direct"]
    assert not node(result, "c")["direct"]
    # Betweenness, normalised by (n-1)(n-2) = 20 with n = 6 (root included):
    # c lies on root->d, root->e, a->d, a->e, b->d, b->e (6); a and b each carry half of root->{c,d,e} (1.5).
    assert node(result, "c")["betweenness"] == pytest.approx(0.3)
    assert node(result, "a")["betweenness"] == pytest.approx(0.075)
    assert node(result, "b")["betweenness"] == pytest.approx(0.075)
    assert node(result, "d")["betweenness"] == 0.0

    root = node(result, "root")
    assert root["type"] == "project" and root["depth"] == 0 and root["transitive_dependencies"] == 5
    assert root["dominated"] is None and root["blast_radius"] is None

    m = result.metrics
    assert (m["node_count"], m["edge_count"], m["package_count"]) == (6, 6, 5)
    assert (m["max_depth"], m["direct_count"], m["transitive_count"], m["unreachable_count"]) == (3, 2, 3, 0)
    assert m["has_cycles"] is False
    assert [p["id"] for p in m["single_points"]] == [ref("c")]
    assert m["single_points"][0]["dominated"] == 2
    assert [p["id"] for p in m["most_depended_upon"]] == [ref("d"), ref("e"), ref("c")]
    assert m["betweenness_method"] == "exact"
    assert m["truncated"] is False and m["truncation_note"] is None


def test_chain_metrics_and_risk_propagation():
    inv = make_inventory([("root", "a"), ("a", "b"), ("b", "c"), ("c", "d")])
    risks = {ref("a"): 10, ref("b"): 70, ref("c"): 20}
    result = build_graph(inv, risk_by_ref=risks)
    for name, depth, dominated, tdeps, blast, between in [
        ("a", 1, 3, 0, 0.0, 0.25),
        ("b", 2, 2, 1, 1 / 3, 1 / 3),
        ("c", 3, 1, 2, 2 / 3, 0.25),
        ("d", 4, 0, 3, 1.0, 0.0),
    ]:
        n = node(result, name)
        assert n["depth"] == depth
        assert n["dominated"] == dominated
        assert n["transitive_dependents"] == tdeps
        assert n["blast_radius"] == pytest.approx(blast, abs=1e-6)
        assert n["direct_exposure"] == 1.0
        assert n["betweenness"] == pytest.approx(between, abs=1e-6)
    assert [node(result, x)["subtree_max_risk"] for x in "abcd"] == [70, 70, 20, None]
    assert node(result, "root")["subtree_max_risk"] == 70
    assert node(result, "b")["severity"] == "high" and node(result, "d")["severity"] is None
    assert [p["id"] for p in result.metrics["single_points"]] == [ref("a"), ref("b")]
    high = result.metrics["high_risk_transitive"]
    assert [h["id"] for h in high] == [ref("b")]
    assert high[0]["introduced_via"] == [ref("a")]


def test_star_fan_in_hub_is_most_depended_upon_but_not_a_single_point():
    inv = make_inventory([("root", x) for x in "abcd"] + [(x, "hub") for x in "abcd"])
    result = build_graph(inv)
    hub = node(result, "hub")
    assert (hub["dependents"], hub["transitive_dependents"], hub["depth"]) == (4, 4, 2)
    assert hub["blast_radius"] == 1.0 and hub["direct_exposure"] == 1.0
    assert hub["dominated"] == 0 and hub["is_single_point"] is False
    leaf = node(result, "a")
    assert leaf["blast_radius"] == 0.0 and leaf["direct_exposure"] == pytest.approx(0.25)
    # root->hub has four equal shortest paths; each spoke carries 1/4 of one pair: 0.25 / 20.
    assert leaf["betweenness"] == pytest.approx(0.0125)
    assert result.metrics["most_depended_upon"][0]["id"] == ref("hub")
    assert result.metrics["single_points"] == []


def test_star_fan_out_hub_dominates_its_leaves():
    inv = make_inventory([("root", "hub")] + [("hub", f"l{i}") for i in range(4)])
    result = build_graph(inv)
    hub = node(result, "hub")
    assert hub["dominated"] == 4 and hub["is_single_point"] is True
    assert hub["transitive_dependencies"] == 4
    assert hub["betweenness"] == pytest.approx(0.2)  # 4 pairs root->leaf / 20
    assert node(result, "l0")["blast_radius"] == pytest.approx(0.25)
    assert result.metrics["single_points"][0]["dominated"] == 4


def test_cycle_is_handled_and_detected():
    inv = make_inventory([("root", "a"), ("a", "b"), ("b", "c"), ("c", "a"), ("a", "a")])
    result = build_graph(inv, risk_by_ref={ref("a"): 10, ref("b"): 50, ref("c"): 90})
    m = result.metrics
    assert m["has_cycles"] is True and m["cyclic_group_count"] == 1
    assert [node(result, x)["depth"] for x in "abc"] == [1, 2, 3]
    assert [node(result, x)["dominated"] for x in "abc"] == [2, 1, 0]
    for x in "abc":
        n = node(result, x)
        assert n["transitive_dependents"] == 2 and n["transitive_dependencies"] == 2
        assert n["dependents"] == 1 and n["blast_radius"] == 1.0 and n["direct_exposure"] == 1.0
        assert n["subtree_max_risk"] == 90
    # n = 4 -> normaliser 6. a: root->b, root->c, c->b; b: root->c, a->c; c: b->a.
    assert [node(result, x)["betweenness"] for x in "abc"] == pytest.approx([0.5, 1 / 3, 1 / 6], abs=1e-6)
    assert (ref("a"), ref("a")) not in depends_on(result)
    assert any("self-dependency" in w for w in result.warnings)


def test_unreachable_components():
    inv = make_inventory([("root", "a"), ("b", "c")])
    result = build_graph(inv)
    m = result.metrics
    assert (m["direct_count"], m["transitive_count"], m["unreachable_count"], m["max_depth"]) == (1, 0, 2, 1)
    b, c = node(result, "b"), node(result, "c")
    assert b["depth"] is None and c["depth"] is None
    assert not b["direct"] and not c["direct"]
    assert c["transitive_dependents"] == 1 and c["blast_radius"] == pytest.approx(0.5)
    assert c["direct_exposure"] == 0.0 and b["dominated"] == 0 and c["dominated"] == 0
    assert node(result, "root")["transitive_dependencies"] == 1


def test_direct_component_without_root_edge_gets_implicit_edge():
    inv = make_inventory([("x", "y")], direct={"x"})
    inv.components[0].specifier = ">=2"
    result = build_graph(inv)
    x = node(result, "x")
    assert x["direct"] is True and x["depth"] == 1 and node(result, "y")["depth"] == 2
    edge = next(e for e in result.edges if e["source"] == ROOT)
    assert edge == {"source": ROOT, "target": ref("x"), "type": "depends_on", "specifier": ">=2"}


def test_duplicate_edges_and_components_are_merged():
    inv = make_inventory([("root", "a", ">=1"), ("root", "a", "<2"), ("root", "a", ">=1"), ("a", "b"), ("a", "b")])
    inv.components.append(
        Component(bom_ref=ref("a"), name="a-dup", normalized_name="a", version="9", purl=None, direct=False)
    )
    result = build_graph(inv)
    assert result.metrics["edge_count"] == 2 and result.metrics["package_count"] == 2
    root_edge = next(e for e in result.edges if e["source"] == ROOT)
    assert root_edge["specifier"] == "<2,>=1"
    assert next(e for e in result.edges if e["source"] == ref("a"))["specifier"] is None
    assert node(result, "b")["dependents"] == 1
    assert node(result, "a")["name"] == "a" and node(result, "a")["direct"] is True
    assert any("duplicate component" in w for w in result.warnings)


def test_missing_refs_are_ignored_with_warnings():
    inv = make_inventory([("root", "a")])
    inv.edges += [
        DependencyEdge(parent=ref("a"), child="pkg:pypi/ghost@1"),
        DependencyEdge(parent="pkg:pypi/phantom@1", child=ref("a")),
        DependencyEdge(parent=None, child=ref("a")),  # type: ignore[arg-type]
        DependencyEdge(parent=ref("a"), child=ROOT),
        DependencyEdge(parent="nope", child="nada"),
    ]
    result = build_graph(inv)
    assert depends_on(result) == {(ROOT, ref("a"))}
    assert node(result, "a")["dependents"] == 0
    joined = "\n".join(result.warnings)
    assert "unknown child" in joined and "unknown parent" in joined and "unknown parent and child" in joined
    assert "project root" in joined
    assert len(result.warnings) == 5


# ------------------------------------------------------------------------------------------ adversarial


def test_hostile_refs_are_sanitised_everywhere():
    token = "ghp_" + "A" * 36
    evil = f"pkg:pypi/evil\x1b[31m‮@1?{token}"
    inv = make_inventory([("root", "a")])
    inv.components.append(Component(bom_ref=evil, name=f"evil\x1b]0;{token}", normalized_name="evil",
                                    version="1\x00", purl=None, direct=True))
    # A separator precedes each token, as with an accidentally leaked credential (``/``, ``=``, space):
    # the shared redaction patterns are word-boundary anchored.
    inv.edges.append(DependencyEdge(parent=ref("a"), child=f"missing\x1b[2J {token}"))
    result = build_graph(inv, vulns_by_ref={evil: [{"id": f"GHSA\x07-{token}", "severity": "high"}]})
    dumped = json.dumps(result.to_dict(), ensure_ascii=False)
    assert token not in dumped
    for ch in ("\x1b", "‮", "\x00", "\x07"):
        assert ch not in dumped
    assert result.metrics["package_count"] == 2  # the hostile component is kept, under a sanitised id


def test_warning_list_is_bounded():
    inv = make_inventory([("root", "a")])
    inv.edges += [DependencyEdge(parent=ref("a"), child=f"pkg:pypi/missing-{i}@1") for i in range(500)]
    result = build_graph(inv)
    assert len(result.warnings) == engine._MAX_WARNINGS + 1
    assert result.warnings[-1].startswith("450 further warning(s) suppressed")


def test_root_reference_collisions_and_invalid_components():
    inv = make_inventory([("root", "a")])
    inv.components += [
        Component(bom_ref=ROOT, name="impostor", normalized_name="impostor", version=None, purl=None),
        Component(bom_ref="", name="blank", normalized_name="blank", version=None, purl=None),
    ]
    result = build_graph(inv)
    assert result.metrics["package_count"] == 1
    assert node(result, "root")["type"] == "project" and node(result, "root")["name"] == "demo"
    assert len(result.warnings) == 2


def test_invalid_risk_decision_and_findings_values():
    inv = make_inventory([("root", x) for x in "abcde"])
    result = build_graph(
        inv,
        risk_by_ref={ROOT: 42, ref("a"): True, ref("b"): float("nan"), ref("c"): "90", ref("d"): 150, ref("e"): 59.5},
        decision_by_ref={ref("a"): "block", ref("b"): 7},
        findings_by_ref={ref("a"): [{}, {}], ref("b"): 3, ref("c"): "many", ref("d"): -4},
    )
    assert [node(result, x)["risk"] for x in "abc"] == [None, None, None]
    assert node(result, "d")["risk"] == 100 and node(result, "d")["severity"] == "critical"
    assert node(result, "e")["risk"] == 59.5 and node(result, "e")["severity"] == "medium"
    assert node(result, "root")["risk"] == 42 and node(result, "root")["subtree_max_risk"] == 100
    assert node(result, "a")["decision"] == "block" and node(result, "b")["decision"] is None
    assert [node(result, x)["findings_count"] for x in "abcd"] == [2, 3, 0, 0]
    assert result.metrics["high_risk_transitive"] == []  # d is risky but direct


def test_severity_band_thresholds():
    assert [severity_band(s) for s in (None, 0, 14.9, 15, 35, 60, 79.9, 80, 100)] == [
        None, "info", "info", "low", "medium", "high", "high", "critical", "critical"
    ]


# ------------------------------------------------------------------------------------------ vulnerabilities


def test_vulnerability_nodes_and_edges():
    inv = make_inventory(DIAMOND)
    baseline = build_graph(inv)
    vulns = {
        ref("c"): [{"id": "GHSA-1", "severity": "high", "cvss_score": 7.5, "kev": False}],
        ref("d"): [{"id": "GHSA-1", "severity": "critical", "kev": True}, {"id": "PYSEC-2", "cvss_score": 5.3}],
        ref("e"): [{"severity": "high"}, "junk"],
        "pkg:pypi/nope@1": [{"id": "X-1"}],
    }
    result = build_graph(inv, vulns_by_ref=vulns)

    ghsa, pysec = result.node("vuln:GHSA-1"), result.node("vuln:PYSEC-2")
    assert ghsa["type"] == "vulnerability" and ghsa["name"] == "GHSA-1"
    assert (ghsa["severity"], ghsa["cvss_score"], ghsa["kev"]) == ("critical", 7.5, True)
    assert (ghsa["dependents"], ghsa["transitive_dependents"], ghsa["depth"]) == (2, 4, 3)
    assert ghsa["blast_radius"] == pytest.approx(0.8) and ghsa["direct_exposure"] == 1.0
    assert (pysec["severity"], pysec["cvss_score"], pysec["kev"]) == ("medium", 5.3, False)
    assert (pysec["dependents"], pysec["transitive_dependents"], pysec["depth"]) == (1, 4, 4)
    assert result.node("vuln:X-1") is None

    vuln_edges = {(e["source"], e["target"]) for e in result.edges if e["type"] == "vulnerable_to"}
    assert vuln_edges == {(ref("c"), "vuln:GHSA-1"), (ref("d"), "vuln:GHSA-1"), (ref("d"), "vuln:PYSEC-2")}
    assert node(result, "c")["vulnerability_ids"] == ["GHSA-1"]
    assert node(result, "d")["vulnerability_ids"] == ["GHSA-1", "PYSEC-2"]
    m = result.metrics
    assert (m["node_count"], m["edge_count"], m["vulnerability_count"], m["dependency_edge_count"]) == (8, 9, 2, 6)
    assert len(result.warnings) == 3  # unknown component, entry without id, non-object entry

    # Vulnerability nodes never change package metrics.
    def without_vuln_ids(n: dict) -> dict:
        return {k: v for k, v in n.items() if k != "vulnerability_ids"}

    for before in baseline.nodes:
        assert without_vuln_ids(result.node(before["id"])) == without_vuln_ids(before)
    # Nodes are sorted: project, packages, vulnerabilities.
    assert [n["type"] for n in result.nodes] == ["project"] + ["package"] * 5 + ["vulnerability"] * 2


def test_vulnerability_on_unreachable_package_and_bad_containers():
    inv = make_inventory([("root", "a"), ("b", "c")])
    result = build_graph(inv, vulns_by_ref={ref("c"): [{"id": "OSV-1"}], ref("a"): {"id": "not-a-list"}})
    osv = result.node("vuln:OSV-1")
    assert osv["depth"] is None and osv["severity"] == "unknown" and osv["direct_exposure"] == 0.0
    assert osv["transitive_dependents"] == 2  # c and its ancestor b
    assert any("expected a list" in w for w in result.warnings)


# ------------------------------------------------------------------------------------------ truncation


def test_truncation_keeps_root_direct_then_bfs():
    inv = make_inventory(
        [("root", "d1"), ("root", "d2"), ("root", "d3"), ("d1", "t1"), ("t1", "t2"), ("d2", "t3")], names=["u1"]
    )
    result = build_graph(inv, max_nodes=5)
    ids = {n["id"] for n in result.nodes}
    assert ids == {ROOT, ref("d1"), ref("d2"), ref("d3"), ref("t1")}
    m = result.metrics
    assert m["truncated"] is True and m["node_count"] == 5 and m["package_count"] == 4
    assert "max_nodes=5" in m["truncation_note"] and "omitted 3 package node(s)" in m["truncation_note"]
    assert all(e["source"] in ids and e["target"] in ids for e in result.edges)
    assert depends_on(result) == {(ROOT, ref("d1")), (ROOT, ref("d2")), (ROOT, ref("d3")), (ref("d1"), ref("t1"))}


def test_truncation_with_more_direct_dependencies_than_budget():
    inv = make_inventory([("root", f"d{i:02d}") for i in range(10)])
    result = build_graph(inv, max_nodes=4)
    assert [n["id"] for n in result.nodes] == [ROOT, ref("d00"), ref("d01"), ref("d02")]
    assert result.metrics["direct_count"] == 3


def test_truncation_drops_vulnerability_nodes_but_keeps_ids():
    inv = make_inventory([("root", "a"), ("a", "b")])
    vulns = {ref("b"): [{"id": "GHSA-9", "severity": "low"}]}
    result = build_graph(inv, vulns_by_ref=vulns, max_nodes=3)
    assert result.metrics["truncated"] is True and result.metrics["vulnerability_count"] == 0
    assert "1 vulnerability node(s)" in result.metrics["truncation_note"]
    assert node(result, "b")["vulnerability_ids"] == ["GHSA-9"]
    assert not any(e["type"] == "vulnerable_to" for e in result.edges)
    assert build_graph(inv, vulns_by_ref=vulns, max_nodes=4).metrics["truncated"] is False


def test_max_nodes_validation_and_settings_default(monkeypatch):
    inv = make_inventory([("root", "a"), ("a", "b"), ("b", "c")])
    for bad in (0, -1, True, 2.5):
        with pytest.raises(ValueError):
            build_graph(inv, max_nodes=bad)  # type: ignore[arg-type]
    assert build_graph(inv, max_nodes=1).metrics["node_count"] == 1
    monkeypatch.setattr(engine.settings, "MAX_GRAPH_NODES", 3)
    result = build_graph(inv)
    assert result.metrics["truncated"] is True and result.metrics["node_count"] == 3


def test_large_graph_uses_deterministic_sampled_betweenness():
    edges: list[tuple[str, str]] = []
    for i in range(20):
        edges.append(("root", f"d{i}"))
        for j in range(30):
            edges.append((f"d{i}", f"t{i}-{j}"))
            if j:
                edges.append((f"t{i}-{j - 1}", f"t{i}-{j}"))
        edges.append((f"d{i}", "shared"))
    inv = make_inventory(edges)
    first, second = build_graph(inv), build_graph(inv)
    assert first.metrics["betweenness_method"] == "sampled"
    assert first.metrics["betweenness_sample_size"] == engine.BETWEENNESS_SAMPLE_SIZE
    assert first.to_dict() == second.to_dict()
    assert all(0.0 <= n["betweenness"] <= 1.0 for n in first.nodes if n["type"] != "vulnerability")


def test_empty_inventory_and_to_dict_isolation():
    result = build_graph(ProjectInventory(project_name="empty", root_ref="project:empty"))
    data = result.to_dict()
    assert set(data) == {"nodes", "edges", "metrics"}
    assert data["metrics"]["node_count"] == 1 and data["edges"] == []
    assert data["nodes"][0]["transitive_dependencies"] == 0
    data["nodes"][0]["name"] = "mutated"
    assert result.nodes[0]["name"] == "empty"
    json.dumps(data)


# ------------------------------------------------------------------------------------------ subgraph


def test_subgraph_neighbourhood():
    result = build_graph(make_inventory(DIAMOND), vulns_by_ref={ref("d"): [{"id": "GHSA-1"}]})
    around_c = subgraph(result.to_dict(), ref("c"), depth=1)
    assert {n["id"] for n in around_c["nodes"]} == {ref(x) for x in "abcde"}
    assert {n["id"]: n["distance"] for n in around_c["nodes"]}[ref("c")] == 0
    assert {(e["source"], e["target"]) for e in around_c["edges"]} == {
        (ref("a"), ref("c")), (ref("b"), ref("c")), (ref("c"), ref("d")), (ref("c"), ref("e"))
    }
    down = subgraph(result, ref("c"), depth=2, direction="dependencies")
    assert {n["id"] for n in down["nodes"]} == {ref("c"), ref("d"), ref("e"), "vuln:GHSA-1"}
    up = subgraph(result, ref("d"), depth=5, direction="dependents")
    assert {n["id"] for n in up["nodes"]} == {ROOT, ref("a"), ref("b"), ref("c"), ref("d")}
    assert [n["id"] for n in subgraph(result, ref("c"), depth=0)["nodes"]] == [ref("c")]
    assert subgraph(result, ref("c"), depth=10_000)["depth"] == engine.MAX_SUBGRAPH_DEPTH


def test_subgraph_errors_and_malformed_input():
    result = build_graph(make_inventory(DIAMOND)).to_dict()
    with pytest.raises(KeyError):
        subgraph(result, "pkg:pypi/unknown@1")
    with pytest.raises(ValueError):
        subgraph(result, ref("a"), depth=-1)
    with pytest.raises(ValueError):
        subgraph(result, ref("a"), direction="sideways")
    with pytest.raises(TypeError):
        subgraph(["not", "a", "graph"], ref("a"))  # type: ignore[arg-type]
    result["nodes"].append("garbage")
    result["edges"] += [None, {"source": ref("a")}, {"source": ref("a"), "target": "ghost", "type": "depends_on"}]
    sub = subgraph(result, ref("a"), depth=1)
    assert {n["id"] for n in sub["nodes"]} == {ROOT, ref("a"), ref("c")}
    sub["nodes"][0]["name"] = "mutated"
    assert result["nodes"][0]["name"] == "demo"


# ------------------------------------------------------------------------------------------ properties


@st.composite
def graph_inputs(draw, acyclic: bool = False, max_packages: int = 9):
    count = draw(st.integers(min_value=0, max_value=max_packages))
    names = [f"p{i}" for i in range(count)]
    edges: list[tuple[str, str]] = []
    if count:
        raw = draw(st.lists(st.tuples(st.integers(-1, count - 1), st.integers(0, count - 1)), max_size=3 * count))
        for parent, child in raw:
            if acyclic and parent >= child:
                continue
            edges.append(("root" if parent < 0 else names[parent], names[child]))
    direct = set(draw(st.lists(st.sampled_from(names), unique=True))) if names else set()
    risks = draw(st.dictionaries(st.sampled_from(names), st.integers(0, 100))) if names else {}
    return names, edges, direct, risks


def _oracle_graph(result: GraphAnalysis) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_nodes_from(n["id"] for n in result.nodes if n["type"] != "vulnerability")
    graph.add_edges_from(depends_on(result))
    return graph


PROPERTY_SETTINGS = hyp_settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@PROPERTY_SETTINGS
@given(graph_inputs())
def test_property_metrics_match_brute_force_oracles(data):
    names, edges, direct, risks = data
    inv = make_inventory(edges, names=names, direct=direct)
    result = build_graph(inv, risk_by_ref={ref(k): v for k, v in risks.items()})
    graph = _oracle_graph(result)
    packages = [n for n in result.nodes if n["type"] == "package"]
    package_ids = {n["id"] for n in packages}
    reachable = nx.descendants(graph, ROOT)
    directs = set(graph.successors(ROOT))
    lengths = nx.single_source_shortest_path_length(graph, ROOT)
    for n in packages:
        pid = n["id"]
        ancestors = nx.ancestors(graph, pid) - {ROOT}
        descendants = nx.descendants(graph, pid)
        assert n["transitive_dependents"] == len(ancestors)
        assert n["transitive_dependencies"] == len(descendants)
        assert n["dependents"] == len(set(graph.predecessors(pid)) - {ROOT})
        assert n["depth"] == lengths.get(pid)
        assert n["direct"] is (pid in directs)
        expected_exposure = sum(1 for d in directs if d == pid or pid in nx.descendants(graph, d))
        assert n["direct_exposure"] == pytest.approx(expected_exposure / len(directs) if directs else 0.0, abs=1e-6)
        if pid in reachable:
            without = graph.copy()
            without.remove_node(pid)
            cut_off = reachable - nx.descendants(without, ROOT) - {pid}
            assert n["dominated"] == len(cut_off)
        else:
            assert n["dominated"] == 0
        subtree = [risks[x[len("pkg:pypi/"):-len("@1.0")]] for x in descendants | {pid}
                   if x[len("pkg:pypi/"):-len("@1.0")] in risks]
        assert n["subtree_max_risk"] == (max(subtree) if subtree else None)
        # invariants
        assert 0.0 <= n["blast_radius"] <= 1.0 and 0.0 <= n["direct_exposure"] <= 1.0
        assert 0.0 <= n["betweenness"] <= 1.0
        assert 0 <= n["dominated"] <= len(packages) and n["dominated"] <= n["transitive_dependencies"]
        assert n["dependents"] <= n["transitive_dependents"] <= max(0, len(packages) - 1)
    m = result.metrics
    assert m["has_cycles"] is (not nx.is_directed_acyclic_graph(graph))
    assert m["direct_count"] + m["transitive_count"] + m["unreachable_count"] == m["package_count"]
    assert m["node_count"] == len(result.nodes) and m["edge_count"] == len(result.edges)
    assert len({n["id"] for n in result.nodes}) == len(result.nodes)
    assert package_ids == {ref(x) for x in names}


@PROPERTY_SETTINGS
@given(graph_inputs(acyclic=True))
def test_property_child_depth_at_most_parent_depth_plus_one(data):
    names, edges, direct, _ = data
    result = build_graph(make_inventory(edges, names=names, direct=direct))
    depth = {n["id"]: n["depth"] for n in result.nodes}
    assert result.metrics["has_cycles"] is False
    for source, target in depends_on(result):
        if depth[source] is not None:
            assert depth[target] is not None and depth[target] <= depth[source] + 1


@PROPERTY_SETTINGS
@given(graph_inputs(), st.integers(min_value=0, max_value=2**32 - 1), st.integers(min_value=1, max_value=12))
def test_property_output_is_deterministic_and_bounded(data, seed, max_nodes):
    names, edges, direct, risks = data
    vulns = {ref(n): [{"id": f"OSV-{i % 3}", "severity": "high"}] for i, n in enumerate(names) if i % 2 == 0}
    kwargs = dict(risk_by_ref={ref(k): v for k, v in risks.items()}, vulns_by_ref=vulns, max_nodes=max_nodes)
    first = build_graph(make_inventory(edges, names=names, direct=direct), **kwargs)
    again = build_graph(make_inventory(edges, names=names, direct=direct), **kwargs)
    assert json.dumps(first.to_dict(), sort_keys=True) == json.dumps(again.to_dict(), sort_keys=True)

    shuffled_inv = make_inventory(edges, names=names, direct=direct)
    rng = random.Random(seed)
    rng.shuffle(shuffled_inv.components)
    rng.shuffle(shuffled_inv.edges)
    shuffled = build_graph(shuffled_inv, **kwargs).to_dict()
    baseline = first.to_dict()
    for data_dict in (shuffled, baseline):
        data_dict["metrics"].pop("warnings")  # warning order follows input order by design
    assert shuffled == baseline

    assert baseline["metrics"]["node_count"] <= max_nodes
    expected_order = sorted(baseline["nodes"], key=engine._node_sort_key)
    assert [n["id"] for n in baseline["nodes"]] == [n["id"] for n in expected_order]
    ids = {n["id"] for n in baseline["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in baseline["edges"])
    for n in baseline["nodes"]:
        if n["type"] in ("package", "vulnerability"):
            assert 0.0 <= n["blast_radius"] <= 1.0 and 0.0 <= n["direct_exposure"] <= 1.0
