import json
import os
import tempfile
import unittest

from netinspect.core.errors import SourceError
from netinspect.core.fetcher import DirectorySource, default_kinds, yaml
from netinspect.core.model import EDGE_CONTAINS, EDGE_POLICY, EDGE_TRAFFIC, Graph, Resource
from netinspect.graph.builder import build_graph

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
MANIFESTS = os.path.join(os.path.dirname(__file__), "manifests")


def load_fixture_graph(namespaces: list[str] | None = None) -> Graph:
    source = DirectorySource(FIXTURES)
    return build_graph(source.load(default_kinds(), namespaces))


class DirectorySourceTest(unittest.TestCase):
    def test_loads_all_and_skips_secret(self) -> None:
        source = DirectorySource(FIXTURES)
        res = source.load(default_kinds() + ["Secret"], None)
        kinds = {r.kind for r in res}
        self.assertNotIn("Secret", kinds)
        self.assertEqual(
            kinds,
            {"Gateway", "VirtualService", "DestinationRule", "ServiceEntry", "EnvoyFilter", "Service",
             "EndpointSlice", "Route"},
        )
        self.assertEqual(source.warnings, [])

    def test_cleanup(self) -> None:
        res = DirectorySource(FIXTURES).load(["Gateway"], ["prod"])
        meta = res[0].raw["metadata"]
        self.assertNotIn("managedFields", meta)
        self.assertNotIn("kubectl.kubernetes.io/last-applied-configuration", meta["annotations"])
        self.assertEqual(meta["annotations"]["owner"], "platform-team")

    def test_namespace_filter(self) -> None:
        res = DirectorySource(FIXTURES).load(default_kinds(), ["staging"])
        self.assertTrue(res)
        self.assertTrue(all(r.namespace == "staging" for r in res))

    def test_missing_dir(self) -> None:
        with self.assertRaises(SourceError):
            DirectorySource("/nonexistent/dir")

    def test_bad_json_is_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "bad.json"), "w") as fh:
                fh.write("{not json")
            source = DirectorySource(tmp)
            self.assertEqual(source.load(default_kinds(), None), [])
            self.assertEqual(len(source.warnings), 1)

    def test_yaml_multidoc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "m.yaml"), "w") as fh:
                fh.write(
                    "kind: Service\nmetadata: {name: a, namespace: x}\nspec: {}\n---\n"
                    "kind: List\nitems:\n- kind: Service\n  metadata: {name: b, namespace: x}\n"
                )
            source = DirectorySource(tmp)
            res = source.load(["Service"], None)
            if yaml is None:
                self.assertEqual(res, [])
                self.assertTrue(any("PyYAML" in w for w in source.warnings))
            else:
                self.assertEqual(sorted(r.name for r in res), ["a", "b"])


class BuilderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.g = load_fixture_graph()

    def edge(self, source: str, target: str, kind: str = EDGE_TRAFFIC) -> str:
        for e in self.g.edges:
            if e.source == source and e.target == target:
                self.assertEqual(e.kind, kind, f"{source} -> {target}")
                return e.label
        self.fail(f"нет ребра {source} -> {target}")

    def no_edge(self, source: str, target: str) -> None:
        self.assertFalse(any(e.source == source and e.target == target for e in self.g.edges), f"{source} -> {target}")

    def test_working_chain(self) -> None:
        # Gateway → VS → subset → Service → EndpointSlice; DR содержит subset
        self.edge("Gateway/prod/public-gw", "VirtualService/prod/reviews")
        self.assertEqual(self.edge("VirtualService/prod/reviews", "Subset/prod/reviews:v1"), ":9080 80%")
        self.assertEqual(self.edge("VirtualService/prod/reviews", "Subset/prod/reviews:v2"), ":9080 20%")
        self.edge("Subset/prod/reviews:v1", "Service/prod/reviews")
        self.edge("DestinationRule/prod/reviews", "Subset/prod/reviews:v1", EDGE_CONTAINS)
        self.edge("Service/prod/reviews", "EndpointSlice/prod/reviews-abc12")
        # маршрут с subset идёт через subset, а не напрямую
        self.no_edge("VirtualService/prod/reviews", "Service/prod/reviews")
        self.no_edge("VirtualService/prod/reviews", "DestinationRule/prod/reviews")
        dr = self.g.nodes["DestinationRule/prod/reviews"]
        self.assertIn("subset v1 ✓", dr.badges)
        self.assertIn("subset v2 ✓", dr.badges)
        self.assertFalse(dr.problems)
        self.assertIn("3 ready", self.g.nodes["EndpointSlice/prod/reviews-abc12"].badges)
        self.assertIn("mesh", self.g.nodes["VirtualService/prod/reviews"].badges)

    def test_subset_nodes(self) -> None:
        v1 = self.g.nodes["Subset/prod/reviews:v1"]
        self.assertIn("version=v1", v1.badges)
        self.assertEqual(v1.resource.spec["labels"], {"version": "v1"})  # манифест subset для панели
        self.assertNotIn("не используется", v1.badges)
        v3 = self.g.nodes["Subset/prod/reviews:v3"]
        self.assertIn("не используется", v3.badges)
        self.assertFalse(v3.problems)
        self.edge("Subset/prod/reviews:v3", "Service/prod/reviews")

    def test_gateway_badges_and_hosts(self) -> None:
        gw = self.g.nodes["Gateway/prod/public-gw"]
        self.assertIn("*.example.com:443", gw.badges)
        self.assertIn("api.example.com:80", gw.badges)  # формат ns/host
        self.assertIn("api.example.com", gw.hosts)

    def test_missing_gateway(self) -> None:
        node = self.g.nodes["Gateway/prod/legacy-gw"]
        self.assertTrue(node.missing)
        self.assertIsNone(node.resource)
        self.edge("Gateway/prod/legacy-gw", "VirtualService/prod/legacy")

    def test_missing_subset(self) -> None:
        dr = self.g.nodes["DestinationRule/prod/ratings"]
        self.assertIn("subset v1 ✓", dr.badges)
        self.assertIn("subset v3 ✗", dr.badges)
        self.assertTrue(any("v3" in p for p in dr.problems))
        self.assertEqual(self.edge("VirtualService/prod/ratings", "DestinationRule/prod/ratings"), "v3 ✗")
        self.assertEqual(self.edge("VirtualService/prod/ratings", "Subset/prod/ratings:v1"), "90%")
        # маршрут на отсутствующий subset ведёт прямо в сервис
        self.assertEqual(self.edge("VirtualService/prod/ratings", "Service/prod/ratings"), "v3 10%")
        self.assertNotIn("Subset/prod/ratings:v3", self.g.nodes)

    def test_service_without_endpoints(self) -> None:
        svc = self.g.nodes["Service/prod/details"]
        self.assertFalse(svc.missing)
        self.assertTrue(svc.problems)
        self.assertIn("нет endpoints", svc.badges)
        self.assertEqual(self.g.out_edges("Service/prod/details"), [])

    def test_not_ready_endpoints(self) -> None:
        es = self.g.nodes["EndpointSlice/prod/ratings-x7k2p"]
        self.assertIn("1 ready", es.badges)
        self.assertIn("1 not ready", es.badges)
        self.assertFalse(self.g.nodes["Service/prod/ratings"].problems)

    def test_cross_namespace_short_and_full(self) -> None:
        self.edge("Gateway/prod/public-gw", "VirtualService/staging/productpage")
        self.edge("VirtualService/staging/productpage", "Service/prod/reviews")  # полный хост
        self.edge("VirtualService/staging/productpage", "Service/staging/productpage")  # короткий
        self.edge("VirtualService/staging/productpage", "DestinationRule/prod/reviews")

    def test_route(self) -> None:
        self.edge("Route/prod/details", "Service/prod/details")
        self.edge("Route/staging/productpage", "Service/staging/productpage")
        missing = self.g.nodes["Service/prod/details-v2"]
        self.assertTrue(missing.missing)
        self.edge("Route/prod/details", "Service/prod/details-v2")
        self.assertIn("details.apps.example.com", self.g.nodes["Route/prod/details"].hosts)

    def test_external_host_with_service_entry(self) -> None:
        self.assertNotIn("ExternalHost/-/api.payments-provider.com", self.g.nodes)
        self.assertIn("tls", self.edge("VirtualService/prod/payments-egress", "ServiceEntry/prod/payments-api"))
        # DR для внешнего хоста связан и не ругается на «сервис не найден»
        self.edge("VirtualService/prod/payments-egress", "DestinationRule/prod/payments-api")
        dr = self.g.nodes["DestinationRule/prod/payments-api"]
        self.assertFalse(dr.problems)
        self.assertIn("tls SIMPLE", dr.badges)

    def test_external_host_without_service_entry(self) -> None:
        node = self.g.nodes["ExternalHost/-/api.analytics.example.net"]
        self.assertFalse(node.missing)
        self.assertFalse(node.problems)
        self.assertIn("нет ServiceEntry", node.badges)
        self.edge("VirtualService/prod/analytics-egress", node.key)

    def test_service_entries(self) -> None:
        ok = self.g.nodes["ServiceEntry/prod/payments-api"]
        self.assertFalse(ok.problems)
        self.assertIn("api.payments-provider.com", ok.hosts)
        for badge in ("443/TLS", "внешний", "resolution DNS"):
            self.assertIn(badge, ok.badges)
        static = self.g.nodes["ServiceEntry/prod/legacy-db"]
        self.assertTrue(any("STATIC" in p for p in static.problems))
        self.assertIn("внутренний", static.badges)
        wildcard = self.g.nodes["ServiceEntry/prod/partner-apis"]
        self.assertTrue(any("wildcard" in p for p in wildcard.problems))

    def test_envoy_filters(self) -> None:
        self.edge("EnvoyFilter/prod/reviews-headers", "Service/prod/reviews", EDGE_POLICY)
        # selector с version=v2 попадает только в subset v2
        self.edge("EnvoyFilter/prod/reviews-v2-debug", "Subset/prod/reviews:v2", EDGE_POLICY)
        self.no_edge("EnvoyFilter/prod/reviews-v2-debug", "Service/prod/reviews")
        self.no_edge("EnvoyFilter/prod/reviews-v2-debug", "Subset/prod/reviews:v1")
        # фильтр шлюза из istio-system → Gateway по selector
        self.edge("EnvoyFilter/istio-system/gateway-lua", "Gateway/prod/public-gw", EDGE_POLICY)
        gw_filter = self.g.nodes["EnvoyFilter/istio-system/gateway-lua"]
        self.assertIn("HTTP_FILTER @ GATEWAY (INSERT_BEFORE)", gw_filter.badges)
        mesh = self.g.nodes["EnvoyFilter/istio-system/mesh-access-log"]
        self.assertIn("весь mesh", mesh.badges)
        self.assertFalse(mesh.problems)
        self.assertEqual(self.g.out_edges(mesh.key), [])
        orphan = self.g.nodes["EnvoyFilter/prod/orphan-filter"]
        self.assertTrue(any("app=payments-v9" in p for p in orphan.problems))

    def test_problem_count(self) -> None:
        keys = sorted(n.key for n in self.g.problem_nodes())
        self.assertEqual(
            keys,
            [
                "DestinationRule/prod/ratings",
                "EnvoyFilter/prod/orphan-filter",
                "Gateway/prod/legacy-gw",
                "Service/prod/details",
                "Service/prod/details-v2",
                "ServiceEntry/prod/legacy-db",
                "ServiceEntry/prod/partner-apis",
            ],
        )

    def test_to_dict_is_json(self) -> None:
        data = json.loads(json.dumps(self.g.to_dict()))
        self.assertEqual(len(data["nodes"]), len(self.g.nodes))
        self.assertEqual(len(data["edges"]), len(self.g.edges))
        self.assertEqual({e["kind"] for e in data["edges"]}, {EDGE_TRAFFIC, EDGE_CONTAINS, EDGE_POLICY})

    def test_in_out_edges(self) -> None:
        self.assertEqual(len(self.g.out_edges("Gateway/prod/public-gw")), 3)
        sources = sorted(e.source for e in self.g.in_edges("Service/prod/reviews"))
        self.assertEqual(
            sources,
            [
                "EnvoyFilter/prod/reviews-headers",
                "Subset/prod/reviews:v1",
                "Subset/prod/reviews:v2",
                "Subset/prod/reviews:v3",
                "VirtualService/prod/legacy",
                "VirtualService/staging/productpage",
            ],
        )


class BuilderUnitTest(unittest.TestCase):
    def res(self, obj: dict) -> Resource:
        return Resource.from_manifest(obj)

    def test_subset_without_dr(self) -> None:
        g = build_graph(
            [
                self.res(
                    {
                        "kind": "VirtualService",
                        "metadata": {"name": "a", "namespace": "ns"},
                        "spec": {"hosts": ["a"], "http": [{"route": [{"destination": {"host": "svc", "subset": "v1"}}]}]},
                    }
                ),
                self.res({"kind": "Service", "metadata": {"name": "svc", "namespace": "ns"}, "spec": {"type": "ExternalName", "externalName": "x.example.com"}}),
            ]
        )
        dr = g.nodes["DestinationRule/ns/svc"]
        self.assertTrue(dr.missing)
        self.assertIn("subset v1 ✗", dr.badges)
        # ExternalName — без проверки endpoints
        self.assertFalse(g.nodes["Service/ns/svc"].problems)

    def test_custom_domain_and_wildcard_dr(self) -> None:
        g = build_graph(
            [
                self.res(
                    {
                        "kind": "VirtualService",
                        "metadata": {"name": "a", "namespace": "ns"},
                        "spec": {"http": [{"route": [{"destination": {"host": "svc.ns.svc.corp.local"}}]}]},
                    }
                ),
                self.res({"kind": "DestinationRule", "metadata": {"name": "all", "namespace": "ns"}, "spec": {"host": "*.ns.svc.corp.local"}}),
                self.res({"kind": "Service", "metadata": {"name": "svc", "namespace": "ns"}, "spec": {}}),
            ],
            domain="corp.local",
        )
        targets = {e.target for e in g.out_edges("VirtualService/ns/a")}
        self.assertEqual(targets, {"Service/ns/svc", "DestinationRule/ns/all"})


class NewKindsUnitTest(unittest.TestCase):
    def res(self, obj: dict) -> Resource:
        return Resource.from_manifest(obj)

    def test_dr_host_typo_and_duplicate_subset(self) -> None:
        g = build_graph(
            [
                self.res({"kind": "Service", "metadata": {"name": "reviews", "namespace": "ns"}, "spec": {}}),
                self.res(
                    {
                        "kind": "DestinationRule",
                        "metadata": {"name": "typo", "namespace": "ns"},
                        "spec": {"host": "revews", "subsets": [{"name": "v1"}, {"name": "v1"}, {"labels": {}}]},
                    }
                ),
            ]
        )
        problems = g.nodes["DestinationRule/ns/typo"].problems
        self.assertTrue(any("revews.ns.svc.cluster.local" in p for p in problems))
        self.assertTrue(any("v1 объявлен дважды" in p for p in problems))
        self.assertTrue(any("без имени" in p for p in problems))
        self.assertIn("без меток: все поды", g.nodes["Subset/ns/typo:v1"].badges)

    def test_wildcard_service_entry_target(self) -> None:
        g = build_graph(
            [
                self.res(
                    {
                        "kind": "ServiceEntry",
                        "metadata": {"name": "partners", "namespace": "ns"},
                        "spec": {"hosts": ["*.partner.example.com"], "ports": [{"number": 443, "protocol": "HTTPS"}],
                                 "resolution": "NONE"},
                    }
                ),
                self.res(
                    {
                        "kind": "VirtualService",
                        "metadata": {"name": "vs", "namespace": "ns"},
                        "spec": {"http": [{"route": [{"destination": {"host": "a.partner.example.com"}}]}]},
                    }
                ),
            ]
        )
        self.assertEqual([e.target for e in g.out_edges("VirtualService/ns/vs")], ["ServiceEntry/ns/partners"])
        self.assertFalse(g.nodes["ServiceEntry/ns/partners"].problems)

    def test_envoyfilter_without_patches_and_other_namespace(self) -> None:
        g = build_graph(
            [
                self.res({"kind": "Service", "metadata": {"name": "web", "namespace": "a"},
                          "spec": {"selector": {"app": "web"}}}),
                # EnvoyFilter в namespace b не действует на поды namespace a
                self.res({"kind": "EnvoyFilter", "metadata": {"name": "ef", "namespace": "b"},
                          "spec": {"workloadSelector": {"labels": {"app": "web"}}}}),
            ]
        )
        problems = g.nodes["EnvoyFilter/b/ef"].problems
        self.assertTrue(any("configPatches" in p for p in problems))
        self.assertTrue(any("не совпадает" in p for p in problems))


@unittest.skipIf(yaml is None, "нужен PyYAML")
class DemoManifestsTest(unittest.TestCase):
    """YAML-набор tests/manifests для тестового кластера: все намеренные ошибки находятся."""

    @classmethod
    def setUpClass(cls) -> None:
        source = DirectorySource(MANIFESTS)
        cls.g = build_graph(source.load(default_kinds(), None))
        cls.warnings = source.warnings

    def problems(self, key: str) -> str:
        return " ".join(self.g.nodes[key].problems)

    def test_loads_without_warnings(self) -> None:
        self.assertEqual(self.warnings, [])

    def test_expected_diagnostics(self) -> None:
        ns = "netinspect-demo"
        self.assertIn("subset v3", self.problems(f"DestinationRule/{ns}/ratings"))
        self.assertIn("revews", self.problems(f"DestinationRule/{ns}/revews-typo"))
        self.assertTrue(self.g.nodes[f"Gateway/{ns}/old-gateway"].missing)
        self.assertIn("STATIC", self.problems(f"ServiceEntry/{ns}/legacy-db"))
        self.assertIn("wildcard", self.problems(f"ServiceEntry/{ns}/partner-apis"))
        self.assertIn("payments-v9", self.problems(f"EnvoyFilter/{ns}/orphan-filter"))
        self.assertIn("не используется", self.g.nodes[f"Subset/{ns}/reviews:v3"].badges)
        self.assertIn("нет ServiceEntry", self.g.nodes["ExternalHost/-/api.analytics.example.net"].badges)

    def test_expected_links(self) -> None:
        ns = "netinspect-demo"
        edges = {(e.source, e.target) for e in self.g.edges}
        for pair in [
            (f"Gateway/{ns}/demo-gateway", f"VirtualService/{ns}/reviews"),
            (f"VirtualService/{ns}/reviews", f"Subset/{ns}/reviews:v1"),
            (f"Subset/{ns}/reviews:v2", f"Service/{ns}/reviews"),
            (f"VirtualService/{ns}/payments-egress", f"ServiceEntry/{ns}/payments"),
            (f"EnvoyFilter/{ns}/reviews-lua", f"Service/{ns}/reviews"),
            (f"EnvoyFilter/{ns}/reviews-v2-lua", f"Subset/{ns}/reviews:v2"),
            (f"EnvoyFilter/{ns}/gateway-lua", f"Gateway/{ns}/demo-gateway"),
            (f"Route/{ns}/productpage", f"Service/{ns}/productpage"),
        ]:
            self.assertIn(pair, edges)


if __name__ == "__main__":
    unittest.main()
