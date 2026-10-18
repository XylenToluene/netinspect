import json
import os
import tempfile
import unittest

from netinspect.core.errors import SourceError
from netinspect.core.fetcher import DirectorySource, default_kinds, yaml
from netinspect.core.model import Graph, Resource
from netinspect.graph.builder import build_graph

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture_graph(namespaces: list[str] | None = None) -> Graph:
    source = DirectorySource(FIXTURES)
    return build_graph(source.load(default_kinds(), namespaces))


class DirectorySourceTest(unittest.TestCase):
    def test_loads_all_and_skips_secret(self) -> None:
        source = DirectorySource(FIXTURES)
        res = source.load(default_kinds() + ["Secret"], None)
        kinds = {r.kind for r in res}
        self.assertNotIn("Secret", kinds)
        self.assertEqual(kinds, {"Gateway", "VirtualService", "DestinationRule", "Service", "EndpointSlice", "Route"})
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

    def edge(self, source: str, target: str) -> str:
        for e in self.g.edges:
            if e.source == source and e.target == target:
                return e.label
        self.fail(f"нет ребра {source} -> {target}")

    def test_working_chain(self) -> None:
        self.edge("Gateway/prod/public-gw", "VirtualService/prod/reviews")
        self.assertIn("80%", self.edge("VirtualService/prod/reviews", "Service/prod/reviews"))
        self.edge("VirtualService/prod/reviews", "DestinationRule/prod/reviews")
        self.edge("Service/prod/reviews", "EndpointSlice/prod/reviews-abc12")
        dr = self.g.nodes["DestinationRule/prod/reviews"]
        self.assertIn("subset v1 ✓", dr.badges)
        self.assertIn("subset v2 ✓", dr.badges)
        self.assertFalse(dr.problems)
        self.assertIn("3 ready", self.g.nodes["EndpointSlice/prod/reviews-abc12"].badges)
        self.assertIn("mesh", self.g.nodes["VirtualService/prod/reviews"].badges)

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
        self.assertIn("v3 ✗", self.edge("VirtualService/prod/ratings", "DestinationRule/prod/ratings"))

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

    def test_external_host(self) -> None:
        node = self.g.nodes["ExternalHost/-/api.payments-provider.com"]
        self.assertFalse(node.missing)
        self.assertFalse(node.problems)
        self.assertIn("tls", self.edge("VirtualService/prod/payments-egress", node.key))

    def test_problem_count(self) -> None:
        keys = sorted(n.key for n in self.g.problem_nodes())
        self.assertEqual(
            keys,
            [
                "DestinationRule/prod/ratings",
                "Gateway/prod/legacy-gw",
                "Service/prod/details",
                "Service/prod/details-v2",
            ],
        )

    def test_to_dict_is_json(self) -> None:
        data = json.loads(json.dumps(self.g.to_dict()))
        self.assertEqual(len(data["nodes"]), len(self.g.nodes))
        self.assertEqual(len(data["edges"]), len(self.g.edges))

    def test_in_out_edges(self) -> None:
        self.assertEqual(len(self.g.out_edges("Gateway/prod/public-gw")), 3)
        self.assertEqual(len(self.g.in_edges("Service/prod/reviews")), 3)


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


if __name__ == "__main__":
    unittest.main()
