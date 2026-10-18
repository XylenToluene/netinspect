import unittest

from netinspect.graph.traverse import find_by_host, host_subgraph, parse_resource_ref, subgraph
from tests.test_builder import load_fixture_graph


class TraverseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.g = load_fixture_graph()

    def test_subgraph_from_vs(self) -> None:
        sub = subgraph(self.g, ["VirtualService/prod/reviews"])
        self.assertEqual(
            set(sub.nodes),
            {
                "Gateway/prod/public-gw",
                "VirtualService/prod/reviews",
                "Subset/prod/reviews:v1",
                "Subset/prod/reviews:v2",
                "DestinationRule/prod/reviews",  # владелец subset
                "Service/prod/reviews",
                "EndpointSlice/prod/reviews-abc12",
                # EnvoyFilter, применяемые к попавшим узлам
                "EnvoyFilter/istio-system/gateway-lua",
                "EnvoyFilter/prod/reviews-headers",
                "EnvoyFilter/prod/reviews-v2-debug",
            },
        )
        # соседние VS через общий Gateway не попадают
        self.assertNotIn("VirtualService/prod/ratings", sub.nodes)
        self.assertTrue(all(e.source in sub.nodes and e.target in sub.nodes for e in sub.edges))

    def test_subgraph_from_service_goes_upstream(self) -> None:
        sub = subgraph(self.g, ["Service/prod/reviews"])
        for key in (
            "VirtualService/prod/reviews",
            "VirtualService/prod/legacy",
            "VirtualService/staging/productpage",
            "Gateway/prod/public-gw",
            "Gateway/prod/legacy-gw",
            "EndpointSlice/prod/reviews-abc12",
        ):
            self.assertIn(key, sub.nodes)
        self.assertNotIn("Service/staging/productpage", sub.nodes)

    def test_unknown_start(self) -> None:
        self.assertEqual(subgraph(self.g, ["Gateway/x/y"]).nodes, {})

    def test_find_by_host_wildcard_gateway(self) -> None:
        keys = set(find_by_host(self.g, "api.example.com"))
        self.assertEqual(keys, {"Gateway/prod/public-gw", "VirtualService/prod/reviews"})

    def test_find_by_host_route(self) -> None:
        # Route + Gateway с wildcard *.example.com
        self.assertEqual(
            set(find_by_host(self.g, "details.apps.example.com")),
            {"Route/prod/details", "Gateway/prod/public-gw"},
        )
        self.assertEqual(find_by_host(self.g, "productpage-staging.apps.example.com")[-1], "Route/staging/productpage")

    def test_host_subgraph(self) -> None:
        sub = host_subgraph(self.g, "api.example.com")
        self.assertIn("Gateway/prod/public-gw", sub.nodes)
        self.assertIn("EndpointSlice/prod/reviews-abc12", sub.nodes)
        self.assertNotIn("VirtualService/prod/ratings", sub.nodes)

    def test_host_subgraph_gateway_only(self) -> None:
        # хост покрыт wildcard Gateway, но VS для него нет
        sub = host_subgraph(self.g, "unknown.example.com")
        self.assertEqual(set(sub.nodes), {"Gateway/prod/public-gw", "EnvoyFilter/istio-system/gateway-lua"})

    def test_parse_resource_ref(self) -> None:
        self.assertEqual(parse_resource_ref("vs/prod/reviews"), "VirtualService/prod/reviews")
        self.assertEqual(parse_resource_ref("gw/prod/public-gw"), "Gateway/prod/public-gw")
        self.assertEqual(parse_resource_ref("dr/a/b"), "DestinationRule/a/b")
        self.assertEqual(parse_resource_ref("svc/a/b"), "Service/a/b")
        self.assertEqual(parse_resource_ref("route/a/b"), "Route/a/b")
        self.assertEqual(parse_resource_ref("VirtualService/a/b"), "VirtualService/a/b")
        with self.assertRaises(ValueError):
            parse_resource_ref("vs/reviews")
        with self.assertRaises(ValueError):
            parse_resource_ref("foo/a/b")


if __name__ == "__main__":
    unittest.main()
