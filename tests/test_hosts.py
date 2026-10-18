import unittest

from netinspect.core.hosts import (
    hosts_intersect,
    is_cluster_host,
    match_host,
    normalize,
    service_fqdn,
    split_ns_host,
    split_service_fqdn,
    to_fqdn,
)


class ToFqdnTest(unittest.TestCase):
    def test_short_name(self) -> None:
        self.assertEqual(to_fqdn("reviews", "prod"), "reviews.prod.svc.cluster.local")

    def test_name_ns(self) -> None:
        self.assertEqual(to_fqdn("reviews.prod", "other"), "reviews.prod.svc.cluster.local")

    def test_name_ns_svc(self) -> None:
        self.assertEqual(to_fqdn("reviews.prod.svc", "other"), "reviews.prod.svc.cluster.local")

    def test_full_fqdn_untouched(self) -> None:
        self.assertEqual(
            to_fqdn("reviews.prod.svc.cluster.local", "other"), "reviews.prod.svc.cluster.local"
        )

    def test_external_untouched(self) -> None:
        self.assertEqual(to_fqdn("api.example.com", "prod"), "api.example.com")

    def test_lowercase_and_trailing_dot(self) -> None:
        self.assertEqual(to_fqdn("Reviews.", "Prod"), "reviews.prod.svc.cluster.local")
        self.assertEqual(to_fqdn("API.Example.COM.", "prod"), "api.example.com")

    def test_custom_domain(self) -> None:
        self.assertEqual(to_fqdn("reviews", "prod", "corp.local"), "reviews.prod.svc.corp.local")
        self.assertEqual(
            to_fqdn("reviews.prod.svc.corp.local", "x", "corp.local"), "reviews.prod.svc.corp.local"
        )
        # с нестандартным доменом cluster.local — уже внешний 5-сегментный хост
        self.assertEqual(
            to_fqdn("reviews.prod.svc.cluster.local", "x", "corp.local"),
            "reviews.prod.svc.cluster.local",
        )

    def test_wildcards_untouched(self) -> None:
        self.assertEqual(to_fqdn("*", "prod"), "*")
        self.assertEqual(to_fqdn("*.example.com", "prod"), "*.example.com")

    def test_two_label_external_is_treated_as_service(self) -> None:
        # поведение Istio: двухсегментное имя — это name.namespace
        self.assertEqual(to_fqdn("example.com", "prod"), "example.com.svc.cluster.local")

    def test_empty(self) -> None:
        self.assertEqual(to_fqdn("", "prod"), "")


class MatchHostTest(unittest.TestCase):
    def test_star(self) -> None:
        self.assertTrue(match_host("*", "anything.example.com"))
        self.assertTrue(match_host("*", "reviews"))

    def test_wildcard_subdomain(self) -> None:
        self.assertTrue(match_host("*.example.com", "a.example.com"))
        self.assertTrue(match_host("*.example.com", "a.b.example.com"))
        self.assertFalse(match_host("*.example.com", "example.com"))
        self.assertFalse(match_host("*.example.com", "a.example.org"))
        self.assertFalse(match_host("*.example.com", "badexample.com"))

    def test_exact(self) -> None:
        self.assertTrue(match_host("api.example.com", "API.example.com."))
        self.assertFalse(match_host("api.example.com", "web.example.com"))

    def test_wildcard_vs_wildcard(self) -> None:
        self.assertTrue(match_host("*.example.com", "*.example.com"))
        self.assertTrue(match_host("*.example.com", "*.api.example.com"))
        self.assertFalse(match_host("*.api.example.com", "*.example.com"))

    def test_host_wildcard_against_name(self) -> None:
        # шаблон Gateway "*.example.com" ищем по конкретному имени — и наоборот
        self.assertTrue(match_host("api.example.com", "*.example.com"))

    def test_empty(self) -> None:
        self.assertFalse(match_host("", "a"))
        self.assertFalse(match_host("a", ""))

    def test_intersect(self) -> None:
        self.assertTrue(hosts_intersect("*.example.com", "api.example.com"))
        self.assertTrue(hosts_intersect("api.example.com", "*.example.com"))
        self.assertFalse(hosts_intersect("api.example.com", "*.example.org"))


class HelpersTest(unittest.TestCase):
    def test_is_cluster_host(self) -> None:
        self.assertTrue(is_cluster_host("reviews.prod.svc.cluster.local"))
        self.assertFalse(is_cluster_host("api.example.com"))
        self.assertTrue(is_cluster_host("a.b.svc.corp.local", "corp.local"))

    def test_split_service_fqdn(self) -> None:
        self.assertEqual(split_service_fqdn("reviews.prod.svc.cluster.local"), ("prod", "reviews"))
        self.assertIsNone(split_service_fqdn("api.example.com"))
        self.assertIsNone(split_service_fqdn("a.b.c.svc.cluster.local"))

    def test_service_fqdn(self) -> None:
        self.assertEqual(service_fqdn("Reviews", "prod"), "reviews.prod.svc.cluster.local")

    def test_split_ns_host(self) -> None:
        self.assertEqual(split_ns_host("prod/api.example.com"), ("prod", "api.example.com"))
        self.assertEqual(split_ns_host("*/api.example.com"), ("*", "api.example.com"))
        self.assertEqual(split_ns_host("api.example.com"), (None, "api.example.com"))

    def test_normalize(self) -> None:
        self.assertEqual(normalize("  A.B. "), "a.b")


if __name__ == "__main__":
    unittest.main()
