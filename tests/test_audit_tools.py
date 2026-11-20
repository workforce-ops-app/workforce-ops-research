"""Tests for audit/check_signed_out.py: it must never send a request anywhere but this
computer, and it must sort answers correctly, or a refused endpoint could be reported as
open (or an open one as refused)."""

import importlib.util
import unittest
from pathlib import Path

# audit/ is not a package, so load the script from its path.
_PATH = Path(__file__).resolve().parent.parent / "audit" / "check_signed_out.py"
_SPEC = importlib.util.spec_from_file_location("check_signed_out", _PATH)
check = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check)


class TargetTest(unittest.TestCase):
    def test_local_targets_are_accepted(self):
        self.assertEqual(check.check_target("http://localhost:8080/"), "http://localhost:8080")
        self.assertEqual(check.check_target("http://127.0.0.1:8000"), "http://127.0.0.1:8000")

    def test_any_other_host_is_refused(self):
        for target in (
            "https://example.com",
            "http://localhost.example.com:8080",
            "http://10.0.0.5:8080",
            "ftp://localhost/",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                check.check_target(target)


class PathTest(unittest.TestCase):
    def test_every_parameter_is_filled(self):
        self.assertEqual(
            check.fill_path("/api/teams/{team_id}/members/{user_id}", "X"), "/api/teams/X/members/X"
        )
        self.assertEqual(check.fill_path("/api/health", "X"), "/api/health")


class ClassifyTest(unittest.TestCase):
    def test_a_401_is_a_refusal(self):
        self.assertEqual(check.classify("GET", "/api/users", 401), "refused")

    def test_anything_else_needs_a_look(self):
        for status in (200, 204, 403, 404, 405, 422, 500):
            with self.subTest(status=status):
                self.assertEqual(check.classify("GET", "/api/users", status), "look")

    def test_public_operations_are_marked_public_whatever_they_answer(self):
        self.assertEqual(check.classify("POST", "/api/sign-up", 422), "public")
        self.assertEqual(check.classify("GET", "/api/health", 200), "public")
        # The same path with another method is not public.
        self.assertEqual(check.classify("GET", "/api/sessions", 200), "look")


class OperationsTest(unittest.TestCase):
    def test_reads_methods_and_sorts(self):
        document = {
            "paths": {
                "/api/b": {"get": {}, "post": {}, "parameters": []},
                "/api/a": {"delete": {}},
            }
        }
        self.assertEqual(
            check.operations(document), [("DELETE", "/api/a"), ("GET", "/api/b"), ("POST", "/api/b")]
        )


if __name__ == "__main__":
    unittest.main()
