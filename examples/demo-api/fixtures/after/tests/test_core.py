from __future__ import annotations

import sys
import unittest
from pathlib import Path

FIXTURE_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(FIXTURE_ROOT))

from core import MAX_PAGE_SIZE, build_user_search  # noqa: E402


class UserSearchTests(unittest.TestCase):
    def test_query_uses_bound_parameters(self):
        query, parameters = build_user_search("alice", 25)
        self.assertNotIn("alice", query)
        self.assertEqual(parameters, ("%alice%", 25))

    def test_page_size_is_bounded(self):
        with self.assertRaises(ValueError):
            build_user_search("alice", MAX_PAGE_SIZE + 1)


if __name__ == "__main__":
    unittest.main()
