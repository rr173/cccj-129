"""Zone file generator: canonical rendering and round-trips."""

import unittest

from dnsrepo.generator import render_zone
from dnsrepo.validate import validate_zone
from dnsrepo.zonefile import parse_master

from .helpers import MASTER_V1


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.records = parse_master(MASTER_V1, "example.com.").records
        self.text = render_zone("example.com.", 2024010100, self.records)

    def test_header(self):
        lines = self.text.splitlines()
        self.assertEqual(lines[0], "$ORIGIN example.com.")
        self.assertTrue(lines[1].startswith("$TTL "))

    def test_soa_rendered_multiline_with_serial(self):
        self.assertIn("2024010100 ; serial", self.text)
        self.assertIn("@ 3600 IN SOA ns1.example.com. "
                      "hostmaster.example.com. (", self.text)

    def test_relative_names_and_explicit_ttls(self):
        self.assertIn("www 300 IN A 192.0.2.80", self.text)
        self.assertIn("ns1 3600 IN A 192.0.2.1", self.text)
        self.assertIn("alias 3600 IN CNAME www.example.com.", self.text)
        self.assertIn("@ 3600 IN MX 10 mail.example.com.", self.text)

    def test_roundtrip_is_stable(self):
        reparsed = parse_master(self.text, "example.com.").records
        validate_zone(reparsed, "example.com.", 2024010100)
        self.assertEqual({r.key() for r in reparsed},
                         {r.key() for r in self.records})
        # rendering again produces identical text
        again = render_zone("example.com.", 2024010100, reparsed)
        self.assertEqual(again, self.text)

    def test_txt_quoting_preserved(self):
        self.assertIn('_text 3600 IN TXT "v=spf1 -all"', self.text)


if __name__ == "__main__":
    unittest.main()
