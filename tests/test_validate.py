"""Zone validation: CNAME conflicts and loops, zone boundary, SOA
presence, serial monotonicity."""

import os
import tempfile
import unittest

from dnsrepo.errors import (CNAMEConflictError, CNAMELoopError,
                            OutOfZoneError, SerialError, ValidationError)
from dnsrepo.repo import Repository

SOA = "@ 300 IN SOA ns1 hostmaster %d 7200 3600 1209600 300\n"


def zone_with(body, serial=1):
    return SOA % serial + body


class ValidationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(os.path.join(self.tmp.name, "test.db"))

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def publish(self, text):
        return self.repo.publish_master("example.com.", text)

    # -- CNAME conflicts --------------------------------------------
    def test_cname_with_a_record_rejected(self):
        with self.assertRaises(CNAMEConflictError):
            self.publish(zone_with(
                "www CNAME other\nwww A 192.0.2.1\n"))

    def test_cname_with_txt_rejected(self):
        with self.assertRaises(CNAMEConflictError):
            self.publish(zone_with(
                'www CNAME other\nwww TXT "x"\n'))

    def test_two_cnames_same_name_rejected(self):
        with self.assertRaises(CNAMEConflictError):
            self.publish(zone_with(
                "www CNAME a\nwww CNAME b\n"))

    def test_cname_at_apex_rejected(self):
        # the apex always has an SOA, so a CNAME there conflicts
        with self.assertRaises(CNAMEConflictError):
            self.publish(zone_with("@ CNAME elsewhere.example.\n"))

    def test_cname_conflicts_with_preserved_unknown(self):
        repo = Repository(os.path.join(self.tmp.name, "u.db"),
                          preserve_unknown=True)
        try:
            with self.assertRaises(CNAMEConflictError):
                repo.publish_master("example.com.", zone_with(
                    "www CNAME other\nwww CAA 0 issue \"ca.example\"\n"))
        finally:
            repo.close()

    # -- CNAME loops --------------------------------------------------
    def test_self_loop_rejected(self):
        with self.assertRaises(CNAMELoopError):
            self.publish(zone_with("loop CNAME loop\n"))

    def test_two_node_loop_rejected(self):
        with self.assertRaises(CNAMELoopError):
            self.publish(zone_with(
                "a CNAME b\nb CNAME a\n"))

    def test_three_node_loop_rejected(self):
        with self.assertRaises(CNAMELoopError):
            self.publish(zone_with(
                "a CNAME b\nb CNAME c\nc CNAME a\n"))

    def test_cname_chain_is_fine(self):
        info = self.publish(zone_with(
            "a CNAME b\nb CNAME c\nc A 192.0.2.1\n"))
        self.assertEqual(info.serial, 1)

    def test_dangling_external_cname_is_fine(self):
        info = self.publish(zone_with(
            "www CNAME host.other-zone.example.\n"))
        self.assertEqual(info.serial, 1)

    # -- zone boundary ------------------------------------------------
    def test_out_of_zone_record_rejected(self):
        with self.assertRaises(OutOfZoneError):
            self.publish(zone_with("evil.other.com. A 192.0.2.1\n"))

    def test_out_of_zone_via_origin_switch(self):
        text = zone_with("") + "$ORIGIN other.com.\nx A 192.0.2.1\n"
        with self.assertRaises(OutOfZoneError):
            self.publish(text)

    def test_subdomain_record_is_in_zone(self):
        info = self.publish(zone_with("deep.sub.example.com. A 192.0.2.1\n"))
        self.assertEqual(info.serial, 1)

    def test_wrong_zone_file_rejected(self):
        # a zone file whose SOA sits at a different apex
        text = ("$ORIGIN other.com.\n"
                "@ 300 IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n")
        with self.assertRaises(ValidationError):
            self.publish(text)

    # -- SOA ------------------------------------------------------------
    def test_missing_soa_rejected(self):
        with self.assertRaises(ValidationError):
            self.publish("www 300 IN A 192.0.2.1\n")

    def test_two_soa_rejected(self):
        with self.assertRaises(ValidationError):
            self.publish(zone_with(
                "sub 300 IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n"))

    def test_duplicate_record_rejected(self):
        with self.assertRaises(ValidationError):
            self.publish(zone_with(
                "www A 192.0.2.1\nwww A 192.0.2.1\n", serial=2))

    # -- serial monotonicity ------------------------------------------
    def test_master_serial_must_increase(self):
        self.publish(zone_with("", serial=100))
        with self.assertRaises(SerialError):
            self.publish(zone_with("", serial=100))
        with self.assertRaises(SerialError):
            self.publish(zone_with("", serial=99))
        info = self.publish(zone_with("", serial=101))
        self.assertEqual(info.serial, 101)

    def test_serial_wraparound_accepted(self):
        self.publish(zone_with("", serial=4294967295))
        info = self.publish(zone_with("", serial=0))
        self.assertEqual(info.serial, 0)

    def test_serial_half_space_rejected(self):
        self.publish(zone_with("", serial=0))
        with self.assertRaises(SerialError):
            self.publish(zone_with("", serial=2147483648))


if __name__ == "__main__":
    unittest.main()
