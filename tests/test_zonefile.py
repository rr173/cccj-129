"""Master file parsing: relative names, TTL handling, TXT escaping,
unknown types, and parse errors."""

import unittest

from dnsrepo.errors import ParseError, UnknownTypeError
from dnsrepo.zonefile import parse_master, tokenize

from .helpers import MASTER_V1


def parse(text, **kw):
    return parse_master(text, "example.com.", **kw).records


def one(text, **kw):
    """Parse and return the last record (fixtures prepend an SOA)."""
    recs = parse(text, **kw)
    assert recs
    return recs[-1]


SOA = "@ 300 IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n"


class RelativeNamesTest(unittest.TestCase):
    def test_bare_name_gets_origin(self):
        rec = one(SOA + "www A 192.0.2.1\n")
        self.assertEqual(rec.owner, "www.example.com.")

    def test_at_is_origin(self):
        rec = one(SOA + "@ MX 10 mail\n")
        self.assertEqual(rec.owner, "example.com.")

    def test_absolute_name_kept(self):
        rec = one(SOA + "www.example.com. A 192.0.2.1\n")
        self.assertEqual(rec.owner, "www.example.com.")

    def test_names_are_lowercased(self):
        rec = one(SOA + "WWW.Example.COM. A 192.0.2.1\n")
        self.assertEqual(rec.owner, "www.example.com.")

    def test_leading_whitespace_inherits_owner(self):
        recs = parse(SOA + "www A 192.0.2.1\n     A 192.0.2.2\n")
        self.assertEqual([r.owner for r in recs],
                         ["example.com.", "www.example.com.",
                          "www.example.com."])

    def test_first_record_without_owner_is_error(self):
        with self.assertRaises(ParseError):
            parse("  A 192.0.2.1\n")

    def test_origin_directive_switches_suffix(self):
        recs = parse(SOA + "$ORIGIN sub.example.com.\nhost A 192.0.2.1\n")
        self.assertEqual(recs[-1].owner, "host.sub.example.com.")

    def test_rdata_names_are_expanded(self):
        recs = parse(SOA + "@ MX 10 mail\nalias CNAME www\n@ NS ns1\n")
        mx, cname, ns = recs[1], recs[2], recs[3]
        self.assertEqual(mx.rdata, "10 mail.example.com.")
        self.assertEqual(cname.rdata, "www.example.com.")
        self.assertEqual(ns.rdata, "ns1.example.com.")

    def test_soa_rdata_names_expanded_serial_parsed(self):
        rec = one("@ IN SOA ns1 hostmaster 2024010100 7200 3600 1209600 300\n")
        self.assertEqual(
            rec.rdata,
            "ns1.example.com. hostmaster.example.com. 2024010100 "
            "7200 3600 1209600 300")

    def test_master_v1_fixture(self):
        parsed = parse_master(MASTER_V1, "example.com.")
        owners = {r.owner for r in parsed.records}
        self.assertIn("www.example.com.", owners)
        self.assertIn("alias.example.com.", owners)
        soa = [r for r in parsed.records if r.rtype == "SOA"][0]
        self.assertEqual(soa.owner, "example.com.")
        self.assertEqual(soa.line_no, 3)


class TtlTest(unittest.TestCase):
    def test_explicit_ttl(self):
        rec = one(SOA + "www 600 A 192.0.2.1\n")
        self.assertEqual(rec.ttl, 600)

    def test_default_ttl_directive(self):
        rec = one(SOA + "$TTL 900\nwww A 192.0.2.1\n")
        self.assertEqual(rec.ttl, 900)

    def test_explicit_ttl_beats_directive(self):
        rec = one(SOA + "$TTL 900\nwww 600 A 192.0.2.1\n")
        self.assertEqual(rec.ttl, 600)

    def test_ttl_after_class(self):
        rec = one(SOA + "www IN 600 A 192.0.2.1\n")
        self.assertEqual(rec.ttl, 600)

    def test_ttl_before_class(self):
        rec = one(SOA + "www 600 IN A 192.0.2.1\n")
        self.assertEqual(rec.ttl, 600)

    def test_soa_minimum_is_fallback(self):
        rec = one("@ SOA ns1 hostmaster 1 7200 3600 1209600 300\n"
                  "www A 192.0.2.1\n")
        self.assertEqual(rec.ttl, 300)

    def test_missing_ttl_and_no_default_is_error(self):
        with self.assertRaises(ParseError):
            parse("www A 192.0.2.1\n")  # no SOA, no $TTL

    def test_ttl_range(self):
        with self.assertRaises(ParseError):
            parse(SOA + "www 2147483648 A 192.0.2.1\n")
        rec = one(SOA + "www 0 A 192.0.2.1\n")
        self.assertEqual(rec.ttl, 0)


class TxtTest(unittest.TestCase):
    def txt(self, rdata):
        return one(SOA + "t TXT %s\n" % rdata).rdata

    def test_simple_quoted(self):
        self.assertEqual(self.txt('"hello"'), '"hello"')

    def test_bare_token(self):
        self.assertEqual(self.txt("v=spf1"), '"v=spf1"')

    def test_string_with_spaces_and_semicolon(self):
        self.assertEqual(self.txt('"v=spf1 -all; still one string"'),
                         '"v=spf1 -all; still one string"')

    def test_multiple_strings(self):
        self.assertEqual(self.txt('"foo" "bar"'), '"foo" "bar"')

    def test_escaped_quote(self):
        self.assertEqual(self.txt(r'"say \"hi\""'), r'"say \"hi\""')

    def test_escaped_backslash(self):
        self.assertEqual(self.txt(r'"a\\b"'), r'"a\\b"')

    def test_decimal_escape_decoded_and_reencoded(self):
        self.assertEqual(self.txt(r'"A\065B"'), '"AAB"')

    def test_non_printable_encoded_as_decimal(self):
        self.assertEqual(self.txt(r'"a\001b"'), r'"a\001b"')

    def test_empty_string(self):
        self.assertEqual(self.txt('""'), '""')

    def test_parens_inside_quotes_are_literal(self):
        self.assertEqual(self.txt('"(not a continuation)"'),
                         '"(not a continuation)"')

    def test_roundtrip_stability(self):
        text = SOA + 't TXT "a" "b \\"c\\" \\\\ \\009 end"\n'
        rdata1 = one(text).rdata
        rdata2 = one(SOA + "t TXT %s\n" % rdata1).rdata
        self.assertEqual(rdata1, rdata2)

    def test_unterminated_string(self):
        with self.assertRaises(ParseError):
            parse(SOA + 't TXT "oops\n')

    def test_bad_decimal_escape(self):
        with self.assertRaises(ParseError):
            self.txt(r'"a\12b"')

    def test_escape_over_255(self):
        with self.assertRaises(ParseError):
            self.txt(r'"a\300b"')

    def test_oversized_string(self):
        with self.assertRaises(ParseError):
            self.txt('"' + "x" * 256 + '"')

    def test_quote_not_allowed_in_other_rdata(self):
        with self.assertRaises(ParseError):
            parse(SOA + 'www CNAME "www"\n')


class UnknownTypeTest(unittest.TestCase):
    def test_unknown_type_rejected_by_default(self):
        with self.assertRaises(UnknownTypeError):
            parse(SOA + "www CAA 0 issue \"ca.example\"\n")

    def test_unknown_type_preserved_raw(self):
        rec = one(SOA + "www CAA 0 issue \"ca.example\"\n",
                  preserve_unknown=True)
        self.assertFalse(rec.known)
        self.assertEqual(rec.rtype, "CAA")
        self.assertEqual(rec.rdata, '0 issue "ca.example"')

    def test_unknown_type_roundtrip(self):
        text = SOA + "www CAA 0 issue \"ca.example\"\n"
        rec1 = one(text, preserve_unknown=True)
        rec2 = one(SOA + "www %s %s\n" % (rec1.rtype, rec1.rdata),
                   preserve_unknown=True)
        self.assertEqual(rec1.rdata, rec2.rdata)

    def test_rfc3597_type_mnemonic(self):
        rec = one(SOA + r"www TYPE65400 \# 4 0A0B0C0D" + "\n",
                  preserve_unknown=True)
        self.assertEqual(rec.rtype, "TYPE65400")
        self.assertEqual(rec.rdata, r"\# 4 0A0B0C0D")


class ParseErrorTest(unittest.TestCase):
    def test_bad_ipv4(self):
        with self.assertRaises(ParseError):
            parse(SOA + "www A 999.1.1.1\n")

    def test_bad_ipv6(self):
        with self.assertRaises(ParseError):
            parse(SOA + "www AAAA 12xz::1\n")

    def test_ipv6_canonicalized(self):
        rec = one(SOA + "www AAAA 2001:0DB8:0:0:0:0:0:1\n")
        self.assertEqual(rec.rdata, "2001:db8::1")

    def test_extra_rdata(self):
        with self.assertRaises(ParseError):
            parse(SOA + "www A 192.0.2.1 extra\n")

    def test_missing_rdata(self):
        with self.assertRaises(ParseError):
            parse(SOA + "www A\n")

    def test_unsupported_class(self):
        with self.assertRaises(ParseError):
            parse(SOA + "www CH A 192.0.2.1\n")

    def test_include_unsupported(self):
        with self.assertRaises(ParseError):
            parse(SOA + "$INCLUDE other.file\n")

    def test_unknown_directive(self):
        with self.assertRaises(ParseError):
            parse(SOA + "$GENERATE 1-9 $\n")

    def test_unbalanced_parens(self):
        with self.assertRaises(ParseError):
            parse(SOA + "www A ( 192.0.2.1\n")

    def test_stray_close_paren(self):
        with self.assertRaises(ParseError):
            parse(SOA + "www A 192.0.2.1 )\n")

    def test_missing_type(self):
        with self.assertRaises(ParseError):
            parse(SOA + "www\n")

    def test_error_reports_line_number(self):
        try:
            parse(SOA + "\n\nwww A 999.1.1.1\n")
        except ParseError as exc:
            self.assertEqual(exc.line, 4)
        else:
            self.fail("expected ParseError")

    def test_comments_and_blank_lines(self):
        recs = parse("; leading comment\n\n" + SOA + "; trailing\n"
                     "www A 192.0.2.1 ; inline\n")
        self.assertEqual(len(recs), 2)

    def test_multiline_record_line_number_is_start(self):
        rec = one("@ SOA ns1 hostmaster (\n 1 7200 3600 1209600 300 )\n")
        self.assertEqual(rec.line_no, 1)


class TokenizerTest(unittest.TestCase):
    def test_parenthesized_record_is_one_logical_line(self):
        lines = tokenize("@ SOA ns1 hostmaster (\n 1 2 3 4 5 )\n")
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].tokens,
                         ["@", "SOA", "ns1", "hostmaster", "1", "2", "3",
                          "4", "5"])

    def test_leading_ws_flag(self):
        lines = tokenize("a A 1.1.1.1\n  A 2.2.2.2\n")
        self.assertFalse(lines[0].leading_ws)
        self.assertTrue(lines[1].leading_ws)


if __name__ == "__main__":
    unittest.main()
