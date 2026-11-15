"""Shared fixtures for dnsrepo tests."""

# A small but complete master zone file.  Line numbers matter to some
# tests; keep the layout stable.
#
#  1  $ORIGIN example.com.
#  2  $TTL 3600
#  3  @   IN  SOA ns1.example.com. hostmaster.example.com. (
#  4          2024010100 ; serial
#  5          7200       ; refresh
#  6          3600       ; retry
#  7          1209600    ; expire
#  8          300 )      ; minimum
#  9      IN  NS  ns1.example.com.
# 10      IN  NS  ns2.example.com.
# 11      IN  MX  10 mail.example.com.
# 12  ns1     A   192.0.2.1
# 13  ns2     A   192.0.2.2
# 14  mail    A   192.0.2.25
# 15  www 300 IN  A   192.0.2.80
# 16  www 300 IN  A   192.0.2.81
# 17  alias   CNAME   www
# 18  _text   TXT "v=spf1 -all"
MASTER_V1 = """\
$ORIGIN example.com.
$TTL 3600
@   IN  SOA ns1.example.com. hostmaster.example.com. (
        2024010100 ; serial
        7200       ; refresh
        3600       ; retry
        1209600    ; expire
        300 )      ; minimum
    IN  NS  ns1.example.com.
    IN  NS  ns2.example.com.
    IN  MX  10 mail.example.com.
ns1     A   192.0.2.1
ns2     A   192.0.2.2
mail    A   192.0.2.25
www 300 IN  A   192.0.2.80
www 300 IN  A   192.0.2.81
alias   CNAME   www
_text   TXT "v=spf1 -all"
"""

# Increment against MASTER_V1 (serial 2024010100 -> 2024010101).
#
#  1  $ZONE example.com.
#  2  $PREREQ 2024010100
#  3  $SERIAL 2024010101
#  4  $ADD
#  5  api 600 IN A 192.0.2.50
#  6  $REPLACE
#  7  www 300 IN A 192.0.2.90
#  8  $DELETE
#  9  mail A
# 10  _text
INCREMENT_V2 = """\
$ZONE example.com.
$PREREQ 2024010100
$SERIAL 2024010101
$ADD
api 600 IN A 192.0.2.50
$REPLACE
www 300 IN A 192.0.2.90
$DELETE
mail A
_text
$END
"""
