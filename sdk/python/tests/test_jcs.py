"""
RFC 8785 (JCS) conformance tests for the Python canonicalizer.

These run without Node.js, so CI catches canonical-form regressions even when
the cross-language interop suite is skipped.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rcpt.hashing import canonical_serialize


def jcs(obj) -> str:
    return canonical_serialize(obj).decode("utf-8")


class TestJCSNumbers(unittest.TestCase):
    """ECMAScript Number.prototype.toString layout (RFC 8785 §3.2.2.3)."""

    VECTORS = [
        (0.0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (-1.0, "-1"),
        (0.5, "0.5"),
        (0.95, "0.95"),
        (123.456, "123.456"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (2.5e-7, "2.5e-7"),
        (1e16, "10000000000000000"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1.5e300, "1.5e+300"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (0.1 + 0.2, "0.30000000000000004"),
        (-123.0, "-123"),
        (333333333.3333333, "333333333.3333333"),
        (4.5e15, "4500000000000000"),
    ]

    def test_vectors(self):
        for value, expected in self.VECTORS:
            with self.subTest(value=value):
                self.assertEqual(jcs(value), expected)

    def test_ints_unchanged(self):
        self.assertEqual(jcs(0), "0")
        self.assertEqual(jcs(-42), "-42")
        self.assertEqual(jcs(10**15), "1000000000000000")

    def test_integral_float_equals_int(self):
        """A float and int of equal value must canonicalize identically (JSON has one number type)."""
        self.assertEqual(jcs({"a": 3.0}), jcs({"a": 3}))

    def test_non_finite_rejected(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    jcs(bad)


class TestJCSStructure(unittest.TestCase):

    def test_null_values_kept(self):
        self.assertEqual(jcs({"b": None, "a": 1}), '{"a":1,"b":null}')

    def test_nested_null_in_list(self):
        self.assertEqual(jcs([1, None, "x"]), '[1,null,"x"]')

    def test_key_order_utf16(self):
        """U+1F600 (surrogate pair D83D...) sorts before U+FB01 in UTF-16, after it by code point."""
        self.assertEqual(jcs({"ﬁ": 1, "\U0001F600": 2}), '{"\U0001F600":2,"ﬁ":1}')

    def test_rfc8785_example_ordering(self):
        """Key-sorting example from RFC 8785 §3.2.3."""
        obj = {"€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh",
               "1": "One", "\U0001f600": "Emoji: Grinning Face", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis"}
        keys_in_order = ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"]
        out = jcs(obj)
        positions = [out.index(f'"{k}"' if k != "\r" else '"\\r"') for k in keys_in_order]
        self.assertEqual(positions, sorted(positions))


if __name__ == "__main__":
    unittest.main()
