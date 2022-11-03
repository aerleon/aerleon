import datetime

from absl.testing import absltest

from aerleon.lib.recognizers import (
    TValue,
    TList,
    TUnion,
    TSection,
)


class PrebuiltRecognizerTest(absltest.TestCase):
    """Test pre-made recognizers."""

    def assertBehaviorTable(self, tests, tokenizer):
        for (value, acceptable, expected) in tests:
            if acceptable:
                self.assertEqual(tokenizer.recognize(value), expected)
            else:
                with self.assertRaises(TypeError):
                    tokenizer.recognize(value)

    def assertBehaviorTableList(self, tests, tokenizer):
        for (value, acceptable, expected) in tests:
            if acceptable:
                self.assertEqual(list(tokenizer.recognize(value)), expected)
            else:
                with self.assertRaises(TypeError):
                    list(tokenizer.recognize(value))

    def testValueStr(self):
        tests = [
            ("INBOUND", True, "INBOUND"),
            ("127.0.0.0/24", True, "127.0.0.0/24"),
            ("NET_INTERNAL", True, "NET_INTERNAL"),
            ("NAME1 NAME2", False, None),
            ("multi\nline\nstring", False, None),
            ("", False, None),
        ]
        tokenizer = TValue.WordString
        self.assertBehaviorTable(tests, tokenizer)

    def testValueAny(self):
        tests = [
            ("127.0.0.0/24", True, "127.0.0.0/24"),
            ("NAME1 NAME2", True, "NAME1 NAME2"),
            ("multi\nline\nstring", True, "multi\nline\nstring"),
        ]
        tokenizer = TValue.AnyString
        self.assertBehaviorTable(tests, tokenizer)

    def testValueYearMonthDay(self):
        tests = [
            ("2022-03-25", True, datetime.date(2022, 3, 25)),
            ("2022/03/25", False, None),
            ("", False, None),
        ]
        tokenizer = TValue.YearMonthDay
        self.assertBehaviorTable(tests, tokenizer)

    def testValueLogLimit(self):
        tests = [
            ("100 / day", True, {"frequency": "100", "period": "day"}),
            ("100", False, None),
            ("", False, None),
        ]
        tokenizer = TValue.LogLimit
        self.assertBehaviorTable(tests, tokenizer)

    def testValueIntegerRange(self):
        tests = [
            ("1000 - 9999", True, {"start": "1000", "end": "9999"}),
            ("1000", False, None),
            ("", False, None),
        ]
        tokenizer = TValue.IntegerRange
        self.assertBehaviorTable(tests, tokenizer)

    def testValueDSCP(self):
        tests = [
            ("b001001", True, "b001001"),
            ("b001001-b100000", False, None),  # DSCPRange
            ("  af11", True, "af11"),
            ("af32", True, "af32"),
            ("be", True, "be"),
            ("ef", True, "ef"),
            ("cs0", True, "cs0"),
            ("cs0 af11", False, None),
            ("", False, None),
        ]
        tokenizer = TValue.DSCP
        self.assertBehaviorTable(tests, tokenizer)

    def testValueDSCPRange(self):
        tests = [
            ("b001001-b100000", True, "b001001-b100000"),
            ("  af11-af41", True, "af11-af41"),
            ("b001001", False, None),
            ("cs0 af11", False, None),
            ("", False, None),
        ]
        tokenizer = TValue.DSCPRange
        self.assertBehaviorTable(tests, tokenizer)

    def testListTargetResourceTuple(self):
        tests = [
            (["(proj-1, vpc1)", "(proj-2, vpc2)"], True, [("proj-1", "vpc1"), ("proj-2", "vpc2")]),
            (
                [["proj-1", "vpc1"], ["proj-2", "vpc2"]],
                True,
                [("proj-1", "vpc1"), ("proj-2", "vpc2")],
            ),
            (["(proj-1, vpc1)"], True, [("proj-1", "vpc1")]),
            ("(proj-1, vpc1)", True, [("proj-1", "vpc1")]),
            (["proj-1", "vpc1"], True, [("proj-1", "vpc1")]),
            ([[]], False, None),
            ([], True, []),
            ("", False, None),
        ]
        tokenizer = TList(of=TValue.TargetResourceTuple, collapsible=True)
        self.assertBehaviorTableList(tests, tokenizer)

    def testListStr(self):
        # Str list
        tests = [
            ("NET_INTERNAL NET_EXTERNAL", True, ["NET_INTERNAL", "NET_EXTERNAL"]),
            ("127.0.1.0/24 127.0.0.0/24", True, ["127.0.1.0/24", "127.0.0.0/24"]),
            (["     INBOUND", "     OUTBOUND"], True, ["INBOUND", "OUTBOUND"]),
            ("SINGLE_VALUE", True, ["SINGLE_VALUE"]),
            (["SINGLE_VALUE"], True, ["SINGLE_VALUE"]),
            ("", True, []),
        ]
        tokenizer = TList(of=TValue.WordString)
        self.assertBehaviorTableList(tests, tokenizer)

    def testListInteger(self):
        # Integer list
        tests = [
            ("1 2 3 4", True, ["1", "2", "3", "4"]),
            (["1", "2", "3", "4"], True, ["1", "2", "3", "4"]),
            ([1, 2, 3, 4], True, ["1", "2", "3", "4"]),
            (1, False, None),  # Collapsed list
            ("word", False, None),
            (["word"], False, None),
        ]
        tokenizer = TList(of=TValue.Integer)
        self.assertBehaviorTableList(tests, tokenizer)

    def testListSection(self):
        # Collapsible section list
        tests = [
            (
                [{"key1": "1 2 3"}, {"key1": "100"}],
                True,
                [{"key1": ["1", "2", "3"]}, {"key1": ["100"]}],
            ),
            ([{"key1": "word"}, {"key1": 100}], False, None),
            ([], True, []),
            ({"key1": "1 2 3"}, True, [{"key1": ["1", "2", "3"]}]),  # Collapsed list
            ("word", False, None),
            (["word"], False, None),
        ]
        tokenizer = TList(of=TSection(of=[("key1", TList(of=TValue.Integer))]), collapsible=True)
        self.assertBehaviorTable(tests, tokenizer)

    def testListCollapse(self):
        # Collapsible integer list
        tests = [
            ([1, 2, 3, 4], True, ["1", "2", "3", "4"]),
            (1, True, ["1"]),  # Collapsed list
            ("word", False, None),
        ]
        tokenizer = TList(of=TValue.Integer, collapsible=True)
        self.assertBehaviorTableList(tests, tokenizer)

    def testFlexMatch(self):
        # Collapsible section list
        tests = [
            (
                {"match-start": "layer-3", "bit-length": 16, "range": "0x08"},
                True,
                {"match-start": "layer-3", "bit-length": "16", "range": "0x08"},
            ),
        ]
        tokenizer = TSection(
            of=[(TValue.WordString, TUnion(of=[TValue.Integer, TValue.Hex, TValue.WordString]))]
        )
        self.assertBehaviorTable(tests, tokenizer)


if __name__ == '__main__':
    absltest.main()
