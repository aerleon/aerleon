import datetime

from absl.testing import absltest, parameterized

from aerleon.lib.recognizers import (
    TValue,
    TList,
    TUnion,
    TSection,
)


class PrebuiltRecognizerTest(parameterized.TestCase):
    """Test pre-made recognizers."""

    def assertTokenizerBehavior(self, tests, tokenizer):
        for (value, acceptable, expected) in tests:
            if acceptable:
                self.assertEqual(tokenizer.recognize(value), expected)
            else:
                with self.assertRaises(TypeError):
                    tokenizer.recognize(value)

    def assertListTokenizerBehavior(self, tests, tokenizer):
        for (value, acceptable, expected) in tests:
            if acceptable:
                self.assertEqual(list(tokenizer.recognize(value)), expected)
            else:
                with self.assertRaises(TypeError):
                    list(tokenizer.recognize(value))

    @parameterized.named_parameters(
        ("Name", "INBOUND", True, "INBOUND"),
        ("CIDR", "127.0.0.0/24", True, "127.0.0.0/24"),
        ("NameUnderscore", "NET_INTERNAL", True, "NET_INTERNAL"),
        ("FailWordList", "NAME1 NAME2", False, None),
        ("FailMultilineStr", "multi\nline\nstring", False, None),
        ("FailEmpty", "", False, None),
    )
    def testValueStr(self, value, acceptable, expected):
        tokenizer = TValue.WordString
        self.assertTokenizerBehavior([(value, acceptable, expected)], tokenizer)

    @parameterized.named_parameters(
        ("CIDR", "127.0.0.0/24", True, "127.0.0.0/24"),
        ("WordList", "NAME1 NAME2", True, "NAME1 NAME2"),
        ("MultilineStr", "multi\nline\nstring", True, "multi\nline\nstring"),
    )
    def testValueAny(self, value, acceptable, expected):
        tokenizer = TValue.AnyString
        self.assertTokenizerBehavior([(value, acceptable, expected)], tokenizer)

    @parameterized.named_parameters(
        ("YMD", "2022-03-25", True, datetime.date(2022, 3, 25)),
        ("FailSlashDate", "2022/03/25", False, None),
        ("FailEmpty", "", False, None),
    )
    def testValueYearMonthDay(self, value, acceptable, expected):
        tokenizer = TValue.YearMonthDay
        self.assertTokenizerBehavior([(value, acceptable, expected)], tokenizer)

    @parameterized.named_parameters(
        ("FrequencyOverPeriod", "100 / day", True, {"frequency": "100", "period": "day"}),
        ("Frequency", "100", False, None),
        ("FailEmpty", "", False, None),
    )
    def testValueLogLimit(self, value, acceptable, expected):
        tokenizer = TValue.LogLimit
        self.assertTokenizerBehavior([(value, acceptable, expected)], tokenizer)

    @parameterized.named_parameters(
        ("Range", "1000 - 9999", True, "1000-9999"),
        ("FailSingleValue", "1000", False, None),
        ("FailEmpty", "", False, None),
    )
    def testValueIntegerRange(self, value, acceptable, expected):
        tokenizer = TValue.IntegerRange
        self.assertTokenizerBehavior([(value, acceptable, expected)], tokenizer)

    @parameterized.named_parameters(
        ("SingleBinaryStr", "b001001", True, "b001001"),
        ("FailRange", "b001001-b100000", False, None),  # DSCPRange
        ("TrimAFValue", "  af11", True, "af11"),
        ("AFValue", "af32", True, "af32"),
        ("BEValue", "be", True, "be"),
        ("EFValue", "ef", True, "ef"),
        ("CSValue", "cs0", True, "cs0"),
        ("FailMultiValueList", "cs0 af11", False, None),
        ("FailEmpty", "", False, None),
    )
    def testValueDSCP(self, value, acceptable, expected):
        tokenizer = TValue.DSCP
        self.assertTokenizerBehavior([(value, acceptable, expected)], tokenizer)

    @parameterized.named_parameters(
        ("BinaryRange", "b001001-b100000", True, "b001001-b100000"),
        ("AFRange", "  af11-af41", True, "af11-af41"),
        ("BinarySingle", "b001001", True, "b001001"),
        ("FailMultiValue", "cs0 af11", False, None),
        ("FailEmpty", "", False, None),
    )
    def testValueDSCPRange(self, value, acceptable, expected):
        tokenizer = TValue.DSCPRange
        self.assertTokenizerBehavior([(value, acceptable, expected)], tokenizer)

    @parameterized.named_parameters(
        (
            "TupleList",
            ["(proj-1, vpc1)", "(proj-2, vpc2)"],
            True,
            [("proj-1", "vpc1"), ("proj-2", "vpc2")],
        ),
        (
            "TupleAsList",
            [["proj-1", "vpc1"], ["proj-2", "vpc2"]],
            True,
            [("proj-1", "vpc1"), ("proj-2", "vpc2")],
        ),
        ("SingleTuple", ["(proj-1, vpc1)"], True, [("proj-1", "vpc1")]),
        ("CollapsedList", "(proj-1, vpc1)", True, [("proj-1", "vpc1")]),
        ("SingleTupleAsList", ["proj-1", "vpc1"], True, [("proj-1", "vpc1")]),
        ("FailNoTuple", [[]], False, None),
        ("EmptyList", [], True, []),
        ("FailEmpty", "", False, None),
    )
    def testListTargetResourceTuple(self, value, acceptable, expected):
        tokenizer = TList(of=TValue.TargetResourceTuple, collapsible=True)
        self.assertListTokenizerBehavior([(value, acceptable, expected)], tokenizer)

    @parameterized.named_parameters(
        ("WordList", "NET_INTERNAL NET_EXTERNAL", True, ["NET_INTERNAL", "NET_EXTERNAL"]),
        ("CIDRWordList", "127.0.1.0/24 127.0.0.0/24", True, ["127.0.1.0/24", "127.0.0.0/24"]),
        ("ListTrim", ["     INBOUND", "     OUTBOUND"], True, ["INBOUND", "OUTBOUND"]),
        ("SingleValue", "SINGLE_VALUE", True, ["SINGLE_VALUE"]),
        ("ListSingleValue", ["SINGLE_VALUE"], True, ["SINGLE_VALUE"]),
        ("FailEmpty", "", True, []),
    )
    def testListStr(self, value, acceptable, expected):
        tokenizer = TList(of=TValue.WordString)
        self.assertListTokenizerBehavior([(value, acceptable, expected)], tokenizer)

    @parameterized.named_parameters(
        ("StringList", "1 2 3 4", True, [1, 2, 3, 4]),
        ("ListStrings", ["1", "2", "3", "4"], True, [1, 2, 3, 4]),
        ("ListInts", [1, 2, 3, 4], True, [1, 2, 3, 4]),
        ("FailSingleInt", 1, False, None),  # Collapsed list
        ("FailSingleWord", "word", False, None),
        ("FailListWord", ["word"], False, None),
    )
    def testListInteger(self, value, acceptable, expected):
        tokenizer = TList(of=TValue.Integer)
        self.assertListTokenizerBehavior([(value, acceptable, expected)], tokenizer)

    @parameterized.named_parameters(
        (
            "SectionList",
            [{"key1": "1 2 3"}, {"key1": 100}],
            True,
            [{"key1": [1, 2, 3]}, {"key1": [100]}],
        ),
        ("FailWrongSectionType", [{"key1": "word"}, {"key1": 100}], False, None),
        ("EmptyList", [], True, []),
        ("CollapsedList", {"key1": "1 2 3"}, True, [{"key1": [1, 2, 3]}]),
        ("FailNotSection", "word", False, None),
        ("FailListNotSection", ["word"], False, None),
    )
    def testListSection(self, value, acceptable, expected):
        tokenizer = TList(
            of=TSection(of=[("key1", TList(of=TValue.Integer, collapsible=True))]),
            collapsible=True,
        )
        self.assertTokenizerBehavior([(value, acceptable, expected)], tokenizer)

    @parameterized.named_parameters(
        ("List", [1, 2, 3, 4], True, [1, 2, 3, 4]),
        ("CollapsedList", 1, True, [1]),  # Collapsed list
        ("FailNotInteger", "word", False, None),
    )
    def testListCollapse(self, value, acceptable, expected):
        tokenizer = TList(of=TValue.Integer, collapsible=True)
        self.assertListTokenizerBehavior([(value, acceptable, expected)], tokenizer)

    def testFlexMatch(self):
        # Collapsible section list
        tests = [
            (
                {"match-start": "layer-3", "bit-length": 16, "range": "0x08"},
                True,
                {"match-start": "layer-3", "bit-length": 16, "range": "0x08"},
            ),
        ]
        tokenizer = TSection(
            of=[(TValue.WordString, TUnion(of=[TValue.Integer, TValue.Hex, TValue.WordString]))]
        )
        self.assertTokenizerBehavior(tests, tokenizer)


if __name__ == '__main__':
    absltest.main()
