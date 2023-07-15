import json

from absl.testing import absltest

from aerleon.lib import yaml
from aerleon.utils.source_map import SourceMap, SourceMapBuilder

example_source_file_name = 'example.pol'
example_source_file_text = """
filters:
-   header:
        targets:
            arista:
    terms:
    -   name: first-term
        action: deny
    -   name: second-term
        action: deny
-   header:
        targets:
            arista:
    terms:
    -   name: first-term
        action: deny
    -   name: second-term
        action: deny
"""

expected_output = '''PREAMBLE
FILTER 0
FILTER 0 > first-term
FILTER 0 > second-term
FILTER 1
FILTER 1 > first-term
FILTER 1 > second-term'''


def buildExampleSourceMap(sm: "SourceMapBuilder"):

    pol = yaml.ParsePolicy(example_source_file_text, filename=example_source_file_name)

    lines = sm.lines
    sm.clear()

    lines.append('PREAMBLE')
    for i, (_, terms) in enumerate(pol.filters):

        sm.nextFilter()
        sm.startSpan('header')
        lines.append(f'FILTER {i}')
        sm.endSpan()

        for j, term in enumerate(terms):
            sm.startSpan('term', term=j, term_name=term.name)
            lines.append(f'FILTER {i} > {term.name}')
            sm.endSpan()
    return pol


class SourceMapBuilderTestSute(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.sm = SourceMapBuilder()
        self.sm.source_file = example_source_file_name
        self.pol = buildExampleSourceMap(self.sm)

    def testSpans(self):
        sm = self.sm
        self.assertEqual(len(sm.spans), 6)
        self.assertEqual(sm.spans[2]['type'], 'term')
        self.assertEqual(sm.spans[2]['data']['term'], 1)
        self.assertEqual(sm.spans[2]['data']['term_name'], 'second-term')

    def testLines(self):
        sm = self.sm
        self.assertEqual(len(sm.lines), 7)
        self.assertEqual('\n'.join(sm.lines), expected_output)

    def testStr(self):
        sm = self.sm
        data = json.loads(str(sm))
        self.assertEqual(len(data), len(sm.spans) + 1)
        self.assertEqual(list(data[0].values())[0]['source_file'], example_source_file_name)


class SourceMapTestSuite(absltest.TestCase):
    def setUp(self):
        super().setUp()
        sm = SourceMapBuilder()
        sm.source_file = example_source_file_name
        self.pol = buildExampleSourceMap(sm)
        self.map = SourceMap.loads(str(sm))
        self.map.setOutput(expected_output)
        self.map.setSource(self.pol)

    def testMapSpans(self):
        self.assertEqual(len(self.map.source_map), 7)

    def testResolveOutputLine(self):
        self.assertEqual(self.map.resolveOutputLine(3), 'FILTER 0 > second-term')

    def testLookup(self):
        line_count = len(expected_output.splitlines())
        locators = []
        for line in range(line_count):
            locators.append(self.map.getSourceLocationForLine(line))
        self.assertEqual(locators[0], None)
        self.assertEqual(locators[1], {'filter': 0, 'type': 'header'})
        self.assertEqual(
            locators[2], {'filter': 0, 'type': 'term', 'term': 0, 'term_name': 'first-term'}
        )
        self.assertEqual(
            locators[3], {'filter': 0, 'type': 'term', 'term': 1, 'term_name': 'second-term'}
        )
        self.assertEqual(locators[4], {'filter': 1, 'type': 'header'})

        resolved_locators = [self.map.resolveSourceLocation(locator) for locator in locators]
        self.assertEqual(resolved_locators[1], self.pol.filters[0])  # Whole filter
        self.assertEqual(resolved_locators[2], self.pol.filters[0][1][0])  # First term object
        self.assertEqual(resolved_locators[3], self.pol.filters[0][1][1])  # Second term object
