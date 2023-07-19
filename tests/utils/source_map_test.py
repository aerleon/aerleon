import json

from absl.testing import absltest

from aerleon.lib import yaml
from aerleon.utils.source_map import SourceMap, SourceMapBuilder, SourceMapFlatten

example_source_file_name = 'example.yaml'
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

expected_concat_output = '''

BEGIN FILTERS
PREAMBLE
FILTER 0
FILTER 0 > first-term
FILTER 0 > second-term
FILTER 1
FILTER 1 > first-term
FILTER 1 > second-term
END FILTERS

'''


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


def buildConcatSourceMap(output_name, output_file):
    concat_output = f"""

BEGIN FILTERS
{output_file}
END FILTERS

"""
    concat_source_map = [{"2:8": {"source_file": output_name}}]
    sm = SourceMap(concat_source_map)
    return concat_output, sm


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


class SourceMapFlattenTestSuite(absltest.TestCase):
    def setUp(self):
        super().setUp()
        smb = SourceMapBuilder()
        smb.source_file = example_source_file_name
        self.pol = buildExampleSourceMap(smb)
        self.map = SourceMap.loads(str(smb))
        self.map.setSource(example_source_file_name, self.pol)
        self.output = '\n'.join(smb.lines)
        self.output_name = 'example.acl'
        self.concat_output, self.concat_sm = buildConcatSourceMap(self.output_name, self.output)
        self.concat_output_name = 'example.cfg'
        self.sm = SourceMapFlatten(
            {
                self.output_name: self.map,
                self.concat_output_name: self.concat_sm,
            }
        ).flatten(self.concat_output_name)

    def testConcatSetup(self):
        # Just test that buildConcatSourceMap did what we expect
        self.assertEqual(self.concat_output, expected_concat_output)
        self.assertEqual(len(self.concat_sm.source_map), 1)
        self.assertEqual(
            list(self.concat_sm.source_map[0].values())[0]['source_file'], self.output_name
        )

    def testFlattenSources(self):
        self.assertEqual(len(self.sm.sources), 1)
        self.assertEqual(self.sm.sources[example_source_file_name], self.pol)

    def testFlattenSourceLookup(self):
        line_count = len(self.concat_output.splitlines())
        locators = []
        for line in range(line_count):
            locators.append(self.sm.getSourceLocationForLine(line))
        self.assertEqual(
            locators[5],
            {
                'filter': 0,
                'type': 'term',
                'source_file': 'example.yaml',
                'term': 1,
                'term_name': 'second-term',
            },
        )


class SourceMapTestSuite(absltest.TestCase):
    def setUp(self):
        super().setUp()
        sm = SourceMapBuilder()
        sm.source_file = example_source_file_name
        self.pol = buildExampleSourceMap(sm)
        self.map = SourceMap.loads(str(sm))
        self.map.setOutput(expected_output)
        self.map.setSource(example_source_file_name, self.pol)

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
        self.assertEqual(
            locators[1], {'filter': 0, 'source_file': 'example.yaml', 'type': 'header'}
        )
        self.assertEqual(
            locators[2],
            {
                'filter': 0,
                'type': 'term',
                'source_file': 'example.yaml',
                'term': 0,
                'term_name': 'first-term',
            },
        )
        self.assertEqual(
            locators[3],
            {
                'filter': 0,
                'type': 'term',
                'source_file': 'example.yaml',
                'term': 1,
                'term_name': 'second-term',
            },
        )
        self.assertEqual(
            locators[4], {'filter': 1, 'source_file': 'example.yaml', 'type': 'header'}
        )

        resolved_locators = [self.map.resolveSourceLocation(locator) for locator in locators]
        self.assertEqual(resolved_locators[1], self.pol.filters[0])  # Whole filter
        self.assertEqual(resolved_locators[2], self.pol.filters[0][1][0])  # First term object
        self.assertEqual(resolved_locators[3], self.pol.filters[0][1][1])  # Second term object
