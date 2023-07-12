import json

from absl.testing import absltest

from aerleon.utils.source_map import SourceMapBuilder

example_source_file_name = 'example.pol'

example_source_file = [
    ['first-term', 'second-term'],
    ['first-term', 'second-term'],
]

expected_output = '''PREAMBLE
FILTER 0
FILTER 0 > first-term
FILTER 0 > second-term
FILTER 1
FILTER 1 > first-term
FILTER 1 > second-term'''


class SourceMapTestSute(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.sm = SourceMapBuilder()
        self.sm.source_file = example_source_file_name
        self.buildExampleSourceMap()

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

    def buildExampleSourceMap(self):
        sm = self.sm

        lines = sm.lines
        sm.clear()

        lines.append('PREAMBLE')
        for i, filter in enumerate(example_source_file):

            sm.nextFilter()
            sm.startSpan('header')
            lines.append(f'FILTER {i}')
            sm.endSpan()

            for j, term in enumerate(filter):
                sm.startSpan('term', term=j, term_name=term)
                lines.append(f'FILTER {i} > {term}')
                sm.endSpan()
