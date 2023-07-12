"""Utilities for building and loading source map files."""

import json
import typing
from typing import Optional, TypedDict

if typing.TYPE_CHECKING:
    from aerleon.lib.policy import Policy


def getCursor(sm: "SourceMapBuilder"):
    l = len(sm.lines)
    if l == 0:
        c = 0
    else:
        c = len(sm.lines[-1])
    return l - 1, c


def formatCursor(pos):
    return ':'.join((str(i) for i in pos))


class SourceMapBuilder:
    """Builds up and emits a source map file.

    The logical structure of the source map is a list of text spans paired with metadata
    about those spans. Not all characters in the generated file are necessarily covered
    by a span with metadata.

    The structure of the source map is an array of objects. Each object has a single key
    which describes the start and end of the span, e.g. "0:0:8:27" represents the text span
    starting at line 0, character 0, ending at line 8, character 27. This names a span in the
    genrated file. The object value for that key is the span metadata. The span metadata can
    have the following fields:

        filter: int (required) - the position of the filter in the file, where 0 means the first
        filter and 1 means the second.
        type: str (required) - can be "header" or "term".
        term: int (optional) - if the type is "term", the position of the term in the filter.
        term list.
        term_name: str (optional) - if the type is "term", the name of the term.

    Conventionally, the first span should refer to the entire file and contain whole-file metadata.

        source_file: str - the name of the Aerleon file used to generate this file

    Members:
        lines: list[str] - The lines of the ACL file being generated.
        spans: list[dict] - Source map spans added by startSpan.
        source_file: str - The name of the source policy file used to generate the ACL file.
    """

    def __init__(self):
        self.lines = []
        self.spans = []
        self.source_file = ''
        self._current_filter = None
        super().__init__()

    def clear(self):
        self.lines.clear()
        self.spans.clear()
        self._current_filter = None

    def nextFilter(self):
        if self._current_filter is None:
            self._current_filter = 0
        else:
            self._current_filter = self._current_filter + 1

    def startSpan(self, span_type, **kwargs):
        self.spans.append(
            {
                "start": getCursor(self),
                "filter": self._current_filter,
                "type": span_type,
                "data": kwargs,
            }
        )

    def endSpan(self):
        if not len(self.spans):
            return
        last_span = self.spans[-1]
        last_span["end"] = getCursor(self)

    def __str__(self):
        emit = []
        key = f"{formatCursor((0,0))}:{formatCursor(getCursor(self))}"
        entry = {key: {"source_file": self.source_file}}
        emit.append(entry)
        for span in self.spans:
            key = f"{formatCursor(span['start'])}:{formatCursor(span['end'])}"
            value = {
                "filter": span['filter'],
                "type": span['type'],
            }
            if span['type'] == 'term':
                value['term'] = span['data']['term']
                value['term_name'] = span['data']['term_name']

            entry = {key: value}
            emit.append(entry)
        return json.dumps(emit)


SourceMapFile = "list[dict[str, SourceMapValue]]"


class SourceMapValue(TypedDict):
    filter: int
    type: str
    term: "Optional[int]"
    term_name: "Optional[str]"


class SourceMap:
    """A source map relates a generated file"""

    @classmethod
    def load(cls, path):
        with open(path, 'r') as f:
            return cls.loads(f.read())

    @classmethod
    def loads(cls, file):
        return cls(json.loads(file))

    def __init__(self, source_map: "SourceMapFile", source=None, output=None):
        self.source_map = source_map
        self.source = source
        self.output = output

    def setSource(self, pol: "Policy"):
        self.source = pol

    def setOutput(self, file: str):
        self.output = file

    def resolveOutputLine(self, line):
        if not self.output:
            return
        return self.output.splitlines()[line]

    def resolveSourceLocation(self, locator: "SourceMapValue"):
        if not self.source:
            return
        vtype = locator['type']
        filter = locator['filter']
        src_filter = self.source.filters[filter]
        if vtype == 'header':
            return src_filter
        if vtype == 'term':
            term = locator['term']
            return src_filter.terms[term]

    def isLineInSpan(self, line, span):
        parts = span.split(':')

    def getSourceLocationForLine(self, line):
        pass
