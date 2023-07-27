"""Utilities for building and loading source map files."""

import json
import typing
from copy import copy, deepcopy
from typing import Optional, TypedDict

if typing.TYPE_CHECKING:
    from aerleon.lib.policy import Policy


def getCursor(sm: "SourceMapBuilder", start: bool = False):
    l = len(sm.lines)
    if l == 0:
        return 0
    if sm._offset_cursor < l:
        # Check latest lines for newlines
        for i in range(sm._offset_cursor, l):
            sm._offset = sm._offset + sm.lines[i].count('\n')
        sm._offset_cursor = l
    l = l + sm._offset
    if start:
        # Start at the beginning of the next line (unless len() == 0)
        l = l + 1
    return l - 1


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

    def __init__(self, source_file=None):
        self.lines = []
        self.spans = []
        self.source_file = source_file if source_file is not None else ''
        self._current_filter = None
        self._offset = 0
        self._offset_cursor = 0
        super().__init__()

    def clear(self):
        self.lines.clear()
        self.spans.clear()
        self._current_filter = None
        self._offset = 0
        self._offset_cursor = 0

    def nextFilter(self):
        if self._current_filter is None:
            self._current_filter = 0
        else:
            self._current_filter = self._current_filter + 1

    def startSpan(self, span_type, **kwargs):
        self.spans.append(
            {
                "start": getCursor(self, start=True),
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

    def toJSON(self):
        emit = []
        key = f"{str(0)}:{str(getCursor(self))}"
        entry = {key: {"source_file": self.source_file}}
        emit.append(entry)
        for span in self.spans:
            key = f"{str(span['start'])}:{str(span['end'])}"
            value = {
                "filter": span['filter'],
                "type": span['type'],
            }
            if span['type'] == 'term':
                value['term'] = span['data']['term']
                value['term_name'] = span['data']['term_name']

            entry = {key: value}
            emit.append(entry)
        return emit

    def __str__(self):
        return json.dumps(self.toJSON())


class SourceMapFlatten(dict):
    """Flatten referenced source maps into a parent source map.

    The journey from an original source file to a generated file sometimes
    has multiple processing steps. For example, a generated ACL might later
    be concatenated into a larger config file. The user ultimately needs
    a single source map file for the final config file and SourceMapFlatten
    is designed to assemble that file from the intermediate source maps.

    Functionally this class extends dict. It expects to be initialized as
    a mapping from file name to SourceMap. Use .flatten(primary_file) to
    produce a source map with simple source_file ranges replaced by
    the source map for the source_file (if we have one)."""

    def flatten(self: "dict[str, SourceMap]", primary_file: str):
        """Flatten referenced source maps into a parent source map."""
        primary = self[primary_file]
        sm = copy(primary)

        def offset(span: str, offset_span: str):
            """Adjust span by the start of offset_span."""
            parts1 = span.split(':')
            parts2 = offset_span.split(':')
            assert len(parts1) == 2 and len(parts2) == 2
            line = int(parts2[0])
            return ":".join(
                [
                    str(int(parts1[0]) + line),
                    str(int(parts1[1]) + line),
                ]
            )

        spans = copy(sm.source_map)
        for span in spans:
            # Look for terminal spans that refer to a source_file
            # for which we have the source map, and don't already
            # contain interior spans
            if _SourceMap_isTerminalSpan(span):
                continue

            source_file = list(span.values())[0].get('source_file', None)
            if source_file not in self:
                continue

            span_key = list(span.keys())[0]
            if len(sm.getIntersectingSpans(span_key)) > 1:
                # If we already have spans within this file locator, assume the
                # source map was already flattened.
                continue

            # Collect the contents of the source map here (filtering out the top-level file span)
            donor_spans = self[source_file]
            # Offset all spans by the file span start location
            for dspan in donor_spans.source_map:
                dspan_items = list(dspan.items())
                dspan_key = dspan_items[0][0]
                dspan_key = offset(dspan_key, span_key)
                dspan = {dspan_key: dspan_items[0][1]}
                sm.source_map.append(dspan)

            # Remove the original non-terminal span
            sm.source_map.remove(span)

            # Copy over any sources on the donor source map
            temp = {}
            temp.update(self[source_file].sources)
            temp.update(sm.sources)
            sm.sources = temp
        return sm


SourceMapFile = "list[dict[str, Locator]]"


class Locator(TypedDict):
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

    def __init__(self, source_map: "SourceMapFile", output: str = None):
        self.source_map = source_map
        self.sources = {}
        self.output = output

    def __copy__(self):
        cls = self.__class__
        result = cls.__new__(cls)
        result.__dict__.update(
            source_map=deepcopy(self.source_map), sources=copy(self.sources), output=self.output
        )
        return result

    def setSource(self, source_file: "str", pol: "Policy"):
        self.sources[source_file] = pol

    def setOutput(self, file: str):
        self.output = file

    def resolveOutputLine(self, line):
        if not self.output:
            return
        return self.output.splitlines()[line]

    def resolveSourceLocation(self, locator: "Locator"):
        if not self.sources:
            return
        if locator is None:
            return
        vtype = locator['type']
        filter = locator['filter']
        source_file = locator.get('source_file', None)
        source = self.sources.get(source_file, None)
        if not source:
            return
        src_filter = source.filters[filter]
        if vtype == 'header':
            return src_filter
        if vtype == 'term':
            term = locator['term']
            return src_filter[1][term]

    def isLineInSpan(self, line, span):
        parts = span.split(':')
        assert len(parts) == 2
        start = int(parts[0])
        end = int(parts[1])
        return start <= line <= end

    def isSpanIntersecting(self, span1, span2):
        # is span1.start > span2.end -> no_overlap
        # else is span1.end > span2.start -> no overlap
        parts1 = span1.split(':')
        assert len(parts1) == 2
        parts2 = span2.split(':')
        assert len(parts2) == 2

        return max(parts1[0], parts2[0]) <= min(parts1[1], parts2[1])

    def getSourceLocationForLine(self, line: int):
        file_locator = None
        for span in self.source_map:
            span_key = list(span.keys())[0]
            span_value = list(span.values())[0]
            if not self.isLineInSpan(line, span_key):
                continue
            if not _SourceMap_isTerminalSpan(span):
                file_locator = span_value
                continue
            # inject source_file into locator
            locator = dict()
            if file_locator:
                locator.update(file_locator)
            locator.update(span_value)
            return locator

    def getIntersectingSpans(self, span_key: str):
        match = []
        for span in self.source_map:
            span_key2 = list(span.keys())[0]
            if self.isSpanIntersecting(span_key, span_key2):
                match.append(span)
        return match


def _SourceMap_isTerminalSpan(span):
    return list(span.values())[0].keys() != {'source_file'}
