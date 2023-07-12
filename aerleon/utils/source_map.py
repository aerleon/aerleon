import json

"""Utilities for generating a source map while emitting an ACL file."""


def getCursor(sm: "SourceMap"):
    l = len(sm.lines)
    if l == 0:
        c = 0
    else:
        c = len(sm.lines[-1])
    return l - 1, c


def formatCursor(pos):
    return ':'.join((str(i) for i in pos))


class SourceMap:
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
        self._current_filter = self._current_filter + 1 if self._current_filter is not None else 0

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
