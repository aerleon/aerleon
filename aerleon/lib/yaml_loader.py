from yaml.loader import SafeLoader


def SpanSafeYamlLoader(*, filename):
    """Configure yaml.load to:
    * Force safe_load mode (disable unpickling).
    * Augment mappings with debug context: __line__, __filename__.

    Post-load user error messages need to provide a filename and line number back to the user.
    Including debugging context in the mappings gives post-load code access to this information.
    Code operating on the native representation must filter out __line__, __filename__ from all
    mappings (dicts) when iterating over user data. This assumes __line__, __filename__ are not
    valid keys in any user data.
    """

    class PluginYamlLoader(SafeLoader):
        def construct_mapping(self, node, deep=False):
            mapping = super(PluginYamlLoader, self).construct_mapping(node, deep=deep)
            # Add 1 so line numbering starts at 1
            # TODO(jb) look at cases where line number does not match up, e.g. filter['__line__']
            mapping['__line__'] = node.start_mark.line + 1
            mapping['__filename__'] = filename
            return mapping

    return PluginYamlLoader
