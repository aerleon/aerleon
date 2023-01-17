# CLI Reference

`aclgen` is the CLI tool that is used translate your policy files into platform specific syntax. We use `abseil` for managing our flags and logging so in order to get a list of all flags you need to use the following command

```bash
aclgen --helpfull
```

This will provide flags for each imported library that supports them. We provide below a current list of the supported flags.

```bash
  --base_directory: The base directory to look for acls; typically where you'd find ./corp and ./prod
    (default: './policies')
  --config_file: A yaml file with the configuration options for aerleon;
    repeat this option to specify a list of values
  --[no]debug: Debug messages
    (default: 'false')
  --definitions_directory: Directory where the definitions can be found.
    (default: './def')
  --exp_info: Print a info message when a term is set to expire in that many weeks.
    (default: '2')
    (an integer)
  --ignore_directories: Don't descend into directories that look like this string
    (default: 'DEPRECATED,def')
    (a comma separated list)
  --max_renderers: Max number of rendering processes to use.
    (default: '10')
    (an integer)
  -o,--[no]optimize: Turn on optimization.
    (default: 'False')
  --output_directory: Directory to output the rendered acls.
    (default: './')
  --policy_file: Individual policy file to generate.
  --[no]recursive: Descend recursively from the base directory rendering acls
    (default: 'true')
  --[no]shade_check: Raise an error when a term is completely shaded by a prior term.
    (default: 'false')
  --[no]verbose: Verbose messages
    (default: 'false')
```