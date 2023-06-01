# CLI Reference

Aerleon contains three command line programs:

* [`aclgen`](#aclgen) generates ACL files from your policy files (the primary program)
* [`aclcheck`](#aclcheck) checks where hosts, ports and protocols are matched in a single policy file
* [`cgrep`](#cgrep) answers queries about addresses, ports and protocols found in the definition files

[`pol2yaml`](#pol2yaml) converts .pol, .inc, .svc, and .net files to equivalent YAML files. It can be found in [its own repository](https://github.com/aerleon/pol2yaml) but is documented here.



## Common Options

Options used by more than one command line program are listed here. Setting these options in your config file is a good practice. See [--config_file](#config_file).

Option | aclgen | aclcheck | pol2yaml | cgrep
---- | --- | --- | --- | ---
base_directory | input,<br>path resolution | path resolution | input,<br>path resolution |
definitions_directory | ✔ | ✔ | ✔ | ✔
output_directory | ✔ |  | ✔
optimize | ✔ |  |  |
debug | ✔ |  |  |
max_renderers | ✔ |  |  |
shade_check | ✔ |  |  |
exp_info | ✔ |  |  |

*Above: which config file options are supported by which program.*


### base_directory

Policy files should be placed in **base_directory**. `aclgen` and `pol2yaml` will search this directory recursively for input files to process, except if the flag `--policy_file` is used to give a specific input file (`aclgen` only). Relative paths that appear in "include" directives will be resolved against base_directory. The default value is './policies'.

### definitions_directory

Network and service definition files should be placed in **definitions_directory**. All files in this directory will be loaded and used to resolve symbolic network and service names. Unlike base_directory, definitions_directory is not searched recursively for input files. The default value is './def'.

### output_directory

`aclgen` will place all generated ACLs in this directory. For `aclgen` the default value is the current directory.

`pol2yaml` will place each converted file adjacent to its input file by default. If **output_directory** is given, `pol2yaml` will mirror the directory structure of the input files in the output_directory, potentially creating directories in the process.

### config_file

In addition to accepting command line arguments, `aclgen`, `aclcheck`, and
`pol2yaml` will look for a config file named 'aerleon.yml' in the current directory.
This location can be configured with the `--config_file` option. Options specified on
the command line take precendence over options in config files.



## Usage: aclgen

```
  --base_directory: The base directory to search recursively for policy files.
                    Relative policy imports are resolved against this directory.
                    If --policy_file is used, aclgen will not search this directory.
    Default: './policies'

  --config_file: A YAML file with configuration options;
    repeat this option to specify a list of values

  --[no]debug: Display detailed messages.
    Default: 'false'

  --definitions_directory: Directory containing network and service definition files.
    Default: './def'

  --exp_info: Print a message when a term is set to expire in that many weeks.
    Default: '2'
    (an integer)

  --ignore_directories: Don't descend into directories that look like this string.
    Default: 'DEPRECATED,def'
    (a comma separated list)

  --max_renderers: Max number of rendering processes to use.
    Default: '10'
    (an integer)

  -o,--[no]optimize: Turn on optimization.
    Default: 'False'

  --output_directory: Directory to output the rendered acls.
    Default: './'

  --policy_file: Individual policy file to generate.

  --[no]shade_check: Raise an error when a term is completely shaded by a prior term.
    Default: 'false'
```



## Usage: aclcheck

```
usage: aclcheck [-h] -p POL [--definitions-directory DEFINITIONS_DIRECTORY] [--base-directory BASE_DIRECTORY] [--config-file CONFIG_FILE] [-d DESTINATION_IP] [-s SOURCE_IP]
                [--proto PROTOCOL] [--dport DESTINATION_PORT] [--sport SOURCE_PORT]

Check where hosts, ports and protocols match in a NAC policy.

options:
  -h, --help            show this help message and exit
  -p POL, --policy-file POL, --policy_file POL
                        The policy file to examine.
  --definitions-directory DEFINITIONS_DIRECTORY, --definitions_directory DEFINITIONS_DIRECTORY
                        The directory where network and service definition files can be found.
  --base-directory BASE_DIRECTORY, --base_directory BASE_DIRECTORY
                        The base directory to use when resolving policy include paths.
  --config-file CONFIG_FILE, --config_file CONFIG_FILE
                        Change the location searched for the configuration YAML file.
  -d DESTINATION_IP, --destination DESTINATION_IP
                        Destination IP.
  -s SOURCE_IP, --source SOURCE_IP
                        Source IP.
  --proto PROTOCOL, --protocol PROTOCOL
                        Protocol (tcp, udp, icmp, etc.)
  --dport DESTINATION_PORT, --destination-port DESTINATION_PORT, --destination_port DESTINATION_PORT
                        Destination port.
  --sport SOURCE_PORT, --source-port SOURCE_PORT, --source-port SOURCE_PORT
                        Source port.
```



## Usage: cgrep

```
usage: cgrep [-h] [-d DEFS] [-i IP [IP ...]] [-t TOKEN] [-c OBJ OBJ | -g IP IP | -o OBJ [OBJ ...] | -s SVC [SVC ...] | -p PORT PROTO]

c[apirca]grep

options:
  -h, --help            show this help message and exit
  -d DEFS, --def DEFS   Network Definitions directory location.
  -c OBJ OBJ, --cmp OBJ OBJ
                        Compare the two given network definition tokens
  -g IP IP, --gmp IP IP
                        Diff the network objects to which the given IP(s) belong
  -o OBJ [OBJ ...], --obj OBJ [OBJ ...]
                        Return list of IP(s) contained within the given token(s)
  -s SVC [SVC ...], --svc SVC [SVC ...]
                        Return list of port(s) contained within given token(s)
  -p PORT PROTO, --port PORT PROTO
                        Returns a list of tokens containing the given port and protocol

  -i IP [IP ...], --ip IP [IP ...]
                        Return list of definitions containing the IP(s).
                        Multiple IPs permitted.
  -t TOKEN, --token TOKEN
                        See if an IP is contained within the given token.
                        Must be used in conjunction with -i/--ip [addr].
```



## Usage: pol2yaml

```
pol2yaml: Convert .pol, .inc policy files and .svc, .net definitions into equivalent YAML files.

Usage: pol2yaml [--base_directory DIRECTORY] [-c|--config_file FILE] [--definitions_directory DIRECTORY]
    [-h|--help] [--no-fix-include] [--output_directory DIRECTORY] [-s|--sanity_check]

Examples:

* Recursively convert all .pol and .inc files in base_directory.
  Original files are left in place. Each YAML files is placed in the same
  directory as the original file. Run sanity_check after (-s).

    npx pol2yaml -s --base_directory policies/


Options:

--base_directory    Convert .pol and .inc files found in this directory to
                    YAML. Original files are left in place. Can be set in
                    the 'aerleon.yml' config file.

--config_file | -c  Defaults to 'aerleon.yml'. Can set base_directory and
                    definitions_directory.

--definitions_directory
                    Convert .net and .svc files found in this directory to
                    YAML. Original files are left in place. Can be set in
                    the 'aerleon.yml' config file.

--help | -h         Display this message and exit.

--no_fix_include    By default, if an #include directive references a file
                    name with the .inc extension, the file name will appear
                    in the YAML output with the extension changed to
                    ".yaml". This flag leaves the file name unchanged.

--output_directory  Default: current directory. Sets the output directory
                    where YAML files will be placed.

--sanity_check | -s Run 'aclgen' on both the original and YAML files and
                    ensure the results are identical.

                    Sanity check requires that either Aerleon or pipx
                    are available. To run 'aclgen' it will try each of
                    the following commands in order:

                        python3 -m aerleon

                        python3 -m pipx run aerleon

                        aclgen
```