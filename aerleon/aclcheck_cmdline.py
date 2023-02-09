# Copyright 2011 Google Inc. All Rights Reserved.
# Modifications Copyright 2022-2023 Aerleon Project Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Command line interface to aclcheck library."""

import pathlib
from argparse import ArgumentParser, RawTextHelpFormatter

from aerleon.lib import aclcheck, naming, policy, yaml
from aerleon.utils import config


def main():
    _parser = ArgumentParser(
        prog='aclcheck',
        formatter_class=RawTextHelpFormatter,
    )
    _parser.add_argument(
        '--definitions-directory',
        dest='definitions_directory',
        help='definitions directory',
    )
    _parser.add_argument(
        '--base-directory',
        dest='base_directory',
        help='The base directory to look for include files.',
    )
    _parser.add_argument(
        '-p',
        '--policy-file',
        dest='pol',
        help='policy file',
        required=True,
    )
    _parser.add_argument(
        '--config-file',
        dest='config_file',
        help='config file',
    )
    _parser.add_argument('-d', '--destination', dest='dst', help='destination IP')
    _parser.add_argument(
        '-s',
        '--source',
        dest='src',
        help='source IP',
    )
    _parser.add_argument(
        '--proto',
        '--protocol',
        dest='proto',
        help='Protocol (tcp, udp, icmp, etc.)',
    )
    _parser.add_argument('--dport', '--destination-port', dest='dport', help='destination port')
    _parser.add_argument('--sport', '--source-port', dest='sport', help='source port')
    FLAGS = _parser.parse_args()

    default_flags = {
        'base_directory': './policies',
        'definitions_directory': './def',
        'pol': None,
        'config_file': None,
        'dst': '200.1.1.1',
        'src': 'any',
        'proto': 'any',
        'dport': '80',
        'sport': '1025',
    }

    configs = {}
    configs.update(default_flags)

    if not (FLAGS.base_directory and FLAGS.definitions_directory):
        common_flags = frozenset(['base_directory', 'definitions_directory'])
        common_configs = config.load_config(config_file=FLAGS.config_file)
        common_configs = {
            key: value for key, value in common_configs.items() if key in common_flags
        }
        configs.update(common_configs)

    # Grab common configs from aerleon.yml
    configs.update({flag: value for flag, value in vars(FLAGS).items() if value})

    defs = naming.Naming(configs['definitions_directory'])

    with open(configs['pol']) as f:
        conf = f.read()

    if pathlib.Path(configs['pol']).suffix in ['.yaml', '.yml']:
        policy_obj = yaml.ParsePolicy(
            conf,
            base_dir=configs['base_directory'],
            filename=configs['pol'],
            definitions=defs,
        )
    else:
        policy_obj = policy.ParsePolicy(conf, defs, base_dir=configs['base_directory'])
    check = aclcheck.AclCheck(
        policy_obj,
        src=configs['src'],
        dst=configs['dst'],
        sport=configs['sport'],
        dport=configs['dport'],
        proto=configs['proto'],
    )
    print(str(check))


if __name__ == '__main__':
    main()
