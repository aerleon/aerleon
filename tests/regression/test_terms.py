from aerleon.lib import yaml as yaml_frontend

def _YamlParsePolicy(
    data, definitions=None, optimize=True, base_dir='', shade_check=False, filename=''
):
    return yaml_frontend.ParsePolicy(
        data,
        filename=filename,
        base_dir=base_dir,
        definitions=definitions,
        optimize=optimize,
        shade_check=shade_check,
    )

def GetTermMap():
    return {
        VERBATIM_TERM: YAML_VERBATIM_TERM,
        CISCOASA_POLICER_TERM: YAML_CISCOASA_POLICER_TERM,
    }


VERBATIM_TERM = """
term good-term-1 {
  verbatim:: ciscoasa "mary had a little lamb"
  verbatim:: iptables "mary had a second lamb"
  verbatim:: juniper "mary had a third lamb"
}
"""
YAML_VERBATIM_TERM = """
- name good-term-1
  verbatim:
    ciscoasa: mary had a little lamb
    iptables: mary had a second lamb
    juniper: mary had a third lamb
    
"""

CISCOASA_POLICER_TERM = """
term good-term-2 {
  verbatim:: ciscoasa "mary had a little lamb"
  policer:: batman
}
"""

YAML_CISCOASA_POLICER_TERM = """
- name policer-term
  verbatim:
    ciscoasa: mary had a little lamb
  policer: batman
"""
