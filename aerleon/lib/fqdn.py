import re
from dataclasses import dataclass


@dataclass
class FQDN:
    """Contains a single fully qualified domain name associated with a token, parent_token and optional comment."""

    # https://regexr.com/3g5j0
    fqdn_re = re.compile(
        r'^(?!.*:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$', re.IGNORECASE
    )
    fqdn: str
    text: str
    token: str
    parent_token: str

    def __init__(self, fqdn: str, token: str, comment: str = ''):
        if not self.fqdn_re.match(fqdn):
            raise ValueError(f"Not a valid FQDN: {fqdn}")
        self.fqdn = fqdn
        self.text = comment
        self.token = token
        self.parent_token = token
