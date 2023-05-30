from dataclasses import dataclass


@dataclass
class FQDN:
    def __init__(self, fqdn: str, token: str, comment: str = ''):
        self.fqdn = fqdn
        self.text = comment
        self.token = token
        self.parent_token = token
