class FQDN:
    def __init__(self, fqdn: str, token: str, comment: str = ''):
        self.fqdn = fqdn
        self.text = comment
        self.token = token
        self.parent_token = token

    def __eq__(self, other):
        if not isinstance(other, FQDN):
            return False
        if self.fqdn != other.fqdn:
            return False
        if self.text != other.text:
            return False
        if self.token != other.token:
            return False
        if self.parent_token != other.parent_token:
            return False
        return True
