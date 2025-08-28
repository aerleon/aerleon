"""SONiC generator."""

from aerleon.lib import openconfig


class Term(openconfig.Term):
    """SONiC term object.

    For when SONiC spec differs from OpenConfig
    """

    def _tcp_established(self) -> dict[str, bool]:
        """Return's openconfig TCP_ESTABLISHED configuration.

        Other vendors (eg. SONiC) have slighly different implementations,
        This function permits inheritance."""
        return {'tcp-session-established': True}


class SONiC(openconfig.OpenConfig):
    """A SONiC policy object.

    SONiC mostly follows the OpenConfig spec, but have some subtles differences here and there.
    """

    _PLATFORM = 'sonic'
    _TERM = Term
