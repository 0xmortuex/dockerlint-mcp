"""One exception type for failures the agent can act on."""

from __future__ import annotations


class UserError(Exception):
    """A problem with the request (bad path, unreadable file, invalid input).

    The server turns these into ToolError so the message reaches the client.
    """


def shorten(text: str, limit: int = 200) -> str:
    """Clip user-supplied text before echoing it in an error message."""
    return text if len(text) <= limit else text[:limit] + f"...[{len(text) - limit} more characters]"
