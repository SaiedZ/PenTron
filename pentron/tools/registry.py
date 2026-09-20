"""
Single point of registration for recon tools.

A tool module calls @register_tool(...) on its run_xxx() function; the menu
(TOOLS_MENU) and the AI dispatch allowlist (ALLOWED_TOOLS) are then built
from what's registered here instead of being separate hand-maintained lists
that can drift out of sync with the actual tool functions.
"""

from collections.abc import Callable
from dataclasses import dataclass

ToolRunner = Callable[..., str]


@dataclass(frozen=True)
class ToolSpec:
    key: str  # menu key, e.g. "1"
    name: str  # display name, e.g. "nmap"
    command_name: str  # binary name checked by the AI dispatch allowlist
    runner: ToolRunner


_REGISTRY: dict[str, ToolSpec] = {}


def register_tool(
    key: str, name: str, command_name: str
) -> Callable[[ToolRunner], ToolRunner]:
    def decorator(func: ToolRunner) -> ToolRunner:
        _REGISTRY[key] = ToolSpec(key, name, command_name, func)
        return func

    return decorator


def all_tools() -> dict[str, ToolSpec]:
    """Registered tools, ordered by menu key ("1".."N") regardless of which
    order the tool modules happened to be imported in."""
    return dict(sorted(_REGISTRY.items(), key=lambda item: int(item[0])))


def allowed_commands() -> frozenset[str]:
    """Binary names the AI is permitted to dispatch via run_tool_by_command."""
    return frozenset(spec.command_name for spec in _REGISTRY.values())


def get(key: str) -> ToolSpec | None:
    return _REGISTRY.get(key)
