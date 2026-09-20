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
    default: bool = False  # part of the standard (non-nikto) recon bundle
    ai_dispatch: bool = True  # may the LLM supply this binary's arguments?


_REGISTRY: dict[str, ToolSpec] = {}


def register_tool(
    key: str,
    name: str,
    command_name: str,
    *,
    default: bool = False,
    ai_dispatch: bool = True,
) -> Callable[[ToolRunner], ToolRunner]:
    def decorator(func: ToolRunner) -> ToolRunner:
        _REGISTRY[key] = ToolSpec(key, name, command_name, func, default, ai_dispatch)
        return func

    return decorator


def all_tools() -> dict[str, ToolSpec]:
    """Registered tools, ordered by menu key ("1".."N") regardless of which
    order the tool modules happened to be imported in."""
    return dict(sorted(_REGISTRY.items(), key=lambda item: int(item[0])))


def allowed_commands() -> frozenset[str]:
    """Binary names the AI is permitted to dispatch via run_tool_by_command."""
    return frozenset(
        spec.command_name for spec in _REGISTRY.values() if spec.ai_dispatch
    )


def default_tool_names() -> list[str]:
    """Display names of the standard (non-nikto) recon bundle, in menu order."""
    return [spec.name for spec in all_tools().values() if spec.default]


def default_keys() -> list[str]:
    """Menu keys of the standard (non-nikto) recon bundle, in menu order."""
    return [spec.key for spec in all_tools().values() if spec.default]


def get(key: str) -> ToolSpec | None:
    return _REGISTRY.get(key)


def find_by_name(name: str) -> ToolSpec | None:
    for spec in _REGISTRY.values():
        if spec.name == name:
            return spec
    return None
