"""
Single point of registration for recon tools.

A tool module calls @register_tool(...) on its run_xxx() function; the menu
(TOOLS_MENU) and the AI dispatch allowlist (ALLOWED_TOOLS) are then built
from what's registered here instead of being separate hand-maintained lists
that can drift out of sync with the actual tool functions.
"""

from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

ToolRunner = Callable[..., str]


class TargetArguments(BaseModel):
    """Only argument an AI may supply to a registered recon tool."""

    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=253)


@dataclass(frozen=True)
class ToolSpec:
    key: str  # menu key, e.g. "1"
    name: str  # display name, e.g. "nmap"
    command_name: str  # binary name checked by the AI dispatch allowlist
    runner: ToolRunner
    default: bool = False  # part of the standard (non-nikto) recon bundle
    ai_dispatch: bool = True  # may the LLM supply this binary's arguments?
    argument_model: type[BaseModel] = TargetArguments


_REGISTRY: dict[str, ToolSpec] = {}


def register_tool(
    key: str,
    name: str,
    command_name: str,
    *,
    default: bool = False,
    ai_dispatch: bool = True,
    argument_model: type[BaseModel] = TargetArguments,
) -> Callable[[ToolRunner], ToolRunner]:
    def decorator(func: ToolRunner) -> ToolRunner:
        _REGISTRY[key] = ToolSpec(
            key, name, command_name, func, default, ai_dispatch, argument_model
        )
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


def ai_tool_specs() -> list[dict]:
    """Provider-neutral JSON schemas for the registered AI-safe tools."""
    return [
        {
            "name": spec.command_name,
            "description": f"Run the registered {spec.name} reconnaissance tool.",
            "parameters": spec.argument_model.model_json_schema(),
        }
        for spec in all_tools().values()
        if spec.ai_dispatch
    ]


def find_by_command(name: str) -> ToolSpec | None:
    normalized = name.strip().lower()
    for spec in _REGISTRY.values():
        if spec.ai_dispatch and spec.command_name == normalized:
            return spec
    return None


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
