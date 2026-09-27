"""Internal allow-list for AI-callable tools, separate from the CLI menu."""

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..search import handle_search_dispatch
from ..tools import registry as recon_registry


class SearchArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=500)

    @field_validator("query")
    @classmethod
    def normalize_query(cls, value: str) -> str:
        query = value.strip()
        if not query:
            raise ValueError("query must contain non-whitespace characters")
        return query


@dataclass(frozen=True)
class AIToolSpec:
    name: str
    description: str
    argument_model: type[BaseModel]
    runner: object
    scope_bound: bool
    call_type: str = "TOOL"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.argument_model.model_json_schema(),
        }


_INTERNAL_TOOLS = {
    "web_search": AIToolSpec(
        name="web_search",
        description="Search public Web sources for CVEs, fixes, or security context.",
        argument_model=SearchArguments,
        runner=handle_search_dispatch,
        scope_bound=False,
        call_type="SEARCH",
    )
}


def all_ai_tools() -> dict[str, AIToolSpec]:
    tools = {
        spec.command_name: AIToolSpec(
            name=spec.command_name,
            description=f"Run the registered {spec.name} reconnaissance tool.",
            argument_model=spec.argument_model,
            runner=spec.runner,
            scope_bound=True,
        )
        for spec in recon_registry.all_tools().values()
        if spec.ai_dispatch
    }
    tools.update(_INTERNAL_TOOLS)
    return tools


def tool_schemas() -> list[dict]:
    return [spec.schema() for spec in all_ai_tools().values()]


def get(name: str) -> AIToolSpec | None:
    return all_ai_tools().get(name.strip().lower())
