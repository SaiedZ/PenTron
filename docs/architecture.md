# Architecture

## AI engine

The AI engine lives under `pentron.ai` and is split by responsibility:

```text
pentron/ai/
├── capabilities.py
├── models.py
├── prompts.py
├── providers/
│   ├── base.py
│   ├── ollama.py
│   ├── openai.py
│   ├── anthropic.py
│   ├── google.py
│   └── factory.py
├── analysis/
│   ├── service.py
│   ├── workflow.py
│   ├── validators.py
│   └── tool_dispatch.py
└── chat/
    ├── service.py
    ├── context.py
    └── compression.py
```

- `analysis.service` is the application-facing entry point for a target
  assessment. The workflow coordinates provider calls, validation, and safe tool
  dispatch without depending on the database.
- `chat.service` handles contextual conversations. `chat.context` builds bounded
  scan context, while `chat.compression` manages long conversation histories.
- `providers` defines the shared provider contract, concrete integrations, and
  the configured-provider factory.
- `capabilities.py` is the single source of truth for provider limits, model
  limits, and context policies. Chat, analysis, and provider request options
  resolve the same policy from the active provider and model.
- `models.py` contains the validated analysis result models shared across the
  engine.
- `prompts.py` contains prompt text used internally by analysis and chat. It is
  not an application service API.

### Supported imports

Application code should use these stable import paths:

```python
from pentron.ai.analysis import AnalysisIncompleteError, analyse_target
from pentron.ai.capabilities import context_policy_for
from pentron.ai.chat import ChatProviderError, build_seed_context, send_chat_message
from pentron.ai.models import AnalysisResult, ExploitSuggestion, VulnerabilityResult
from pentron.ai.providers import ProviderResponse, get_provider
```

Provider implementations are also available from `pentron.ai.providers` when an
interface must instantiate one explicitly. Lower-level workflow, validation,
context, compression, and prompt modules are implementation details; tests for
those components may import their defining module directly.

The former `pentron.llm`, `pentron.chat`, and `pentron.providers` facades were
removed before the first stable release. Downstream code must migrate to the
`pentron.ai.*` paths above; there is no compatibility alias or deprecation
period to maintain.

### Model limits and context policy

Provider capabilities and model capabilities are intentionally distinct. The
effective limits are the lower bound of both, while optional features are only
enabled when both layers support them. An unregistered provider or model gets a
deterministic 8,192-token context, a 2,048-token maximum output, and no optional
features. This is a safety fallback, not a claim about the model's real limits.

Every workflow calls `context_policy_for(provider, model)`. The policy reserves
output and a safety margin before allocating the remaining input budget:

```text
input budget = context window - output reserve - safety margin
```

The current token estimator deliberately remains provider-independent. Exact
tokenizers would add SDK dependencies, model-version coupling, and network/API
accounting differences. Adopt provider-specific counting only if measurements
against representative PenTron prompts show the approximation regularly differs
from provider-reported input usage by more than 15%, or causes context-limit
failures. Until telemetry can provide that evidence, the decision is to defer.

## Database schema

Seven tables, six of them linked by `sl_no` (session number) from the
`history` table; `settings` is a standalone single-row table for runtime
configuration. Source of truth: [`docker/schema.sql`](../docker/schema.sql)
— update this diagram if it drifts.

```
history              ← one row per scan session (sl_no is the spine)
    │
    ├── vulnerabilities   ← vulns found, linked by sl_no
    │       │
    │       └── fixes     ← fixes per vuln, linked by vuln_id + sl_no
    │
    ├── exploit_suggestions ← AI-proposed exploit ideas (name/rationale/tool/safe validation), linked by sl_no
    │
    ├── ai_tool_calls      ← every AI-dispatched [TOOL:]/[SEARCH:] call, blocked or not, linked by sl_no
    │
    └── summary           ← full AI analysis dump, linked by sl_no

settings              ← single row: active provider, model, timeouts, API key
                         (read/written from both the web UI and the CLI Settings screen)
```

For the top-level file/package layout, see the "Project Structure" section
in the main [README](../README.md).
