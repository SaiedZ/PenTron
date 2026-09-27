# Architecture

## AI engine

The AI engine lives under `pentron.ai` and is split by responsibility:

```text
pentron/ai/
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
- `models.py` contains the validated analysis result models shared across the
  engine.
- `prompts.py` contains prompt text used internally by analysis and chat. It is
  not an application service API.

### Supported imports

Application code should use these stable import paths:

```python
from pentron.ai.analysis import AnalysisIncompleteError, analyse_target
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
