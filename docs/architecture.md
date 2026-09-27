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
  assessment. `analysis.graph` coordinates evidence-driven LangGraph branches
  and bounded tool cycles over the typed state in `analysis.state`, without
  changing the service contract. Durable checkpointing is explicit and opt-in.
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

### Analysis orchestration

LangGraph is adopted behind `run_analysis_workflow`; callers of
`analysis.service` keep the same inputs and outputs. The graph operates on the
typed `AnalysisState` introduced after provider capabilities, bounded context,
targeted retrieval, and evidence provenance were established. Its branches are
domain decisions: sufficient evidence proceeds to finalization, while a tool
proposal proceeds through safe dispatch and a bounded investigation cycle.

The procedural workflow remains a reference implementation for behavioral
fixtures during the migration. Iteration exhaustion raises
`AnalysisLimitReached`, whose `state` contains the observations, executions,
and provenance collected before the limit.

Checkpointing is disabled by default. A caller must supply both a checkpointer
and a unique `thread_id`; resuming an existing thread is another explicit
choice. This prevents transient scans from being persisted accidentally while
allowing an interrupted long-running analysis to continue without repeating
completed tool side effects. Production storage is intentionally deferred
until retention, encryption, and multi-user isolation requirements are known.

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

Session chat divides that input budget into three independent categories:
scan-session evidence, a rolling conversation summary, and recent history.
Evidence is truncated only against its protected allocation, so conversation
growth cannot evict it. Recent history is retained newest-first by estimated
tokens rather than by a fixed message count. When history crosses its
policy-defined pressure threshold, older messages and the previous summary are
compressed into one replacement summary. Both compression requests and final
chat requests are bounded deterministically by the active context policy.

The current token estimator deliberately remains provider-independent. Exact
tokenizers would add SDK dependencies, model-version coupling, and network/API
accounting differences. Adopt provider-specific counting only if measurements
against representative PenTron prompts show the approximation regularly differs
from provider-reported input usage by more than 15%, or causes context-limit
failures. Until telemetry can provide that evidence, the decision is to defer.

## Database schema

Ten tables, with scan results and proposed-action audit records linked to the
session in `history`; `settings` is a standalone single-row table for runtime
configuration. Source of truth: [`docker/schema.sql`](../docker/schema.sql) —
update this diagram if it drifts.

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
    ├── analysis_domains   ← versioned observations, facts, hypotheses, and findings, linked by sl_no
    │
    ├── proposed_actions   ← current authorization state, actor, risk, and timestamps, linked by session_id
    │       │
    │       └── proposed_action_events ← immutable lifecycle transition log, linked by action_id
    │
    └── summary            ← full AI analysis dump, linked by sl_no

settings              ← single row: active provider, model, timeouts, API key
                         (read/written from both the web UI and the CLI Settings screen)
```

For the top-level file/package layout, see the "Project Structure" section
in the main [README](../README.md).
