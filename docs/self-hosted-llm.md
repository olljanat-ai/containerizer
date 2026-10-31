# Self-hosted LLM instead of Claude

The AI fallback (`--ai` on `assess`, `verify` and `analyze`, the `ai` command, and the `bench`
AI techniques) can use a self-hosted LLM instead of Claude. The rules stay first: the LLM is only
asked about components the rules are unsure of and failures no failure rule explains, exactly as
with Claude, and everything it answers is validated and recorded with `source: ai` and the model
name before it is used or learned.

Any server with an OpenAI-compatible `/v1/chat/completions` endpoint works: Ollama, vLLM,
LM Studio, llama.cpp `llama-server`, LocalAI, TGI and similar. No extra Python package is needed.

## Configure

Scheduled organization scans take the LLM an administrator sets under **Admin → Source control & LLM**
([source-control.md](source-control.md#the-llm)): server, model and key, sealed for the scan worker.
The variables below are for command line runs, and for scans when nothing is set there.

| Variable | Meaning |
| --- | --- |
| `CONTAINERIZER_LLM_BASE_URL` | Base URL of the server, up to and including `/v1`. Setting it selects the self-hosted backend. |
| `CONTAINERIZER_MODEL` (or `--model`) | Model name as the server knows it. Required: there is no default for a self-hosted server. |
| `CONTAINERIZER_LLM_API_KEY` | Optional key, sent as `Authorization: Bearer ...` (vLLM `--api-key`, a gateway, ...). |
| `CONTAINERIZER_AI_BACKEND` | `openai` to force this backend; `api` / `cli` for Claude. Defaults to `openai` when the base URL is set. |
| `CONTAINERIZER_LLM_JSON_MODE` | `json_schema` (default), `json_object` or `none`: the strongest structured output mode to try. |
| `CONTAINERIZER_LLM_MAX_TOKENS` | Answer token limit (default 16000). Raise it for reasoning models that think at length. |
| `CONTAINERIZER_LLM_TIMEOUT` | Seconds per request (default 900). |
| `CONTAINERIZER_LLM_ALLOW_HTTP` | `1` to allow sending the API key over plain `http` to a non-loopback host (refused by default). |

Examples:

```sh
# Ollama on this machine
export CONTAINERIZER_LLM_BASE_URL=http://localhost:11434/v1
export CONTAINERIZER_MODEL=qwen3:32b
python -m containerizer analyze ../my-app --out out/ --ai

# vLLM on a GPU server, behind TLS with a key
export CONTAINERIZER_LLM_BASE_URL=https://llm.example.internal/v1
export CONTAINERIZER_LLM_API_KEY=...                  # from your secret store
python -m containerizer assess ../my-app --ai --model Qwen/Qwen3-32B

# LM Studio / llama.cpp server
export CONTAINERIZER_LLM_BASE_URL=http://localhost:1234/v1   # llama-server: http://localhost:8080/v1
```

## How answers are kept reliable

- Every request carries the JSON schema twice: as `response_format` (`json_schema`, which Ollama,
  vLLM, LM Studio and llama.cpp enforce with constrained decoding) and in the prompt. If the server
  rejects `json_schema` (HTTP 400/422) the tool falls back to `json_object`, then to plain text.
- Every answer is checked against the schema here (required keys, types, enum values such as the
  severity scale). An invalid answer is retried once with the errors listed; a second invalid
  answer is an error, and the component keeps the rules' verdict.
- `<think>...</think>` blocks from reasoning models (DeepSeek-R1, Qwen3, ...) are ignored.
- Requests use `temperature: 0`, and answers are cached in `.work/ai-cache/` keyed by prompt,
  model and server URL, so runs are repeatable.
- What a model learns goes to `rules/learned/` with its model name, as with Claude. Review it
  before trusting it; smaller models propose more regexes that are wrong, and the tool keeps only
  regexes that compile, do not match trivial code, and fire on the code they were learned from.

## Choosing a model

The quality of the fallback follows the quality of the model. Use the largest instruction-tuned
model your hardware serves comfortably, ideally one that knows .NET well (for example a 30B+
Qwen, Llama, Mistral or DeepSeek model). Compare it against the rules alone with the benchmark:

```sh
python -m containerizer bench --technique hybrid --model qwen3:32b
python -m containerizer bench --technique rules
```

Token counts are tracked for self-hosted models; cost is reported as 0.

## Security

- Evidence packs contain source code excerpts, project files and the README of the assessed
  application. A self-hosted server keeps them inside your network; check that the server is the
  one you intend (`https` for anything beyond the local machine).
- The base URL must be `http` or `https` and must not contain credentials; put the key in
  `CONTAINERIZER_LLM_API_KEY` (a secret), never in the URL or in a committed file.
- The API key is not sent over plain `http` to a remote host unless `CONTAINERIZER_LLM_ALLOW_HTTP=1`.
- The LLM never runs commands or edits the application: it only returns JSON that the tool
  validates, and build-plan patches are limited to the same allow-list as with Claude.
- Standard proxy variables (`HTTPS_PROXY`, `NO_PROXY`) apply; add the LLM host to `NO_PROXY` if
  it is internal.

## CI

GitHub Action: set `ai: true`, `llm-base-url`, `model`, and optionally
`llm-api-key: ${{ secrets.LLM_API_KEY }}`. The runner (usually self-hosted) must reach the server.

Azure Pipelines template: parameters `ai: true`, `llmBaseUrl`, `model`, and an optional
`LLM_API_KEY` secret variable.
