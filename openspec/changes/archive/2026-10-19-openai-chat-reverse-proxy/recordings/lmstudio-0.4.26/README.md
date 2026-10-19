# LM Studio 0.4.26 recordings

Recorded on 2026-10-17 from LM Studio 0.4.26 (`~/LMStudio/LM-Studio-0.4.26-4-linux-x64.AppImage`),
server on `http://localhost:1234`, model `google/gemma-4-26b-a4b-qat`. Source material for
task 5.1 and design D9. They hold no PII.

Each `req-<case>.json` was posted with
`curl -D resp-<case>.headers -o resp-<case>.json -H 'Content-Type: application/json' --data-binary @req-<case>.json http://localhost:1234/v1/chat/completions`.
The stream case used `-N` and writes `resp-stream.txt`.

| Case | Status | Content type | Fixture it becomes |
|---|---|---|---|
| `plain` | 200 | `application/json; charset=utf-8` | `lmstudio-0.4.26-response.json` |
| `tools` | 200 | `application/json; charset=utf-8` | `lmstudio-0.4.26-response-tool-call.json` |
| `error-bad-role` | 400 | `application/json; charset=utf-8` | `lmstudio-0.4.26-error-flat.json` |
| `error-bad-json` | 400 | `application/json; charset=utf-8` | `lmstudio-0.4.26-error-object.json` |
| `stream` | 200 | `text/event-stream` | `lmstudio-0.4.26-stream.txt` |

Notes:

- An unknown `model` does not fail: LM Studio answers with the loaded model.
- `error-bad-role` returns a flat string, `{"error": "…"}`, that echoes the role it got.
- `error-bad-json` returns `{"error": {"message", "type": "invalid_request", "code"}}`.
- Responses carry `message.reasoning_content` and a top-level `stats` key.
