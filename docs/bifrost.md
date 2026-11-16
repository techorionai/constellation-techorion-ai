# Bifrost spike

This document records the Bifrost spike (roadmap item R04, issue #1). The spike runs the upstream Bifrost image with PostgreSQL. Integration tests examine three claims of `VISION.md` section 12.1. The tests also examine the behavior of the management API that the design needs.

## Images

All image references are in `resources/test/containers/images.go`. Each reference has an exact tag and the sha256 digest of the image index.

| Use | Image |
| --- | ----- |
| Bifrost | `maximhq/bifrost:v2.5.1@sha256:5ec9873acaf1687556b6e4dd854b92b539d9debf87a5a683b66338648b84d3c8` |
| PostgreSQL | `postgres:18.7-alpine@sha256:b6972e1115a4ff8eba5d7f7d19184926d1e16d7d1136ae1e1a7ebf286da0f015` |
| Capture container and helper | `nicolaka/netshoot:v0.14@sha256:7f08c4aff13ff61a35d30e30c5c1ea8396eac6ab4ce19fd02d5a4b3b5d0d09a2` |

`testcontainers-go` v0.45.0 selects two more images. The tests do not set them.

| Use | Image |
| --- | ----- |
| Host access (SSH tunnel to the test process) | `testcontainers/sshd:1.4.0` |
| Cleanup | `testcontainers/ryuk:0.14.0` |

A bump of `testcontainers-go` can change these tags.

## Configuration

`bifrost/config.json` is the configuration of the spike. The file has no secret value. Each secret is an `env.` value.

| Key | Value | Reason |
| --- | ----- | ------ |
| `encryption_key`, `setup_token` | `env.` values | Secrets come from the environment. |
| `governance.auth_config` | enabled, `env.` user and password | The management API needs admin credentials. A call without them returns 401. |
| `client.enforce_auth_on_inference` | `true` | `/v1/*` needs a virtual key. |
| `config_store`, `logs_store` | `postgres`, `db_name: bifrost` | Without `logs_store`, Bifrost makes a SQLite file. |
| `framework.pricing.pricing_url`, `model_parameters_url`, `mcp_library_url` | `file:///app/local-data/...` | Bifrost does not download these files from `getbifrost.ai`. |
| `framework.pricing.mcp_library_sync_interval` | `0` | Stops the library sync. |
| `framework.pricing.live_models_sync_interval` | `0` | Stops the model list sync of the providers. |
| `providers.openai` | one key with `models: ["gpt-4o"]`, `max_retries: 0` | See "Differences from VISION.md". |
| `plugins` | not set | The upstream image cannot load plugins. |

The files in `bifrost/local-data/` come from Bifrost at the tag `transports/v2.5.1`. They are test data. `bifrost/NOTICE` gives the source and the license. The files are not the full pricing data. R20 decides the source of these files for production.

The test copies `config.json` into the container. It adds two values to `providers.openai.network_config`: `base_url` (the scripted model server) and `allow_private_network: true`. The file in the repository does not have them. See the differences table.

### Operator step for the news feed

Bifrost has no configuration key that turns off the news feed. Until the first `PUT /api/rss/settings` with `{"enabled":false}`, the first `GET /api/rss/items` calls `getbifrost.ai`. The operator (or R20) must send the `PUT` with admin credentials right after Bifrost is healthy and before the UI is open to users.

## How to run the tests

Unit tests:

```sh
go test -race ./...
```

Integration tests (Docker is necessary):

```sh
go test -race -tags=integration -timeout 25m ./...
```

The `-timeout 25m` flag is necessary. The default limit of `go test` is 10 minutes for each test binary. The package `test/bifrost` pulls images, starts the containers, waits 6 minutes for the capture (D12), and runs I15. The CI job limit is 30 minutes.

For a faster run while you change the tests, set `SPIKE_CAPTURE_WAIT_SECONDS`. The test then waits for this number of seconds in place of 6 minutes. Do not use the result of such a run as proof for the claim about outbound calls.

## Test design

- The test starts a Docker network, PostgreSQL, and the capture container. The capture container owns the network namespace. It runs `tcpdump` from before Bifrost starts.
- Bifrost starts after the capture container with `NetworkMode: container:<capture container>`. Bifrost has no extra capability. Bifrost is on a normal network, so an unwanted call can occur and the capture records it.
- The test MCP server and the scripted model server run in the test process. Bifrost reaches them with the testcontainers host access (`host.testcontainers.internal`).
- The analyzer in `resources/test/capture` reads the pcap file. It counts only outbound TCP SYN packets and outbound UDP packets from the addresses of the namespace. It decodes DNS queries to the Docker DNS server `127.0.0.11`. An empty, truncated, or malformed file is an error.
- I15 is the positive control. It shows that the capture sees a DNS name and an outbound connection from the namespace.
- All secret values are random for each run (D16).

## Results

The results come from a local run on Windows 11 with Docker Desktop, and from the CI run on `ubuntu-latest`. The PR shows the CI result.

| Test | Claim | Result |
| ---- | ----- | ------ |
| U1 to U4 | The configuration has the outbound settings, the stores, the authentication, no secret value, and valid data files. | Pass |
| U5 | Each image has an exact tag and a digest. | Pass |
| U6 to U12 | The analyzer finds unexpected DNS names and peers, ignores inbound and SYN-ACK packets, handles IPv6, and gives an error for a bad file. | Pass |
| U13 | The secret helper gives different random values. | Pass |
| I1 | Bifrost starts with the PostgreSQL stores. It makes no SQLite file. The capture shows the first SYN to PostgreSQL. | Pass |
| I2 | `PUT /api/rss/settings` turns the news feed off. The feed is empty. | Pass |
| I3, I18 | The management API returns 401 without credentials and with a wrong password. | Pass |
| I4 | Discovery at add time carries no `Authorization` header. | Pass (see difference 3) |
| I5, I6 | The per-call `Authorization` header gets to `tools/call`. A second call carries the second token only. | Pass |
| I7 | The server rejects a token with 401. Bifrost returns 400. | Pass. Message: `MCP tool call failed for helpdesk_test-echo: transport error: authorization required: mcp tool call failed` |
| I8 | No `Authorization` header from the caller means no header to the server. The virtual key is not forwarded. | Pass |
| I9, I17 | No virtual key, or an unknown virtual key, returns 401. The server gets no `tools/call`. | Pass |
| I10 | Default tool mode: the tool call goes back to the caller. Bifrost does not run it. | Pass |
| I11 | `x-bf-mcp-include-tools` with an unknown tool removes the MCP tools from the model request. | Pass |
| I16 | A key with an empty `tools_to_execute` gets no MCP tools. The tool call returns 403: `MCP tool 'helpdesk_test-echo' is not allowed for virtual key 'spike_no_tools'`. | Pass |
| I12 | `PUT` keeps the stored URL (and returns 200). `refresh-tools` returns 200 with `tool_count` 1. `reconnect` returns 400. `DELETE` removes the client. | Pass. `reconnect` message: `client uses per-call connections; there is no persistent connection to reconnect: reconnect is not applicable for this client type` |
| I13 | The three tokens are not in the container log, and not in a text column of the `bifrost` database. | Pass |
| I14 | In the full capture, Bifrost made no call to a peer or a DNS name that is not in the allow list. | Pass |
| I15 | The analyzer reports `getbifrost.ai` and `1.1.1.1:443` from a helper in the namespace. | Pass |

## Differences from VISION.md

A claim test asserts the behavior that Bifrost shows (D15). This table lists each difference between that behavior and `VISION.md`. It also lists the design decisions of the spike that change `VISION.md`.

| No. | VISION.md says | Bifrost or the spike shows | Proposed change |
| --- | -------------- | -------------------------- | --------------- |
| 1 | 5.1, 12.1, 19: We build our own Bifrost image from a pinned release tag, with a dynamic build, a plugin, and a repository mirror. | Decision D1. The spike uses the upstream image `maximhq/bifrost:v2.5.1`, pinned by digest. The official image is static and cannot load plugins. | Use the upstream image, pinned by tag and digest. Remove the own build, the plugins, and the mirror. |
| 2 | 12.1, 12.2, 19: The guardrails are a Bifrost plugin. | Decision D2. The upstream image has no plugin. | TechOrion AI applies the guardrails before and after each model call and each tool call. |
| 3 | 12.1: Bifrost forwards the `Authorization` header to the application. | Bifrost forwards the header on `tools/call` and on the `server/discover` request of the same call. It does not send the header on discovery at add time (`server/discover`, `tools/list`) or on `refresh-tools`. The tests I4, I5 and I12 show this. The periodic tool check also sends no header, but only the source code shows this. No test covers it. | Application MCP servers answer `server/discover` and `tools/list` without a token. They check the token and the scopes on `tools/call` (D5). |
| 4 | 12.1: The design does not name the MCP protocol. | Bifrost v2.5.1 sends the protocol version 2026-07-28 header. It sends `server/discover` and no `initialize`. The test MCP server (Go MCP SDK v1.8.0, stateless mode) works with it. | Application MCP servers must support `server/discover`. |
| 5 | 12.1: TechOrion AI calls `POST /v1/mcp/tool/execute` with the token in the `Authorization` header. | The call also needs a virtual key in the `x-bf-vk` header (`enforce_auth_on_inference: true`). With `Authorization` and without a virtual key, Bifrost returns 401 (I9). A virtual key that does not exist returns 401 (I17). | Inference calls send a virtual key in `x-bf-vk`. The per-call token stays in `Authorization`. |
| 6 | 12.1: Not specified. | A virtual key has no provider key unless the body lists the key in `key_ids`. The key needs `models` that include the model, or the virtual key gets 403 `model not allowed` for `allowed_models: ["*"]`. See the "Virtual key observations" section. | The R20 plan must create the virtual key with `key_ids` and give the provider keys explicit `models`. |
| 7 | 12.1: `POST /api/mcp/client/{id}/reconnect` and `refresh-tools` repair a connection. | `reconnect` returns 400 for a client with `connection_type: http` and `auth_type: none`, because each call opens its own connection. `refresh-tools` works (I12). | The MCP servers page uses `refresh-tools` only (D6). |
| 8 | 12.1: `PUT /api/mcp/client/{id}` cannot change the URL of a server. | Agrees. `PUT` with a new `connection_string` returns 200 and the stored URL does not change (I12). The call gives no error. | Add: the `PUT` call gives no error when the body has a URL. The page must not send it. |
| 9 | 12.1: Models include OpenAI-compatible endpoints. | The field `network_config.base_url` of `config.json` does not accept an `env.` value. The management API refuses a private address in `base_url`. A provider connection to a private IP address fails with `connection to private IP ... is not allowed` unless `network_config.allow_private_network` is `true`. The test sets both values in the copy of `config.json`. | Add: a model endpoint on a private network needs `allow_private_network: true`. R20 must set it per provider. |
| 10 | 12.1: Not specified. | The tool name is `<client name>-<tool name>`. The tests use the client name `helpdesk_test`. | Application names for Bifrost clients use underscores and no hyphen. |
| 11 | 12.1: Not specified. | A tool call with a token that the application rejects with 401 returns 400 from Bifrost. The message is `MCP tool call failed for helpdesk_test-echo: transport error: authorization required: mcp tool call failed` (I7). A virtual key without the tool returns 403 (I16). | TechOrion AI maps these statuses and messages. |
| 12 | 14: The settings for no outbound call are `pricing_url`, `model_parameters_url`, `mcp_library_url`, `mcp_library_sync_interval` and the news feed `PUT`. | The configuration also sets `live_models_sync_interval: 0`. The news feed is on until the first `PUT /api/rss/settings` (D13). The tests did not run Bifrost without `live_models_sync_interval: 0`, so the need for this key comes from the source code only. | Add `live_models_sync_interval: 0`. Write that the `PUT` must occur before the UI opens to users. |
| 13 | 12.1: The Bifrost design is "from reading the source and documentation". | The three checks now have integration tests. I14 found no unexpected outbound call in a capture of the full run. I5 and I6 show the per-call header. I10 shows the default tool mode. | Change the verification status in 12.1 and 14. Add the digest of the tested image. |

### Virtual key observations

These results come from the exploration for the tests (the same Bifrost image and configuration).

| Step | Result |
| ---- | ------ |
| Provider key with `models: []`, virtual key with `allowed_models: ["*"]` and no `key_ids` | 403 `Model 'gpt-4o' is not allowed for virtual key` |
| Provider key with `models: ["gpt-4o"]`, virtual key without `key_ids` | 400 `no keys found for provider: openai and model: gpt-4o` |
| Provider key with `models: ["gpt-4o"]`, virtual key with `key_ids` of that key | 200 |

The tests use the last form. The test reads the key ID from `GET /api/providers/openai/keys`.

## Proposed changes to VISION.md

- 5.1 and 12.1: use the upstream Bifrost image, pinned by tag and digest. Remove the own dynamic build, the plugins, and the repository mirror.
- 12.1 and 12.2: TechOrion AI applies the guardrails before and after each model call and each tool call. Remove "as a Bifrost plugin".
- 12.1: application MCP servers answer `server/discover` and `tools/list` without a token. The MCP servers page uses `refresh-tools`, not `reconnect`. Inference calls and `POST /v1/mcp/tool/execute` send a virtual key in `x-bf-vk`. A virtual key lists the provider key IDs and the provider keys list their models. A provider on a private network needs `allow_private_network: true`.
- 14: add `live_models_sync_interval: 0`. Write that the news feed `PUT` must occur before the UI opens to users. Replace "A network capture test in Phase 3 will check" with the result of the capture test.
- 19, Phase 3: change "own dynamic image build from a pinned tag, repository mirror" to "upstream image pinned by digest". Change "as a Bifrost plugin" to "in TechOrion AI".
