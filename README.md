# constellation-techorion-ai

TechOrion AI is the AI layer of the Constellation platform. It holds the agents, the workflows, the approval flow, and the review inbox.

This repository is at the start. It holds the Bifrost spike (roadmap item R04). The spike runs the upstream Bifrost image with PostgreSQL and examines three claims with integration tests. See [docs/bifrost.md](docs/bifrost.md).

## Tests

Unit tests:

```sh
go test -race ./...
```

Integration tests need Docker:

```sh
go test -race -tags=integration -timeout 25m ./...
```

The Bifrost integration tests need about 10 minutes, because the network capture runs for 6 minutes after the last call.

## Lint

```sh
test -z "$(gofmt -l .)" && go vet ./... && golangci-lint run
```
