.PHONY: up down api-dev api-test discovery-build discovery-test lint

up:            ## start local infra (postgres, redis, nats, minio, vault) + api
	docker compose -f deploy/docker-compose.yml up -d --build

down:
	docker compose -f deploy/docker-compose.yml down

api-dev:
	cd services/api && uv run uvicorn app.main:app --reload --port 8000

api-test:
	cd services/api && uv run pytest -q

discovery-build:
	cd sensor/discovery && cargo build --release

discovery-test:
	cd sensor/discovery && cargo test

lint:
	cd services/api && uv run ruff check . && uv run mypy app
	cd sensor/discovery && cargo clippy -- -D warnings
