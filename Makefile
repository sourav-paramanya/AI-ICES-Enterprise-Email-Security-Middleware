.PHONY: help install dev lint format test coverage clean build up down restart logs shell db-init db-migrate

help:
	@echo "AI-ICES Development Commands"
	@echo "============================="
	@echo "install     - Install project dependencies"
	@echo "dev         - Start development servers"
	@echo "lint        - Run linters (ruff, mypy)"
	@echo "format      - Format code (ruff)"
	@echo "test        - Run tests"
	@echo "coverage    - Run tests with coverage report"
	@echo "clean       - Clean build artifacts"
	@echo "build       - Build Docker images"
	@echo "up          - Start all Docker services"
	@echo "down        - Stop all Docker services"
	@echo "restart     - Restart all Docker services"
	@echo "logs        - View Docker logs"
	@echo "shell       - Open Python shell"
	@echo "db-init     - Initialize database tables"
	@echo "db-migrate  - Run Alembic migrations"

install:
	pip install --upgrade pip
	pip install -e ".[dev]"

dev-core-hub:
	uvicorn apps.core_hub.main:app --reload --host 0.0.0.0 --port 8000

dev-gateway:
	uvicorn apps.gateway.main:app --reload --host 0.0.0.0 --port 8899

dev-governance:
	uvicorn apps.governance_api.main:app --reload --host 0.0.0.0 --port 8080

dev-dashboard:
	uvicorn apps.dashboard_backend.main:app --reload --host 0.0.0.0 --port 3000

lint:
	ruff check .
	mypy shared/ apps/ services/ workers/

format:
	ruff format .

test:
	pytest -v --tb=short

coverage:
	pytest --cov=shared --cov=apps --cov=services --cov-report=term --cov-report=html

clean:
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .ruff_cache/ .mypy_cache/ htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

build:
	docker compose -f deployment/compose/docker-compose.yml build

up:
	docker compose -f deployment/compose/docker-compose.yml up -d

down:
	docker compose -f deployment/compose/docker-compose.yml down

restart: down up

logs:
	docker compose -f deployment/compose/docker-compose.yml logs -f

shell:
	python -c "from shared.config.settings import get_settings; s = get_settings(); print(s)"

db-init:
	python -c "import asyncio; from shared.database.session import init_db; asyncio.run(init_db())"

db-migrate:
	alembic upgrade head
