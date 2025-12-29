.PHONY: help install dev-install setup clean test lint format docker-up docker-down docker-logs

help: ## Show this help message
	@echo "AdversarialShield - Makefile commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Run initial setup script
	@bash scripts/setup.sh

install: ## Install Python dependencies
	@pip install -e .

dev-install: ## Install Python dependencies with dev extras
	@pip install -e ".[dev]"

frontend-install: ## Install frontend dependencies
	@cd frontend && npm install

clean: ## Clean up temporary files and caches
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name "*.pyo" -delete
	@find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	@rm -rf build dist
	@echo "✨ Cleaned up!"

test: ## Run tests
	@pytest backend/tests -v --cov=backend --cov-report=html

test-watch: ## Run tests in watch mode
	@pytest-watch backend/tests

lint: ## Run linters
	@echo "Running ruff..."
	@ruff check backend/
	@echo "Running mypy..."
	@mypy backend/
	@echo "✅ Linting complete!"

format: ## Format code with black and ruff
	@echo "Formatting with black..."
	@black backend/
	@echo "Formatting with ruff..."
	@ruff check --fix backend/
	@echo "✨ Code formatted!"

docker-up: ## Start all services with Docker Compose
	@cd docker && docker-compose up -d
	@echo "🚀 Services started!"
	@echo "Backend: http://localhost:8000"
	@echo "Frontend: http://localhost:3000"
	@echo "Flower: http://localhost:5555"

docker-down: ## Stop all Docker services
	@cd docker && docker-compose down
	@echo "🛑 Services stopped!"

docker-logs: ## Show Docker logs
	@cd docker && docker-compose logs -f

docker-build: ## Rebuild Docker images
	@cd docker && docker-compose build
	@echo "🔨 Images rebuilt!"

docker-restart: ## Restart Docker services
	@make docker-down
	@make docker-up

backend-dev: ## Run backend in development mode
	@source venv/bin/activate && python -m backend.api.main

frontend-dev: ## Run frontend in development mode
	@cd frontend && npm run dev

db-migrate: ## Run database migrations
	@alembic upgrade head

db-revision: ## Create a new database migration
	@read -p "Enter migration message: " msg; \
	alembic revision --autogenerate -m "$$msg"

db-downgrade: ## Downgrade database by one revision
	@alembic downgrade -1

seed-data: ## Seed database with initial data
	@python scripts/seed_attack_patterns.py

pre-commit: ## Run pre-commit hooks
	@pre-commit run --all-files

ci: lint test ## Run CI checks locally

.DEFAULT_GOAL := help
