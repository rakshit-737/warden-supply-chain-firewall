.PHONY: help install train test lint security run demo benchmark cli-scan up down build fmt frontend-install frontend-dev frontend-build

help:
	@echo "Warden — Software Supply-Chain Firewall"
	@echo ""
	@echo "Backend:"
	@echo "  make install        Install backend runtime + dev dependencies"
	@echo "  make train          Generate dataset + train and persist the ML model"
	@echo "  make test           Run the backend test suite (SQLite, no services needed)"
	@echo "  make lint           Ruff lint the backend"
	@echo "  make security       Run bandit + pip-audit security checks"
	@echo "  make run            Run the API locally (SQLite/in-process cache)"
	@echo "  make demo           Seed a local database with real results from the benchmark corpus"
	@echo "  make benchmark      Run the synthetic detection benchmark"
	@echo "  make cli-scan PKG=requests==2.32.3 TOKEN=...   Scan via the CLI"
	@echo ""
	@echo "Frontend:"
	@echo "  make frontend-install / frontend-dev / frontend-build"
	@echo ""
	@echo "Full stack (Docker):"
	@echo "  make up             docker compose up --build"
	@echo "  make down           docker compose down -v"

install:
	cd backend && pip install -r requirements-dev.txt

train:
	cd backend && python -m ml.train

test:
	cd backend && python -m pytest

lint:
	cd backend && ruff check .

security:
	cd backend && bandit -q -r app cli -c pyproject.toml && pip-audit --strict -r requirements.txt

run:
	cd backend && uvicorn app.main:app --reload --port 8000

demo:
	cd backend && python -m scripts.seed_demo

benchmark:
	cd backend && python -m benchmark.run

cli-scan:
	cd backend && python -m cli.warden_cli scan $(PKG) --api http://localhost:8000 --token $(TOKEN)

frontend-install:
	cd frontend && npm install

frontend-dev:
	cd frontend && npm run dev

frontend-build:
	cd frontend && npm run build

up:
	docker compose up --build

down:
	docker compose down -v

build:
	docker compose build
