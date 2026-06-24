# AI-ICES Enterprise Email Security Middleware

Production-grade middleware for enterprise email security, leveraging AI-powered threat detection, automated remediation, and centralized governance.

## Architecture Overview

AI-ICES is a modular, event-driven system designed to intercept, analyze, and remediate email-based threats in real-time. It follows a clean architecture pattern with distinct service boundaries to ensure scalability, reliability, and maintainability.

### Core Components
*   **Gateway**: Milter-based email interception handler.
*   **Core Hub**: Ingestion service for raw email payloads, responsible for initial validation and RabbitMQ distribution.
*   **AI Engines**:
    *   **NLP Engine**: Classifies email intent and detects phishing patterns.
    *   **Vision Engine**: OCR and QR code detection for malicious visual content.
*   **URL Protection**: Real-time URL rewriting, reputation checks, and redirection.
*   **CDR Engine**: Sanitizes suspicious file attachments.
*   **Threat Orchestrator**: Aggregates security signals, scores threats, and determines verdicts.
*   **Remediation Engine**: Automated clawback actions via Zimbra SOAP API.
*   **Governance API**: Central control plane for user management, RBAC, and audit trails.
*   **Dashboard Backend**: Aggregated metrics and threat monitoring for SOC operations.

## Technology Stack
*   **Language**: Python 3.12
*   **Framework**: FastAPI
*   **Persistence**: PostgreSQL (SQLAlchemy 2.0 + Alembic)
*   **Messaging**: RabbitMQ (aio-pika)
*   **Caching**: Redis
*   **Containerization**: Docker & Docker Compose
*   **Task Queue**: Celery (for resource-intensive AI tasks)

## Getting Started

### Prerequisites
*   Docker & Docker Compose
*   Python 3.12+ (for local development)

### Running the System
```bash
# Start all services
docker-compose -f deployment/compose/docker-compose.yml up --build
```

## Project Structure
```text
├── alembic/              # Database migrations
├── apps/                 # API services (gateway, core_hub, governance_api, dashboard_backend)
├── deployment/           # Dockerfiles, docker-compose, k8s manifests
├── services/             # Background processing services (nlp, vision, etc.)
├── shared/               # Shared libraries, config, security, database models, schemas
├── tests/                # Test suite
└── workers/              # Celery task definitions
```

## Documentation
Additional architectural details, workflow specifications, and development guidelines can be found in the `docs/` folder (or within corresponding `README.md` files in subdirectories).
