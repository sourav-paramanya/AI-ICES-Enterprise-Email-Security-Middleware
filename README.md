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
*   Docker & Docker Compose (ensure Docker Engine is running)
*   Python 3.12+ (if you wish to run services locally outside of Docker)

### Setup Instructions

1.  **Clone the repository**:
    ```bash
    git clone <repository-url>
    cd AI-ICES-Enterprise-Email-Security-Middleware
    ```

2.  **Configure environment variables**:
    Copy the example environment file and customize it for your environment:
    ```bash
    cp .env.example .env
    # Edit the .env file to set required secrets (e.g., SECRET_KEY, DB_PASSWORD, RABBITMQ_PASSWORD)
    ```

3.  **Database Migration**:
    Before starting the services, ensure the database schema is up-to-date:
    ```bash
    # If running with docker-compose:
    docker-compose -f deployment/compose/docker-compose.yml run governance_api alembic upgrade head
    ```

### Running the System

1.  **Using Docker Compose (Recommended)**:
    Start all services in detached mode:
    ```bash
    docker-compose -f deployment/compose/docker-compose.yml up -d --build
    ```

2.  **Verify Service Status**:
    Check the logs for any startup errors:
    ```bash
    docker-compose -f deployment/compose/docker-compose.yml logs -f
    ```

3.  **Check Health**:
    Each service provides a `/health` endpoint. You can verify they are running via curl or a web browser:
    ```bash
    curl http://localhost:8300/health  # Governance API example
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
