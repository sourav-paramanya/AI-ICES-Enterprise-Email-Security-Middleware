# Kubernetes Deployment

This directory contains Kubernetes manifests for production deployment of AI-ICES.

## Structure

- `namespace.yaml` - AI-ICES namespace definition
- `configmap.yaml` - Environment configuration
- `secrets.yaml` - Secret definitions (use Vault in production)
- `postgres/` - PostgreSQL StatefulSet
- `rabbitmq/` - RabbitMQ StatefulSet
- `redis/` - Redis StatefulSet
- `gateway/` - Gateway deployment
- `core-hub/` - Core Hub deployment
- `governance/` - Governance API deployment
- `dashboard/` - Dashboard backend deployment
- `nlp-engine/` - NLP Engine deployment (GPU)
- `vision-engine/` - Vision Engine deployment (GPU)
- `url-protection/` - URL Protection deployment
- `cdr-engine/` - CDR Engine deployment
- `orchestrator/` - Threat Orchestrator deployment
- `remediation/` - Remediation Engine deployment
- `celery/` - Celery worker deployment
- `monitoring/` - Prometheus & Grafana
- `ingress/` - Ingress controller configuration

## Prerequisites

- Kubernetes 1.28+
- Helm 3.0+
- NVIDIA GPU Operator (for GPU workloads)
- Cert-Manager (for TLS)
- External Secrets Operator or Vault (for secrets)

## Installation

```bash
kubectl apply -k deployment/kubernetes/
```
