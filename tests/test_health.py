"""Health check endpoint tests for scaffolding verification."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_core_hub_health(async_client: AsyncClient) -> None:
    response = await async_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"
    assert "core_hub" in data["services"]
    assert data["services"]["core_hub"]["status"] == "running"


@pytest.mark.asyncio
async def test_health_response_structure(async_client: AsyncClient) -> None:
    response = await async_client.get("/health")
    data = response.json()
    assert "status" in data
    assert "version" in data
    assert "timestamp" in data
    assert "services" in data


@pytest.mark.asyncio
async def test_health_service_name(async_client: AsyncClient) -> None:
    response = await async_client.get("/health")
    data = response.json()
    assert data["services"]["core_hub"]["status"] == "running"
