"""Tests for the FastAPI REST API: routing, health, and the API-key gate."""

import importlib

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


def _make_client(monkeypatch, api_key: str | None = None) -> TestClient:
    if api_key is None:
        monkeypatch.delenv("SECSUITE_API_KEY", raising=False)
    else:
        monkeypatch.setenv("SECSUITE_API_KEY", api_key)
    # create_app() reads the key at construction time, so build after setting env.
    server = importlib.import_module("api.server")
    return TestClient(server.create_app())


def test_health_ok_without_key(monkeypatch):
    client = _make_client(monkeypatch)
    resp = client.get("/health")
    assert resp.status_code == 200


def test_modules_endpoint_lists_modules(monkeypatch):
    client = _make_client(monkeypatch)
    resp = client.get("/api/v1/modules/")
    assert resp.status_code == 200
    assert isinstance(resp.json(), (list, dict))


def test_openapi_schema_available(monkeypatch):
    client = _make_client(monkeypatch)
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    assert resp.json()["info"]["title"] == "Security Suite API"


def test_health_stays_open_when_key_required(monkeypatch):
    client = _make_client(monkeypatch, api_key="secret")
    # /health is explicitly unprotected even when a key is configured.
    assert client.get("/health").status_code == 200


def test_protected_endpoint_rejects_missing_key(monkeypatch):
    client = _make_client(monkeypatch, api_key="secret")
    resp = client.get("/api/v1/modules/")
    assert resp.status_code == 401


def test_protected_endpoint_accepts_valid_key(monkeypatch):
    client = _make_client(monkeypatch, api_key="secret")
    resp = client.get("/api/v1/modules/", headers={"X-API-Key": "secret"})
    assert resp.status_code == 200
