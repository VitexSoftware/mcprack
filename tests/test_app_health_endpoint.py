from unittest.mock import patch


def test_health_endpoint_is_unauthenticated_and_reports_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert data["checks"]["database"] is True


def test_health_endpoint_leaks_no_config_values(client):
    resp = client.get("/health")
    body = resp.data.decode()
    assert "BW_" not in body
    assert "SECRET_KEY" not in body
    assert "sqlite" not in body.lower()
    assert "://" not in body


def test_health_endpoint_reports_degraded_on_db_failure(client):
    with patch("mcprack.extensions.db.session.execute", side_effect=RuntimeError("db down")):
        resp = client.get("/health")
    assert resp.status_code == 503
    data = resp.get_json()
    assert data["status"] == "degraded"
    assert data["checks"]["database"] is False
