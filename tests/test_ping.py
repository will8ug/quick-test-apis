from fastapi.testclient import TestClient
from app.main import app


def test_ping_endpoint():
    """Test that the /ping endpoint returns the expected response."""
    client = TestClient(app)
    response = client.get("/ping")

    assert response.status_code == 200
    assert response.text == "PONG from quick-test-apis"


def test_nginx_502_endpoint():
    """Test that the /nginx-502 endpoint returns the expected 502 response."""
    client = TestClient(app)
    response = client.get("/nginx-502")

    assert response.status_code == 502
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert "<title>502 Bad Gateway</title>" in response.text
    assert "<h1>502 Bad Gateway</h1>" in response.text
    assert "nginx" in response.text

