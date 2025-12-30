from fastapi.testclient import TestClient
from app.main import app


def test_ping_endpoint():
    """Test that the /ping endpoint returns the expected response."""
    client = TestClient(app)
    response = client.get("/ping")
    
    assert response.status_code == 200
    assert response.text == "POND from quick-test-apis"

