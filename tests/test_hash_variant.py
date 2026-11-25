import pytest
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)

URL = "/api/v1/lab/crypto/hash-benchmark-results"


def test_full_report():
    response = client.get(URL)
    assert response.status_code == 200
    assert len(response.json()["results"]) == 56


@pytest.mark.parametrize(
    "algorithm",
    ["sha256", "sha1", "md5"],
)
def test_algorithm_filter(algorithm):
    response = client.get(
        URL,
        params={"algorithm": algorithm},
    )

    assert response.status_code == 200

    results = response.json()["results"]

    assert len(results) == 8
    assert all(
        row["algorithm"] == algorithm
        for row in results
    )


@pytest.mark.parametrize(
    "algorithm",
    ["invalid", "sha999", ""],
)
def test_invalid_algorithm(algorithm):
    response = client.get(
        URL,
        params={"algorithm": algorithm},
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "field",
    ["algorithms", "avalanche", "checks"],
)
def test_filter_preserves_metadata(field):
    full = client.get(URL)
    filtered = client.get(
        URL,
        params={"algorithm": "sha256"},
    )

    assert full.status_code == 200
    assert filtered.status_code == 200

    assert filtered.json()[field] == full.json()[field]