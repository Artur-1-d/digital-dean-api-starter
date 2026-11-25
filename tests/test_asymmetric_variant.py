
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api import asymmetric_lab as lab


ROUTE = "/api/v1/lab/crypto/asymmetric-benchmark-results"

PROFILES = [
    ("rsa2048-oaep", 2),
    ("rsa3072-oaep", 2),
    ("rsa3072-oaep-aes256gcm", 6),
    ("hpke-x25519-aes256gcm", 6),
    ("hpke-p256-aes256gcm", 6),
]

REPORT_PATH = (
    Path(__file__).resolve().parents[1]
    / "results/practice-03/report.json"
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.mark.parametrize("profile,count", PROFILES)
def test_profile_filter(client, profile, count):
    response = client.get(
        ROUTE,
        params={"profile": profile},
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data["results"]) == count

    assert all(
        item["profile"] == profile
        for item in data["results"]
    )

    assert len(data["key_generation"]) == 4
    assert len(data["checks"]) == 22


def test_invalid_profile(client):
    response = client.get(
        ROUTE,
        params={"profile": "unknown"},
    )

    assert response.status_code == 422


def test_complete_report(client):
    response = client.get(ROUTE)

    assert response.status_code == 200

    data = response.json()

    assert len(data["results"]) == 22
    assert len(data["key_generation"]) == 4
    assert len(data["checks"]) == 22

    assert all(
        item["passed"]
        for item in data["checks"]
    )


def test_filter_does_not_modify_report(client):
    original = REPORT_PATH.read_bytes()

    response = client.get(
        ROUTE,
        params={"profile": "hpke-x25519-aes256gcm"},
    )

    assert response.status_code == 200
    assert REPORT_PATH.read_bytes() == original


def test_invalid_report_before_filter(
    client, tmp_path, monkeypatch
):
    data = json.loads(
        REPORT_PATH.read_text(encoding="utf-8")
    )

    data["results"].pop()

    path = tmp_path / "invalid.json"

    path.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    monkeypatch.setattr(lab, "REPORT_PATH", path)

    response = client.get(
        ROUTE,
        params={"profile": "hpke-x25519-aes256gcm"},
    )

    assert response.status_code == 500

    assert response.json() == {
        "detail": "benchmark report invalid"
    }


def test_api_version():
    assert app.version == "0.4.0"
