from dataclasses import replace
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.repositories.student_repository import student_repository
from app.schemas.secure_note import NoteCreate
from app.security.keys import create_process_key
from app.repositories.secure_note_repository import repository


@pytest.fixture
def client():
    repository.clear()
    student_repository.clear()
    with TestClient(app) as test_client:
        app.state.process_key = create_process_key()
        try:
            yield test_client
        finally:
            repository.clear()
            student_repository.clear()


@pytest.fixture
def student_id(client):
    response = client.post(
        "/api/v1/students",
        json={
            "full_name": "Тестовий Студент",
            "email": f"{uuid4().hex}@example.com",
            "group_code": "KH-31",
            "study_program": "Облік і оподаткування"
        }
    )

    assert response.status_code == 201
    return response.json()["id"]


def create_note(client, student_id, text="Навчальна примітка"):
    response = client.post(
        f"/api/v1/students/{student_id}/secure-notes",
        json={"text": text}
    )

    assert response.status_code == 201
    return response.json()


@pytest.mark.parametrize(
    "text",
    ("x" * 4096, "я" * 2048, "  текст  ")
)
def test_accepted_text_is_preserved(text):
    assert NoteCreate(text=text).text == text


@pytest.mark.parametrize("payload", (
    {"text": ""},
    {"text": " "},
    {"text": "x" * 4097},
    {"text": "я" * 2049},
    {"text": 42},
    {"text": "demo", "key": "do-not-accept"},
))
def test_invalid_note_input(payload):
    with pytest.raises(ValidationError):
        NoteCreate(**payload)


def test_unknown_student_is_not_found(client):
    response = client.get(
        f"/api/v1/students/{uuid4()}/secure-notes/{uuid4()}"
    )

    assert response.status_code == 404


def test_note_api_and_internal_storage(client, student_id):
    text = "  Захищена навчальна примітка  "
    body = create_note(client, student_id, text)

    assert set(body) == {
        "id", "student_id", "algorithm"
    }

    assert body["algorithm"] == "AES-256-GCM"

    note_id = body["id"]

    response = client.get(
        f"/api/v1/students/{student_id}/secure-notes/{note_id}"
    )

    assert response.status_code == 200
    assert response.json()["text"] == text

    stored = repository.get(
        UUID(student_id), UUID(note_id)
    )

    assert not hasattr(stored, "text")
    assert not hasattr(stored, "key")
    assert len(stored.nonce) == 12
    assert len(stored.tag) == 16
    assert stored.ciphertext != text.encode("utf-8")


def test_damaged_note_is_rejected_without_plaintext(
    client, student_id
):
    text = "Protected test message"
    body = create_note(client, student_id, text)
    note_id = UUID(body["id"])

    stored = repository.get(
        UUID(student_id), note_id
    )

    damaged_tag = (
        bytes([stored.tag[0] ^ 1])
        + stored.tag[1:]
    )

    repository._items[note_id] = replace(
        stored, tag=damaged_tag
    )

    response = client.get(
        f"/api/v1/students/{student_id}/secure-notes/{note_id}"
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Protected note unavailable"
    }
    assert text not in response.text


def test_nonce_limit_rejects_only_new_writes(
    client, student_id
):
    app.state.process_key = create_process_key(limit=2)

    first = create_note(client, student_id, "First note")
    second = create_note(client, student_id, "Second note")

    first_stored = repository.get(
        UUID(student_id), UUID(first["id"])
    )

    second_stored = repository.get(
        UUID(student_id), UUID(second["id"])
    )

    assert first_stored.nonce != second_stored.nonce

    response = client.post(
        f"/api/v1/students/{student_id}/secure-notes",
        json={"text": "Third note"}
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Protected note unavailable"
    }

    response = client.get(
        f"/api/v1/students/{student_id}/secure-notes/{first['id']}"
    )

    assert response.status_code == 200
    assert response.json()["text"] == "First note"


def test_patch_note(client, student_id):
    body = create_note(client, student_id, "Old text")
    note_id = body["id"]

    url = (
        f"/api/v1/students/{student_id}"
        f"/secure-notes/{note_id}"
    )

    old_note = repository.get(
        UUID(student_id), UUID(note_id)
    )

    response = client.patch(
        url,
        json={"text": "Updated text"}
    )

    assert response.status_code == 200
    assert response.json()["id"] == note_id
    assert response.json()["student_id"] == student_id

    new_note = repository.get(
        UUID(student_id), UUID(note_id)
    )

    assert old_note.nonce != new_note.nonce

    response = client.get(url)

    assert response.status_code == 200
    assert response.json()["text"] == "Updated text"

    response = client.patch(
        url,
        json={"text": "Test", "key": "invalid"}
    )

    assert response.status_code == 422


def test_benchmark_report_reader():
    pytest.fail(
        "Implement fixed-path benchmark report reader checks"
    )