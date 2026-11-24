from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.repositories.student_repository import student_repository

URL = '/api/v1/students'
client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_repository():
    student_repository.clear()
    yield
    student_repository.clear()


def payload(**changes):
    return {
        'full_name': 'Іван Петренко',
        'email': 'ivan.petrenko@example.com',
        'group_code': 'КН-31',
        'study_program': 'Облік і оподаткування',
        **changes,
    }


def create(**changes):
    response = client.post(URL, json=payload(**changes))
    assert response.status_code == 201, response.text
    return response.json()


def test_create_student():
    student = create()
    assert student == {**payload(), 'id': student['id']}
    from uuid import UUID
    UUID(student['id'])


def test_invalid_email():
    assert client.post(URL, json=payload(email='invalid')).status_code == 422


def test_list_students():
    student = create()
    response = client.get(URL)
    assert response.status_code == 200
    assert response.json() == [student]


def test_get_student():
    student = create()
    response = client.get(f"{URL}/{student['id']}")
    assert response.status_code == 200
    assert response.json() == student


def test_student_not_found():
    assert client.get(f'{URL}/{uuid4()}').status_code == 404


def test_partial_update():
    student = create()
    url = f"{URL}/{student['id']}"
    response = client.patch(url, json={'group_code': 'КН-32'})
    assert response.status_code == 200
    expected = {**student, 'group_code': 'КН-32'}
    assert response.json() == expected
    assert client.get(url).json() == expected


def test_unknown_field():
    student = create()
    url = f"{URL}/{student['id']}"
    assert client.patch(url, json={'is_admin': True}).status_code == 422
    assert client.get(url).json() == student


def test_filter_study_program():
    student = create()
    create(email='other@example.com', study_program='Економіка')
    response = client.get(URL, params={'study_program': student['study_program']})
    assert response.status_code == 200
    assert response.json() == [student]


def test_study_program_too_short():
    assert client.post(URL, json=payload(study_program='А')).status_code == 422


def test_study_program_too_long():
    assert client.post(URL, json=payload(study_program='А' * 101)).status_code == 422


def test_duplicate_email():
    create()
    assert client.post(URL, json=payload()).status_code == 409


def test_empty_update():
    student = create()
    assert client.patch(f"{URL}/{student['id']}", json={}).status_code == 422


def test_null_update():
    student = create()
    assert client.patch(f"{URL}/{student['id']}", json={'study_program': None}).status_code == 422


def test_update_study_program():
    student = create()
    response = client.patch(f"{URL}/{student['id']}", json={'study_program': 'Економіка'})
    assert response.status_code == 200
    assert response.json() == {**student, 'study_program': 'Економіка'}
