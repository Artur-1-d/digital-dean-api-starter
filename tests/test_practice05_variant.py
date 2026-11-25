
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.api.accounts import get_user_repository
from app.db.connection import open_database
from app.db.initialize import initialize_database
from app.main import app
from app.repositories.user_repository import UserRepository
from tests.practice05_support import (
    PASSWORD,
    PUBLIC_KEYS,
    account_client,
    account_database,
    account_repository,
)


def body(login="variant08", **changes):
    data = {
        "name": "Test Student 08",
        "email": f"{login}@example.com",
        "login": login,
        "password": PASSWORD,
        "status_id": 1,
    }
    data.update(changes)
    return data


def register(client, login="variant08"):
    response = client.post(
        "/api/v1/users", json=body(login)
    )
    assert response.status_code == 201
    return response.json()


def login(client, username="variant08"):
    return client.post(
        "/api/v1/auth/login",
        json={"login": username, "password": PASSWORD},
    )


def test_variant_foreign_keys(account_database):
    with open_database(account_database) as con:
        assert con.execute(
            "PRAGMA foreign_keys"
        ).fetchone()[0] == 1

        with pytest.raises(sqlite3.IntegrityError):
            con.execute(
                "INSERT INTO user_role(user_id, role_id) "
                "VALUES (?, ?)",
                (999999, 4),
            )


def test_variant_two_connections(
    account_client, account_database
):
    user = register(account_client)

    with open_database(account_database) as first:
        with open_database(account_database) as second:
            assert first is not second

            for con in (first, second):
                row = con.execute(
                    'SELECT login FROM "user" WHERE id=?',
                    (user["id"],),
                ).fetchone()

                assert row[0] == "variant08"


def test_variant_block_preserves_password(
    account_client, account_database
):
    user = register(account_client)
    user_id = user["id"]

    with open_database(account_database) as con:
        before = tuple(con.execute(
            'SELECT password, salt FROM "user" WHERE id=?',
            (user_id,),
        ).fetchone())

    for _ in range(2):
        response = account_client.patch(
            f"/api/v1/users/{user_id}/block"
        )
        assert response.status_code == 200
        assert response.json()["status_id"] == 2
        assert set(response.json()) == PUBLIC_KEYS

    with open_database(account_database) as con:
        after = tuple(con.execute(
            'SELECT password, salt FROM "user" WHERE id=?',
            (user_id,),
        ).fetchone())

    assert before == after
    assert login(account_client).json() is False


@pytest.mark.parametrize("target", ["student", "teacher"])
def test_variant_grade_delete_rollback(
    account_client, account_database, target
):
    student = register(account_client, "student08")
    teacher = register(account_client, "teacher08")

    with open_database(account_database) as con:
        con.execute(
            "INSERT INTO course(id, name) VALUES (?, ?)",
            (1, "Security"),
        )
        con.execute(
            "INSERT INTO user_role VALUES (?, ?)",
            (student["id"], 4),
        )
        con.execute(
            "INSERT INTO user_role VALUES (?, ?)",
            (teacher["id"], 3),
        )
        con.execute(
            "INSERT INTO grade VALUES (?, ?, ?, ?)",
            (student["id"], teacher["id"], 1, 95),
        )

    user_id = (
        student["id"] if target == "student"
        else teacher["id"]
    )

    response = account_client.delete(
        f"/api/v1/users/{user_id}"
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "user has grade references"
    )

    with open_database(account_database) as con:
        assert con.execute(
            'SELECT COUNT(*) FROM "user"'
        ).fetchone()[0] == 2

        assert con.execute(
            "SELECT COUNT(*) FROM user_role"
        ).fetchone()[0] == 2

        assert con.execute(
            "SELECT grade FROM grade"
        ).fetchone()[0] == 95


def test_variant_safe_validation(account_client):
    marker = "Synthetic secret marker 08!"

    response = account_client.post(
        "/api/v1/users",
        json=body(password=marker, status_id=None),
    )

    assert response.status_code == 422
    assert marker not in response.text

    for error in response.json()["detail"]:
        assert "input" not in error
        assert "ctx" not in error


def test_variant_database_unavailable(tmp_path):
    invalid_path = (
        tmp_path / "missing_directory" / "database.sqlite3"
    )

    previous = app.dependency_overrides.copy()

    app.dependency_overrides[get_user_repository] = (
        lambda: UserRepository(invalid_path)
    )

    try:
        with TestClient(
            app, raise_server_exceptions=False
        ) as client:
            response = client.post(
                "/api/v1/users", json=body()
            )

        assert response.status_code == 500
        assert response.json() == {
           "detail": "database error"
        }
        assert PASSWORD not in response.text
        assert str(invalid_path) not in response.text

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


def test_variant_persistence_after_reopen(tmp_path):
    path = tmp_path / "restart.sqlite3"
    initialize_database(path)

    previous = app.dependency_overrides.copy()

    try:
        app.dependency_overrides[get_user_repository] = (
            lambda: UserRepository(path)
        )

        with TestClient(app) as client:
            user = register(client)
            assert login(client).json() is True

        initialize_database(path)

        app.dependency_overrides[get_user_repository] = (
            lambda: UserRepository(path)
        )

        with TestClient(app) as client:
            assert login(client).json() is True

            response = client.patch(
                f'/api/v1/users/{user["id"]}/block'
            )
            assert response.status_code == 200

        initialize_database(path)

        with TestClient(app) as client:
            assert login(client).json() is False

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


def test_variant_previous_routes():
    paths = app.openapi()["paths"]

    assert "get" in paths["/health"]
    assert "post" in paths["/api/v1/students"]

    assert "get" in paths[
        "/api/v1/lab/crypto/hash-benchmark-results"
    ]

    assert "get" in paths[
        "/api/v1/lab/crypto/asymmetric-benchmark-results"
    ]

    assert app.version == "0.5.0"
