
"""Persistent account operations on separate short connections."""

import sqlite3
from pathlib import Path

from app.db.connection import open_database, write_transaction
from app.schemas.user_account import UserCreate, UserPublic
from app.security.passwords import make_password_record, verify_password


class UserNotFound(Exception):
    """No account with the requested id."""


class UserConflict(Exception):
    """The canonical login or email is already used."""


class UserReferenced(Exception):
    """Academic records prohibit physical deletion."""


class UserRepository:
    def __init__(self, database_path: Path):
        self.database_path = Path(database_path)

    def register_user(self, data: UserCreate) -> UserPublic:
        record, salt = make_password_record(
            data.password.get_secret_value()
        )

        try:
            with open_database(self.database_path) as con:
                with write_transaction(con):
                    cursor = con.execute(
                        '''
                        INSERT INTO "user"
                        (name, email, login, password, salt, status_id)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ''',
                        (
                            data.name,
                            str(data.email),
                            data.login,
                            record,
                            salt,
                            data.status_id,
                        ),
                    )

                    user = UserPublic(
                        id=cursor.lastrowid,
                        name=data.name,
                        email=str(data.email),
                        login=data.login,
                        status_id=data.status_id,
                    )

            return user

        except sqlite3.IntegrityError as exc:
            if exc.sqlite_errorcode == sqlite3.SQLITE_CONSTRAINT_UNIQUE:
                raise UserConflict() from None
            raise

    def delete_user(self, user_id: int) -> None:
        with open_database(self.database_path) as con:
            with write_transaction(con):
                user = con.execute(
                    'SELECT id FROM "user" WHERE id = ?',
                    (user_id,),
                ).fetchone()

                if user is None:
                    raise UserNotFound()

                reference = con.execute(
                    '''
                    SELECT 1 FROM grade
                    WHERE student_id = ? OR teacher_id = ?
                    LIMIT 1
                    ''',
                    (user_id, user_id),
                ).fetchone()

                if reference is not None:
                    raise UserReferenced()

                con.execute(
                    'DELETE FROM "user" WHERE id = ?',
                    (user_id,),
                )

    def block_user(self, user_id: int) -> UserPublic:
        with open_database(self.database_path) as con:
            with write_transaction(con):
                cursor = con.execute(
                    'UPDATE "user" SET status_id = 2 WHERE id = ?',
                    (user_id,),
                )

                if cursor.rowcount == 0:
                    raise UserNotFound()

                row = con.execute(
                    '''
                    SELECT id, name, email, login, status_id
                    FROM "user" WHERE id = ?
                    ''',
                    (user_id,),
                ).fetchone()

                return UserPublic(**dict(row))

    def login(self, login: str, password: str) -> bool:
        with open_database(self.database_path) as con:
            row = con.execute(
                '''
                SELECT password, salt, status_id
                FROM "user" WHERE login = ?
                ''',
                (login,),
            ).fetchone()

        if row is None:
            return False

        valid = verify_password(
            password,
            row["password"],
            row["salt"],
        )

        return valid and row["status_id"] == 1
