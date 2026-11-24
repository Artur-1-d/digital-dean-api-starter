
from uuid import UUID, uuid4

from app.schemas.student import (
    StudentCreate,
    StudentRead,
    StudentUpdate,
)


class StudentNotFoundError(KeyError):
    """Запис студента не знайдено."""


class DuplicateEmailError(ValueError):
    """Електронна адреса вже використовується."""


class InMemoryStudentRepository:
    def __init__(self) -> None:
        self._students: dict[UUID, StudentRead] = {}

    def create(self, payload: StudentCreate) -> StudentRead:
        for student in self._students.values():
            if student.email.casefold() == payload.email.casefold():
                raise DuplicateEmailError

        student = StudentRead(
            id=uuid4(),
            **payload.model_dump()
        )

        self._students[student.id] = student
        return student

    def list(
        self, *, variant_filter: str | None = None
    ) -> list[StudentRead]:
        students = list(self._students.values())

        if variant_filter is not None:
            students = [
                student for student in students
                if student.study_program == variant_filter
            ]

        return students

    def get(self, student_id: UUID) -> StudentRead:
        if student_id not in self._students:
            raise StudentNotFoundError(student_id)

        return self._students[student_id]

    def update(
        self, student_id: UUID, payload: StudentUpdate
    ) -> StudentRead:
        student = self.get(student_id)
        changes = payload.model_dump(exclude_unset=True)

        if "email" in changes:
            for other in self._students.values():
                if (
                    other.id != student_id
                    and other.email.casefold()
                    == changes["email"].casefold()
                ):
                    raise DuplicateEmailError

        updated = StudentRead.model_validate({
            **student.model_dump(),
            **changes
        })

        self._students[student_id] = updated
        return updated

    def clear(self) -> None:
        self._students.clear()


student_repository = InMemoryStudentRepository()
