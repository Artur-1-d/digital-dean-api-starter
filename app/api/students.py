
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from app.schemas.student import (
    StudentCreate,
    StudentRead,
    StudentUpdate,
)

from app.repositories.student_repository import (
    student_repository,
    StudentNotFoundError,
    DuplicateEmailError,
)


router = APIRouter(
    prefix="/api/v1/students",
    tags=["students"]
)


@router.post("", response_model=StudentRead, status_code=201)
def create_student(payload: StudentCreate):
    try:
        return student_repository.create(payload)
    except DuplicateEmailError:
        raise HTTPException(
            status_code=409,
            detail="Email already exists"
        )


@router.get("", response_model=list[StudentRead])
def list_students(
    study_program: str | None = Query(
        default=None,
        min_length=2,
        max_length=100
    )
):
    return student_repository.list(
        variant_filter=study_program
    )


@router.get("/{student_id}", response_model=StudentRead)
def get_student(student_id: UUID):
    try:
        return student_repository.get(student_id)
    except StudentNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Student not found"
        )


@router.patch("/{student_id}", response_model=StudentRead)
def update_student(
    student_id: UUID,
    payload: StudentUpdate
):
    try:
        return student_repository.update(
            student_id, payload
        )
    except StudentNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Student not found"
        )
    except DuplicateEmailError:
        raise HTTPException(
            status_code=409,
            detail="Email already exists"
        )
