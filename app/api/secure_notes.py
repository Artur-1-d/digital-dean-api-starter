from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request

from app.schemas.secure_note import (
    NoteCreate,
    NoteUpdate,
    NoteMetadata,
    NoteRead,
)
from app.repositories.student_repository import (
    student_repository,
    StudentNotFoundError,
)
from app.repositories.secure_note_repository import (
    repository,
    EncryptedNote,
)
from app.security.adapters import (
    seal_bytes,
    open_bytes,
    CiphertextError,
)
from app.security.context import note_aad


router = APIRouter(
    prefix="/api/v1/students",
    tags=["secure-notes"]
)

ALGORITHM = "AES-256-GCM"
BACKEND = "cryptography"
ERROR_DETAIL = "Protected note unavailable"


def require_student(student_id):
    try:
        student_repository.get(student_id)
    except StudentNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Student not found"
        )


def require_note(student_id, note_id):
    require_student(student_id)

    try:
        return repository.get(student_id, note_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail="Note not found"
        )


def encrypt_note(request, student_id, note_id, text):
    material = request.app.state.process_key

    try:
        nonce = material.nonces.next()
    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail=ERROR_DETAIL
        ) from None

    aad = note_aad(
        student_id,
        note_id,
        ALGORITHM,
        material.key_id
    )

    ciphertext, tag = seal_bytes(
        BACKEND,
        ALGORITHM,
        material.key,
        nonce,
        text.encode("utf-8"),
        aad
    )

    return EncryptedNote(
        version=1,
        student_id=student_id,
        note_id=note_id,
        algorithm=ALGORITHM,
        backend=BACKEND,
        key_id=material.key_id,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag
    )


def decrypt_note(request, note, student_id, note_id):
    material = request.app.state.process_key

    try:
        if (
            note.version != 1
            or note.algorithm != ALGORITHM
            or note.backend != BACKEND
            or note.key_id != material.key_id
            or note.student_id != student_id
            or note.note_id != note_id
            or len(note.nonce) != 12
            or len(note.tag) != 16
        ):
            raise ValueError("Invalid envelope")

        aad = note_aad(
            student_id,
            note_id,
            ALGORITHM,
            material.key_id
        )

        return open_bytes(
            BACKEND,
            ALGORITHM,
            material.key,
            note.nonce,
            note.ciphertext,
            note.tag,
            aad
        ).decode("utf-8")

    except (CiphertextError, ValueError, TypeError):
        raise HTTPException(
            status_code=500,
            detail=ERROR_DETAIL
        ) from None


def metadata(note):
    return NoteMetadata(
        id=note.note_id,
        student_id=note.student_id,
        algorithm=note.algorithm
    )


@router.post(
    "/{student_id}/secure-notes",
    response_model=NoteMetadata,
    status_code=201
)
def create_note(
    student_id: UUID,
    payload: NoteCreate,
    request: Request
):
    require_student(student_id)

    note = encrypt_note(
        request,
        student_id,
        uuid4(),
        payload.text
    )

    repository.add(note)
    return metadata(note)


@router.get(
    "/{student_id}/secure-notes/{note_id}",
    response_model=NoteRead
)
def read_note(
    student_id: UUID,
    note_id: UUID,
    request: Request
):
    note = require_note(student_id, note_id)

    text = decrypt_note(
        request, note, student_id, note_id
    )

    return NoteRead(
        **metadata(note).model_dump(),
        text=text
    )


@router.patch(
    "/{student_id}/secure-notes/{note_id}",
    response_model=NoteMetadata
)
def update_note(
    student_id: UUID,
    note_id: UUID,
    payload: NoteUpdate,
    request: Request
):
    old_note = require_note(student_id, note_id)

    decrypt_note(
        request, old_note, student_id, note_id
    )

    updated = encrypt_note(
        request,
        student_id,
        note_id,
        payload.text
    )

    repository.update(updated)
    return metadata(updated)