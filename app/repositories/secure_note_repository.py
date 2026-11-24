from dataclasses import dataclass
from threading import RLock
from uuid import UUID


@dataclass(frozen=True)
class EncryptedNote:
    version: int
    student_id: UUID
    note_id: UUID
    algorithm: str
    backend: str
    key_id: UUID
    nonce: bytes
    ciphertext: bytes
    tag: bytes


class SecureNoteRepository:
    def __init__(self):
        self._items: dict[UUID, EncryptedNote] = {}
        self._lock = RLock()

    def add(self, note: EncryptedNote) -> None:
        with self._lock:
            if note.note_id in self._items:
                raise ValueError("Duplicate note ID")

            self._items[note.note_id] = note

    def get(
        self, student_id: UUID, note_id: UUID
    ) -> EncryptedNote:
        with self._lock:
            note = self._items.get(note_id)

            if note is None or note.student_id != student_id:
                raise KeyError(note_id)

            return note

    def update(self, note: EncryptedNote) -> None:
        with self._lock:
            self.get(note.student_id, note.note_id)
            self._items[note.note_id] = note

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


repository = SecureNoteRepository()