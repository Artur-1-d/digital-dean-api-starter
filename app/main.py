from fastapi import FastAPI

from app.api.students import router as students_router
from app.api.secure_notes import router as secure_notes_router
from app.security.keys import create_process_key


app = FastAPI(
    title="Digital Dean API",
    version="0.2.0",
    description="Навчальний API системи «Цифровий деканат»",
)

app.state.process_key = create_process_key()


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(students_router)
app.include_router(secure_notes_router)