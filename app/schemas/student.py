
from typing import Annotated, Self
from uuid import UUID

from pydantic import (
    BaseModel, ConfigDict, EmailStr,
    StringConstraints, model_validator
)


FullName = Annotated[
    str, StringConstraints(min_length=5, max_length=120)
]

GroupCode = Annotated[
    str, StringConstraints(pattern=r"^[A-ZА-ЯІЇЄҐ0-9]+-[0-9]{2}$")
]

StudyProgram = Annotated[
    str, StringConstraints(min_length=2, max_length=100)
]


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True
    )


class StudentCreate(StrictModel):
    full_name: FullName
    email: EmailStr
    group_code: GroupCode
    study_program: StudyProgram


class StudentRead(StudentCreate):
    id: UUID


class StudentUpdate(StrictModel):
    full_name: FullName | None = None
    email: EmailStr | None = None
    group_code: GroupCode | None = None
    study_program: StudyProgram | None = None

    @model_validator(mode="after")
    def validate_update(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("Update must not be empty")

        for field in self.model_fields_set:
            if getattr(self, field) is None:
                raise ValueError("Null values are not allowed")

        return self
