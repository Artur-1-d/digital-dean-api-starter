"""Hash benchmark results API."""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError

from app.schemas.hash_report import (
    HashReport,
    HashResponse,
    validate_report,
)
from app.security.hashing.profiles import AlgorithmID


router = APIRouter(
    prefix="/api/v1/lab/crypto",
    tags=["hash-lab"],
)

REPORT_PATH = (
    Path(__file__).resolve().parents[2]
    / "results/practice-04/report.json"
)

MAX_REPORT_BYTES = 1048576


def _reject_constant(value: str):
    raise ValueError("non-finite JSON number")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")

        result[key] = value

    return result


def load_report() -> HashReport:
    try:
        with REPORT_PATH.open("rb") as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)

        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("report too large")

        data = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )

        return validate_report(data)

    except FileNotFoundError as exc:
        raise HTTPException(
            404,
            "hash report not found",
        ) from exc

    except (OSError, ValueError, ValidationError) as exc:
        raise HTTPException(
            500,
            "hash report invalid",
        ) from exc


@router.get(
    "/hash-benchmark-results",
    response_model=HashResponse,
    summary="Read local hashing benchmark results",
    description=(
        "Reads and validates the complete saved report. "
        "Variant 0 filters performance results by algorithm. "
        "Algorithm statuses, avalanche results and checks "
        "remain complete. No benchmark is executed."
    ),
    responses={
        404: {"description": "Hash report not found"},
        500: {"description": "Hash report invalid"},
        422: {"description": "Invalid algorithm"},
    },
)
def get_hash_benchmark_results(
    algorithm: AlgorithmID | None = Query(
        default=None,
        description="Filter results by hashing algorithm",
    ),
) -> HashResponse:

    report = load_report()

    data = report.model_dump()

    if algorithm is not None:
        data["results"] = [
            row
            for row in data["results"]
            if row["algorithm"] == algorithm
        ]

    return HashResponse.model_validate(data)