"""Структура звіту; змістову перевірку validate_report реалізує студент."""
from typing import Annotated, Literal
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StrictInt
from app.security.hashing.profiles import AlgorithmID, Mode


def _exact_int(value):
    if type(value) is not int:
        raise ValueError("integer required; bool/float/string is not an integer")
    return value


Version = Annotated[Literal[1], BeforeValidator(_exact_int)]
Int5 = Annotated[Literal[5], BeforeValidator(_exact_int)]
Int10 = Annotated[Literal[10], BeforeValidator(_exact_int)]
Int100 = Annotated[Literal[100], BeforeValidator(_exact_int)]
Int1000 = Annotated[Literal[1000], BeforeValidator(_exact_int)]
Int1024 = Annotated[Literal[1024], BeforeValidator(_exact_int)]
Int16384 = Annotated[Literal[16384], BeforeValidator(_exact_int)]
PositiveInt = Annotated[StrictInt, Field(gt=0)]
NonnegativeInt = Annotated[StrictInt, Field(ge=0)]
Positive = Annotated[float, Field(gt=0)]
Nonnegative = Annotated[float, Field(ge=0)]


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", allow_inf_nan=False)


class Parameters(StrictModel):
    sizes: list[PositiveInt] = Field(min_length=4, max_length=4)
    chunk_bytes: Int16384
    warmup: Int10
    series: Int5
    repeats_small: Int1000
    repeats_large: Int100
    avalanche_trials: Int100
    avalanche_bytes: Int1024


class Environment(StrictModel):
    python: str = Field(min_length=1, max_length=160)
    openssl_ssl: str = Field(min_length=1, max_length=160)
    os: str = Field(min_length=1, max_length=240)
    cpu: str = Field(min_length=1, max_length=160)
    architecture: str = Field(min_length=1, max_length=80)


class AlgorithmStatus(StrictModel):
    algorithm: AlgorithmID
    available: bool
    reason: Literal["not_available_in_environment"] | None
    implementation: str | None = Field(max_length=160)


class PerformanceResult(StrictModel):
    algorithm: AlgorithmID
    mode: Mode
    payload_bytes: PositiveInt
    digest_bytes: PositiveInt
    repeats: PositiveInt
    median_ns: Positive
    iqr_ns: Nonnegative
    throughput_mib_s: Positive


class AvalancheResult(StrictModel):
    algorithm: AlgorithmID
    input_bytes: Int1024
    trials: Int100
    digest_bits: PositiveInt
    min_flipped_bits: NonnegativeInt
    max_flipped_bits: NonnegativeInt
    mean_flipped_bits: Nonnegative
    mean_fraction: float = Field(ge=0, le=1)


class CorrectnessCheck(StrictModel):
    algorithm: AlgorithmID
    name: Literal["known-abc", "known-empty", "unicode-utf8", "determinism",
                  "digest-length", "stream-equivalence"]
    passed: bool


class Summary(StrictModel):
    algorithms_count: PositiveInt
    available_count: PositiveInt
    results_count: NonnegativeInt
    checks_count: NonnegativeInt
    all_checks_passed: bool


class HashReport(StrictModel):
    schema_version: Version
    created_at: str = Field(min_length=20, max_length=40)
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    parameters: Parameters
    environment: Environment
    algorithms: list[AlgorithmStatus] = Field(min_length=7, max_length=7)
    results: list[PerformanceResult] = Field(min_length=40, max_length=56)
    avalanche: list[AvalancheResult] = Field(min_length=5, max_length=7)
    checks: list[CorrectnessCheck] = Field(min_length=30, max_length=42)


class HashResponse(HashReport):
    # Filtering may return fewer results; full disk report must stay complete.
    results: list[PerformanceResult] = Field(max_length=56)
    summary: Summary | None = None


def validate_report(data: object) -> HashReport:
    from datetime import datetime, timedelta
    from math import isclose

    from app.security.hashing.profiles import (
        PROFILES,
        PAYLOAD_SIZES,
        CHECK_NAMES,
        repeat_count,
    )

    report = HashReport.model_validate(data)

    def require(condition, message):
        if not condition:
            raise ValueError(message)

    created = datetime.fromisoformat(
        report.created_at.replace("Z", "+00:00")
    )

    require(
        created.utcoffset() == timedelta(0),
        "UTC timestamp required",
    )

    require(
        report.parameters.sizes == list(PAYLOAD_SIZES),
        "invalid payload sizes",
    )

    algorithms = [row.algorithm for row in report.algorithms]

    require(
        len(algorithms) == len(set(algorithms))
        and set(algorithms) == set(PROFILES),
        "invalid algorithm coverage",
    )

    available = set()

    for row in report.algorithms:
        if row.available:
            require(
                row.reason is None
                and bool(row.implementation)
                and bool(row.implementation.strip()),
                "invalid available status",
            )
            available.add(row.algorithm)
        else:
            require(
                row.algorithm in ("md5", "sha1")
                and row.reason == "not_available_in_environment"
                and row.implementation is None,
                "invalid unavailable status",
            )

    expected_results = {
        (algorithm, mode, size)
        for algorithm in available
        for mode in ("whole", "chunked")
        for size in PAYLOAD_SIZES
    }

    actual_results = [
        (row.algorithm, row.mode, row.payload_bytes)
        for row in report.results
    ]

    require(
        len(actual_results) == len(set(actual_results))
        and set(actual_results) == expected_results,
        "invalid performance coverage",
    )

    for row in report.results:
        require(
            row.digest_bytes
            == PROFILES[row.algorithm].digest_bytes,
            "invalid digest length",
        )

        require(
            row.repeats == repeat_count(row.payload_bytes),
            "invalid repeat count",
        )

        expected_throughput = (
            row.payload_bytes * 1e9
            / (2**20 * row.median_ns)
        )

        require(
            isclose(
                row.throughput_mib_s,
                expected_throughput,
                rel_tol=1e-6,
            ),
            "invalid throughput",
        )

    avalanche_algorithms = [
        row.algorithm for row in report.avalanche
    ]

    require(
        len(avalanche_algorithms)
        == len(set(avalanche_algorithms))
        and set(avalanche_algorithms) == available,
        "invalid avalanche coverage",
    )

    for row in report.avalanche:
        bits = PROFILES[row.algorithm].digest_bytes * 8

        require(
            row.digest_bits == bits,
            "invalid avalanche digest length",
        )

        require(
            0 <= row.min_flipped_bits
            <= row.mean_flipped_bits
            <= row.max_flipped_bits
            <= bits,
            "invalid avalanche bounds",
        )

        require(
            isclose(
                row.mean_fraction,
                row.mean_flipped_bits / bits,
                rel_tol=1e-6,
                abs_tol=1e-9,
            ),
            "invalid avalanche fraction",
        )

    expected_checks = {
        (algorithm, name)
        for algorithm in available
        for name in CHECK_NAMES
    }

    actual_checks = [
        (row.algorithm, row.name)
        for row in report.checks
    ]

    require(
        len(actual_checks) == len(set(actual_checks))
        and set(actual_checks) == expected_checks,
        "invalid correctness coverage",
    )

    return report
