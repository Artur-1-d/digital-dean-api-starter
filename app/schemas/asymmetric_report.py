"""Asymmetric benchmark report schema and validation."""

import math
from datetime import datetime, timedelta
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
)

from app.security.asymmetric.profiles import (
    PROFILES,
    KEY_PROFILES,
    HYBRID_SIZES,
    expected_ciphertext_bytes,
)


def _exact_integer(value: object) -> int:
    if type(value) is not int:
        raise ValueError("an exact integer is required")
    return value


One = Annotated[Literal[1], BeforeValidator(_exact_integer)]
Five = Annotated[Literal[5], BeforeValidator(_exact_integer)]
Ten = Annotated[Literal[10], BeforeValidator(_exact_integer)]
Twenty = Annotated[Literal[20], BeforeValidator(_exact_integer)]
SixtyFour = Annotated[Literal[64], BeforeValidator(_exact_integer)]


ProfileId = Literal[
    "rsa2048-oaep",
    "rsa3072-oaep",
    "rsa3072-oaep-aes256gcm",
    "hpke-x25519-aes256gcm",
    "hpke-p256-aes256gcm",
]

KeyId = Literal[
    "rsa-2048",
    "rsa-3072",
    "x25519",
    "p256",
]

PositiveFloat = Annotated[
    float,
    Field(gt=0, allow_inf_nan=False),
]

NonNegativeFloat = Annotated[
    float,
    Field(ge=0, allow_inf_nan=False),
]


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )


class Experiment(StrictModel):
    series: Five
    operations_per_series: Twenty
    warmup: Ten
    keygen_runs: Five
    direct_payload_bytes: SixtyFour
    hybrid_sizes_bytes: list[int]
    source_commit: str = Field(
        pattern=r"^[0-9a-f]{40}$"
    )
    created_at_utc: str = Field(
        min_length=20,
        max_length=40,
    )


class Environment(StrictModel):
    python: str = Field(
        min_length=1,
        max_length=100,
    )
    cryptography: Literal["48.0.1"]
    openssl: str = Field(
        min_length=1,
        max_length=150,
    )
    os: str = Field(
        min_length=1,
        max_length=150,
    )
    cpu: str = Field(
        min_length=1,
        max_length=200,
    )


class KeyGeneration(StrictModel):
    key_profile: KeyId
    runs: Five
    median_ns: PositiveFloat
    iqr_ns: NonNegativeFloat
    public_key_der_bytes: int = Field(
        gt=0,
        le=4096,
    )


class Result(StrictModel):
    profile: ProfileId
    group: Literal["direct", "hybrid"]
    operation: Literal["encrypt", "decrypt"]
    payload_bytes: int = Field(
        gt=0,
        le=1048576,
    )
    series: Five
    operations_per_series: Twenty
    median_ns: PositiveFloat
    iqr_ns: NonNegativeFloat
    ciphertext_bytes: int = Field(
        gt=0,
        le=1048988,
    )
    throughput_mib_s: PositiveFloat | None


class Check(StrictModel):
    profile: ProfileId
    name: Literal[
        "roundtrip",
        "wrong_key",
        "tamper",
        "wrong_context",
        "oaep_boundary",
    ]
    passed: bool


class BenchmarkReport(StrictModel):
    schema_version: One
    experiment: Experiment
    environment: Environment

    key_generation: list[KeyGeneration] = Field(
        min_length=4,
        max_length=4,
    )

    results: list[Result] = Field(
        min_length=22,
        max_length=22,
    )

    checks: list[Check] = Field(
        min_length=22,
        max_length=22,
    )


class BenchmarkResponse(BenchmarkReport):
    results: list[Result] = Field(
        max_length=22,
    )


def validate_complete_report(data: object) -> BenchmarkReport:
    report = BenchmarkReport.model_validate(data)

    if report.experiment.hybrid_sizes_bytes != list(HYBRID_SIZES):
        raise ValueError("invalid hybrid sizes")

    created = datetime.fromisoformat(
        report.experiment.created_at_utc.replace(
            "Z", "+00:00"
        )
    )

    if created.utcoffset() != timedelta(0):
        raise ValueError("UTC timestamp required")

    keys = [
        item.key_profile
        for item in report.key_generation
    ]

    if (
        len(keys) != len(set(keys))
        or set(keys) != set(KEY_PROFILES)
    ):
        raise ValueError(
            "invalid key generation coverage"
        )

    expected = {
        (profile, size, operation)
        for profile, spec in PROFILES.items()
        for size in spec.sizes
        for operation in ("encrypt", "decrypt")
    }

    seen = set()

    for item in report.results:
        identity = (
            item.profile,
            item.payload_bytes,
            item.operation,
        )

        if identity in seen or identity not in expected:
            raise ValueError("invalid result coverage")

        seen.add(identity)

        spec = PROFILES[item.profile]

        if item.group != spec.group:
            raise ValueError("invalid group")

        expected_size = expected_ciphertext_bytes(
            item.profile,
            item.payload_bytes,
        )

        if item.ciphertext_bytes != expected_size:
            raise ValueError("invalid ciphertext size")

        if spec.group == "direct":
            if item.throughput_mib_s is not None:
                raise ValueError(
                    "invalid direct throughput"
                )

        else:
            throughput = (
                item.payload_bytes * 1_000_000_000
                / item.median_ns
                / 1048576
            )

            if item.throughput_mib_s is None:
                raise ValueError("missing throughput")

            if not math.isclose(
                item.throughput_mib_s,
                throughput,
                rel_tol=1e-6,
            ):
                raise ValueError("invalid throughput")

    if seen != expected:
        raise ValueError("incomplete results")

    expected_checks = {
        (profile, name)
        for profile in PROFILES
        for name in (
            "roundtrip",
            "wrong_key",
            "tamper",
            "wrong_context",
        )
    }

    expected_checks.update({
        ("rsa2048-oaep", "oaep_boundary"),
        ("rsa3072-oaep", "oaep_boundary"),
    })

    actual_checks = [
        (item.profile, item.name)
        for item in report.checks
    ]

    if (
        len(actual_checks) != len(set(actual_checks))
        or set(actual_checks) != expected_checks
    ):
        raise ValueError("invalid check coverage")

    return report