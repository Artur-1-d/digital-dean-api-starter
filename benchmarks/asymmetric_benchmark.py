"""Offline asymmetric cryptography benchmark."""

import csv
import json
import os
import platform
import statistics
import subprocess

from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter_ns

import cryptography

from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import serialization

from app.security.asymmetric.adapters import (
    generate_keypair,
    encrypt,
    decrypt,
    DecryptionError,
)

from app.security.asymmetric.profiles import (
    PROFILES,
    KEY_PROFILES,
    HYBRID_SIZES,
    DIRECT_SIZE,
    oaep_max_bytes,
    expected_ciphertext_bytes,
)

from app.schemas.asymmetric_report import (
    validate_complete_report,
)


SERIES = 5
OPERATIONS = 20
WARMUP = 10
KEYGEN_RUNS = 5

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "results" / "practice-03"

CSV_COLUMNS = (
    "group",
    "profile",
    "operation",
    "payload_bytes",
    "series_index",
    "operations",
    "elapsed_ns",
    "ns_per_operation",
    "ciphertext_bytes",
)


def measure_batch(operation, count=OPERATIONS):
    if count < 1:
        raise ValueError("count must be positive")

    started = perf_counter_ns()

    for _ in range(count):
        operation()

    elapsed = perf_counter_ns() - started

    return elapsed, elapsed / count


def summarize(samples):
    if len(samples) != SERIES:
        raise ValueError("five series required")

    q1, _, q3 = statistics.quantiles(
        samples,
        n=4,
        method="inclusive",
    )

    return (
        float(statistics.median(samples)),
        float(q3 - q1),
    )


def rejected(operation):
    try:
        operation()
    except DecryptionError:
        return True

    return False


def boundary_check(profile, private, public):
    bits = 2048 if profile == "rsa2048-oaep" else 3072
    limit = oaep_max_bytes(bits)

    message = os.urandom(limit)

    envelope = encrypt(
        profile,
        public,
        message,
    )

    if decrypt(profile, private, envelope) != message:
        return False

    try:
        encrypt(
            profile,
            public,
            os.urandom(limit + 1),
        )
    except ValueError:
        return True

    return False


def correctness_checks(keys):
    checks = []

    for profile, spec in PROFILES.items():
        private, public = keys[spec.key_profile]

        wrong_private, _ = generate_keypair(
            spec.key_profile
        )

        message = os.urandom(spec.sizes[0])

        envelope = encrypt(
            profile,
            public,
            message,
        )

        damaged = bytearray(envelope)
        damaged[-1] ^= 1
        damaged = bytes(damaged)

        results = {
            "roundtrip": (
                decrypt(profile, private, envelope)
                == message
            ),

            "wrong_key": rejected(
                lambda: decrypt(
                    profile,
                    wrong_private,
                    envelope,
                )
            ),

            "tamper": rejected(
                lambda: decrypt(
                    profile,
                    private,
                    damaged,
                )
            ),

            "wrong_context": rejected(
                lambda: decrypt(
                    profile,
                    private,
                    envelope,
                    context=b"wrong-context",
                )
            ),
        }

        if spec.group == "direct":
            results["oaep_boundary"] = boundary_check(
                profile,
                private,
                public,
            )

        for name, passed in results.items():
            checks.append({
                "profile": profile,
                "name": name,
                "passed": passed,
            })

    return checks


def run_experiment():
    raw_rows = []
    key_results = []
    results = []

    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
    ).strip()

    created_at = datetime.now(
        timezone.utc
    ).isoformat()

    print("Preparing recipient keys...")

    keys = {
        key_profile: generate_keypair(key_profile)
        for key_profile in KEY_PROFILES
    }

    print("Measuring key generation...")

    for key_profile in KEY_PROFILES:
        samples = []
        public = None

        for index in range(1, KEYGEN_RUNS + 1):
            started = perf_counter_ns()

            private, public = generate_keypair(
                key_profile
            )

            elapsed = perf_counter_ns() - started

            samples.append(float(elapsed))

            raw_rows.append({
                "group": "key_generation",
                "profile": key_profile,
                "operation": "keygen",
                "payload_bytes": 0,
                "series_index": index,
                "operations": 1,
                "elapsed_ns": elapsed,
                "ns_per_operation": float(elapsed),
                "ciphertext_bytes": 0,
            })

        der = public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        median, iqr = summarize(samples)

        key_results.append({
            "key_profile": key_profile,
            "runs": KEYGEN_RUNS,
            "median_ns": median,
            "iqr_ns": iqr,
            "public_key_der_bytes": len(der),
        })

        print(
            f"  {key_profile}: "
            f"{median / 1e6:.3f} ms"
        )

    print("Preparing benchmark payloads...")

    cases = {}
    samples = {}

    for profile, spec in PROFILES.items():
        private, public = keys[spec.key_profile]

        for size in spec.sizes:
            message = os.urandom(size)

            envelope = encrypt(
                profile,
                public,
                message,
            )

            ciphertext_size = expected_ciphertext_bytes(
                profile,
                size,
            )

            if len(envelope) != ciphertext_size:
                raise ValueError(
                    "unexpected ciphertext size"
                )

            if decrypt(
                profile,
                private,
                envelope,
            ) != message:
                raise ValueError(
                    "roundtrip verification failed"
                )

            cases[(profile, size)] = (
                private,
                public,
                message,
                ciphertext_size,
            )

            samples[(profile, size, "encrypt")] = []
            samples[(profile, size, "decrypt")] = []

            for _ in range(WARMUP):
                encrypt(
                    profile,
                    public,
                    message,
                )

                decrypt(
                    profile,
                    private,
                    envelope,
                )

    print("Measuring encryption and decryption...")

    profiles = list(PROFILES)

    for series_index in range(1, SERIES + 1):
        offset = series_index - 1

        order = (
            profiles[offset:]
            + profiles[:offset]
        )

        print(f"Series {series_index}/{SERIES}")

        for profile in order:
            spec = PROFILES[profile]

            for size in spec.sizes:
                (
                    private,
                    public,
                    message,
                    ciphertext_size,
                ) = cases[(profile, size)]

                elapsed, average = measure_batch(
                    lambda: encrypt(
                        profile,
                        public,
                        message,
                    )
                )

                samples[
                    (profile, size, "encrypt")
                ].append(average)

                raw_rows.append({
                    "group": spec.group,
                    "profile": profile,
                    "operation": "encrypt",
                    "payload_bytes": size,
                    "series_index": series_index,
                    "operations": OPERATIONS,
                    "elapsed_ns": elapsed,
                    "ns_per_operation": average,
                    "ciphertext_bytes": ciphertext_size,
                })

                # Prepare envelopes outside the timer.
                envelopes = [
                    encrypt(
                        profile,
                        public,
                        message,
                    )
                    for _ in range(OPERATIONS)
                ]

                iterator = iter(envelopes)

                elapsed, average = measure_batch(
                    lambda: decrypt(
                        profile,
                        private,
                        next(iterator),
                    )
                )

                samples[
                    (profile, size, "decrypt")
                ].append(average)

                raw_rows.append({
                    "group": spec.group,
                    "profile": profile,
                    "operation": "decrypt",
                    "payload_bytes": size,
                    "series_index": series_index,
                    "operations": OPERATIONS,
                    "elapsed_ns": elapsed,
                    "ns_per_operation": average,
                    "ciphertext_bytes": ciphertext_size,
                })

    for profile, spec in PROFILES.items():
        for size in spec.sizes:
            for operation in ("encrypt", "decrypt"):
                median, iqr = summarize(
                    samples[(profile, size, operation)]
                )

                throughput = None

                if spec.group == "hybrid":
                    throughput = (
                        size * 1e9
                        / (2 ** 20 * median)
                    )

                results.append({
                    "profile": profile,
                    "group": spec.group,
                    "operation": operation,
                    "payload_bytes": size,
                    "series": SERIES,
                    "operations_per_series": OPERATIONS,
                    "median_ns": median,
                    "iqr_ns": iqr,
                    "ciphertext_bytes": (
                        expected_ciphertext_bytes(
                            profile,
                            size,
                        )
                    ),
                    "throughput_mib_s": throughput,
                })

    print("Running correctness checks...")

    checks = correctness_checks(keys)

    cpu = (
        platform.processor()
        or os.environ.get("PROCESSOR_IDENTIFIER")
        or platform.machine()
        or "Unknown CPU"
    )

    report = {
        "schema_version": 1,

        "experiment": {
            "series": SERIES,
            "operations_per_series": OPERATIONS,
            "warmup": WARMUP,
            "keygen_runs": KEYGEN_RUNS,
            "direct_payload_bytes": DIRECT_SIZE,
            "hybrid_sizes_bytes": list(HYBRID_SIZES),
            "source_commit": source_commit,
            "created_at_utc": created_at,
        },

        "environment": {
            "python": platform.python_version(),
            "cryptography": cryptography.__version__,
            "openssl": backend.openssl_version_text(),
            "os": (
                f"{platform.system()} "
                f"{platform.release()} "
                f"{platform.version()}"
            ),
            "cpu": cpu,
        },

        "key_generation": key_results,
        "results": results,
        "checks": checks,
    }

    validated = validate_complete_report(report)

    if len(raw_rows) != 130:
        raise ValueError("expected 130 raw rows")

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    csv_path = OUTPUT_DIR / "raw.csv"
    json_path = OUTPUT_DIR / "report.json"

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=CSV_COLUMNS,
        )

        writer.writeheader()
        writer.writerows(raw_rows)

    with json_path.open(
        "w",
        encoding="utf-8",
    ) as stream:
        json.dump(
            validated.model_dump(),
            stream,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )

    passed = sum(
        check["passed"]
        for check in checks
    )

    print()
    print("Benchmark completed.")
    print(f"Raw CSV rows: {len(raw_rows)}")
    print(f"Key generation results: {len(key_results)}")
    print(f"Benchmark results: {len(results)}")
    print(f"Correctness checks: {passed}/{len(checks)}")
    print("Created: results/practice-03/raw.csv")
    print("Created: results/practice-03/report.json")

    return passed == len(checks)


def main():
    return 0 if run_experiment() else 1


if __name__ == "__main__":
    raise SystemExit(main())
