"""Reproducible local hashing benchmark."""

import csv
import json
import platform
import ssl
import subprocess

from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median, quantiles
from time import perf_counter_ns

from app.schemas.hash_report import validate_report

from app.security.hashing.adapters import (
    prepare_operation,
    hash_bytes,
    hamming_bits,
)

from app.security.hashing.profiles import (
    PROFILES,
    PAYLOAD_SIZES,
    CHUNK_BYTES,
    SERIES,
    WARMUP,
    AVALANCHE_TRIALS,
    AVALANCHE_BYTES,
    make_hasher,
    probe_profiles,
    repeat_count,
    synthetic_payload,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "results" / "practice-04"


KNOWN = {
    "sha256": (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    "sha512": (
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    ),
    "sha3-256": (
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    ),
    "blake2b-256": (
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
        "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
    ),
    "blake2s-256": (
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
    ),
    "md5": (
        "900150983cd24fb0d6963f7d28e17f72",
        "d41d8cd98f00b204e9800998ecf8427e",
    ),
    "sha1": (
        "a9993e364706816aba3e25717850c26c9cd0d89d",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    ),
}


def git_output(*args):
    return subprocess.check_output(
        ["git", *args],
        cwd=ROOT,
        text=True,
    ).strip()


def measure_elapsed(operation, repeats: int) -> int:
    if type(repeats) is not int or repeats <= 0:
        raise ValueError("positive repeat count required")

    start = perf_counter_ns()

    for _ in range(repeats):
        operation()

    return perf_counter_ns() - start


def measure_batch(operation, repeats: int) -> float:
    return measure_elapsed(operation, repeats) / repeats


def summarize(samples: list[float]) -> tuple[float, float]:
    if len(samples) != SERIES:
        raise ValueError("five series required")

    q1, _, q3 = quantiles(
        samples,
        n=4,
        method="inclusive",
    )

    return median(samples), q3 - q1


def reference_digest(algorithm, payload):
    hasher = make_hasher(algorithm)
    hasher.update(payload)
    return hasher.digest()


def correctness_checks(algorithm):
    abc_expected, empty_expected = KNOWN[algorithm]

    unicode_payload = "Digital Dean \u0423\u043a\u0440\u0430\u0457\u043d\u0430".encode(
        "utf-8"
    )

    payload = synthetic_payload(65536)

    checks = {
        "known-abc": (
            hash_bytes(algorithm, b"abc").hex()
            == abc_expected
        ),
        "known-empty": (
            hash_bytes(algorithm, b"").hex()
            == empty_expected
        ),
        "unicode-utf8": (
            hash_bytes(algorithm, unicode_payload)
            == reference_digest(algorithm, unicode_payload)
        ),
        "determinism": (
            hash_bytes(algorithm, payload)
            == hash_bytes(algorithm, payload)
        ),
        "digest-length": (
            len(hash_bytes(algorithm, payload))
            == PROFILES[algorithm].digest_bytes
        ),
        "stream-equivalence": all(
            hash_bytes(
                algorithm,
                synthetic_payload(size),
                "whole",
            )
            == hash_bytes(
                algorithm,
                synthetic_payload(size),
                "chunked",
            )
            for size in PAYLOAD_SIZES
        ),
    }

    return [
        {
            "algorithm": algorithm,
            "name": name,
            "passed": passed,
        }
        for name, passed in checks.items()
    ]


def measure_performance(algorithm):
    raw_rows = []
    results = []

    for size in PAYLOAD_SIZES:
        payload = synthetic_payload(size)
        repeats = repeat_count(size)

        for mode in ("whole", "chunked"):
            operation = prepare_operation(
                algorithm,
                payload,
                mode,
            )

            for _ in range(WARMUP):
                operation()

            samples = []

            for series in range(1, SERIES + 1):
                elapsed_ns = measure_elapsed(
                    operation,
                    repeats,
                )

                ns_per_op = elapsed_ns / repeats
                samples.append(ns_per_op)

                raw_rows.append({
                    "algorithm": algorithm,
                    "mode": mode,
                    "payload_bytes": size,
                    "series": series,
                    "repeats": repeats,
                    "elapsed_ns": elapsed_ns,
                    "ns_per_op": ns_per_op,
                })

            median_ns, iqr_ns = summarize(samples)

            results.append({
                "algorithm": algorithm,
                "mode": mode,
                "payload_bytes": size,
                "digest_bytes": PROFILES[algorithm].digest_bytes,
                "repeats": repeats,
                "median_ns": median_ns,
                "iqr_ns": iqr_ns,
                "throughput_mib_s": (
                    size * 1e9 / (2**20 * median_ns)
                ),
            })

            print(
                f"{algorithm:12} "
                f"{mode:8} "
                f"{size:8} bytes: "
                f"{median_ns:.2f} ns/op",
                flush=True,
            )

    return raw_rows, results


def measure_avalanche(algorithm):
    original = synthetic_payload(AVALANCHE_BYTES)
    original_digest = hash_bytes(algorithm, original)

    digest_bits = len(original_digest) * 8

    rows = []
    distances = []

    for i in range(AVALANCHE_TRIALS):
        modified = bytearray(original)

        modified[i // 8] ^= 1 << (i % 8)

        modified_digest = hash_bytes(
            algorithm,
            bytes(modified),
        )

        flipped = hamming_bits(
            original_digest,
            modified_digest,
        )

        distances.append(flipped)

        rows.append({
            "algorithm": algorithm,
            "trial": i,
            "bit_index": i,
            "digest_bits": digest_bits,
            "flipped_bits": flipped,
            "fraction": flipped / digest_bits,
        })

    average = mean(distances)

    result = {
        "algorithm": algorithm,
        "input_bytes": AVALANCHE_BYTES,
        "trials": AVALANCHE_TRIALS,
        "digest_bits": digest_bits,
        "min_flipped_bits": min(distances),
        "max_flipped_bits": max(distances),
        "mean_flipped_bits": average,
        "mean_fraction": average / digest_bits,
    }

    return rows, result


def write_csv(path, rows, fields):
    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields,
        )

        writer.writeheader()
        writer.writerows(rows)


def run_experiment():
    if git_output("status", "--porcelain"):
        raise SystemExit(
            "Working tree must be clean before benchmark."
        )

    source_commit = git_output("rev-parse", "HEAD")

    created_at = datetime.now(timezone.utc).isoformat()

    print("Practice 4 hashing benchmark")
    print("Source commit:", source_commit)
    print()

    statuses = probe_profiles()

    raw_rows = []
    avalanche_rows = []
    results = []
    avalanche = []
    checks = []

    for status in statuses:
        algorithm = status["algorithm"]

        if not status["available"]:
            print(f"{algorithm}: unavailable")
            continue

        print(f"\nTesting {algorithm}")

        checks.extend(
            correctness_checks(algorithm)
        )

        raw, performance = measure_performance(
            algorithm
        )

        raw_rows.extend(raw)
        results.extend(performance)

        rows, avalanche_result = measure_avalanche(
            algorithm
        )

        avalanche_rows.extend(rows)
        avalanche.append(avalanche_result)

    report = {
        "schema_version": 1,
        "created_at": created_at,
        "source_commit": source_commit,

        "parameters": {
            "sizes": list(PAYLOAD_SIZES),
            "chunk_bytes": CHUNK_BYTES,
            "warmup": WARMUP,
            "series": SERIES,
            "repeats_small": repeat_count(64),
            "repeats_large": repeat_count(1048576),
            "avalanche_trials": AVALANCHE_TRIALS,
            "avalanche_bytes": AVALANCHE_BYTES,
        },

        "environment": {
            "python": platform.python_version(),
            "openssl_ssl": ssl.OPENSSL_VERSION,
            "os": (
                f"{platform.system()} "
                f"{platform.release()} "
                f"{platform.version()}"
            ),
            "cpu": (
                platform.processor()
                or platform.machine()
                or "unknown"
            ),
            "architecture": (
                platform.machine() or "unknown"
            ),
        },

        "algorithms": statuses,
        "results": results,
        "avalanche": avalanche,
        "checks": checks,
    }

    validated = validate_report(report)

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    write_csv(
        OUTPUT_DIR / "raw.csv",
        raw_rows,
        [
            "algorithm",
            "mode",
            "payload_bytes",
            "series",
            "repeats",
            "elapsed_ns",
            "ns_per_op",
        ],
    )

    write_csv(
        OUTPUT_DIR / "avalanche.csv",
        avalanche_rows,
        [
            "algorithm",
            "trial",
            "bit_index",
            "digest_bits",
            "flipped_bits",
            "fraction",
        ],
    )

    (OUTPUT_DIR / "report.json").write_text(
        json.dumps(
            validated.model_dump(mode="json"),
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        ) + "\n",
        encoding="utf-8",
    )

    all_passed = all(
        check["passed"]
        for check in checks
    )

    print("\nBenchmark completed")
    print("Available algorithms:", sum(
        status["available"]
        for status in statuses
    ))
    print("Performance results:", len(results))
    print("Raw measurements:", len(raw_rows))
    print("Avalanche results:", len(avalanche))
    print("Avalanche trials:", len(avalanche_rows))
    print("Correctness checks:", len(checks))
    print("All checks passed:", all_passed)
    print("Report validation: OK")
    print("Results saved to results/practice-04/")

    if not all_passed:
        raise SystemExit(
            "One or more correctness checks failed."
        )


if __name__ == "__main__":
    run_experiment()