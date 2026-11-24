import json
import math
from pathlib import Path
from itertools import product
from statistics import median, quantiles

from fastapi import APIRouter, HTTPException

router = APIRouter(
    prefix="/api/v1/lab/crypto",
    tags=["crypto-lab"]
)

REPORT_PATH = (
    Path(__file__).resolve().parents[2]
    / "results/practice-02/report.json"
)

SIZES = (1024, 65536, 1048576)

ALGORITHMS = (
    "AES-128-GCM",
    "AES-256-GCM",
    "ChaCha20-Poly1305"
)

BACKENDS = ("cryptography", "pycryptodome")


def load_benchmark_report(path: Path) -> dict:
    report = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(report, dict):
        raise ValueError("Invalid report")

    if report.get("schema_version") != 1:
        raise ValueError("Invalid schema version")

    if not isinstance(report.get("run_id"), str):
        raise ValueError("Invalid run ID")

    for field in ("environment", "parameters"):
        if not isinstance(report.get(field), dict):
            raise ValueError("Invalid report metadata")

    rows = report.get("results")

    if not isinstance(rows, list) or len(rows) != 36:
        raise ValueError("Invalid result count")

    expected = set(product(
        BACKENDS,
        ALGORITHMS,
        SIZES,
        ("encrypt", "decrypt")
    ))

    seen = set()

    for row in rows:
        key = (
            row["backend"],
            row["algorithm"],
            row["size_bytes"],
            row["operation"]
        )

        if key not in expected or key in seen:
            raise ValueError("Invalid combination")

        seen.add(key)

        values = row["series_mean_ns"]

        if not isinstance(values, list) or len(values) != 5:
            raise ValueError("Invalid series")

        if any(
            type(v) not in (int, float)
            or not math.isfinite(v)
            or v <= 0
            for v in values
        ):
            raise ValueError("Invalid measurements")

        typical = median(values)
        q1, _, q3 = quantiles(
            values, n=4, method="inclusive"
        )

        metrics = {
            "median_ns": typical,
            "iqr_ns": q3 - q1,
            "throughput_mib_s":
                row["size_bytes"] * 1e9 / (2**20 * typical)
        }

        for name, value in metrics.items():
            if not math.isclose(
                row[name], value, rel_tol=1e-9
            ):
                raise ValueError("Invalid metrics")

    return report


@router.get("/benchmark-results")
def benchmark_results() -> dict:
    try:
        return load_benchmark_report(REPORT_PATH)

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Benchmark results unavailable"
        ) from None

    except (OSError, ValueError, TypeError, KeyError,
            AttributeError, OverflowError):
        raise HTTPException(
            status_code=500,
            detail="Benchmark results unavailable"
        ) from None