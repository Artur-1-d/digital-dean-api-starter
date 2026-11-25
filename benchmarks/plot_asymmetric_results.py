
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "results" / "practice-03"

with (OUTPUT / "report.json").open(
    encoding="utf-8"
) as file:
    report = json.load(file)


profiles = {
    "rsa3072-oaep-aes256gcm": "RSA-3072 + AES-GCM",
    "hpke-x25519-aes256gcm": "HPKE X25519",
    "hpke-p256-aes256gcm": "HPKE P-256",
}

sizes = [1024, 65536, 1048576]
labels = ["1 KiB", "64 KiB", "1 MiB"]

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 11,
    "figure.dpi": 150,
})


def save_chart(fig, filename):
    fig.text(
        0.5,
        0.015,
        "Source: results/practice-03/report.json",
        ha="center",
        fontsize=9,
    )

    fig.tight_layout(rect=(0, 0.05, 1, 1))

    path = OUTPUT / filename

    fig.savefig(path, dpi=200)
    plt.close(fig)

    print(f"Created: {path.name}")


def plot_operation(operation):
    fig, axes = plt.subplots(
        1, 2,
        figsize=(13, 6),
        gridspec_kw={"width_ratios": [1, 2]},
    )

    direct = [
        item for item in report["results"]
        if item["group"] == "direct"
        and item["operation"] == operation
    ]

    axes[0].bar(
        [item["profile"] for item in direct],
        [item["median_ns"] / 1e6 for item in direct],
        label="Median time",
    )

    axes[0].set_title("Direct RSA: 64 bytes")
    axes[0].set_ylabel("Time (ms)")
    axes[0].tick_params(axis="x", rotation=15)
    axes[0].grid(axis="y", alpha=0.25)
    axes[0].legend()

    x = np.arange(len(sizes))
    width = 0.24

    for index, (profile, name) in enumerate(
        profiles.items()
    ):
        values = []

        for size in sizes:
            item = next(
                row for row in report["results"]
                if row["profile"] == profile
                and row["payload_bytes"] == size
                and row["operation"] == operation
            )

            values.append(item["median_ns"] / 1e6)

        axes[1].bar(
            x + (index - 1) * width,
            values,
            width,
            label=name,
        )

    axes[1].set_title("Hybrid encryption profiles")
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(labels)
    axes[1].set_xlabel("Payload size")
    axes[1].set_ylabel("Time (ms)")
    axes[1].set_yscale("log")
    axes[1].grid(axis="y", alpha=0.25)
    axes[1].legend()

    fig.suptitle(
        f"{operation.capitalize()} — median execution time",
        fontsize=15,
        fontweight="bold",
    )

    save_chart(fig, f"{operation}_time.png")


def plot_key_generation():
    names = [
        item["key_profile"]
        for item in report["key_generation"]
    ]

    values = [
        item["median_ns"] / 1e6
        for item in report["key_generation"]
    ]

    fig, ax = plt.subplots(figsize=(10, 6))

    bars = ax.bar(
        names,
        values,
        label="Median key generation time",
    )

    ax.set_yscale("log")
    ax.set_title("Key generation performance")
    ax.set_xlabel("Key profile")
    ax.set_ylabel("Time (ms, logarithmic scale)")
    ax.grid(axis="y", alpha=0.25)
    ax.legend()

    for bar, value in zip(bars, values):
        ax.annotate(
            f"{value:.4f} ms",
            (
                bar.get_x() + bar.get_width() / 2,
                value,
            ),
            xytext=(0, 6),
            textcoords="offset points",
            ha="center",
        )

    ax.set_ylim(
        min(values) / 2,
        max(values) * 3,
    )

    save_chart(fig, "key_generation.png")


if __name__ == "__main__":
    plot_operation("encrypt")
    plot_operation("decrypt")
    plot_key_generation()

    print()
    print("All 3 charts created successfully.")
