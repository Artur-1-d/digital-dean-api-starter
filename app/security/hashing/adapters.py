
from collections.abc import Callable

from app.security.hashing.profiles import (
    CHUNK_BYTES,
    PROFILES,
    make_hasher,
)


def prepare_operation(
    algorithm: str,
    payload: bytes,
    mode: str = "whole",
) -> Callable[[], bytes]:

    if algorithm not in PROFILES:
        raise ValueError("unknown hash profile")

    if mode not in ("whole", "chunked"):
        raise ValueError("unknown hashing mode")

    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")

    if mode == "whole":
        blocks = (payload,)
    else:
        blocks = tuple(
            payload[i:i + CHUNK_BYTES]
            for i in range(0, len(payload), CHUNK_BYTES)
        )

    def operation() -> bytes:
        hasher = make_hasher(algorithm)

        for block in blocks:
            hasher.update(block)

        return hasher.digest()

    return operation


def hash_bytes(
    algorithm: str,
    payload: bytes,
    mode: str = "whole",
) -> bytes:
    return prepare_operation(algorithm, payload, mode)()


def hamming_bits(left: bytes, right: bytes) -> int:

    if not isinstance(left, bytes):
        raise TypeError("left digest must be bytes")

    if not isinstance(right, bytes):
        raise TypeError("right digest must be bytes")

    if not left or len(left) != len(right):
        raise ValueError("invalid digest lengths")

    return sum(
        (a ^ b).bit_count()
        for a, b in zip(left, right)
    )
