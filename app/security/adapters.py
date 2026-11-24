from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)
from cryptography.exceptions import InvalidTag
from Crypto.Cipher import AES, ChaCha20_Poly1305

from app.security.profiles import (
    BACKENDS,
    TAG_BYTES,
    validate_profile,
)


class CiphertextError(Exception):
    pass


def seal_bytes(backend, algorithm, key, nonce, data, aad):
    validate_profile(algorithm, key, nonce)

    if backend not in BACKENDS:
        raise ValueError("Unknown backend")

    if backend == "cryptography":
        cipher = (
            ChaCha20Poly1305(key)
            if algorithm == "ChaCha20-Poly1305"
            else AESGCM(key)
        )
        result = cipher.encrypt(nonce, data, aad)
        return result[:-TAG_BYTES], result[-TAG_BYTES:]

    if algorithm == "ChaCha20-Poly1305":
        cipher = ChaCha20_Poly1305.new(
            key=key, nonce=nonce
        )
    else:
        cipher = AES.new(
            key, AES.MODE_GCM,
            nonce=nonce, mac_len=TAG_BYTES
        )

    cipher.update(aad)
    return cipher.encrypt_and_digest(data)


def open_bytes(backend, algorithm, key, nonce, ct, tag, aad):
    validate_profile(algorithm, key, nonce)

    if backend not in BACKENDS:
        raise ValueError("Unknown backend")

    if len(tag) != TAG_BYTES:
        raise CiphertextError("Invalid tag length")

    try:
        if backend == "cryptography":
            cipher = (
                ChaCha20Poly1305(key)
                if algorithm == "ChaCha20-Poly1305"
                else AESGCM(key)
            )
            return cipher.decrypt(nonce, ct + tag, aad)

        if algorithm == "ChaCha20-Poly1305":
            cipher = ChaCha20_Poly1305.new(
                key=key, nonce=nonce
            )
        else:
            cipher = AES.new(
                key, AES.MODE_GCM,
                nonce=nonce, mac_len=TAG_BYTES
            )

        cipher.update(aad)
        return cipher.decrypt_and_verify(ct, tag)

    except (InvalidTag, ValueError):
        raise CiphertextError(
            "Authentication failed"
        ) from None