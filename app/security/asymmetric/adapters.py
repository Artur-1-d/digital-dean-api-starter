import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    rsa, padding, x25519, ec
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hpke import (
    Suite, KEM, KDF, AEAD
)

from app.security.asymmetric.profiles import (
    CONTEXT,
    PROFILES,
    KEY_PROFILES,
    oaep_max_bytes,
)


class DecryptionError(ValueError):
    pass


def generate_keypair(key_profile: str):
    if key_profile not in KEY_PROFILES:
        raise ValueError("unsupported key profile")

    if key_profile == "rsa-2048":
        private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    elif key_profile == "rsa-3072":
        private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )

    elif key_profile == "x25519":
        private = x25519.X25519PrivateKey.generate()

    elif key_profile == "p256":
        private = ec.generate_private_key(ec.SECP256R1())

    return private, private.public_key()


def _oaep(context):
    return padding.OAEP(
        mgf=padding.MGF1(
            algorithm=hashes.SHA256()
        ),
        algorithm=hashes.SHA256(),
        label=context,
    )


def _hpke_suite(profile: str):
    if profile == "hpke-x25519-aes256gcm":
        kem = KEM.X25519

    elif profile == "hpke-p256-aes256gcm":
        kem = KEM.P256

    else:
        raise ValueError("unsupported HPKE profile")

    return Suite(
        kem,
        KDF.HKDF_SHA256,
        AEAD.AES_256_GCM,
    )


def encrypt(
    profile: str,
    public: object,
    message: bytes,
    *,
    context: bytes = CONTEXT,
) -> bytes:

    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")

    if profile in ("rsa2048-oaep", "rsa3072-oaep"):
        bits = 2048 if profile == "rsa2048-oaep" else 3072

        if len(message) > oaep_max_bytes(bits):
            raise ValueError("message too large")

        return public.encrypt(
            message,
            _oaep(context),
        )

    if profile == "rsa3072-oaep-aes256gcm":
        key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)

        wrapped_key = public.encrypt(
            key,
            _oaep(context),
        )

        ciphertext = AESGCM(key).encrypt(
            nonce,
            message,
            context,
        )

        return wrapped_key + nonce + ciphertext

    return _hpke_suite(profile).encrypt(
        message,
        public,
        info=context,
    )


def _decrypt(
    profile: str,
    private: object,
    envelope: bytes,
    context: bytes,
) -> bytes:

    if profile in ("rsa2048-oaep", "rsa3072-oaep"):
        expected = 256 if profile == "rsa2048-oaep" else 384

        if len(envelope) != expected:
            raise ValueError("invalid envelope")

        return private.decrypt(
            envelope,
            _oaep(context),
        )

    if profile == "rsa3072-oaep-aes256gcm":
        if len(envelope) < 412:
            raise ValueError("invalid envelope")

        wrapped_key = envelope[:384]
        nonce = envelope[384:396]
        ciphertext = envelope[396:]

        key = private.decrypt(
            wrapped_key,
            _oaep(context),
        )

        if len(key) != 32:
            raise ValueError("invalid key")

        return AESGCM(key).decrypt(
            nonce,
            ciphertext,
            context,
        )

    minimum = PROFILES[profile].overhead_bytes

    if len(envelope) < minimum:
        raise ValueError("invalid envelope")

    return _hpke_suite(profile).decrypt(
        envelope,
        private,
        info=context,
    )


def decrypt(
    profile: str,
    private: object,
    envelope: bytes,
    *,
    context: bytes = CONTEXT,
) -> bytes:

    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")

    try:
        return _decrypt(
            profile,
            private,
            envelope,
            context,
        )

    except (InvalidTag, ValueError) as exc:
        raise DecryptionError(
            "decryption rejected"
        ) from exc