"""Decryption core — byte-identical across all six SDKs.

Every person value arrives as a ciphertext wrapper, encrypted **for the
service public key**; the SDK decrypts with the service private key. The
algorithm MUST match the platform's Web Crypto encryption exactly:

    wrapper = {"_enc":1,
               "k":  base64(rsa_oaep_sha256(aesKey, servicePublicKey)),
               "iv": base64(iv12),
               "d":  base64(aes256gcm_ciphertext_with_tag)}

    decrypt(wrapper, servicePrivateKey):
      aesKey    = RSA-OAEP(SHA-256, MGF1-SHA256) decrypt wrapper.k   # 32 bytes
      plaintext = AES-256-GCM decrypt wrapper.d with aesKey, iv=wrapper.iv
                  # the 16-byte GCM tag is the LAST 16 bytes of d
      return utf8(plaintext)

The service private key is the OpenSSL-encrypted PKCS#8 PEM downloaded from the
portal (PBES2 = PBKDF2-HMAC-SHA256 + AES-256-CBC, ~100k iters).
``cryptography``'s ``load_pem_private_key`` reads it directly given the
passphrase.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from typing import Union

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key

GCM_TAG_LEN = 16  # bytes — appended to the AES-GCM ciphertext
GCM_IV_LEN = 12   # bytes


class DecryptError(Exception):
    """Wrapper malformed, wrong key, or GCM tag mismatch."""


def load_private_key(
    encrypted_pem_bytes: bytes, passphrase: str
) -> rsa.RSAPrivateKey:
    """Load an OpenSSL-encrypted PKCS#8 PEM into an in-memory RSA private key.

    The PEM is PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC). ``cryptography``'s
    OpenSSL backend handles the SHA-256 PRF; the key is never written back to
    disk in plaintext.

    Config-only key handling: this is the single place a passphrase is used,
    and it is driven by ``Config.key_passphrase`` — never passed in by
    application code.
    """
    if isinstance(passphrase, str):
        pw = passphrase.encode("utf-8")
    else:  # pragma: no cover - defensive
        pw = passphrase
    try:
        key = load_pem_private_key(encrypted_pem_bytes, password=pw)
    except (ValueError, TypeError) as exc:
        # ValueError covers a wrong passphrase / malformed PEM.
        raise DecryptError(f"could not load private key PEM: {exc}") from exc
    except UnsupportedAlgorithm as exc:  # pragma: no cover - environment-specific
        raise DecryptError(
            f"unsupported PEM encryption algorithm: {exc}"
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise DecryptError("PEM did not contain an RSA private key")
    return key


def _b64decode(value: str, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise DecryptError(f"wrapper field {field_name!r} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise DecryptError(f"wrapper field {field_name!r} is not valid base64") from exc


def decrypt(
    wrapper: Union[dict, str], private_key: rsa.RSAPrivateKey
) -> str:
    """Decrypt a platform ``{"_enc":1,k,iv,d}`` wrapper → utf-8 plaintext string.

    For a *text* value the plaintext is the value itself. For a *binary* value
    the plaintext is a JSON envelope STRING (photo: ``{"full":"data:...","thumb":...}``;
    document: ``{"file":"data:...","original_name":...}``) — NOT raw bytes. The
    full binary-handle parse (envelope -> data-URI -> bytes) lives on
    :class:`BinaryHandle`; here we only ever decrypt to that envelope string.

    Raises :class:`DecryptError` on a malformed wrapper, the wrong key, or a GCM
    tag mismatch.
    """
    if isinstance(wrapper, str):
        try:
            wrapper = json.loads(wrapper)
        except json.JSONDecodeError as exc:
            raise DecryptError("wrapper string is not valid JSON") from exc
    if not isinstance(wrapper, dict):
        raise DecryptError("wrapper must be a dict or a JSON object string")

    for field_name in ("k", "iv", "d"):
        if field_name not in wrapper:
            raise DecryptError(f"wrapper missing required field {field_name!r}")

    enc_key = _b64decode(wrapper["k"], "k")
    iv = _b64decode(wrapper["iv"], "iv")
    ciphertext_with_tag = _b64decode(wrapper["d"], "d")

    if len(iv) != GCM_IV_LEN:
        raise DecryptError(
            f"iv must be {GCM_IV_LEN} bytes, got {len(iv)}"
        )
    if len(ciphertext_with_tag) < GCM_TAG_LEN:
        raise DecryptError("ciphertext too short to contain a GCM tag")

    # 1) RSA-OAEP(SHA-256, MGF1-SHA256) unwrap the AES key.
    #    Pin SHA-256 for both the OAEP digest AND MGF1 (never accept a SHA-1
    #    default) — matches Web Crypto RSA-OAEP/SHA-256.
    try:
        aes_key = private_key.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError as exc:
        raise DecryptError(f"RSA-OAEP unwrap failed (wrong key?): {exc}") from exc

    if len(aes_key) != 32:
        raise DecryptError(
            f"unwrapped AES key must be 32 bytes (AES-256), got {len(aes_key)}"
        )

    # 2) AES-256-GCM decrypt. cryptography's AESGCM expects the 16-byte tag
    #    appended to the ciphertext, which is exactly the platform's layout.
    try:
        plaintext = AESGCM(aes_key).decrypt(iv, ciphertext_with_tag, None)
    except InvalidTag as exc:
        raise DecryptError("AES-GCM tag mismatch (wrong key or corrupt data)") from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptError("decrypted plaintext is not valid UTF-8") from exc


class BinaryHandle:
    """Lazy handle for a binary (photo/document) value.

    A binary answer is stored server-side as a file, exposed in the hardened API
    as a slot-keyed ``value_url`` (never the source field). On ``.bytes()`` /
    ``.save()`` the handle GETs that URL, receives the ``{"_enc":1,...}`` wrapper,
    runs the same decrypt as text → a JSON envelope STRING (photo:
    ``{"full":"data:...","thumb":...}``; document: ``{"file":"data:...",...}``) —
    NOT raw bytes — then parses the envelope and base64-decodes the primary
    data-URI payload (``full`` for photos, ``file`` for documents) into the file
    bytes.

    The fetch + decrypt are supplied by the client as plain callables:

    * ``value_url`` + ``fetch`` — ``fetch(value_url)`` returns the encrypted
      wrapper (dict or its JSON string), the way the slot file endpoint serves
      ``{"encrypted": true, "value": "<wrapper>"}`` (the client passes a callback
      that does the GET + unwraps to the inner wrapper).
    * ``decrypt`` — ``decrypt(wrapper)`` returns the decrypted envelope string
      (a closure over the loaded service private key, so no key is ever passed
      to this handle — config-only key handling).

    When the decrypted envelope is already in hand, a handle can also be built
    directly from ``envelope_json`` (no fetch).
    """

    # Envelope keys that hold the primary binary data URI, in priority order.
    _DATA_URI_KEYS = ("full", "file")

    def __init__(
        self,
        *,
        envelope_json: str | None = None,
        value_url: str | None = None,
        fetch=None,
        decrypt=None,
    ):
        # Either: the decrypted envelope is already in hand (inline),
        # or: a lazy fetch+decrypt pair that produces it on first .bytes()/.save().
        self._envelope_json = envelope_json
        self._value_url = value_url
        self._fetch = fetch
        self._decrypt = decrypt

    @property
    def value_url(self) -> str | None:
        """The slot-keyed file URL this handle fetches from (opaque to callers)."""
        return self._value_url

    def _resolve_envelope(self) -> str:
        """Return the decrypted envelope string, fetching+decrypting on first use."""
        if self._envelope_json is not None:
            return self._envelope_json
        if self._fetch is None or self._decrypt is None or self._value_url is None:
            raise DecryptError(
                "BinaryHandle has no envelope and no fetch/decrypt wiring "
                "(build it with envelope_json, or value_url + fetch + decrypt)"
            )
        wrapper = self._fetch(self._value_url)
        envelope_json = self._decrypt(wrapper)
        # Cache so repeated .bytes()/.save() don't re-fetch.
        self._envelope_json = envelope_json
        return envelope_json

    @staticmethod
    def parse_envelope_bytes(envelope_json: str) -> bytes:
        """Turn a decrypted binary envelope STRING into the primary file bytes.

        Photo envelope -> the ``full`` data-URI payload; document envelope ->
        the ``file`` data-URI payload. Raises :class:`DecryptError` on a
        malformed envelope.
        """
        try:
            envelope = json.loads(envelope_json)
        except json.JSONDecodeError as exc:
            raise DecryptError("binary envelope is not valid JSON") from exc
        if not isinstance(envelope, dict):
            raise DecryptError("binary envelope must be a JSON object")

        data_uri = None
        for key in BinaryHandle._DATA_URI_KEYS:
            if isinstance(envelope.get(key), str):
                data_uri = envelope[key]
                break
        if data_uri is None:
            raise DecryptError(
                "binary envelope has no 'full'/'file' data-URI payload"
            )

        # data:<mime>;base64,<payload>
        marker = "base64,"
        idx = data_uri.find(marker)
        if idx == -1:
            raise DecryptError("binary data URI is not base64-encoded")
        payload = data_uri[idx + len(marker):]
        try:
            return base64.b64decode(payload)
        except (ValueError, base64.binascii.Error) as exc:
            raise DecryptError("binary data-URI payload is not valid base64") from exc

    def bytes(self) -> bytes:
        """Fetch (if needed), decrypt, and return the decoded primary file bytes."""
        return self.parse_envelope_bytes(self._resolve_envelope())

    def save(self, path: str) -> int:
        """Write the decoded file bytes to ``path``; return the number of bytes written.

        Crash-safe (matching the buffer's atomic-write discipline):
        the bytes are written to a temp file in the same directory, fsync'd, and
        atomically ``os.replace``-d into place — so a crash mid-write never leaves
        a truncated output file (the destination is either the old file, or the
        complete new one).
        """
        data = self.bytes()
        directory = os.path.dirname(os.path.abspath(path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp_", suffix=".part")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)  # atomic rename over any existing file
        except BaseException:
            # Clean up the temp file on any failure so we never leak partials.
            try:
                os.unlink(tmp)
            except OSError:  # pragma: no cover
                pass
            raise
        return len(data)
