"""Decryption core tests.

These prove the Python decryptor reproduces the shared test vector
(``testdata/decryption-vector.json``), and — crucially, to avoid
circularity — that the vector's wrappers are PLATFORM-correct, by decrypting
the text wrapper through a fully INDEPENDENT toolchain (the OpenSSL CLI for the
PBES2 PEM + the RSA-OAEP-SHA256 unwrap, then Node ``crypto`` for the AES-256-GCM
step) and getting the same plaintext.
"""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile

import pytest

from allus_company_data.crypto import (
    BinaryHandle,
    DecryptError,
    decrypt,
    load_private_key,
)

VECTOR_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), "..", "testdata", "decryption-vector.json"
    )
)


@pytest.fixture(scope="module")
def vector():
    with open(VECTOR_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def private_key(vector):
    pem = vector["encrypted_private_key_pem"].encode("ascii")
    return load_private_key(pem, vector["passphrase"])


# ── Self-consistent decryption (the SDK's own crypto core) ──────────────────

def test_load_private_key_from_pbes2_pem(vector):
    pem = vector["encrypted_private_key_pem"].encode("ascii")
    key = load_private_key(pem, vector["passphrase"])
    assert key.key_size == 2048


def test_load_private_key_wrong_passphrase_raises(vector):
    pem = vector["encrypted_private_key_pem"].encode("ascii")
    with pytest.raises(DecryptError):
        load_private_key(pem, "the-wrong-passphrase")


def test_decrypt_text_wrapper_matches_plaintext(vector, private_key):
    plaintext = decrypt(vector["text"]["wrapper"], private_key)
    assert plaintext == vector["text"]["plaintext"]


def test_decrypt_accepts_wrapper_as_json_string(vector, private_key):
    wrapper_str = json.dumps(vector["text"]["wrapper"])
    assert decrypt(wrapper_str, private_key) == vector["text"]["plaintext"]


def test_decrypt_binary_wrapper_to_envelope_and_inner_bytes(vector, private_key):
    # Decrypting a binary wrapper yields a JSON envelope STRING.
    envelope_json = decrypt(vector["binary"]["wrapper"], private_key)
    assert (
        hashlib.sha256(envelope_json.encode("utf-8")).hexdigest()
        == vector["binary"]["decrypted_json_sha256"]
    )

    # The BinaryHandle parses the envelope -> base64-decodes the "full"/"file"
    # data-URI payload -> the inner file bytes.
    inner = BinaryHandle.parse_envelope_bytes(envelope_json)
    assert (
        hashlib.sha256(inner).hexdigest() == vector["binary"]["inner_full_sha256"]
    )

    # And via the handle's public .bytes() entry point.
    handle = BinaryHandle(envelope_json=envelope_json)
    assert hashlib.sha256(handle.bytes()).hexdigest() == vector["binary"][
        "inner_full_sha256"
    ]


# ── Error paths ─────────────────────────────────────────────────────────────

def test_decrypt_tag_mismatch_raises(vector, private_key):
    bad = dict(vector["text"]["wrapper"])
    raw = bytearray(base64.b64decode(bad["d"]))
    raw[-1] ^= 0xFF  # corrupt the last byte of the GCM tag
    bad["d"] = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(DecryptError):
        decrypt(bad, private_key)


def test_decrypt_missing_field_raises(private_key):
    with pytest.raises(DecryptError):
        decrypt({"_enc": 1, "k": "AAAA", "iv": "AAAA"}, private_key)  # no "d"


def test_decrypt_bad_base64_raises(vector, private_key):
    bad = dict(vector["text"]["wrapper"])
    bad["k"] = "not valid base64 !!!"
    with pytest.raises(DecryptError):
        decrypt(bad, private_key)


def test_decrypt_wrong_iv_length_raises(vector, private_key):
    bad = dict(vector["text"]["wrapper"])
    bad["iv"] = base64.b64encode(os.urandom(16)).decode("ascii")  # 16, not 12
    with pytest.raises(DecryptError):
        decrypt(bad, private_key)


def test_parse_envelope_without_full_or_file_raises():
    with pytest.raises(DecryptError):
        BinaryHandle.parse_envelope_bytes(json.dumps({"thumb": "x"}))


# ── Fix 3: BinaryHandle.save() is atomic (temp + os.replace) ─────────────────


def test_binary_handle_save_writes_bytes_and_count(vector, private_key, tmp_path):
    """save() writes the decoded file bytes and returns the byte count."""
    envelope_json = decrypt(vector["binary"]["wrapper"], private_key)
    handle = BinaryHandle(envelope_json=envelope_json)
    out = tmp_path / "out.bin"
    n = handle.save(str(out))
    data = out.read_bytes()
    assert n == len(data)
    assert hashlib.sha256(data).hexdigest() == vector["binary"]["inner_full_sha256"]


def test_binary_handle_save_is_atomic_no_partial_on_crash(vector, private_key, tmp_path):
    """A crash mid-write must NOT leave a truncated output file (atomic os.replace).

    We point save() at an EXISTING file, then make the bytes-flush raise partway
    through (a patched temp-file write). The original destination must survive
    intact (never half-overwritten), and no stray temp/partial file is left in
    the directory — the temp file is unlinked on failure.
    """
    envelope_json = decrypt(vector["binary"]["wrapper"], private_key)
    handle = BinaryHandle(envelope_json=envelope_json)

    dest = tmp_path / "existing.bin"
    original = b"ORIGINAL-CONTENT-MUST-SURVIVE"
    dest.write_bytes(original)

    class _Boom(Exception):
        pass

    # Patch the temp file's write so the atomic write blows up AFTER the temp file
    # is created but BEFORE os.replace — exercising the cleanup-on-failure path.
    import allus_company_data.crypto as cryptomod

    real_fdopen = os.fdopen

    def boom_fdopen(fd, *a, **k):
        fh = real_fdopen(fd, *a, **k)
        orig_write = fh.write

        def failing_write(_data):
            raise _Boom("disk full mid-write")

        fh.write = failing_write  # type: ignore[assignment]
        _ = orig_write  # keep a reference; unused
        return fh

    cryptomod.os.fdopen = boom_fdopen  # type: ignore[attr-defined]
    try:
        with pytest.raises(_Boom):
            handle.save(str(dest))
    finally:
        cryptomod.os.fdopen = real_fdopen  # type: ignore[attr-defined]

    # The destination is untouched (atomic: replace never happened) …
    assert dest.read_bytes() == original
    # … and no temp/partial file leaked into the directory.
    leftovers = [n for n in os.listdir(tmp_path) if n.startswith(".tmp_")]
    assert leftovers == []


# ── Anti-circularity: independent openssl + node cross-check ────────────────

def _independent_decrypt_text(vector) -> str:
    """Decrypt the vector's text wrapper WITHOUT this SDK or `cryptography`.

    OpenSSL CLI: decrypt the PBES2 PEM, then RSA-OAEP-SHA256 unwrap `k`.
    Node `crypto`: AES-256-GCM decrypt `d` (tag = last 16 bytes). Returns the
    decrypted plaintext string. This proves the wrapper format is platform-
    correct, not merely self-consistent with crypto.py.
    """
    w = vector["text"]["wrapper"]
    tmp = tempfile.mkdtemp(prefix="allus-xcheck-")
    try:
        pem_path = os.path.join(tmp, "key.pem")
        plain_pem = os.path.join(tmp, "key_plain.pem")
        k_path = os.path.join(tmp, "k.bin")
        aes_path = os.path.join(tmp, "aeskey.bin")
        iv_path = os.path.join(tmp, "iv.bin")
        d_path = os.path.join(tmp, "d.bin")

        with open(pem_path, "w", encoding="ascii") as fh:
            fh.write(vector["encrypted_private_key_pem"])
        with open(k_path, "wb") as fh:
            fh.write(base64.b64decode(w["k"]))
        with open(iv_path, "wb") as fh:
            fh.write(base64.b64decode(w["iv"]))
        with open(d_path, "wb") as fh:
            fh.write(base64.b64decode(w["d"]))

        # 1) OpenSSL: decrypt the PBES2 PKCS#8 PEM with the passphrase.
        subprocess.run(
            [
                "openssl", "pkcs8", "-in", pem_path,
                "-passin", f"pass:{vector['passphrase']}",
                "-out", plain_pem,
            ],
            check=True, capture_output=True,
        )
        # 2) OpenSSL: RSA-OAEP-SHA256 (MGF1-SHA256) unwrap the AES key.
        subprocess.run(
            [
                "openssl", "pkeyutl", "-decrypt", "-inkey", plain_pem,
                "-pkeyopt", "rsa_padding_mode:oaep",
                "-pkeyopt", "rsa_oaep_md:sha256",
                "-pkeyopt", "rsa_mgf1_md:sha256",
                "-in", k_path, "-out", aes_path,
            ],
            check=True, capture_output=True,
        )
        # 3) Node crypto: AES-256-GCM decrypt (independent of cryptography).
        node_script = (
            "const fs=require('fs'),crypto=require('crypto');"
            f"const k=fs.readFileSync({aes_path!r});"
            f"const iv=fs.readFileSync({iv_path!r});"
            f"const d=fs.readFileSync({d_path!r});"
            "const tag=d.subarray(d.length-16),ct=d.subarray(0,d.length-16);"
            "const dc=crypto.createDecipheriv('aes-256-gcm',k,iv);"
            "dc.setAuthTag(tag);"
            "process.stdout.write(Buffer.concat([dc.update(ct),dc.final()]).toString('utf8'));"
        )
        out = subprocess.run(
            ["node", "-e", node_script], check=True, capture_output=True
        )
        return out.stdout.decode("utf-8")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.skipif(
    shutil.which("openssl") is None or shutil.which("node") is None,
    reason="openssl + node required for the independent cross-check",
)
def test_independent_openssl_node_crosscheck(vector):
    """The vector's text wrapper decrypts to the SAME plaintext via an
    independent openssl+node toolchain — proving the format is platform-correct
    (anti-circularity), not just self-consistent with crypto.py."""
    assert _independent_decrypt_text(vector) == vector["text"]["plaintext"]
