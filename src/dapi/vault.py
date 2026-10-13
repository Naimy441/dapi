"""Encrypted credential vault.

Secret values are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) and
referenced everywhere else by an opaque, deterministic reference such as
``s_3fa9c01b2d``. Deterministic references (an HMAC of the value) mean the
same token seen in a login response and later in an ``Authorization`` header
maps to the same reference, which is what lets dapi trace authentication
flows without ever exposing a credential to a model, a log or a file.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import threading
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus

from cryptography.fernet import Fernet, InvalidToken

from dapi.store import Store

PLACEHOLDER_RE = re.compile(r"\{\{secret:(s_[0-9a-f]{10})\}\}")
MIN_SCRUB_LEN = 6
KEYRING_SERVICE = "dapi-vault"


def placeholder(ref: str) -> str:
    return "{{secret:" + ref + "}}"


def refs_in(text: str | None) -> list[str]:
    return PLACEHOLDER_RE.findall(text or "")


class VaultKeyError(RuntimeError):
    pass


def load_or_create_key(home: Path, store: Store) -> tuple[bytes, str]:
    """Resolve the vault key. Order: $DAPI_VAULT_KEY, OS keyring (if chosen), key file.

    On first use the OS keyring is preferred when the optional ``keyring``
    package is installed and functional; otherwise a ``vault.key`` file with
    0600 permissions is created inside the workspace (which is git-ignored).
    """
    env_key = os.environ.get("DAPI_VAULT_KEY")
    if env_key:
        return env_key.encode(), "env:DAPI_VAULT_KEY"

    source = store.kv_get("vault_key_source")
    key_file = home / "vault.key"
    keyring_user = hashlib.sha256(str(home.resolve()).encode()).hexdigest()[:16]

    if source == "keyring" or source is None:
        try:
            import keyring  # type: ignore

            existing = keyring.get_password(KEYRING_SERVICE, keyring_user)
            if existing:
                return existing.encode(), "keyring"
            if source is None and not key_file.exists():
                new = Fernet.generate_key().decode()
                keyring.set_password(KEYRING_SERVICE, keyring_user, new)
                if keyring.get_password(KEYRING_SERVICE, keyring_user) == new:
                    store.kv_set("vault_key_source", "keyring")
                    return new.encode(), "keyring"
        except Exception:
            if source == "keyring":
                raise VaultKeyError(
                    "This workspace's vault key lives in the OS keyring, which is unavailable. "
                    "Set DAPI_VAULT_KEY or restore keyring access."
                ) from None

    if key_file.exists():
        return key_file.read_bytes().strip(), "file"
    key = Fernet.generate_key()
    fd = os.open(str(key_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    store.kv_set("vault_key_source", "file")
    return key, "file"


class Vault:
    def __init__(self, store: Store, key: bytes, key_source: str = "unknown"):
        self.store = store
        self.key_source = key_source
        try:
            self._fernet = Fernet(key)
        except (ValueError, TypeError) as exc:
            raise VaultKeyError("Invalid vault key (expected a urlsafe base64 Fernet key)") from exc
        self._ref_key = hashlib.sha256(b"dapi-ref-v1" + key).digest()
        self._lock = threading.RLock()
        self._known: dict[str, str] | None = None  # value -> ref (decrypted cache, in memory only)
        self._scrub_re: re.Pattern[str] | None = None
        self._scrub_map: dict[str, str] = {}

    # -- references ----------------------------------------------------------------------
    def ref_for_value(self, value: str) -> str:
        digest = hmac.new(self._ref_key, value.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()
        return "s_" + digest[:10]

    def put(self, value: str, kind: str, meta: dict[str, Any] | None = None) -> str:
        """Store a secret (idempotent) and return its reference."""
        ref = self.ref_for_value(value)
        with self._lock:
            row = self.store.get_secret(ref)
            if row is None:
                token = self._fernet.encrypt(value.encode("utf-8", "surrogatepass"))
                full_meta = {"kind": kind, "length": len(value), **(meta or {})}
                self.store.put_secret(ref, kind, token, full_meta)
                if self._known is not None:
                    self._known[value] = ref
                    self._scrub_re = None
            elif meta:
                current = json.loads(row["meta"])
                merged = {**meta, **current}  # first observation wins
                if merged != current:
                    self.store.update_secret_meta(ref, merged)
        return ref

    def reveal(self, ref: str) -> str:
        """Decrypt a secret. For internal use when sending requests; never return to a model."""
        row = self.store.get_secret(ref)
        if row is None:
            raise KeyError(f"unknown secret reference {ref}")
        try:
            return self._fernet.decrypt(row["ciphertext"]).decode("utf-8", "surrogatepass")
        except InvalidToken as exc:
            raise VaultKeyError("Vault key does not match this workspace's secrets") from exc

    def resolve(self, text: str) -> str:
        """Replace every ``{{secret:...}}`` placeholder in ``text`` with its real value."""
        return PLACEHOLDER_RE.sub(lambda m: self.reveal(m.group(1)), text)

    def meta(self, ref: str) -> dict[str, Any]:
        row = self.store.get_secret(ref)
        return json.loads(row["meta"]) if row else {}

    def update_meta(self, ref: str, **fields: Any) -> None:
        with self._lock:
            row = self.store.get_secret(ref)
            if row is not None:
                self.store.update_secret_meta(ref, {**json.loads(row["meta"]), **fields})

    def list(self) -> list[dict[str, Any]]:
        out = []
        for row in self.store.list_secrets():
            meta = json.loads(row["meta"])
            out.append({"ref": row["ref"], "placeholder": placeholder(row["ref"]), **meta})
        return out

    def delete(self, ref: str) -> bool:
        with self._lock:
            self._known = None
            self._scrub_re = None
            return self.store.delete_secret(ref)

    # -- scrubbing -----------------------------------------------------------------------
    def _known_values(self) -> dict[str, str]:
        with self._lock:
            if self._known is None:
                known: dict[str, str] = {}
                for row in self.store.list_secrets():
                    try:
                        value = self._fernet.decrypt(row["ciphertext"]).decode("utf-8", "surrogatepass")
                    except InvalidToken:
                        continue
                    known[value] = row["ref"]
                self._known = known
            return self._known

    def invalidate(self) -> None:
        """Drop in-memory caches (call after another process may have added secrets)."""
        with self._lock:
            self._known = None
            self._scrub_re = None

    def scrub(self, text: str) -> str:
        """Replace any known secret value (and URL-encoded variants) in ``text`` with its placeholder."""
        if not text:
            return text
        with self._lock:
            known = self._known_values()
            if self._scrub_re is None:
                variants: dict[str, str] = {}
                for value, ref in known.items():
                    if len(value) < MIN_SCRUB_LEN:
                        continue
                    variants[value] = ref
                    for enc in (quote(value, safe=""), quote_plus(value), json.dumps(value)[1:-1]):
                        if enc != value:
                            variants[enc] = ref
                    try:
                        variants[base64.b64encode(value.encode()).decode()] = ref
                    except Exception:
                        pass
                if not variants:
                    return text
                ordered = sorted(variants, key=len, reverse=True)
                self._scrub_re = re.compile("|".join(re.escape(v) for v in ordered))
                self._scrub_map = variants
            pattern, mapping = self._scrub_re, self._scrub_map
        return pattern.sub(lambda m: placeholder(mapping[m.group(0)]), text)

    def scrub_obj(self, obj: Any) -> Any:
        """Recursively scrub every string in a JSON-like structure."""
        if isinstance(obj, str):
            return self.scrub(obj)
        if isinstance(obj, dict):
            return {
                self.scrub(str(k)) if isinstance(k, str) else k: self.scrub_obj(v) for k, v in obj.items()
            }
        if isinstance(obj, list | tuple):
            return [self.scrub_obj(v) for v in obj]
        return obj
