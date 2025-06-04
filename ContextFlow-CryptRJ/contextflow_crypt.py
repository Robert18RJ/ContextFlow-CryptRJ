"""
ContextFlow-Crypt  -  Reference prototype  (Python 3.9+)

• Adaptive, context-aware block cipher (128-bit blocks)
• Authenticated encryption:  (ciphertext ‖ MAC)
• Variable rounds (8-16) driven by SHA-256(context)
• Operations: XOR, bit inversion, byte-rotation
"""

from __future__ import annotations
import hashlib
import hmac
import os
import secrets
import socket
import time
import uuid
from typing import List, Dict, Tuple


class ContextFlowCrypt:
    BLOCK_SIZE = 16            # 128 bits
    MIN_ROUNDS = 8
    MAX_ROUNDS = 16
    MAC_LEN    = 32            # SHA-256

    # ---------- public API ---------- #
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, str]:
        """Returns (ciphertext‖MAC, context_vector)."""
        ContextFlowCrypt._validate_key(key)
        context_vec = ContextFlowCrypt._collect_context()
        cfc = ContextFlowCrypt(key, context_vec)
        ctxt = cfc._encrypt_blocks(plaintext)
        mac  = cfc._make_mac(ctxt)
        return ctxt + mac, context_vec

    @staticmethod
    def decrypt(pkg: bytes, key: bytes, context_vec: str) -> bytes:
        """Verifies MAC with the provided context and returns plaintext."""
        ContextFlowCrypt._validate_key(key)
        if len(pkg) < ContextFlowCrypt.MAC_LEN:
            raise ValueError("Package too short")
        ctxt, mac = pkg[:-ContextFlowCrypt.MAC_LEN], pkg[-ContextFlowCrypt.MAC_LEN:]
        cfc = ContextFlowCrypt(key, context_vec)
        if not hmac.compare_digest(mac, cfc._make_mac(ctxt)):
            raise ValueError("MAC verification failed")
        return cfc._decrypt_blocks(ctxt)

    # ---------- construction ---------- #
    def __init__(self, key: bytes, context_vec: str):
        self.key          = key
        self.context_vec  = context_vec
        self.context_hash = hashlib.sha256(context_vec.encode()).digest()
        self.n_rounds     = (int.from_bytes(self.context_hash[24:28], "big") %
                            (self.MAX_ROUNDS - self.MIN_ROUNDS + 1)) + self.MIN_ROUNDS
        self.round_keys   = self._expand_key_schedule()

    # ---------- context & key utilities ---------- #
    @staticmethod
    def _collect_context() -> str:
        ts_ns = str(time.time_ns())
        try:
            username = os.getlogin()
        except OSError:
            import getpass
            username = getpass.getuser()
        hostname = socket.gethostname()
        session_uuid = str(uuid.uuid4())
        return f"{ts_ns}|{username}|{hostname}|{session_uuid}"

    @staticmethod
    def _validate_key(key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes")
        if len(key) < 16:
            raise ValueError("key length must be ≥128 bits")

    # ---------- key schedule ---------- #
    def _expand_key_schedule(self) -> List[bytes]:
        rk = []
        for r in range(self.n_rounds + 1):  # +1 whitening
            data = self.key + r.to_bytes(4, "big")
            rk.append(hashlib.blake2s(data, digest_size=self.BLOCK_SIZE,
                                      person=b"CFCkey").digest())
        return rk

    # ---------- operation derivation ---------- #
    def _derive_operations(self, round_num: int) -> List[Dict]:
        seed = self.context_hash + round_num.to_bytes(4, "big")
        stream = hashlib.blake2s(seed, digest_size=32, person=b"CFCRYPT").digest()
        ops: List[Dict] = []
        for i in range(0, 8, 2):  # 4 ops
            op_type = stream[i] % 3
            param   = stream[i + 1]
            if op_type == 2:
                param %= 8
            ops.append({"type": op_type, "param": param})
        return ops

    # ---------- padding helpers ---------- #
    def _pad(self, data: bytes) -> bytes:
        pad_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        return data + bytes([pad_len]) * pad_len

    def _unpad(self, data: bytes) -> bytes:
        pad_len = data[-1]
        if pad_len == 0 or pad_len > self.BLOCK_SIZE:
            raise ValueError("Invalid padding length")
        if data[-pad_len:] != bytes([pad_len]) * pad_len:
            raise ValueError("Invalid padding")
        return data[:-pad_len]

    @staticmethod
    def _rotate_bytes(block: bytearray, shift: int) -> bytearray:
        if shift == 0:
            return block
        return block[shift:] + block[:shift]

    # ---------- encryption / decryption ---------- #
    def _encrypt_blocks(self, plaintext: bytes) -> bytes:
        pt = self._pad(plaintext)
        ct = bytearray()

        for off in range(0, len(pt), self.BLOCK_SIZE):
            block = bytearray(pt[off: off + self.BLOCK_SIZE])

            # Whitening
            for i in range(self.BLOCK_SIZE):
                block[i] ^= self.round_keys[0][i]

            # Rounds
            for r in range(1, self.n_rounds + 1):
                ops = self._derive_operations(r)
                block = self._apply_ops(block, ops)
                rk = self.round_keys[r]
                for i in range(self.BLOCK_SIZE):
                    block[i] ^= rk[i]

            ct.extend(block)
        return bytes(ct)

    def _decrypt_blocks(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length multiple of block size required")
        pt = bytearray()

        for off in range(0, len(ciphertext), self.BLOCK_SIZE):
            block = bytearray(ciphertext[off: off + self.BLOCK_SIZE])

            # Reverse rounds
            for r in range(self.n_rounds, 0, -1):
                rk = self.round_keys[r]
                for i in range(self.BLOCK_SIZE):
                    block[i] ^= rk[i]
                ops = self._derive_operations(r)
                block = self._apply_ops_inv(block, ops)

            # Unwhitening
            for i in range(self.BLOCK_SIZE):
                block[i] ^= self.round_keys[0][i]

            pt.extend(block)
        return self._unpad(pt)

    # ---------- operations ---------- #
    def _apply_ops(self, state: bytearray, ops: List[Dict]) -> bytearray:
        for op in ops:
            typ, param = op["type"], op["param"]
            if typ == 0:  # XOR
                state[:] = bytearray(b ^ param for b in state)
            elif typ == 1:  # INVERT
                for idx in range(self.BLOCK_SIZE):
                    if param & (1 << (idx % 8)):
                        state[idx] ^= 0xFF
            else:  # ROTATE
                state[:] = self._rotate_bytes(state, param)
        return state

    def _apply_ops_inv(self, state: bytearray, ops: List[Dict]) -> bytearray:
        for op in reversed(ops):
            typ, param = op["type"], op["param"]
            if typ == 0:  # XOR
                state[:] = bytearray(b ^ param for b in state)
            elif typ == 1:  # INVERT
                for idx in range(self.BLOCK_SIZE):
                    if param & (1 << (idx % 8)):
                        state[idx] ^= 0xFF
            else:  # ROTATE inverse
                state[:] = self._rotate_bytes(state, -param % self.BLOCK_SIZE)
        return state

    # ---------- MAC ---------- #
    def _make_mac(self, ciphertext: bytes) -> bytes:
        return hmac.new(self.key, self.context_vec.encode() + ciphertext,
                        hashlib.sha256).digest()


# --------------- Demo ----------------- #
if __name__ == "__main__":
    key = secrets.token_bytes(32)  # 256-bit
    msg = b"Attack at dawn! Meet at the oak tree."
    package, ctx = ContextFlowCrypt.encrypt(msg, key)
    print("Cipher (partial):", package.hex()[:60], "…")
    recovered = ContextFlowCrypt.decrypt(package, key, ctx)
    assert recovered == msg
    print("✅ Successful round-trip")
