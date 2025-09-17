import os
import numpy as np
from typing import Optional, Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from .utils import (
    SALT_HEADER, PREHEADER_LEN, pack_preheader, unpack_preheader,
    Header, unpack_header, sha256,
    open_image_rgb, save_image_rgb, calc_capacity_bits, flatten_channels
)

# ---- Key derivation & PRNG ----
def derive_key(password: str, salt: bytes, length: int = 32, rounds: int = 200_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=rounds,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))

def rng_indices(total_channels: int, skip_first_channels: int, password: str, salt: bytes) -> np.ndarray:
    from hashlib import sha256 as _sha
    seed_bytes = derive_key(password, salt, length=32)
    seed = int.from_bytes(_sha(seed_bytes).digest()[:8], "little", signed=False)
    rng = np.random.default_rng(seed)
    rest = np.arange(skip_first_channels, total_channels, dtype=np.int64)
    rng.shuffle(rest)
    return rest

# ---- Bit packing helpers ----
def bytes_to_bits_le(data: bytes) -> np.ndarray:
    bits = np.zeros(len(data) * 8, dtype=np.uint8)
    idx = 0
    for b in data:
        for i in range(8):
            bits[idx] = (b >> i) & 1
            idx += 1
    return bits

def bits_le_to_bytes(bits: np.ndarray) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for b in range(8):
            if i + b < len(bits):
                v |= (int(bits[i+b]) & 1) << b
        out.append(v)
    return bytes(out)

# ---- Channel-level write/read ----
def write_bits_sequential(values: np.ndarray, start_ch: int, lsb_depth: int, bits: np.ndarray) -> int:
    k = lsb_depth
    mask_clear = ~((1 << k) - 1) & 0xFF
    idx_bits = 0
    ch = start_ch
    total = len(values)
    while idx_bits < len(bits):
        if ch >= total:
            raise ValueError("Insufficient capacity while writing header.")
        v = int(values[ch])
        w = 0
        for i in range(k):
            if idx_bits + i < len(bits):
                w |= (int(bits[idx_bits + i]) & 1) << i
        v = (v & mask_clear) | w
        values[ch] = v
        ch += 1
        idx_bits += k
    return ch

def read_bits_sequential(values: np.ndarray, start_ch: int, lsb_depth: int, num_bits: int) -> Tuple[np.ndarray, int]:
    k = lsb_depth
    bits = np.zeros(num_bits, dtype=np.uint8)
    idx_bits = 0
    ch = start_ch
    total = len(values)
    while idx_bits < num_bits:
        if ch >= total:
            raise ValueError("Insufficient data while reading header.")
        v = int(values[ch])
        for i in range(k):
            if idx_bits < num_bits:
                bits[idx_bits] = (v >> i) & 1
                idx_bits += 1
        ch += 1
    return bits, ch

def write_bits_permuted(values: np.ndarray, start_skip: int, lsb_depth: int, bits: np.ndarray, password: str, salt: bytes):
    k = lsb_depth
    mask_clear = ~((1 << k) - 1) & 0xFF
    idx_bits = 0
    total = len(values)
    order = rng_indices(total, start_skip, password, salt)
    for ch in order:
        if idx_bits >= len(bits):
            break
        v = int(values[ch])
        w = 0
        for i in range(k):
            if idx_bits + i < len(bits):
                w |= (int(bits[idx_bits + i]) & 1) << i
        v = (v & mask_clear) | w
        values[ch] = v
        idx_bits += k
    if idx_bits < len(bits):
        raise ValueError("Insufficient capacity while writing payload.")

def read_bits_permuted(values: np.ndarray, start_skip: int, lsb_depth: int, num_bits: int, password: str, salt: bytes) -> np.ndarray:
    k = lsb_depth
    bits = np.zeros(num_bits, dtype=np.uint8)
    idx_bits = 0
    order = rng_indices(len(values), start_skip, password, salt)
    for ch in order:
        if idx_bits >= num_bits:
            break
        v = int(values[ch])
        for i in range(k):
            if idx_bits < num_bits:
                bits[idx_bits] = (v >> i) & 1
                idx_bits += 1
    if idx_bits < num_bits:
        raise ValueError("Not enough embedded bits available.")
    return bits

# ---- Crypto helpers ----
def encrypt_if_needed(payload: bytes, key: Optional[str], salt: bytes, nonce: bytes) -> Tuple[bytes, bool]:
    if not key:
        return payload, False
    k = derive_key(key, salt, 32)
    aead = ChaCha20Poly1305(k)
    ct = aead.encrypt(nonce, payload, None)
    return ct, True

def decrypt_if_needed(data: bytes, key: Optional[str], salt: bytes, nonce: bytes) -> bytes:
    if not key:
        return data
    k = derive_key(key, salt, 32)
    aead = ChaCha20Poly1305(k)
    return aead.decrypt(nonce, data, None)

# ---- Public API ----
def encode_image(cover_path: str, payload_path: str, out_path: str, lsb_depth: int, key: Optional[str] = None):
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be 1..8")
    arr, pil = open_image_rgb(cover_path)
    values = flatten_channels(arr).copy()

    with open(payload_path, "rb") as f:
        payload = f.read()

    # Build header
    salt = os.urandom(16)
    nonce = os.urandom(12) if key else b"\x00" * 12
    sha = sha256(payload)
    hdr = Header(lsb_depth, bool(key), len(payload), sha, os.path.basename(payload_path), salt, nonce)

    # Encrypt if needed
    data_for_embed, _ = encrypt_if_needed(payload, key, salt, nonce)

    header_body = hdr.pack()
    preheader = pack_preheader(len(header_body))

    # Check capacity
    total_bits_needed = (len(preheader) + len(header_body) + len(data_for_embed)) * 8
    if total_bits_needed > calc_capacity_bits(arr, lsb_depth):
        raise ValueError("Not enough capacity in cover image.")

    # Write preheader + header sequentially
    ch = 0
    ch = write_bits_sequential(values, ch, lsb_depth, bytes_to_bits_le(preheader))
    ch = write_bits_sequential(values, ch, lsb_depth, bytes_to_bits_le(header_body))

    # Write payload permuted
    write_bits_permuted(values, ch, lsb_depth, bytes_to_bits_le(data_for_embed), password=(key or "no-key"), salt=salt)

    save_image_rgb(values.reshape(arr.shape), pil, out_path)

def decode_image(stego_path: str, out_payload_path: Optional[str] = None, key: Optional[str] = None) -> Header:
    arr, pil = open_image_rgb(stego_path)
    values = flatten_channels(arr)

    # Read preheader
    pre_bits, ch = read_bits_sequential(values, 0, 1, PREHEADER_LEN * 8)
    pre = bits_le_to_bytes(pre_bits)
    header_len, _ = unpack_preheader(pre)

    # Read header
    hdr_bits, ch2 = read_bits_sequential(values, ch, 1, header_len * 8)
    hdr_blob = bits_le_to_bytes(hdr_bits)
    hdr, _ = unpack_header(hdr_blob)

    # Read payload
    data_bits = (hdr.payload_len + (16 if hdr.encrypted else 0)) * 8
    bits_payload = read_bits_permuted(values, ch2, hdr.lsb_depth, data_bits, password=(key or "no-key"), salt=hdr.salt)
    data = bits_le_to_bytes(bits_payload)

    # Decrypt and verify
    plaintext = decrypt_if_needed(data, key if hdr.encrypted else None, hdr.salt, hdr.nonce)
    if sha256(plaintext) != hdr.sha256_plain:
        raise ValueError("Integrity check failed. Wrong key or corrupted stego.")

    with open(out_payload_path or hdr.filename, "wb") as f:
        f.write(plaintext)
    return hdr
