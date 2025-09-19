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
    open_image_rgb, save_image_rgb, calc_capacity_bits, flatten_channels,
    open_gif_as_frames, save_frames_as_gif,
    open_video_as_frames, save_frames_as_video
)

from .utils_audio import open_wav_as_samples, save_samples_as_wav, calc_capacity_wav

# ======================================================
# ---- Key derivation & PRNG ----
# ======================================================
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

# ======================================================
# ---- Bit packing helpers ----
# ======================================================
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

# ======================================================
# ---- Channel-level write/read ----
# ======================================================
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

# ======================================================
# ---- Crypto helpers ----
# ======================================================
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

# ======================================================
# ---- Public API: Images ----
# ======================================================
def encode_image(cover_path: str, payload_path: str, out_path: str, lsb_depth: int, key: Optional[str] = None):
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be 1..8")
    arr, pil = open_image_rgb(cover_path)
    values = flatten_channels(arr).copy()

    with open(payload_path, "rb") as f:
        payload = f.read()

    salt = os.urandom(16)
    nonce = os.urandom(12) if key else b"\x00" * 12
    sha = sha256(payload)
    hdr = Header(lsb_depth, bool(key), len(payload), sha, os.path.basename(payload_path), salt, nonce)

    data_for_embed, _ = encrypt_if_needed(payload, key, salt, nonce)

    header_body = hdr.pack()
    preheader = pack_preheader(len(header_body))

    total_bits_needed = (len(preheader) + len(header_body) + len(data_for_embed)) * 8
    if total_bits_needed > calc_capacity_bits(arr, lsb_depth):
        raise ValueError("Not enough capacity in cover image.")

    ch = 0
    ch = write_bits_sequential(values, ch, lsb_depth, bytes_to_bits_le(preheader))
    ch = write_bits_sequential(values, ch, lsb_depth, bytes_to_bits_le(header_body))
    write_bits_permuted(values, ch, lsb_depth, bytes_to_bits_le(data_for_embed), password=(key or "no-key"), salt=salt)

    save_image_rgb(values.reshape(arr.shape), pil, out_path)

def decode_image(stego_path: str, out_payload_path: Optional[str] = None, key: Optional[str] = None) -> Header:
    arr, _ = open_image_rgb(stego_path)
    values = flatten_channels(arr)

    pre_bits, ch = read_bits_sequential(values, 0, 1, PREHEADER_LEN * 8)
    pre = bits_le_to_bytes(pre_bits)
    header_len, _ = unpack_preheader(pre)

    hdr_bits, ch2 = read_bits_sequential(values, ch, 1, header_len * 8)
    hdr_blob = bits_le_to_bytes(hdr_bits)
    hdr, _ = unpack_header(hdr_blob)

    data_bits = (hdr.payload_len + (16 if hdr.encrypted else 0)) * 8
    bits_payload = read_bits_permuted(values, ch2, hdr.lsb_depth, data_bits, password=(key or "no-key"), salt=hdr.salt)
    data = bits_le_to_bytes(bits_payload)

    plaintext = decrypt_if_needed(data, key if hdr.encrypted else None, hdr.salt, hdr.nonce)
    if sha256(plaintext) != hdr.sha256_plain:
        raise ValueError("Integrity check failed. Wrong key or corrupted stego.")

    with open(out_payload_path or hdr.filename, "wb") as f:
        f.write(plaintext)
    return hdr

# ======================================================
# ---- Public API: GIFs ----
# ======================================================
def encode_gif(cover_gif: str, payload_path: str, out_gif: str, lsb_depth: int, key: Optional[str] = None):
    frames = open_gif_as_frames(cover_gif)
    tmp_path = "tmp_frame.png"
    frames[0].save(tmp_path)
    encode_image(tmp_path, payload_path, tmp_path, lsb_depth, key)
    frames[0] = open_image_rgb(tmp_path)[1]
    save_frames_as_gif(frames, out_gif)

def decode_gif(stego_gif: str, out_payload: str, key: Optional[str] = None) -> Header:
    frames = open_gif_as_frames(stego_gif)
    tmp_path = "tmp_decode.png"
    frames[0].save(tmp_path)
    return decode_image(tmp_path, out_payload, key)

# ======================================================
# ---- Public API: Videos ----
# ======================================================
def encode_video(cover_video: str, payload_path: str, out_video: str, lsb_depth: int, key: Optional[str] = None):
    frames = open_video_as_frames(cover_video)
    tmp_path = "tmp_frame.png"
    from PIL import Image
    Image.fromarray(frames[0]).save(tmp_path)
    encode_image(tmp_path, payload_path, tmp_path, lsb_depth, key)
    frames[0] = np.array(Image.open(tmp_path))
    save_frames_as_video(frames, out_video)

def decode_video(stego_video: str, out_payload: str, key: Optional[str] = None) -> Header:
    frames = open_video_as_frames(stego_video)
    tmp_path = "tmp_decode.png"
    from PIL import Image
    Image.fromarray(frames[0]).save(tmp_path)
    return decode_image(tmp_path, out_payload, key)

# ======================================================
# ---- Public API: WAV ----
# ======================================================
def encode_wav(cover_path: str, payload_path: str, out_path: str, lsb_depth: int, key: str):
    if not key or not key.isdigit():
        raise ValueError("Numeric key required for WAV encoding.")
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be 1..8")

    samples, params = open_wav_as_samples(cover_path)
    values = samples.flatten().astype(np.int32)

    with open(payload_path, "rb") as f:
        payload = f.read()

    salt = os.urandom(16)
    nonce = os.urandom(12)
    sha = sha256(payload)
    hdr = Header(lsb_depth, True, len(payload), sha, os.path.basename(payload_path), salt, nonce)

    data_for_embed, _ = encrypt_if_needed(payload, key, salt, nonce)
    header_blob = hdr.pack()
    preheader = pack_preheader(len(header_blob))

    total_bits_needed = (len(preheader) + len(header_blob) + len(data_for_embed)) * 8
    if total_bits_needed > calc_capacity_wav(samples, lsb_depth):
        raise ValueError("Not enough capacity in WAV file.")

    ch = 0
    ch = write_bits_sequential(values, ch, lsb_depth, bytes_to_bits_le(preheader))
    ch = write_bits_sequential(values, ch, lsb_depth, bytes_to_bits_le(header_blob))
    write_bits_permuted(values, ch, lsb_depth, bytes_to_bits_le(data_for_embed), password=key, salt=salt)

    samples = values.reshape(samples.shape)
    save_samples_as_wav(samples, params, out_path)

def decode_wav(stego_path: str, out_payload_path: str, key: str):
    if not key or not key.isdigit():
        raise ValueError("Numeric key required for WAV decoding.")
    samples, params = open_wav_as_samples(stego_path)
    values = samples.flatten().astype(np.int32)

    pre_bits, ch = read_bits_sequential(values, 0, 1, PREHEADER_LEN * 8)
    pre = bits_le_to_bytes(pre_bits)
    header_len, _ = unpack_preheader(pre)

    hdr_bits, ch2 = read_bits_sequential(values, ch, 1, header_len * 8)
    hdr_blob = bits_le_to_bytes(hdr_bits)
    hdr, _ = unpack_header(hdr_blob)

    data_bits = (hdr.payload_len + (16 if hdr.encrypted else 0)) * 8
    bits_payload = read_bits_permuted(values, ch2, hdr.lsb_depth, data_bits, password=key, salt=hdr.salt)
    data = bits_le_to_bytes(bits_payload)

    plaintext = decrypt_if_needed(data, key, hdr.salt, hdr.nonce)
    if sha256(plaintext) != hdr.sha256_plain:
        raise ValueError("Integrity check failed.")

    with open(out_payload_path or hdr.filename, "wb") as f:
        f.write(plaintext)
    return hdr
