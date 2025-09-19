import hashlib
import numpy as np
from dataclasses import dataclass
from typing import Tuple, List
from PIL import Image, ImageSequence
import cv2  # requires opencv-python

# Constants
MAGIC = b"LSB1"
VERSION = 1
SALT_HEADER = b"LSB_HDR_SALT__v1"
PREHEADER_LEN = 7


# ---------------- Preheader Helpers ----------------
def pack_preheader(header_len: int) -> bytes:
    if not (0 <= header_len <= 65535):
        raise ValueError("header_len must fit in uint16")
    return MAGIC + bytes([VERSION]) + header_len.to_bytes(2, "little")


def unpack_preheader(buf: bytes) -> Tuple[int, int]:
    if buf[:4] != MAGIC:
        raise ValueError("Not a valid preheader")
    ver = buf[4]
    if ver != VERSION:
        raise ValueError("Unsupported version")
    header_len = int.from_bytes(buf[5:7], "little")
    return header_len, PREHEADER_LEN


# ---------------- Header ----------------
@dataclass
class Header:
    lsb_depth: int
    encrypted: bool
    payload_len: int
    sha256_plain: bytes
    filename: str
    salt: bytes
    nonce: bytes

    def pack(self) -> bytes:
        flags = 1 if self.encrypted else 0
        name_bytes = self.filename.encode("utf-8")[:255]
        return b"".join([
            bytes([self.lsb_depth]),
            bytes([flags]),
            self.payload_len.to_bytes(8, "little"),
            self.sha256_plain,
            bytes([len(name_bytes)]),
            name_bytes,
            self.salt,
            self.nonce
        ])


def unpack_header(buf: bytes) -> Tuple[Header, int]:
    pos = 0
    lsb_depth = buf[pos]; pos += 1
    flags = buf[pos]; pos += 1
    encrypted = bool(flags & 1)
    payload_len = int.from_bytes(buf[pos:pos+8], "little"); pos += 8
    sha256_plain = buf[pos:pos+32]; pos += 32
    name_len = buf[pos]; pos += 1
    name = buf[pos:pos+name_len].decode("utf-8"); pos += name_len
    salt = buf[pos:pos+16]; pos += 16
    nonce = buf[pos:pos+12]; pos += 12
    return Header(lsb_depth, encrypted, payload_len, sha256_plain, name, salt, nonce), pos


# ---------------- Utils ----------------
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def open_image_rgb(path: str):
    im = Image.open(path).convert("RGB")
    arr = np.array(im)
    return arr, im


def save_image_rgb(arr: np.ndarray, ref_image: Image.Image, out_path: str):
    Image.fromarray(arr.astype(np.uint8), mode="RGB").save(out_path)


def calc_capacity_bits(arr: np.ndarray, lsb_depth: int) -> int:
    h, w, c = arr.shape
    return h * w * c * lsb_depth


def flatten_channels(arr: np.ndarray) -> np.ndarray:
    return arr.reshape(-1, 3).reshape(-1)


# ---------------- GIF Helpers ----------------
def open_gif_as_frames(path: str) -> List[Image.Image]:
    im = Image.open(path)
    frames = [frame.copy().convert("RGB") for frame in ImageSequence.Iterator(im)]
    return frames


def save_frames_as_gif(frames: List[Image.Image], out_path: str, duration: int = 100, loop: int = 0):
    frames[0].save(out_path, save_all=True, append_images=frames[1:], duration=duration, loop=loop)


# ---------------- Video Helpers ----------------
def open_video_as_frames(path: str) -> List[np.ndarray]:
    cap = cv2.VideoCapture(path)
    frames = []
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        frames.append(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
    cap.release()
    return frames


def save_frames_as_video(frames: List[np.ndarray], out_path: str, fps: int = 24):
    if not frames:
        raise ValueError("No frames to save")
    h, w, _ = frames[0].shape
    fourcc = cv2.VideoWriter_fourcc(*"XVID")
    out = cv2.VideoWriter(out_path, fourcc, fps, (w, h))
    for f in frames:
        out.write(cv2.cvtColor(f, cv2.COLOR_RGB2BGR))
    out.release()
