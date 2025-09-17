import numpy as np
from PIL import Image

def diff_image(cover_path: str, stego_path: str, out_path: str, amplify: int = 32):
    c = np.array(Image.open(cover_path).convert("RGB"), dtype=np.int16)
    s = np.array(Image.open(stego_path).convert("RGB"), dtype=np.int16)
    if c.shape != s.shape:
        raise ValueError("Cover and stego must be same size")
    d = np.clip(np.abs(c - s) * amplify, 0, 255).astype(np.uint8)
    Image.fromarray(d, mode="RGB").save(out_path)
