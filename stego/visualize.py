import numpy as np
from PIL import Image

def diff_map(cover_arr: np.ndarray, stego_arr: np.ndarray, lsb_depth: int):
    mask = (1 << lsb_depth) - 1
    diff = (cover_arr & mask) ^ (stego_arr & mask)
    # scale to 0-255 for visualization
    diff_img = (diff > 0).astype(np.uint8) * 255
    return Image.fromarray(diff_img.astype(np.uint8))
