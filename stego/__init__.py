# stego/__init__.py
"""
Stego Package
-------------
This package provides image steganography functions, utilities, and visualization helpers.
"""

# Import key functions/classes so they are available at the package level
from .core import encode_image, decode_image
from .utils import (
    open_image_rgb,
    save_image_rgb,
    calc_capacity_bits,
    flatten_channels,
    sha256,
)
from .visualize import diff_image

__all__ = [
    "encode_image",
    "decode_image",
    "open_image_rgb",
    "save_image_rgb",
    "calc_capacity_bits",
    "flatten_channels",
    "sha256",
    "diff_image",
]
