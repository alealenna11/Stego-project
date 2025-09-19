# stego/__init__.py
"""
Stego Package
-------------
This package provides image/audio/video steganography functions, utilities, and visualization helpers.
"""

from .core import (
    # Image
    encode_image, decode_image,
    # GIF & Video
    encode_gif, decode_gif,
    encode_video, decode_video,
    # WAV (Audio)
    encode_wav, decode_wav,
)

from .utils import (
    open_image_rgb,
    save_image_rgb,
    calc_capacity_bits,
    flatten_channels,
    sha256,
)

from .visualize import diff_image as diff_image  # keep if you rely on this in your demo

__all__ = [
    # image
    "encode_image", "decode_image",
    # gif/video
    "encode_gif", "decode_gif",
    "encode_video", "decode_video",
    # audio (WAV)
    "encode_wav", "decode_wav",

    # utils
    "open_image_rgb", "save_image_rgb",
    "calc_capacity_bits", "flatten_channels", "sha256",
    "diff_image",
]
