import wave
import numpy as np

def open_wav_as_samples(path: str):
    with wave.open(path, "rb") as wf:
        params = wf.getparams()
        n_channels, sampwidth, framerate, n_frames, _, _ = params
        if sampwidth != 2:  # 16-bit PCM
            raise ValueError("Only 16-bit PCM WAV supported.")
        raw = wf.readframes(n_frames)
        samples = np.frombuffer(raw, dtype=np.int16)
        samples = samples.reshape(-1, n_channels)
    return samples, params

def save_samples_as_wav(samples: np.ndarray, params, out_path: str):
    n_channels, sampwidth, framerate, _, _, _ = params
    samples = samples.astype(np.int16)
    raw = samples.tobytes()
    with wave.open(out_path, "wb") as wf:
        wf.setnchannels(n_channels)
        wf.setsampwidth(sampwidth)
        wf.setframerate(framerate)
        wf.writeframes(raw)

def calc_capacity_wav(samples: np.ndarray, lsb_depth: int) -> int:
    num_samples, num_channels = samples.shape
    return num_samples * num_channels * lsb_depth
