# run_gui.py
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import os

# Core APIs
from stego.core import (
    encode_image, decode_image,
    encode_gif, decode_gif,
    encode_video, decode_video,
    encode_wav, decode_wav,              # NEW
)

# Utils for capacity preview
from stego.utils import open_image_rgb, calc_capacity_bits
from stego.utils_audio import open_wav_as_samples, calc_capacity_wav  # NEW


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LSB Steganography (Image/GIF/Video/WAV)")
        self.geometry("1100x650")

        self.cover_path = None
        self.payload_path = None
        self.stego_path = None

        # Left panel
        left = tk.Frame(self)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        tk.Label(left, text="Workflow", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 6))

        ttk.Button(left, text="1) Load Cover File", command=self.load_cover).pack(fill=tk.X, pady=4)
        ttk.Button(left, text="2) Load Payload File", command=self.load_payload).pack(fill=tk.X, pady=4)

        self.lsb_var = tk.IntVar(value=1)
        ttk.Label(left, text="LSB depth (1–8)").pack(anchor="w", pady=(10, 0))
        ttk.Spinbox(left, from_=1, to=8, textvariable=self.lsb_var, width=5).pack(anchor="w")

        ttk.Label(left, text="Key (optional)").pack(anchor="w", pady=(10, 0))
        self.key_entry = ttk.Entry(left, show="*")
        self.key_entry.pack(fill=tk.X)

        self.capacity_lbl = ttk.Label(left, text="Capacity: -")
        self.capacity_lbl.pack(anchor="w", pady=(10, 0))

        ttk.Button(left, text="3) Encode & Save Stego", command=self.encode).pack(fill=tk.X, pady=8)
        ttk.Separator(left, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        ttk.Button(left, text="Load Stego File", command=self.load_stego).pack(fill=tk.X, pady=4)
        ttk.Button(left, text="Decode → Save Payload", command=self.decode).pack(fill=tk.X, pady=4)

        # Right panel (previews)
        right = tk.Frame(self)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.cover_canvas = tk.Label(right, text="Cover Preview", relief=tk.SUNKEN)
        self.cover_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.stego_canvas = tk.Label(right, text="Stego Preview", relief=tk.SUNKEN)
        self.stego_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        self.cover_imgtk = None
        self.stego_imgtk = None

    # ---------- Actions ----------
    def load_cover(self):
        p = filedialog.askopenfilename(filetypes=[("Media", "*.png;*.bmp;*.jpg;*.jpeg;*.gif;*.mp4;*.avi;*.wav")])
        if not p:
            return
        self.cover_path = p
        ext = os.path.splitext(p)[1].lower()

        if ext in (".png", ".bmp", ".jpg", ".jpeg"):
            self.show_image(p, "cover")
        else:
            self.cover_canvas.config(text=f"Cover loaded: {os.path.basename(p)}", image="")

        self.update_capacity()

    def load_payload(self):
        p = filedialog.askopenfilename()
        if not p:
            return
        self.payload_path = p
        self.update_capacity()

    def load_stego(self):
        p = filedialog.askopenfilename(filetypes=[("Media", "*.png;*.bmp;*.jpg;*.jpeg;*.gif;*.mp4;*.avi;*.wav")])
        if not p:
            return
        self.stego_path = p
        ext = os.path.splitext(p)[1].lower()
        if ext in (".png", ".bmp", ".jpg", ".jpeg"):
            self.show_image(p, "stego")
        else:
            self.stego_canvas.config(text=f"Stego loaded: {os.path.basename(p)}", image="")

    def update_capacity(self):
        """Show capacity for image or WAV; omit for GIF/Video (multi-frame)."""
        if not self.cover_path:
            return

        lsb = int(self.lsb_var.get())
        try:
            ext = os.path.splitext(self.cover_path)[1].lower()
            if ext in (".png", ".bmp", ".jpg", ".jpeg"):
                arr, _ = open_image_rgb(self.cover_path)
                cap_bytes = calc_capacity_bits(arr, lsb) // 8
            elif ext == ".wav":
                samples, _ = open_wav_as_samples(self.cover_path)
                cap_bytes = calc_capacity_wav(samples, lsb) // 8
            else:
                self.capacity_lbl.config(text="Capacity: (not shown for GIF/Video)")
                return

            txt = f"Capacity: {cap_bytes:,} bytes"
            if self.payload_path and os.path.exists(self.payload_path):
                sz = os.path.getsize(self.payload_path)
                txt += f" | Payload: {sz:,} bytes"
                if sz + 512 > cap_bytes:
                    txt += " ⚠"
            self.capacity_lbl.config(text=txt)
        except Exception as e:
            self.capacity_lbl.config(text=f"Capacity: n/a ({e})")

    def encode(self):
        if not (self.cover_path and self.payload_path):
            messagebox.showerror("Error", "Load cover and payload first")
            return
        ext = os.path.splitext(self.cover_path)[1].lower()
        out = filedialog.asksaveasfilename(defaultextension=ext, filetypes=[("Media", f"*{ext}")])
        if not out:
            return

        try:
            if ext in (".png", ".bmp", ".jpg", ".jpeg"):
                encode_image(self.cover_path, self.payload_path, out, self.lsb_var.get(), self.key_entry.get() or None)
                self.show_image(out, "stego")
            elif ext == ".gif":
                encode_gif(self.cover_path, self.payload_path, out, self.lsb_var.get(), self.key_entry.get() or None)
            elif ext in (".mp4", ".avi"):
                encode_video(self.cover_path, self.payload_path, out, self.lsb_var.get(), self.key_entry.get() or None)
            elif ext == ".wav":  # NEW
                encode_wav(self.cover_path, self.payload_path, out, self.lsb_var.get(), self.key_entry.get() or "")
                self.stego_canvas.config(text=f"Stego saved: {os.path.basename(out)}", image="")
            else:
                raise ValueError("Unsupported cover type")
            self.stego_path = out
            messagebox.showinfo("Success", f"Stego saved: {out}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decode(self):
        if not self.stego_path:
            messagebox.showerror("Error", "Load stego first")
            return
        ext = os.path.splitext(self.stego_path)[1].lower()
        out = filedialog.asksaveasfilename()
        if not out:
            return
        try:
            if ext in (".png", ".bmp", ".jpg", ".jpeg"):
                hdr = decode_image(self.stego_path, out, self.key_entry.get() or None)
            elif ext == ".gif":
                hdr = decode_gif(self.stego_path, out, self.key_entry.get() or None)
            elif ext in (".mp4", ".avi"):
                hdr = decode_video(self.stego_path, out, self.key_entry.get() or None)
            elif ext == ".wav":  # NEW
                hdr = decode_wav(self.stego_path, out, self.key_entry.get() or "")
            else:
                raise ValueError("Unsupported stego type")

            if hasattr(hdr, "filename"):
                messagebox.showinfo("Decoded", f"Saved payload as {out}\nOriginal: {hdr.filename}")
            else:
                messagebox.showinfo("Decoded", f"Saved payload as {out}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_image(self, path, which):
        im = Image.open(path).convert("RGB")
        im.thumbnail((520, 520))
        imgtk = ImageTk.PhotoImage(im)
        if which == "cover":
            self.cover_imgtk = imgtk
            self.cover_canvas.config(image=imgtk, text="")
        else:
            self.stego_imgtk = imgtk
            self.stego_canvas.config(image=imgtk, text="")


if __name__ == "__main__":
    App().mainloop()
