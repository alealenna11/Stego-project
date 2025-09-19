import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional

# call into your engine
from stego.core import encode_image, decode_image

class StegoApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("LSB Stego Tool")
        self.root.geometry("720x340")

        self.cover_path: Optional[str] = None
        self.payload_path: Optional[str] = None
        self.stego_path: Optional[str] = None

        frm = ttk.Frame(root, padding=12)
        frm.pack(fill="both", expand=True)

        # --- ENCODE ---
        enc_lab = ttk.Label(frm, text="Encode (hide payload into image)", font=("Segoe UI", 11, "bold"))
        enc_lab.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 6))

        ttk.Button(frm, text="Choose Cover Image...", command=self.choose_cover).grid(row=1, column=0, sticky="w")
        self.lbl_cover = ttk.Label(frm, text="(none)")
        self.lbl_cover.grid(row=1, column=1, columnspan=2, sticky="w")

        ttk.Button(frm, text="Choose Payload (any file)...", command=self.choose_payload).grid(row=2, column=0, sticky="w")
        self.lbl_payload = ttk.Label(frm, text="(none)")
        self.lbl_payload.grid(row=2, column=1, columnspan=2, sticky="w")

        ttk.Label(frm, text="Password (optional):").grid(row=3, column=0, sticky="w")
        self.ent_password = ttk.Entry(frm, show="*")
        self.ent_password.grid(row=3, column=1, sticky="we", padx=(6, 0))

        ttk.Label(frm, text="LSB depth (1–4):").grid(row=4, column=0, sticky="w")
        self.spn_lsb = ttk.Spinbox(frm, from_=1, to=4, width=4)
        self.spn_lsb.set(1)
        self.spn_lsb.grid(row=4, column=1, sticky="w", padx=(6, 0))

        ttk.Button(frm, text="Encode → Save Stego Image...", command=self.encode_action) \
            .grid(row=5, column=0, sticky="w", pady=(6, 12))

        ttk.Separator(frm, orient="horizontal").grid(row=6, column=0, columnspan=3, sticky="ew", pady=8)

        # --- DECODE ---
        dec_lab = ttk.Label(frm, text="Decode (extract payload from stego image)", font=("Segoe UI", 11, "bold"))
        dec_lab.grid(row=7, column=0, columnspan=3, sticky="w", pady=(0, 6))

        ttk.Button(frm, text="Choose Stego Image...", command=self.choose_stego).grid(row=8, column=0, sticky="w")
        self.lbl_stego = ttk.Label(frm, text="(none)")
        self.lbl_stego.grid(row=8, column=1, columnspan=2, sticky="w")

        ttk.Label(frm, text="Password (if used):").grid(row=9, column=0, sticky="w")
        self.ent_password_dec = ttk.Entry(frm, show="*")
        self.ent_password_dec.grid(row=9, column=1, sticky="we", padx=(6, 0))

        ttk.Button(frm, text="Decode → Save Payload As...", command=self.decode_action) \
            .grid(row=10, column=0, sticky="w", pady=(6, 0))

        frm.columnconfigure(1, weight=1)

    # ---------- ENCODE ----------
    def choose_cover(self):
        path = filedialog.askopenfilename(
            title="Choose cover image",
            filetypes=[("Images", "*.png;*.bmp;*.jpg;*.jpeg;*.tif;*.tiff"), ("All files", "*.*")]
        )
        if path:
            self.cover_path = path
            self.lbl_cover.config(text=path)

    def choose_payload(self):
        path = filedialog.askopenfilename(title="Choose payload file", filetypes=[("All files", "*.*")])
        if path:
            self.payload_path = path
            self.lbl_payload.config(text=path)

    def encode_action(self):
        if not self.cover_path or not self.payload_path:
            messagebox.showwarning("Missing input", "Choose a cover image and a payload file first.")
            return
        out_path = filedialog.asksaveasfilename(
            title="Save stego image as",
            defaultextension=".png",
            filetypes=[("PNG image", "*.png"), ("BMP image", "*.bmp"), ("All files", "*.*")]
        )
        if not out_path:
            return
        try:
            lsb_depth = int(self.spn_lsb.get())
            if not (1 <= lsb_depth <= 4):
                raise ValueError
        except Exception:
            messagebox.showerror("Invalid LSB depth", "Please enter an integer between 1 and 4.")
            return

        password = self.ent_password.get() or None
        try:
            encode_image(self.cover_path, self.payload_path, out_path, lsb_depth, password)
            messagebox.showinfo("Success", f"Stego image saved:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Encode failed", str(e))

    # ---------- DECODE ----------
    def choose_stego(self):
        path = filedialog.askopenfilename(
            title="Choose stego image",
            filetypes=[("Images", "*.png;*.bmp;*.jpg;*.jpeg;*.tif;*.tiff"), ("All files", "*.*")]
        )
        if path:
            self.stego_path = path
            self.lbl_stego.config(text=path)

    def decode_action(self):
        if not self.stego_path:
            messagebox.showwarning("Missing input", "Choose a stego image first.")
            return
        out_payload = filedialog.asksaveasfilename(title="Save extracted payload as", filetypes=[("All files", "*.*")])
        if not out_payload:
            return
        password = self.ent_password_dec.get() or None
        try:
            decode_image(self.stego_path, out_payload, password)
            messagebox.showinfo("Success", f"Payload saved:\n{out_payload}")
        except Exception as e:
            messagebox.showerror("Decode failed", str(e))
