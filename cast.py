import os
import time
import threading
import json
import glob
import hashlib
import numpy as np
from PIL import Image
from Crypto.Cipher import CAST
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import customtkinter as ctk
from tkinter import filedialog, messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from skimage.metrics import structural_similarity as ssim, mean_squared_error, peak_signal_noise_ratio

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

IMAGE_FILETYPES = [
    ("All image files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tiff;*.tif;*.webp"),
    ("PNG", "*.png"),
    ("JPEG", "*.jpg;*.jpeg"),
    ("BMP", "*.bmp"),
    ("TIFF", "*.tiff;*.tif"),
    ("WebP", "*.webp"),
    ("All files", "*.*")
]

class cast(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CastApp")
        self.geometry("1100x650")

        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color="#202123")
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        ctk.CTkLabel(
            self.sidebar,
            text="CastApp",
            font=("Segoe UI", 22, "bold"),
            text_color="#2E8BFF"
        ).pack(pady=25, padx=20)

        self.active_color = "#2E8BFF"
        self.inactive_color = "transparent"
        self.hover_color = "#2D2F31"
        self.text_color = "#E5E5E5"

        self.btn_home = ctk.CTkButton(
            self.sidebar, text="🏠 Beranda", command=self.menu_beranda,
            fg_color=self.inactive_color, hover_color=self.hover_color,
            text_color=self.text_color, anchor="w", height=40, corner_radius=8,
            font=("Segoe UI Semibold", 14)
        )
        self.btn_home.pack(fill="x", padx=10, pady=5)

        self.btn_enkrip = ctk.CTkButton(
            self.sidebar, text="🔒 Enkripsi", command=self.menu_enkripsi,
            fg_color=self.inactive_color, hover_color=self.hover_color,
            text_color=self.text_color, anchor="w", height=40, corner_radius=8,
            font=("Segoe UI Semibold", 14)
        )
        self.btn_enkrip.pack(fill="x", padx=10, pady=5)

        self.btn_dekrip = ctk.CTkButton(
            self.sidebar, text="🔓 Dekripsi", command=self.menu_dekripsi,
            fg_color=self.inactive_color, hover_color=self.hover_color,
            text_color=self.text_color, anchor="w", height=40, corner_radius=8,
            font=("Segoe UI Semibold", 14)
        )
        self.btn_dekrip.pack(fill="x", padx=10, pady=5)

        self.sidebar_buttons = [self.btn_home, self.btn_enkrip, self.btn_dekrip]

        self.btn_logout = ctk.CTkButton(
            self.sidebar, text="⬅️ Logout", command=self.destroy,
            fg_color="#3C3F41", text_color="white", hover_color="#FF5C5C", height=40,
            font=("Segoe UI Semibold", 14)
        )
        self.btn_logout.pack(side="bottom", fill="x", padx=10, pady=20)

        self.main_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#202123")
        self.main_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        self.menu_beranda()

    def set_active_button(self, active_button):
        """Mengatur warna tombol yang aktif dan menonaktifkan yang lain."""
        for button in self.sidebar_buttons:
            if button == active_button:
                button.configure(fg_color=self.active_color)
            else:
                button.configure(fg_color=self.inactive_color)

    def clear_main(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def menu_beranda(self):
        self.set_active_button(self.btn_home)
        self.clear_main()
        ctk.CTkLabel(
            self.main_frame,
            text="🔰 Algoritma CAST-128",
            font=("Segoe UI", 22, "bold"),
            text_color="#2E8BFF"
        ).pack(pady=20)

        desc = (
            "CAST-128 (juga dikenal sebagai CAST5) adalah algoritma enkripsi simetris berbasis blok "
            "yang dikembangkan oleh Carlisle Adams dan Stafford Tavares.\n\n"
            "Algoritma ini menggunakan panjang blok 64-bit dan panjang kunci variabel antara 40 hingga 128 bit.\n\n"
            "Dalam aplikasi ini, CAST-128 digunakan dalam mode CTR (Counter Mode) untuk mengenkripsi citra digital "
            "dengan kunci yang diturunkan dari password pengguna menggunakan PBKDF2, "
            "serta dilengkapi validasi hash untuk memastikan integritas data hasil dekripsi."
        )

        ctk.CTkTextbox(
            self.main_frame,
            height=180,
            width=750,
            fg_color="#202123",
            text_color="#E5E5E5",
            font=("Segoe UI", 14),
            wrap="word"
        ).pack(pady=10)

        textbox = self.main_frame.winfo_children()[-1]
        textbox.insert("1.0", desc)
        textbox.configure(state="disabled")

        gallery_frame = ctk.CTkScrollableFrame(self.main_frame, width=820, height=420, fg_color="#2D2F31", corner_radius=10)
        gallery_frame.pack(pady=(10, 20), padx=20, fill="both", expand=True)

        ctk.CTkLabel(gallery_frame, text="Galeri Hasil Enkripsi & Dekripsi",
                     font=("Segoe UI", 14, "bold"), text_color="#2E8BFF").pack(anchor="w", padx=15, pady=10)

        image_files = sorted(glob.glob("img/*_CAST.png"))
        if not image_files:
            ctk.CTkLabel(gallery_frame, text="Belum ada hasil enkripsi atau dekripsi.",
                         font=("Segoe UI", 13), text_color="#9CA3AF").pack(pady=10)
        else:
            grid_frame = ctk.CTkFrame(gallery_frame, fg_color="#2D2F31")
            grid_frame.pack(pady=5, padx=10)

            columns = 3
            row, col = 0, 0

            for file in image_files:
                try:
                    with Image.open(file) as im:
                        im_copy = im.copy()
                    im_copy.thumbnail((200, 200))
                    img_ctk = ctk.CTkImage(light_image=im_copy, size=im_copy.size)

                    frame = ctk.CTkFrame(grid_frame, fg_color="#202123", corner_radius=12)
                    frame.grid(row=row, column=col, padx=10, pady=10)

                    ctk.CTkLabel(frame, image=img_ctk, text="").pack(padx=5, pady=5)

                    label_text = os.path.basename(file)
                    status = "🔒 Enkripsi" if "encrypted" in file else "🔓 Dekripsi"
                    ctk.CTkLabel(frame, text=f"{label_text}\n{status}",
                                 font=("Segoe UI", 11), text_color="#E5E5E5").pack(pady=(2, 5))

                    col += 1
                    if col >= columns:
                        col = 0
                        row += 1

                except Exception as e:
                    print(f"Gagal menampilkan {file}: {e}")

    def menu_enkripsi(self):
        self.set_active_button(self.btn_enkrip)
        self.clear_main()
        ctk.CTkLabel(self.main_frame, text="🔒 Enkripsi Gambar", font=("Segoe UI", 20, "bold"), text_color="#2E8BFF").pack(pady=(20, 10))
        ctk.CTkButton(self.main_frame, text="Pilih Gambar", command=lambda: self.proses_gambar("enkripsi"),
                      fg_color="#2E8BFF", hover_color="#1E6FD6", width=200).pack(pady=5)
        self.progress = ctk.CTkProgressBar(self.main_frame, width=400, progress_color="#2E8BFF")
        self.progress.pack(pady=(5, 10))
        self.progress.set(0)

        results_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        results_frame.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkLabel(results_frame, text="Gambar Asli", text_color="#2E8BFF", font=("Segoe UI", 14)).grid(row=0, column=0)
        ctk.CTkLabel(results_frame, text="Gambar Hasil", text_color="#2E8BFF", font=("Segoe UI", 14)).grid(row=0, column=1)
        
        self.img_asli_label = ctk.CTkLabel(results_frame, text="", fg_color="#2D2F31", height=250)
        self.img_asli_label.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.img_hasil_label = ctk.CTkLabel(results_frame, text="", fg_color="#2D2F31", height=250)
        self.img_hasil_label.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        
        ctk.CTkLabel(results_frame, text="Evaluasi Hasil Enkripsi", text_color="#2E8BFF", font=("Segoe UI", 14)).grid(row=2, column=0, columnspan=2, pady=(15, 5))
        
        eval_container = ctk.CTkFrame(results_frame, fg_color="transparent")
        eval_container.grid(row=3, column=0, columnspan=2, sticky="nsew")
        eval_container.grid_columnconfigure(0, weight=1)
        eval_container.grid_columnconfigure(1, weight=1)

        metrics_frame = ctk.CTkFrame(eval_container, fg_color="transparent")
        metrics_frame.grid(row=0, column=0, sticky="nsew", padx=5)
        
        self.metric_labels = {}
        metrics = ["Waktu Proses", "Ukuran Gambar Asli", "Ukuran Gambar Hasil", "Entropy", "NPCR", "UACI", "Status"]
        for i, metric in enumerate(metrics):
            frame = ctk.CTkFrame(metrics_frame, fg_color="#2D2F31", height=30)
            frame.pack(fill="x", pady=2)
            label_text = ctk.CTkLabel(frame, text=f"{metric} :", font=("Segoe UI", 12), anchor="w")
            label_text.pack(side="left", padx=10)
            label_value = ctk.CTkLabel(frame, text="", font=("Segoe UI", 12, "bold"), anchor="e")
            label_value.pack(side="right", padx=10)
            self.metric_labels[metric] = label_value

        self.hist_frame = ctk.CTkFrame(eval_container, fg_color="#2D2F31")
        self.hist_frame.grid(row=0, column=1, sticky="nsew", padx=5)
        ctk.CTkLabel(self.hist_frame, text="Histogram :", font=("Segoe UI", 12)).pack(anchor="nw", padx=10, pady=5)

    def menu_dekripsi(self):
        self.set_active_button(self.btn_dekrip)
        self.clear_main()
        ctk.CTkLabel(self.main_frame, text="🔓 Dekripsi Gambar", font=("Segoe UI", 20, "bold"), text_color="#2E8BFF").pack(pady=(20, 10))
        ctk.CTkButton(self.main_frame, text="Pilih Gambar", command=lambda: self.proses_gambar("dekripsi"),
                      fg_color="#2E8BFF", hover_color="#1E6FD6", width=200).pack(pady=5)
        self.progress = ctk.CTkProgressBar(self.main_frame, width=400, progress_color="#2E8BFF")
        self.progress.pack(pady=(5, 10))
        self.progress.set(0)

        results_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        results_frame.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkLabel(results_frame, text="Gambar Asli", text_color="#2E8BFF", font=("Segoe UI", 14)).grid(row=0, column=0)
        ctk.CTkLabel(results_frame, text="Gambar Hasil", text_color="#2E8BFF", font=("Segoe UI", 14)).grid(row=0, column=1)

        self.img_asli_label = ctk.CTkLabel(results_frame, text="", fg_color="#2D2F31", height=250)
        self.img_asli_label.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.img_hasil_label = ctk.CTkLabel(results_frame, text="", fg_color="#2D2F31", height=250)
        self.img_hasil_label.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)

        ctk.CTkLabel(results_frame, text="Evaluasi Hasil Dekripsi", text_color="#2E8BFF", font=("Segoe UI", 14)).grid(row=2, column=0, columnspan=2, pady=(15, 5))

        eval_container = ctk.CTkFrame(results_frame, fg_color="transparent")
        eval_container.grid(row=3, column=0, columnspan=2, sticky="nsew")
        eval_container.grid_columnconfigure(0, weight=1)
        eval_container.grid_columnconfigure(1, weight=1)

        metrics_frame = ctk.CTkFrame(eval_container, fg_color="transparent")
        metrics_frame.grid(row=0, column=0, sticky="nsew", padx=5)

        self.metric_labels = {}
        metrics = ["Waktu Proses", "Ukuran Gambar Asli", "Ukuran Gambar Hasil", "SSIM", "MSE", "PSNR", "Status"]
        for i, metric in enumerate(metrics):
            frame = ctk.CTkFrame(metrics_frame, fg_color="#2D2F31", height=30)
            frame.pack(fill="x", pady=2)
            label_text = ctk.CTkLabel(frame, text=f"{metric} :", font=("Segoe UI", 12), anchor="w")
            label_text.pack(side="left", padx=10)
            label_value = ctk.CTkLabel(frame, text="", font=("Segoe UI", 12, "bold"), anchor="e")
            label_value.pack(side="right", padx=10)
            self.metric_labels[metric] = label_value

        self.hist_frame = ctk.CTkFrame(eval_container, fg_color="#2D2F31")
        self.hist_frame.grid(row=0, column=1, sticky="nsew", padx=5)
        ctk.CTkLabel(self.hist_frame, text="Histogram :", font=("Segoe UI", 12)).pack(anchor="nw", padx=10, pady=5)

    def proses_gambar(self, mode):
        self.after(0, lambda: threading.Thread(target=self._proses_gambar_thread, args=(mode,), daemon=True).start())

    def _proses_gambar_thread(self, mode):
        start_time = time.time()
        
        path = filedialog.askopenfilename(filetypes=IMAGE_FILETYPES)
        if not path:
            return

        self.after(0, self.progress.set, 0)

        password = None
        if mode == "enkripsi":
            password_dialog = ctk.CTkInputDialog(text="Masukkan Password:", title="Password")
            password = password_dialog.get_input()
            if not password:
                self.after(0, lambda: messagebox.showerror("Error", "Password tidak boleh kosong!"))
                return
        
        try:
            dir_name = os.path.dirname(path)
            base_name = os.path.splitext(os.path.basename(path))[0]
            if mode == "enkripsi":
                out_img = os.path.join(dir_name, f"{base_name}_encrypted_CAST.png")
                salt_path = os.path.join(dir_name, f"{base_name}_salt_CAST.bin")
                nonce_path = os.path.join(dir_name, f"{base_name}_nonce_CAST.bin")
                meta_path = os.path.join(dir_name, f"{base_name}_meta_CAST.json")
                with Image.open(path) as img:
                    orig_mode = img.mode
                    arr = np.array(img)
                original_shape = arr.shape
                dtype_str = str(arr.dtype)
                data = arr.tobytes()
                salt = get_random_bytes(16)
                key = PBKDF2(password.encode(), salt, dkLen=16, count=1000000)
                nonce = get_random_bytes(4)
                cipher = CAST.new(key, CAST.MODE_CTR, nonce=nonce)
                enc_data = cipher.encrypt(data)
                orig_hash = hashlib.sha256(data).hexdigest()
                enc_arr = np.frombuffer(enc_data, dtype=np.uint8).reshape(original_shape)
                Image.fromarray(enc_arr).save(out_img)
                with open(salt_path, "wb") as f: f.write(salt)
                with open(nonce_path, "wb") as f: f.write(nonce)
                
                meta = {
                    "orig_mode": orig_mode, "shape": list(original_shape), "dtype": dtype_str, "hash": orig_hash,
                    "encrypted_image": os.path.basename(out_img), "original_filename": os.path.basename(path) 
                }
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(meta, f, ensure_ascii=False, indent=2)
                
                self.after(0, lambda: self.progress.set(1.0))
                self.after(0, lambda: self.tampilkan_hasil(path, out_img, "Hasil Enkripsi", start_time))

            else:
                base_name_noenc = base_name.replace("_encrypted_CAST", "")
                meta_path = os.path.join(dir_name, f"{base_name_noenc}_meta_CAST.json")
                if not os.path.exists(meta_path):
                    raise FileNotFoundError("File metadata tidak ditemukan!")
                
                with open(meta_path, "r", encoding="utf-8") as f: meta = json.load(f)
                
                original_filename = meta.get("original_filename")
                original_path = os.path.join(dir_name, original_filename) if original_filename else None
                orig_hash = meta.get("hash")
                salt_path = os.path.join(dir_name, f"{base_name_noenc}_salt_CAST.bin")
                nonce_path = os.path.join(dir_name, f"{base_name_noenc}_nonce_CAST.bin")

                if not (os.path.exists(salt_path) and os.path.exists(nonce_path)):
                    raise FileNotFoundError("Salt atau nonce tidak ditemukan!")
                
                with open(salt_path, "rb") as f: salt = f.read()
                with open(nonce_path, "rb") as f: nonce = f.read()
                with Image.open(path) as img: enc_bytes = np.array(img).tobytes()

                dec_bytes = None
                while True:
                    if password is None:
                        password_dialog = ctk.CTkInputDialog(text="Masukkan Password:", title="Password Dekripsi")
                        password = password_dialog.get_input()
                        if not password:
                            self.after(0, lambda: messagebox.showwarning("Batal", "Dekripsi dibatalkan."))
                            return

                    key = PBKDF2(password.encode(), salt, dkLen=16, count=1000000)
                    cipher = CAST.new(key, CAST.MODE_CTR, nonce=nonce)
                    dec_bytes = cipher.encrypt(enc_bytes)
                    computed_hash = hashlib.sha256(dec_bytes).hexdigest()
                    
                    if computed_hash != orig_hash:
                        self.after(0, lambda: messagebox.showerror("Error", "Password salah silakan coba lagi!"))
                        password = None; continue
                    else: break
                
                dtype = np.dtype(meta["dtype"]) if meta["dtype"] else np.uint8
                dec_arr = np.frombuffer(dec_bytes, dtype=dtype).reshape(tuple(meta["shape"]))
                out_img = os.path.join(dir_name, f"{base_name_noenc}_decrypted_CAST.png")
                Image.fromarray(dec_arr).save(out_img)

                self.after(0, lambda: self.progress.set(1.0))
                self.after(0, lambda: self.tampilkan_hasil(path, out_img, "Hasil Dekripsi", start_time, original_path=original_path))

        except FileNotFoundError as fnf:
            self.after(0, lambda: messagebox.showerror("Error", f"{fnf}"))
        except Exception as e:
            self.after(0, lambda e=e: messagebox.showerror("Error", f"Terjadi kesalahan:\n{e}"))

    def tampilkan_hasil(self, file1, file2, title, start_time, original_path=None):
        img1 = Image.open(file1)
        img1.thumbnail((350, 350))
        img1_ctk = ctk.CTkImage(light_image=img1, size=img1.size)
        self.img_asli_label.configure(image=img1_ctk)
        self.img_asli_label.image = img1_ctk

        img2 = Image.open(file2)
        img2.thumbnail((350, 350))
        img2_ctk = ctk.CTkImage(light_image=img2, size=img2.size)
        self.img_hasil_label.configure(image=img2_ctk)
        self.img_hasil_label.image = img2_ctk

        t = round(time.time() - start_time, 2)
        size1 = os.path.getsize(file1) / 1024
        size2 = os.path.getsize(file2) / 1024
        
        self.metric_labels["Waktu Proses"].configure(text=f"{t:.2f} detik")
        self.metric_labels["Ukuran Gambar Asli"].configure(text=f"{size1:.2f} KB")
        self.metric_labels["Ukuran Gambar Hasil"].configure(text=f"{size2:.2f} KB")

        arr1 = np.array(Image.open(file1).convert("RGB"), dtype=np.float32)
        arr2 = np.array(Image.open(file2).convert("RGB"), dtype=np.float32)

        if "Enkripsi" in title:
            H = -np.sum((hist := np.histogram(arr2.flatten(), bins=256, range=(0,255))[0] / arr2.size)[hist > 0] * np.log2(hist[hist > 0]))
            N = np.sum(arr1 != arr2) * 100 / arr1.size
            U = np.mean(np.abs(arr1 - arr2) / 255) * 100
            
            self.metric_labels["Entropy"].configure(text=f"{H:.4f}")
            self.metric_labels["NPCR"].configure(text=f"{N:.4f} %")
            self.metric_labels["UACI"].configure(text=f"{U:.4f} %")
            self.metric_labels["Status"].configure(text="✅ Enkripsi Berhasil")
        else:
            if original_path and os.path.exists(original_path):
                arr_orig = np.array(Image.open(original_path).convert("RGB"), dtype=np.float32)
                mse_val = mean_squared_error(arr_orig, arr2)
                try: psnr_val = peak_signal_noise_ratio(arr_orig, arr2, data_range=255)
                except ZeroDivisionError: psnr_val = float('inf')
                ssim_val = ssim(arr_orig, arr2, channel_axis=2, data_range=255)

                self.metric_labels["SSIM"].configure(text=f"{ssim_val:.4f}")
                self.metric_labels["MSE"].configure(text=f"{mse_val:.4f}")
                self.metric_labels["PSNR"].configure(text=f"{psnr_val:.4f} dB")
            else:
                for metric in ["SSIM", "MSE", "PSNR"]: self.metric_labels[metric].configure(text="N/A")
            self.metric_labels["Status"].configure(text="✅ Dekripsi Berhasil")

        for widget in self.hist_frame.winfo_children():
            if not isinstance(widget, ctk.CTkLabel) or "Histogram" not in widget.cget("text"):
                widget.destroy()

        fig, ax = plt.subplots(figsize=(5.5, 2.8), facecolor="#2D2F31")
        ax.set_facecolor("#2D2F31")
        for i, color in enumerate(["#FF5C5C", "#5CFF79", "#5C95FF"]): 
            ax.hist(arr2[..., i].flatten(), bins=256, color=color, alpha=0.7)
        ax.tick_params(colors='white', which='both')
        ax.set_title("Histogram RGB", fontsize=10, color="white")
        ax.set_xlabel("Intensitas", color="white", fontsize=9)
        ax.set_ylabel("Frekuensi", color="white", fontsize=9)
        ax.set_xlim(0, 255)
        ax.grid(alpha=0.1)
        fig.tight_layout(pad=0.5)

        canvas = FigureCanvasTkAgg(fig, master=self.hist_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=(0,5))
        plt.close(fig)

        messagebox.showinfo("Sukses", f"{title} berhasil disimpan!")

if __name__ == "__main__":
    app = cast()
    app.mainloop()