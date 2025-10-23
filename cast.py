import os
import time
import threading
import json
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

# --- Ukuran ---
IMG_THUMBNAIL_WIDTH, IMG_THUMBNAIL_HEIGHT = 400, 225  # Ukuran thumbnail MAKSIMUM
HIST_WIDTH, HIST_HEIGHT = 400, 150   # Ukuran box histogram
HIST_FIGSIZE = (5.0, 1.8)            # Ukuran plot (lebar, tinggi dalam inci)
TABLE_HEIGHT = 120                   # Ukuran box tabel

class cast(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CastApp")
        self.geometry("1100x650")
        self.configure(fg_color="#202123")

        # Variabel state
        self.path_asli = None
        self.path_enkripsi = None
        self.path_dekripsi = None
        self.arr_asli = None
        self.arr_enkripsi = None
        self.arr_dekripsi = None
        self.temp_files = []

        self.create_widgets()

    def create_widgets(self):
        # Konfigurasi grid untuk jendela utama (self)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)    # Baris 0 (Kontrol)
        self.grid_rowconfigure(1, weight=1)    # Baris 1 (Gambar) - AKAN MENGAMBIL SEMUA RUANG SISA
        self.grid_rowconfigure(2, weight=0)    # Baris 2 (Histogram)
        self.grid_rowconfigure(3, weight=0)    # Baris 3 (Tabel)
        
        # == ZONA 1: HEADER DAN KONTROL ==
        # [MODIFIKASI] Frame utama transparan dan 3-kolom untuk centering
        controls_frame = ctk.CTkFrame(self, fg_color="transparent") 
        controls_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        controls_frame.grid_columnconfigure(0, weight=1) # Kolom 0: Judul (Kiri)
        controls_frame.grid_columnconfigure(5, weight=1) # Kolom 1: Aksi (Tengah)
        controls_frame.grid_columnconfigure(2, weight=2) # Kolom 2: Kosong (Kanan)

        # --- Komponen Kolom 0 (Kiri) ---
        title_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        # [MODIFIKASI] sticky="w" untuk rata kiri, dan padding lebih kecil
        title_frame.grid(row=0, column=0, sticky="w", padx=20, pady=10) 
        ctk.CTkLabel(title_frame, text="CastApp", font=("Segoe UI", 28, "bold"), text_color="#2E8BFF").pack(anchor="w")
        ctk.CTkLabel(title_frame, text="Kriptografi Gambar\nDengan Metode CAST-128",
                       font=("Segoe UI", 16), text_color="#E5E5E5", anchor="w", justify="left").pack(anchor="w", pady=(0, 5))

        # --- Komponen Kolom 1 (Tengah) ---
        # [MODIFIKASI] Frame ini dipindah ke kolom 1 dan dibuat sticky=""
        # Frame ini sekarang menampung SEMUA tombol dan progress bar
        actions_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        actions_frame.grid(row=0, column=1, sticky="", padx=20) 
        
        # Konfigurasi grid lama tidak lagi diperlukan, kita gunakan .pack()
        # actions_frame.grid_columnconfigure(0, weight=1) ... dst

        self.btn_pilih = ctk.CTkButton(actions_frame, text="Pilih Gambar",
                                         command=self.pilih_gambar_asli, font=("Segoe UI Semibold", 14),
                                         height=35)
        # [MODIFIKASI] Gunakan .pack() untuk susun vertikal
        self.btn_pilih.pack(pady=(5, 5)) 

        self.progress = ctk.CTkProgressBar(actions_frame, progress_color="#2E8BFF", width=600)
        # [MODIFIKASI] Gunakan .pack() untuk susun vertikal
        self.progress.pack(pady=5)
        self.progress.set(0)
        
        button_row_frame = ctk.CTkFrame(actions_frame, fg_color="transparent")
        button_row_frame.pack(pady=10) 
        
        # --- [MODIFIKASI DI SINI] ---
        # Tambahkan Tombol Reset dan Logout

        self.btn_enkrip = ctk.CTkButton(button_row_frame, text="ENKRIPSI",
                                         command=lambda: self.proses_gambar("enkripsi"),
                                         fg_color="#1F7A1F", hover_color="#1A591A",
                                         font=("Segoe UI Semibold", 14), height=35, state="disabled")
        # Sesuaikan padding dan kolom grid
        self.btn_enkrip.grid(row=0, column=0, padx=5) 
        
        self.btn_dekrip = ctk.CTkButton(button_row_frame, text="DEKRIPSI",
                                         command=lambda: self.proses_gambar("dekripsi"),
                                         fg_color="#FFA500", hover_color="#B37400",
                                         font=("Segoe UI Semibold", 14), height=35, state="disabled")
        # Sesuaikan padding dan kolom grid
        self.btn_dekrip.grid(row=0, column=1, padx=5) 

        # Tombol Reset
        self.btn_reset = ctk.CTkButton(button_row_frame, text="RESET",
                                        command=self.reset_ui_state, # Panggil fungsi reset
                                        fg_color="#7F8C8D", hover_color="#626D6E", # Warna abu-abu
                                        font=("Segoe UI Semibold", 14), height=35)
        self.btn_reset.grid(row=0, column=2, padx=5)

        # Tombol Logout
        self.btn_logout = ctk.CTkButton(button_row_frame, text="LOGOUT",
                                         command=self.destroy, # Panggil self.destroy untuk menutup
                                         fg_color="#E74C3C", hover_color="#C0392B", # Warna merah
                                         font=("Segoe UI Semibold", 14), height=35)
        self.btn_logout.grid(row=0, column=3, padx=5)
        # --- [AKHIR MODIFIKASI] ---

        # == ZONA 2: VISUALISASI GAMBAR ==
        images_frame = ctk.CTkFrame(self, fg_color="#2D2F31", corner_radius=10)
        images_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        
        # Tambahkan 'uniform="image_cols"' untuk memaksa 3 kolom memiliki lebar yang sama
        images_frame.grid_columnconfigure((0, 1, 2), weight=1, uniform="image_cols")
        images_frame.grid_rowconfigure(1, weight=1) 
        
        ctk.CTkLabel(images_frame, text="Gambar Asli", text_color="#2E8BFF", font=("Segoe UI", 16)).grid(row=0, column=0, pady=10)
        ctk.CTkLabel(images_frame, text="Gambar Enkripsi", text_color="#2E8BFF", font=("Segoe UI", 16)).grid(row=0, column=1, pady=10)
        ctk.CTkLabel(images_frame, text="Gambar Dekripsi", text_color="#2E8BFF", font=("Segoe UI", 16)).grid(row=0, column=2, pady=10)
        
        # Ubah 'fg_color' menjadi "transparent"
        self.img_asli_label = ctk.CTkLabel(images_frame, text="", fg_color="transparent")
        self.img_asli_label.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

        self.img_enkrip_label = ctk.CTkLabel(images_frame, text="", fg_color="transparent")
        self.img_enkrip_label.grid(row=1, column=1, sticky="nsew", padx=10, pady=5)

        self.img_dekrip_label = ctk.CTkLabel(images_frame, text="", fg_color="transparent")
        self.img_dekrip_label.grid(row=1, column=2, sticky="nsew", padx=10, pady=5)
        
        # == ZONA 3: HISTOGRAM FIX SIZE ==
        hist_frame_container = ctk.CTkFrame(self, fg_color="#2D2F31", corner_radius=10)
        hist_frame_container.grid(row=2, column=0, sticky="ew", padx=10, pady=5)
        hist_frame_container.grid_columnconfigure((0,1,2), weight=1)
        ctk.CTkLabel(hist_frame_container, text="Evaluasi Hasil", text_color="#2E8BFF", font=("Segoe UI", 16)).grid(row=0, column=1, pady=5)
        self.hist_asli_frame = ctk.CTkFrame(hist_frame_container, fg_color="#202123", corner_radius=8,
                                              width=HIST_WIDTH, height=HIST_HEIGHT)
        self.hist_asli_frame.grid(row=1, column=0, padx=10, pady=5)
        self.hist_asli_frame.pack_propagate(False)
        self.hist_enkrip_frame = ctk.CTkFrame(hist_frame_container, fg_color="#202123", corner_radius=8,
                                               width=HIST_WIDTH, height=HIST_HEIGHT)
        self.hist_enkrip_frame.grid(row=1, column=1, padx=10, pady=5)
        self.hist_enkrip_frame.pack_propagate(False)
        self.hist_dekrip_frame = ctk.CTkFrame(hist_frame_container, fg_color="#202123", corner_radius=8,
                                               width=HIST_WIDTH, height=HIST_HEIGHT)
        self.hist_dekrip_frame.grid(row=1, column=2, padx=10, pady=5)
        self.hist_dekrip_frame.pack_propagate(False)

        # == ZONA 4: TABEL METRIK FIX HEIGHT ==
        table_frame = ctk.CTkFrame(self, fg_color="#2D2F31", corner_radius=10, height=TABLE_HEIGHT)
        table_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=(5,10))
        table_frame.pack_propagate(False)
        
        # --- [MODIFIKASI DI SINI] ---
        # "UACI" dihapus dari daftar headers
        headers = ["Jenis", "Waktu", "Ukuran", "Entropy", "MSE", "PSNR", "NPCR", "SSIM", "Status"]
        # --- [AKHIR MODIFIKASI] ---

        self.table_labels = {}
        for c, header in enumerate(headers):
            table_frame.grid_columnconfigure(c, weight=1)
            ctk.CTkLabel(table_frame, text=header, font=("Segoe UI", 12, "bold"),
                         fg_color="#202123", pady=5).grid(row=0, column=c, sticky="nsew", padx=1, pady=1)
        rows = ["Asli", "Enkripsi", "Dekripsi"]
        for r, row_name in enumerate(rows):
            self.table_labels[row_name] = {}
            ctk.CTkLabel(table_frame, text=row_name, font=("Segoe UI", 12, "bold"),
                         fg_color="#252627", anchor="w", padx=10).grid(row=r+1, column=0, sticky="nsew", padx=1, pady=1)
            for c, header in enumerate(headers[1:]):
                label = ctk.CTkLabel(table_frame, text="-", font=("Segoe UI", 12), fg_color="#252627")
                label.grid(row=r+1, column=c+1, sticky="nsew", padx=1, pady=1)
                self.table_labels[row_name][header] = label

    def pilih_gambar_asli(self):
        path = filedialog.askopenfilename(filetypes=IMAGE_FILETYPES)
        if not path:
            return
        
        # --- [MODIFIKASI DI SINI] ---
        # Reset UI *sebelum* menyimpan path baru
        self.reset_ui_state() 
        # --- [AKHIR MODIFIKASI] ---

        start_time = time.time() # <-- Mulai hitung waktu
        
        self.path_asli = path # <-- Path baru disimpan *setelah* reset
        
        try:
            img = Image.open(self.path_asli) # <-- Sekarang self.path_asli valid
            # Konversi ke RGB di sini untuk konsistensi, tapi simpan array float32
            self.arr_asli = np.array(img.convert("RGB"), dtype=np.float32)
            
            # Buat thumbnail dari gambar 'img' (yang mungkin punya mode 'P' atau 'RGBA')
            img_copy = img.copy()
            img_copy.thumbnail((IMG_THUMBNAIL_WIDTH, IMG_THUMBNAIL_HEIGHT)) 
            img_ctk = ctk.CTkImage(light_image=img_copy, size=img_copy.size)
            
            self.img_asli_label.configure(image=img_ctk, text="")
            self.img_asli_label.image = img_ctk
            # Plot histogram dari array float32 RGB
            self.plot_histogram(self.arr_asli, self.hist_asli_frame, "Histogram Asli")
            
            size_kb = os.path.getsize(self.path_asli) / 1024
            self.table_labels["Asli"]["Ukuran"].configure(text=f"{size_kb:.2f} KB")
            
            # HANYA WAKTU, UKURAN, DAN STATUS YANG DIISI
            t = time.time() - start_time
            self.table_labels["Asli"]["Waktu"].configure(text=f"{t:.2f} s")
            self.table_labels["Asli"]["Status"].configure(text="Berhasil", text_color="#5CFF79")
            
            self.btn_enkrip.configure(state="normal")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal memuat gambar: {e}")
            self.path_asli = None # Jika gagal load, set path_asli ke None lagi
            self.reset_ui_state() # Reset lagi jika load gagal total

    def reset_ui_state(self):
        self.progress.set(0)
        self.btn_enkrip.configure(state="disabled")
        self.btn_dekrip.configure(state="disabled")

        # Beri komentar agar file tidak terhapus
        # for f in self.temp_files:
        #      if os.path.exists(f): os.remove(f)
        # self.temp_files.clear()

        self.path_enkripsi = None
        self.path_dekripsi = None
        self.arr_asli = None # Hapus array lama
        self.arr_enkripsi = None
        self.arr_dekripsi = None
        self.img_asli_label.configure(image=None, text="") 
        self.img_enkrip_label.configure(image=None, text="")
        self.img_dekrip_label.configure(image=None, text="")
        
        for frame in [self.hist_asli_frame, self.hist_enkrip_frame, self.hist_dekrip_frame]:
            for widget in frame.winfo_children():
                widget.destroy()
        
        # --- [MODIFIKASI DI SINI] ---
        # "UACI" dihapus dari daftar headers
        headers = ["Waktu", "Ukuran", "Entropy", "MSE", "PSNR", "NPCR", "SSIM", "Status"]
        # --- [AKHIR MODIFIKASI] ---

        for row_name in ["Asli", "Enkripsi", "Dekripsi"]:
            for header in headers:
                if header in self.table_labels[row_name]:
                    self.table_labels[row_name][header].configure(text="-")

    def plot_histogram(self, arr, master_frame, title):
        for widget in master_frame.winfo_children():
            widget.destroy()
        if arr is None:
            return
        try:
            fig, ax = plt.subplots(figsize=HIST_FIGSIZE, facecolor="#202123")
            ax.set_facecolor("#202123")
            colors = ["#FF5C5C", "#5CFF79", "#5C95FF"]
            if arr.ndim == 3:
                for i, color in enumerate(colors): 
                    ax.hist(arr[..., i].flatten(), bins=256, color=color, alpha=0.7, range=(0, 255))
            else:
                ax.hist(arr.flatten(), bins=256, color="gray", alpha=0.7, range=(0, 255))
            ax.tick_params(colors='white', which='both', labelsize=8)
            ax.set_title(title, fontsize=10, color="white")
            ax.set_xlabel("Intensitas", color="white", fontsize=9)
            ax.set_ylabel("Frekuensi", color="white", fontsize=9)
            ax.set_xlim(0, 255)
            ax.grid(alpha=0.1)
            fig.tight_layout(pad=0.2) 
            canvas = FigureCanvasTkAgg(fig, master=master_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=5)
            plt.close(fig)
        except Exception as e:
            print(f"Gagal plot histogram: {e}")
            ctk.CTkLabel(master_frame, text="Gagal plot histogram.").pack()

    def proses_gambar(self, mode):
        self.progress.set(0)
        self.btn_pilih.configure(state="disabled")
        self.btn_enkrip.configure(state="disabled")
        self.btn_dekrip.configure(state="disabled")
        self.after(0, lambda: threading.Thread(target=self._proses_gambar_thread, args=(mode,), daemon=True).start())

    def _proses_gambar_thread(self, mode):
        start_time = time.time()
        try:
            if mode == "enkripsi":
                if not self.path_asli:
                    self.after(0, lambda: messagebox.showerror("Error", "Pilih gambar asli terlebih dahulu!"))
                    self.after(0, self.reset_setelah_proses)
                    return
                password_dialog = ctk.CTkInputDialog(text="Masukkan Password Enkripsi:", title="Password")
                password = password_dialog.get_input()
                if not password:
                    self.after(0, lambda: messagebox.showerror("Error", "Password tidak boleh kosong!"))
                    self.after(0, self.reset_setelah_proses)
                    return
                self.after(0, self.progress.start)
                dir_name = "temp_results"
                os.makedirs(dir_name, exist_ok=True)
                base_name = os.path.splitext(os.path.basename(self.path_asli))[0]
                out_img = os.path.join(dir_name, f"{base_name}_encrypted_CAST.png")
                
                # --- [PERBAIKAN BUG 1] ---
                self.path_enkripsi = out_img  # <-- SIMPAN PATH ENKRIPSI
                
                salt_path = os.path.join(dir_name, f"{base_name}_salt_CAST.bin")
                nonce_path = os.path.join(dir_name, f"{base_name}_nonce_CAST.bin")
                meta_path = os.path.join(dir_name, f"{base_name}_meta_CAST.json")
                self.temp_files.extend([out_img, salt_path, nonce_path, meta_path])
                
                with Image.open(self.path_asli) as img:
                    orig_mode = img.mode
                    # PENTING: Jangan konversi ke RGB di sini. Enkripsi data mentahnya.
                    arr = np.array(img)
                original_shape = arr.shape
                dtype_str = str(arr.dtype) # <-- Dtype asli disimpan di sini
                if arr.dtype != np.uint8:
                    arr = (arr / np.max(arr) * 255).astype(np.uint8)
                data = arr.tobytes()
                salt = get_random_bytes(16)
                key = PBKDF2(password.encode(), salt, dkLen=16, count=1000000)
                nonce = get_random_bytes(4)
                cipher = CAST.new(key, CAST.MODE_CTR, nonce=nonce)
                enc_data = cipher.encrypt(data)
                orig_hash = hashlib.sha256(data).hexdigest()
                
                # --- PERBAIKAN BUG DTYPE ---
                try:
                    # Gunakan dtype_str yang sudah Anda simpan
                    original_dtype = np.dtype(dtype_str) 
                    enc_arr = np.frombuffer(enc_data, dtype=original_dtype).reshape(original_shape)
                except ValueError:
                    # Fallback jika terjadi kesalahan (seharusnya tidak terjadi sekarang)
                    enc_arr_flat = np.frombuffer(enc_data, dtype=np.uint8)
                    size = enc_arr_flat.size
                    w = int(np.ceil(np.sqrt(size)))
                    h = int(np.ceil(size / w))
                    padded_size = w * h
                    if padded_size > size:
                        enc_arr_flat = np.pad(enc_arr_flat, (0, padded_size - size), 'constant')
                    enc_arr = enc_arr_flat.reshape((h, w))
                # --- AKHIR PERBAIKAN ---
                    
                Image.fromarray(enc_arr).save(out_img, format="PNG")
                with open(salt_path, "wb") as f: f.write(salt)
                with open(nonce_path, "wb") as f: f.write(nonce)
                meta = {
                    "orig_mode": orig_mode, "shape": list(original_shape), "dtype": dtype_str, "hash": orig_hash,
                    "encrypted_image": os.path.basename(out_img), "original_filename": os.path.basename(self.path_asli) 
                }
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(meta, f, ensure_ascii=False, indent=2)
                
                # Buka file yang BARU DISIMPAN, lalu konversi ke RGB untuk array metrik
                self.arr_enkripsi = np.array(Image.open(out_img).convert("RGB"), dtype=np.float32)
                t = time.time() - start_time
                self.after(0, lambda: self.update_ui_post_encrypt(t))

            elif mode == "dekripsi":
                if not self.path_enkripsi:
                    self.after(0, lambda: messagebox.showerror("Error", "Enkripsi gambar terlebih dahulu!"))
                    self.after(0, self.reset_setelah_proses)
                    return
                dir_name = os.path.dirname(self.path_enkripsi)
                base_name_enc = os.path.basename(self.path_enkripsi)
                base_name_noenc = base_name_enc.replace("_encrypted_CAST.png", "")
                meta_path = os.path.join(dir_name, f"{base_name_noenc}_meta_CAST.json")
                if not os.path.exists(meta_path):
                    raise FileNotFoundError("File metadata tidak ditemukan!")
                with open(meta_path, "r", encoding="utf-8") as f: meta = json.load(f)
                orig_hash = meta.get("hash")
                salt_path = os.path.join(dir_name, f"{base_name_noenc}_salt_CAST.bin")
                nonce_path = os.path.join(dir_name, f"{base_name_noenc}_nonce_CAST.bin")
                if not (os.path.exists(salt_path) and os.path.exists(nonce_path)):
                    raise FileNotFoundError("Salt atau nonce tidak ditemukan!")
                self.after(0, self.progress.start)
                with open(salt_path, "rb") as f: salt = f.read()
                with open(nonce_path, "rb") as f: nonce = f.read()
                
                # Buka file terenkripsi dan dapatkan data mentahnya
                with Image.open(self.path_enkripsi) as img: 
                    # PENTING: Jangan konversi. Baca byte mentahnya
                    enc_arr_from_file = np.array(img)
                    enc_bytes = enc_arr_from_file.tobytes()

                dec_bytes = None
                password = None
                while True:
                    if password is None:
                        password_dialog = ctk.CTkInputDialog(text="Masukkan Password Dekripsi:", title="Password Dekripsi")
                        password = password_dialog.get_input()
                        if not password:
                            self.after(0, lambda: messagebox.showwarning("Batal", "Dekripsi dibatalkan."))
                            self.after(0, self.reset_setelah_proses)
                            return
                    key = PBKDF2(password.encode(), salt, dkLen=16, count=1000000)
                    cipher = CAST.new(key, CAST.MODE_CTR, nonce=nonce)
                    dec_bytes = cipher.encrypt(enc_bytes) # Dekripsi data mentah
                    computed_hash = hashlib.sha256(dec_bytes).hexdigest()
                    if computed_hash != orig_hash:
                        self.after(0, lambda: messagebox.showerror("Error", "Password salah silakan coba lagi!"))
                        password = None; continue
                    else: break
                
                # Gunakan dtype dari meta.json
                dtype = np.dtype(meta["dtype"])
                dec_arr = np.frombuffer(dec_bytes, dtype=dtype).reshape(tuple(meta["shape"]))
                out_img = os.path.join(dir_name, f"{base_name_noenc}_decrypted_CAST.png")
                
                # --- [PERBAIKAN BUG 2] ---
                self.path_dekripsi = out_img # <-- SIMPAN PATH DEKRIPSI
                
                self.temp_files.append(out_img)
                # Simpan array yang didekripsi menggunakan mode aslinya
                Image.fromarray(dec_arr, mode=meta["orig_mode"]).save(out_img, format="PNG")

                # Buka file yang BARU DISIMPAN, lalu konversi ke RGB untuk array metrik
                self.arr_dekripsi = np.array(Image.open(out_img).convert("RGB"), dtype=np.float32)
                t = time.time() - start_time
                self.after(0, lambda: self.update_ui_post_decrypt(t))
        except FileNotFoundError as fnf:
            self.after(0, lambda: messagebox.showerror("Error", f"{fnf}"))
            self.after(0, self.reset_setelah_proses)
        except Exception as e:
            self.after(0, lambda e=e: messagebox.showerror("Error", f"Terjadi kesalahan:\n{e}"))
            self.after(0, self.reset_setelah_proses)
        finally:
            self.after(0, self.progress.stop)
            self.after(0, self.progress.set, 1.0)

    def update_ui_post_encrypt(self, t):
        try:
            # Pastikan path_enkripsi sudah di-set di _proses_gambar_thread
            if not self.path_enkripsi or not os.path.exists(self.path_enkripsi):
                 raise FileNotFoundError(f"File enkripsi tidak ditemukan di: {self.path_enkripsi}")

            img = Image.open(self.path_enkripsi)
            img_copy = img.copy()
            img_copy.thumbnail((IMG_THUMBNAIL_WIDTH, IMG_THUMBNAIL_HEIGHT))
            img_ctk = ctk.CTkImage(light_image=img_copy, size=img_copy.size)
            self.img_enkrip_label.configure(image=img_ctk, text="")
            self.img_enkrip_label.image = img_ctk
            
            # Gunakan arr_enkripsi (yang sudah RGB) untuk plot
            self.plot_histogram(self.arr_enkripsi, self.hist_enkrip_frame, "Histogram Enkripsi")
            hist, _ = np.histogram(self.arr_enkripsi.flatten(), bins=256, range=(0,255))
            p = hist / np.sum(hist)
            p = p[p > 0]
            H = -np.sum(p * np.log2(p))

            
            if self.arr_asli is not None:
                # arr_asli dan arr_enkripsi keduanya sudah RGB float32
                if self.arr_asli.shape == self.arr_enkripsi.shape:
                    N = np.sum(self.arr_asli.astype(np.uint8) != self.arr_enkripsi.astype(np.uint8)) * 100 / self.arr_asli.size
                    
                    # --- [MODIFIKASI DI SINI] ---
                    # Perhitungan dan tampilan UACI dihapus
                    # U = np.mean(np.abs(self.arr_asli - self.arr_enkripsi) / 255) * 100 
                    self.table_labels["Enkripsi"]["NPCR"].configure(text=f"{N:.4f} %")
                    # self.table_labels["Enkripsi"]["UACI"].configure(text=f"{U:.4f} %")

                    # --- TAMBAHAN UNTUK METRIK "ENKRIPSI" ---
                    mse_val = mean_squared_error(self.arr_asli, self.arr_enkripsi)
                    try: 
                        psnr_val = peak_signal_noise_ratio(self.arr_asli, self.arr_enkripsi, data_range=255)
                    except ZeroDivisionError: 
                        psnr_val = float('inf')
                    ssim_val = ssim(self.arr_asli, self.arr_enkripsi, channel_axis=2, data_range=255)
                    
                    self.table_labels["Enkripsi"]["MSE"].configure(text=f"{mse_val:.4f}")
                    self.table_labels["Enkripsi"]["PSNR"].configure(text=f"{psnr_val:.2f} dB")
                    self.table_labels["Enkripsi"]["SSIM"].configure(text=f"{ssim_val:.4f}")
                    # --- AKHIR TAMBAHAN ---
                    
                else:
                    self.table_labels["Enkripsi"]["NPCR"].configure(text="N/A (dim mismatch)")
                    # self.table_labels["Enkripsi"]["UACI"].configure(text="N/A (dim mismatch)") # <-- DIHAPUS
                    self.table_labels["Enkripsi"]["MSE"].configure(text="N/A (dim mismatch)")
                    self.table_labels["Enkripsi"]["PSNR"].configure(text="N/A (dim mismatch)")
                    self.table_labels["Enkripsi"]["SSIM"].configure(text="N/A (dim mismatch)")
            # --- [AKHIR MODIFIKASI] ---

            size_kb = os.path.getsize(self.path_enkripsi) / 1024
            self.table_labels["Enkripsi"]["Waktu"].configure(text=f"{t:.2f} s")
            self.table_labels["Enkripsi"]["Ukuran"].configure(text=f"{size_kb:.2f} KB")
            self.table_labels["Enkripsi"]["Entropy"].configure(text=f"{H:.4f}")
            self.table_labels["Enkripsi"]["Status"].configure(text="Berhasil", text_color="#5CFF79")
            self.after(0, lambda: messagebox.showinfo("Sukses", "Enkripsi berhasil!"))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"Gagal update UI Enkripsi: {e}"))
        finally:
            self.reset_setelah_proses(mode="enkripsi")

    def update_ui_post_decrypt(self, t):
        try:
            # Pastikan file hasil dekripsi tersedia
            if not self.path_dekripsi or not os.path.exists(self.path_dekripsi):
                raise FileNotFoundError(f"File dekripsi tidak ditemukan di: {self.path_dekripsi}")

            # Buka hasil dekripsi dalam mode RGB agar entropy benar
            img = Image.open(self.path_dekripsi).convert("RGB")
            img_copy = img.copy()
            img_copy.thumbnail((IMG_THUMBNAIL_WIDTH, IMG_THUMBNAIL_HEIGHT))
            img_ctk = ctk.CTkImage(light_image=img_copy, size=img_copy.size)
            self.img_dekrip_label.configure(image=img_ctk, text="")
            self.img_dekrip_label.image = img_ctk

            # Simpan array RGB hasil dekripsi untuk metrik dan histogram
            self.arr_dekripsi = np.array(img, dtype=np.uint8)

            # Plot histogram hasil dekripsi
            self.plot_histogram(self.arr_dekripsi, self.hist_dekrip_frame, "Histogram Dekripsi")

            # --- Hitung ENTROPY dengan benar ---
            hist, _ = np.histogram(self.arr_dekripsi.flatten(), bins=256, range=(0, 255))
            p = hist / np.sum(hist)
            p = p[p > 0]
            dec_entropy = -np.sum(p * np.log2(p))
            self.table_labels["Dekripsi"]["Entropy"].configure(text=f"{dec_entropy:.4f}")

            # --- Hitung MSE, PSNR, SSIM ---
            if self.arr_asli is not None:
                mse_val = mean_squared_error(self.arr_asli, self.arr_dekripsi)
            try:
                psnr_val = peak_signal_noise_ratio(self.arr_asli, self.arr_dekripsi, data_range=255)
            except ZeroDivisionError:
                psnr_val = float("inf")

            ssim_val = ssim(self.arr_asli, self.arr_dekripsi, channel_axis=2, data_range=255)

            self.table_labels["Dekripsi"]["MSE"].configure(text=f"{mse_val:.4f}")
            self.table_labels["Dekripsi"]["PSNR"].configure(
                text=f"{psnr_val if np.isfinite(psnr_val) else '∞'} dB"
            )
            self.table_labels["Dekripsi"]["SSIM"].configure(text=f"{ssim_val:.4f}")

            # --- Ukuran file dan waktu ---
            size_kb = os.path.getsize(self.path_dekripsi) / 1024
            self.table_labels["Dekripsi"]["Ukuran"].configure(text=f"{size_kb:.2f} KB")
            self.table_labels["Dekripsi"]["Waktu"].configure(text=f"{t:.2f} s")

            # --- Status ---
            self.table_labels["Dekripsi"]["Status"].configure(text="Berhasil", text_color="#5CFF79")
            self.after(0, lambda: messagebox.showinfo("Sukses", "Dekripsi berhasil!"))

        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"Gagal update UI Dekripsi: {e}"))

        finally:
            self.reset_setelah_proses(mode="dekripsi")
            
    def reset_setelah_proses(self, mode=None):
        self.btn_pilih.configure(state="normal")
        if self.path_asli:
            self.btn_enkrip.configure(state="normal")
        if mode == "enkripsi" or self.path_enkripsi:
            self.btn_dekrip.configure(state="normal")

if __name__ == "__main__":
    app = cast()
    app.mainloop()