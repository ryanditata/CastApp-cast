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

ctk.set_appearance_mode("dark") 
ctk.set_default_color_theme("blue") 

# === Tipe file gambar yang didukung ===
IMAGE_FILETYPES = [
    ("All image files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tiff;*.tif;*.webp"),
    ("PNG", "*.png"),
    ("JPEG", "*.jpg;*.jpeg"),
    ("BMP", "*.bmp"),
    ("TIFF", "*.tiff;*.tif"),
    ("WebP", "*.webp"),
    ("All files", "*.*")
]

# === Kelas utama aplikasi CAST ===
class cast(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CastApp")
        self.geometry("1100x650")

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0, fg_color="#202123")
        self.sidebar.pack(side="left", fill="y")

        # Label judul aplikasi
        ctk.CTkLabel(
            self.sidebar,
            text="CastApp",
            font=("Segoe UI", 22, "bold"),
            text_color="#2E8BFF" 
        ).pack(pady=25)

        # Tombol sidebar
        self.btn_home = ctk.CTkButton(
            self.sidebar, text="🏠 Beranda",
            command=self.menu_beranda, width=180, fg_color="#2D2F31", hover_color="#3C3F41"
        )
        self.btn_home.pack(pady=10)

        self.btn_enkrip = ctk.CTkButton(
            self.sidebar, text="🔒 Enkripsi",
            command=self.menu_enkripsi, width=180, fg_color="#2D2F31", hover_color="#3C3F41"
        )
        self.btn_enkrip.pack(pady=10)

        self.btn_dekrip = ctk.CTkButton(
            self.sidebar, text="🔓 Dekripsi",
            command=self.menu_dekripsi, width=180, fg_color="#2D2F31", hover_color="#3C3F41"
        )
        self.btn_dekrip.pack(pady=10)

        self.btn_logout = ctk.CTkButton(
            self.sidebar, text="⬅️ Logout",
            command=self.destroy, width=190, fg_color="#3C3F41", text_color="white", hover_color="#FF5C5C"
        )
        self.btn_logout.pack(side="bottom", pady=20)

        # Area utama untuk konten dinamis
        self.main_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#202123")
        self.main_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        # Default tampilan pertama
        self.menu_beranda() 
  
    # === Menghapus semua widget di area utama sebelum berpindah menu ===
    def clear_main(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    # === Menu Beranda ===
    def menu_beranda(self):
        self.clear_main()
        ctk.CTkLabel(
            self.main_frame,
            text="🔰 Algoritma CAST-128",
            font=("Segoe UI", 22, "bold"),
            text_color="#2E8BFF"
        ).pack(pady=20)

        # Deskripsi algoritma CAST-128
        desc = (
            "CAST-128 (juga dikenal sebagai CAST5) adalah algoritma enkripsi simetris berbasis blok "
            "yang dikembangkan oleh Carlisle Adams dan Stafford Tavares.\n\n"
            "Algoritma ini menggunakan panjang blok 64-bit dan panjang kunci variabel antara 40 hingga 128 bit. "
            "CAST-128 banyak digunakan pada berbagai aplikasi keamanan seperti PGP (Pretty Good Privacy) "
            "dan menawarkan keseimbangan antara keamanan dan efisiensi tinggi.\n\n"
            "Dalam aplikasi ini, CAST-128 digunakan dalam mode CTR (Counter Mode) untuk mengenkripsi citra digital "
            "dengan kunci yang diturunkan dari password pengguna menggunakan PBKDF2 (Password-Based Key Derivation Function 2), "
            "serta dilengkapi validasi hash untuk memastikan integritas data hasil dekripsi."
        )

        # Kotak teks deskripsi
        ctk.CTkTextbox(
            self.main_frame,
            height=400,
            width=750,
            fg_color="#202123",
            text_color="#E5E5E5",
            font=("Segoe UI", 14),
            wrap="word"
        ).pack(pady=10)

        textbox = self.main_frame.winfo_children()[-1]
        textbox.insert("1.0", desc)
        textbox.configure(state="disabled")

    # === Menu Enkripsi ===
    def menu_enkripsi(self):
        self.clear_main()
        ctk.CTkLabel(self.main_frame, text="🔒 Enkripsi Gambar", font=("Segoe UI", 20, "bold"), text_color="#2E8BFF").pack(pady=10)
        ctk.CTkButton(self.main_frame, text="Pilih Gambar", command=lambda: self.proses_gambar("enkripsi"),
                      fg_color="#2E8BFF", hover_color="#1E6FD6", width=200).pack(pady=10)
        # Progress bar enkripsi
        self.progress = ctk.CTkProgressBar(self.main_frame, width=400, progress_color="#2E8BFF")
        self.progress.pack(pady=15)
        self.progress.set(0)
        self.result_label = ctk.CTkLabel(self.main_frame, text="", text_color="#E5E5E5")
        self.result_label.pack(pady=10)
        self.image_frame = ctk.CTkFrame(self.main_frame, fg_color="#2D2F31")
        self.image_frame.pack(pady=10)

    # === Menu Dekripsi ===
    def menu_dekripsi(self):
        self.clear_main()
        ctk.CTkLabel(self.main_frame, text="🔓 Dekripsi Gambar", font=("Segoe UI", 20, "bold"), text_color="#2E8BFF").pack(pady=10)
        ctk.CTkButton(self.main_frame, text="Pilih Gambar", command=lambda: self.proses_gambar("dekripsi"),
                      fg_color="#2E8BFF", hover_color="#1E6FD6", width=200).pack(pady=10)
        # Progress bar dekripsi
        self.progress = ctk.CTkProgressBar(self.main_frame, width=400, progress_color="#2E8BFF")
        self.progress.pack(pady=15)
        self.progress.set(0)
        self.result_label = ctk.CTkLabel(self.main_frame, text="", text_color="#E5E5E5")
        self.result_label.pack(pady=10)
        self.image_frame = ctk.CTkFrame(self.main_frame, fg_color="#2D2F31")
        self.image_frame.pack(pady=10)

    # === Jalankan proses enkripsi/dekripsi dalam thread terpisah agar GUI tidak freeze ===
    def proses_gambar(self, mode):
        threading.Thread(target=self._proses_gambar_thread, args=(mode,), daemon=True).start()

    # === Proses utama enkripsi dan dekripsi ===
    def _proses_gambar_thread(self, mode):
        start_time = time.time()
        self.progress.set(0)

        # Pilih file gambar
        path = filedialog.askopenfilename(filetypes=IMAGE_FILETYPES)
        if not path:
            return messagebox.showwarning("Batal", "Tidak ada file yang dipilih.")

        # Input password untuk enkripsi
        if mode == "enkripsi":
            password = ctk.CTkInputDialog(text="Masukkan Password:", title="Password").get_input()
            if not password:
                return messagebox.showerror("Error", "Password tidak boleh kosong!")
        else:
            password = None

        try:
            dir_name = os.path.dirname(path)
            base_name = os.path.splitext(os.path.basename(path))[0]

            # === MODE ENKRIPSI ===
            if mode == "enkripsi":
                out_img = os.path.join(dir_name, f"{base_name}_encrypted_CAST.png")
                salt_path = os.path.join(dir_name, f"{base_name}_salt_CAST.bin")
                nonce_path = os.path.join(dir_name, f"{base_name}_nonce_CAST.bin")
                meta_path = os.path.join(dir_name, f"{base_name}_meta_CAST.json")

                # Baca gambar asli dan konversi ke array numpy
                with Image.open(path) as img:
                    orig_mode = img.mode
                    arr = np.array(img)
                original_shape = arr.shape
                dtype_str = str(arr.dtype)
                data = arr.tobytes()

                # Buat salt dan nonce acak
                salt = get_random_bytes(16)
                key = PBKDF2(password.encode(), salt, dkLen=16, count=1000000)
                nonce = get_random_bytes(3)
                cipher = CAST.new(key, CAST.MODE_CTR, nonce=nonce)
                enc_data = cipher.encrypt(data)

                # Simpan hash data asli untuk validasi nanti
                orig_hash = hashlib.sha256(data).hexdigest()

                # Simpan gambar hasil enkripsi
                enc_arr = np.frombuffer(enc_data, dtype=np.uint8).reshape(original_shape)
                Image.fromarray(enc_arr).save(out_img)

                # Simpan salt, nonce, dan metadata
                with open(salt_path, "wb") as f:
                    f.write(salt)
                with open(nonce_path, "wb") as f:
                    f.write(nonce)
                meta = {
                    "orig_mode": orig_mode,
                    "shape": original_shape,
                    "dtype": dtype_str,
                    "hash": orig_hash,
                    "encrypted_image": os.path.basename(out_img)
                }
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(meta, f, ensure_ascii=False, indent=2)

                self.progress.set(1.0)
                self.tampilkan_hasil(path, out_img, "Hasil Enkripsi", start_time)

            # === MODE DEKRIPSI ===
            else:
                base_name_noenc = base_name.replace("_encrypted_CAST", "")
                meta_path = os.path.join(dir_name, f"{base_name_noenc}_meta_CAST.json")
                if not os.path.exists(meta_path):
                    raise FileNotFoundError("File metadata tidak ditemukan!")

                # Baca metadata
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)

                orig_mode = meta["orig_mode"]
                original_shape = tuple(meta["shape"])
                dtype_str = meta["dtype"]
                orig_hash = meta.get("hash")

                salt_path = os.path.join(dir_name, f"{base_name_noenc}_salt_CAST.bin")
                nonce_path = os.path.join(dir_name, f"{base_name_noenc}_nonce_CAST.bin")
                if not (os.path.exists(salt_path) and os.path.exists(nonce_path)):
                    raise FileNotFoundError("Salt atau nonce tidak ditemukan!")

                # Baca salt dan nonce
                with open(salt_path, "rb") as f:
                    salt = f.read()
                with open(nonce_path, "rb") as f:
                    nonce = f.read()

                # Baca gambar terenkripsi
                with Image.open(path) as img:
                    enc_arr_img = np.array(img)
                enc_bytes = enc_arr_img.tobytes()

                # Loop untuk validasi password dekripsi
                while True:
                    if password is None:
                        password = ctk.CTkInputDialog(text="Masukkan Password:", title="Password Dekripsi").get_input()
                        if not password:
                            return messagebox.showwarning("Batal", "Dekripsi dibatalkan.")

                    key = PBKDF2(password.encode(), salt, dkLen=16, count=1000000)
                    cipher = CAST.new(key, CAST.MODE_CTR, nonce=nonce)
                    dec_bytes = cipher.encrypt(enc_bytes)

                    # Validasi hash
                    computed_hash = hashlib.sha256(dec_bytes).hexdigest()
                    if computed_hash != orig_hash:
                        messagebox.showerror("Error", "Password salah silakan coba lagi!")
                        password = None
                        continue
                    else:
                        break

                # Simpan hasil dekripsi
                dtype = np.dtype(dtype_str) if dtype_str else np.uint8
                dec_arr = np.frombuffer(dec_bytes, dtype=dtype).reshape(original_shape)
                out_img = os.path.join(dir_name, f"{base_name_noenc}_decrypted_CAST.png")
                Image.fromarray(dec_arr).save(out_img)

                self.progress.set(1.0)
                self.tampilkan_hasil(path, out_img, "Hasil Dekripsi", start_time)

        # === Penanganan error ===
        except FileNotFoundError as fnf:
            messagebox.showerror("Error", f"{fnf}")
        except Exception as e:
            messagebox.showerror("Error", f"Terjadi kesalahan:\n{e}")

    # === Menampilkan hasil gambar dan evaluasi ===
    def tampilkan_hasil(self, file1, file2, title, start_time):
        for widget in self.image_frame.winfo_children():
            widget.destroy()

        # Fungsi bantu untuk resize gambar
        def load_and_resize(path, max_size=(350, 350)):
            with Image.open(path) as im:
                im_copy = im.copy()
            im_copy.thumbnail(max_size)
            return im_copy

        img1 = load_and_resize(file1)
        img2 = load_and_resize(file2)
        img1_ctk = ctk.CTkImage(light_image=img1, size=img1.size)
        img2_ctk = ctk.CTkImage(light_image=img2, size=img2.size)

        # Tampilkan gambar asli dan hasil
        ctk.CTkLabel(self.image_frame, text="Gambar Asli", text_color="#2E8BFF").grid(row=0, column=0, padx=20, pady=10)
        ctk.CTkLabel(self.image_frame, text="Gambar Hasil", text_color="#2E8BFF").grid(row=0, column=1, padx=20, pady=10)
        ctk.CTkLabel(self.image_frame, image=img1_ctk, text="").grid(row=1, column=0, padx=20)
        ctk.CTkLabel(self.image_frame, image=img2_ctk, text="").grid(row=1, column=1, padx=20)

        # Evaluasi hasil proses
        t = round(time.time() - start_time, 2)
        size1 = os.path.getsize(file1) / 1024
        size2 = os.path.getsize(file2) / 1024

        eval_text = f"📊 Evaluasi {title}\n\n" \
                    f"• Waktu Proses : {t} detik\n" \
                    f"• Ukuran Gambar Asli : {size1:.2f} KB\n" \
                    f"• Ukuran Gambar Hasil : {size2:.2f} KB\n" \
                    f"• Status : ✅ Berhasil"

        ctk.CTkLabel(self.image_frame, text=eval_text, font=("Segoe UI", 13), text_color="#E5E5E5").grid(row=2, column=0, columnspan=2, pady=15)
        messagebox.showinfo("Sukses", f"{title} berhasil disimpan!")

# === Jalankan aplikasi utama ===
if __name__ == "__main__":
    app = cast()
    app.mainloop()