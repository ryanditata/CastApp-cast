from flask import Flask, request, jsonify, send_file
import os, json, hashlib, time
import numpy as np
from PIL import Image
from Crypto.Cipher import CAST
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
RESULT_FOLDER = "static/hasil"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)


# ===== Fungsi bantu untuk enkripsi =====
def encrypt_image(image_path, password):
    with Image.open(image_path) as img:
        arr = np.array(img)
        shape = arr.shape
        dtype_str = str(arr.dtype)
        data = arr.tobytes()

    salt = get_random_bytes(16)
    nonce = get_random_bytes(3)
    key = PBKDF2(password.encode(), salt, dkLen=16, count=1000000)
    cipher = CAST.new(key, CAST.MODE_CTR, nonce=nonce)
    enc_data = cipher.encrypt(data)

    enc_arr = np.frombuffer(enc_data, dtype=np.uint8).reshape(shape)
    out_name = os.path.splitext(os.path.basename(image_path))[0] + "_encrypted_CAST.png"
    out_path = os.path.join(RESULT_FOLDER, out_name)
    Image.fromarray(enc_arr).save(out_path)

    # simpan metadata
    meta = {
        "shape": shape,
        "dtype": dtype_str,
        "hash": hashlib.sha256(data).hexdigest(),
        "salt": salt.hex(),
        "nonce": nonce.hex()
    }

    return out_path, meta


# ===== Fungsi bantu untuk dekripsi =====
def decrypt_image(image_path, password, meta):
    with Image.open(image_path) as img:
        enc_arr = np.array(img)
        enc_data = enc_arr.tobytes()

    salt = bytes.fromhex(meta["salt"])
    nonce = bytes.fromhex(meta["nonce"])
    shape = tuple(meta["shape"])
    dtype_str = meta["dtype"]
    orig_hash = meta["hash"]

    key = PBKDF2(password.encode(), salt, dkLen=16, count=1000000)
    cipher = CAST.new(key, CAST.MODE_CTR, nonce=nonce)
    dec_data = cipher.encrypt(enc_data)

    # validasi hash
    if hashlib.sha256(dec_data).hexdigest() != orig_hash:
        return None, "Password salah atau file korup!"

    dtype = np.dtype(dtype_str)
    dec_arr = np.frombuffer(dec_data, dtype=dtype).reshape(shape)
    out_name = os.path.splitext(os.path.basename(image_path))[0] + "_decrypted_CAST.png"
    out_path = os.path.join(RESULT_FOLDER, out_name)
    Image.fromarray(dec_arr).save(out_path)
    return out_path, None


# ====== ROUTE API ======

@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    """
    POST /api/encrypt
    Form-data:
      - file : gambar
      - password : password
    """
    if "file" not in request.files or "password" not in request.form:
        return jsonify({"error": "file dan password wajib disertakan"}), 400

    file = request.files["file"]
    password = request.form["password"]

    path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(path)

    start = time.time()
    out_path, meta = encrypt_image(path, password)
    duration = round(time.time() - start, 2)

    meta_path = out_path.replace(".png", "_meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    return jsonify({
        "message": "Enkripsi berhasil",
        "encrypted_file": out_path,
        "meta_file": meta_path,
        "durasi": f"{duration} detik"
    })


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    """
    POST /api/decrypt
    Form-data:
      - file : gambar terenkripsi
      - password : password
      - meta : file JSON metadata
    """
    if "file" not in request.files or "password" not in request.form or "meta" not in request.files:
        return jsonify({"error": "file, meta, dan password wajib disertakan"}), 400

    file = request.files["file"]
    meta_file = request.files["meta"]
    password = request.form["password"]

    path = os.path.join(UPLOAD_FOLDER, file.filename)
    meta_path = os.path.join(UPLOAD_FOLDER, "meta_temp.json")
    file.save(path)
    meta_file.save(meta_path)

    with open(meta_path, "r") as f:
        meta = json.load(f)

    start = time.time()
    out_path, error = decrypt_image(path, password, meta)
    duration = round(time.time() - start, 2)

    if error:
        return jsonify({"error": error}), 400

    return jsonify({
        "message": "Dekripsi berhasil",
        "decrypted_file": out_path,
        "durasi": f"{duration} detik"
    })


@app.route("/download", methods=["GET"])
def download_file():
    """Endpoint untuk mengunduh hasil"""
    filename = request.args.get("file")
    if not filename or not os.path.exists(filename):
        return jsonify({"error": "File tidak ditemukan"}), 404
    return send_file(filename, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)