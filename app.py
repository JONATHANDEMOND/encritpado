from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib
import base64
from passlib.hash import pbkdf2_sha256

app = Flask(__name__)
CORS(app)

# Cifrado Simétrico AES
@app.route('/encrypt_aes', methods=['POST'])
def encrypt_aes():
    data = request.form['data']
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return jsonify({
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'key': base64.b64encode(key).decode(),
        'tag': base64.b64encode(tag).decode()
    })


# Cifrado Asimétrico RSA
@app.route('/encrypt_rsa', methods=['POST'])
def encrypt_rsa():
    data = request.form['data']
    key = RSA.generate(2048)
    public_key = base64.b64encode(key.publickey().export_key()).decode()
    private_key = base64.b64encode(key.export_key()).decode()
    cipher_rsa = PKCS1_OAEP.new(key.publickey())
    ciphertext = cipher_rsa.encrypt(data.encode())
    return jsonify({
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'public_key': public_key,
        'private_key': private_key
    })

# Verificación de Integridad (SHA-256)
@app.route('/hash_file', methods=['POST'])
def hash_file():
    file = request.files['file']
    file_data = file.read()
    sha256_hash = hashlib.sha256(file_data).hexdigest()
    return jsonify({'sha256': sha256_hash})

# Análisis de Fortalezas de Contraseñas
@app.route('/analyze_password', methods=['POST'])
def analyze_password():
    password = request.form['password']
    strong = is_strong_password(password)
    return jsonify({'is_strong': strong})

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c in "!@#$%^&*()" for c in password):
        return False
    return True

if __name__ == '__main__':
    app.run(debug=True)
