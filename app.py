from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Configura CORS para permitir solicitudes desde cualquier origen

@app.route('/encrypt_text_aes', methods=['POST'])
def encrypt_text_aes():
    try:
        data = request.get_json()
        if not data or 'plaintext' not in data:
            return jsonify({'status': 'success'}), 400

        plaintext = data.get('plaintext', '').encode()

        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        response_data = {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'key': base64.b64encode(key).decode(),
            'tag': base64.b64encode(tag).decode(),
            'nonce': base64.b64encode(cipher.nonce).decode()
        }

        return jsonify(response_data), 200

    except Exception as e:
        print(f'Error in /encrypt_text_aes: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/decrypt_text_aes', methods=['POST'])
def decrypt_text_aes():
    try:
        data = request.get_json()
        key = base64.b64decode(data.get('key', ''))
        nonce = base64.b64decode(data.get('nonce', ''))
        tag = base64.b64decode(data.get('tag', ''))
        ciphertext = base64.b64decode(data.get('ciphertext', ''))
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        
        return jsonify({'plaintext': decrypted_data.decode('utf-8')})
    
    except (ValueError, KeyError, TypeError) as e:
        return jsonify({'error': f'Error en la desencriptación: {str(e)}'}), 400
    
    except Exception as e:
        print(f'Error en /decrypt_text_aes: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': f'Error inesperado: {str(e)}'}), 500

@app.route('/encrypt_rsa', methods=['POST'])
def encrypt_rsa():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        file_content = file.read()

        key = RSA.generate(2048)
        public_key = base64.b64encode(key.publickey().export_key()).decode()
        private_key = base64.b64encode(key.export_key()).decode()

        cipher_rsa = PKCS1_OAEP.new(key.publickey())
        ciphertext = cipher_rsa.encrypt(file_content)

        response_data = {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'public_key': public_key,
            'private_key': private_key,
            'filename': file.filename
        }

        return jsonify(response_data), 200

    except Exception as e:
        print(f'Error in /encrypt_rsa: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/decrypt_rsa', methods=['POST'])
def decrypt_rsa():
    try:
        data = request.get_json()
        if not all(k in data for k in ('ciphertext', 'private_key')):
            return jsonify({'error': 'Faltan datos en la solicitud'}), 400

        ciphertext = base64.b64decode(data['ciphertext'])
        private_key = RSA.import_key(base64.b64decode(data['private_key']))

        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_data = cipher_rsa.decrypt(ciphertext)

        return jsonify({'decrypted_data': decrypted_data.decode()}), 200

    except Exception as e:
        print(f'Error in /decrypt_rsa: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/encrypt_text_rsa', methods=['POST'])
def encrypt_text_rsa():
    try:
        data = request.get_json()
        if not data or 'plaintext' not in data:
            return jsonify({'error': 'Faltan datos en la solicitud'}), 400

        plaintext = data.get('plaintext', '').encode()

        key = RSA.generate(2048)
        public_key = base64.b64encode(key.publickey().export_key()).decode()
        private_key = base64.b64encode(key.export_key()).decode()

        cipher_rsa = PKCS1_OAEP.new(key.publickey())
        ciphertext = cipher_rsa.encrypt(plaintext)

        response_data = {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'public_key': public_key,
            'private_key': private_key
        }

        return jsonify(response_data), 200

    except Exception as e:
        print(f'Error in /encrypt_text_rsa: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/decrypt_text_rsa', methods=['POST'])
def decrypt_text_rsa():
    try:
        data = request.get_json()
        if not all(k in data for k in ('ciphertext', 'private_key')):
            return jsonify({'error': 'Faltan datos en la solicitud'}), 400

        ciphertext = base64.b64decode(data['ciphertext'])
        private_key = RSA.import_key(base64.b64decode(data['private_key']))

        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_data = cipher_rsa.decrypt(ciphertext)

        return jsonify({'decrypted_data': decrypted_data.decode()}), 200

    except Exception as e:
        print(f'Error in /decrypt_text_rsa: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/analyze_password', methods=['POST'])
def analyze_password():
    try:
        password = request.json.get('password', '')
        strong = is_strong_password(password)
        return jsonify({'strength': 'strong' if strong else 'weak'}), 200

    except Exception as e:
        print(f'Error in /analyze_password: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Internal Server Error'}), 500

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
