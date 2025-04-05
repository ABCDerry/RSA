from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify
import sqlite3
import os
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from PIL import Image
import base64
import io

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -------------------- DATABASE SETUP --------------------
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    public_key TEXT,
                    private_key TEXT
                )''')
    conn.commit()
    conn.close()

init_db()

# -------------------- RSA KEY GENERATION --------------------
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_pem.decode('utf-8'), private_pem.decode('utf-8')

# -------------------- AUTHENTICATION --------------------
@app.route('/')
def root():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        public_key, private_key = generate_keys()

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, public_key, private_key) VALUES (?, ?, ?, ?)",
                      (username, password, public_key, private_key))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists."
        conn.close()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = username
            return redirect('/dashboard')
        else:
            return "Invalid credentials."
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# -------------------- DASHBOARD --------------------
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username != ?", (session['username'],))
    users = [row[0] for row in c.fetchall()]
    conn.close()
    return render_template('index.html', users=users)

# -------------------- STEGANOGRAPHY --------------------
def lsb_encode(image, message):
    encoded = image.copy()
    width, height = image.size
    index = 0
    message += chr(0)
    binary_message = ''.join([format(ord(c), '08b') for c in message])

    for y in range(height):
        for x in range(width):
            if index < len(binary_message):
                r, g, b = image.getpixel((x, y))
                r = (r & ~1) | int(binary_message[index])
                index += 1
                encoded.putpixel((x, y), (r, g, b))
            else:
                break
    return encoded

def lsb_decode(image):
    binary_message = ''
    for y in range(image.size[1]):
        for x in range(image.size[0]):
            r, g, b = image.getpixel((x, y))
            binary_message += str(r & 1)

    message = ''
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        char = chr(int(byte, 2))
        if char == chr(0):
            break
        message += char
    return message

# -------------------- ENCRYPT --------------------
@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'username' not in session:
        return redirect('/login')

    image_file = request.files['image']
    message = request.form['message']
    recipient = request.form['recipient']

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (recipient,))
    result = c.fetchone()
    conn.close()
    if not result:
        return "Recipient not found."

    recipient_pubkey = serialization.load_pem_public_key(result[0].encode('utf-8'))
    encrypted_message = recipient_pubkey.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    b64_encrypted = base64.b64encode(encrypted_message).decode()

    image = Image.open(image_file)
    encoded = lsb_encode(image, b64_encrypted)
    output_path = os.path.join(UPLOAD_FOLDER, 'encrypted.png')
    encoded.save(output_path)
    return send_file(output_path, as_attachment=True)

# -------------------- DECRYPT --------------------
@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'})

    image_file = request.files['image']
    image = Image.open(image_file)
    hidden_message = lsb_decode(image)

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT private_key FROM users WHERE username = ?", (session['username'],))
    result = c.fetchone()
    conn.close()
    if not result:
        return jsonify({'error': 'Private key not found'})

    private_key = serialization.load_pem_private_key(result[0].encode(), password=None)
    try:
        decrypted = private_key.decrypt(
            base64.b64decode(hidden_message),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ).decode()
        return jsonify({'message': decrypted})
    except Exception as e:
        return jsonify({'error': 'Failed to decrypt: ' + str(e)})

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
