from flask import Flask, render_template,url_for, jsonify, redirect,request, session
from datetime import datetime
import time
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
SECRET_KEY_FOR_DELETION = '46'


users = {
    'admin': generate_password_hash('admin'),
    'yar': generate_password_hash('yar'),

}
# /delete_user/admin?secret_key=46
app.secret_key = '46'
methods = {}
sessions = {}
session_id_counter = 1
history_encrypt = {}
ALPHABET = ',.:(_)-0123456789АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ'

def caesar_cipher(text, shift, encrypt=True):
    alphabet = ',.:(_)-0123456789АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ'
    result = ''
    alphabet_length = len(alphabet)

    for char in text:
       if char.upper() in alphabet:
            idx = alphabet.index(char.upper())
            if encrypt:
              idx = (idx + shift) % alphabet_length
            else:
             idx = (idx - shift) % alphabet_length
            result += alphabet[idx] if char.isupper() else alphabet[idx].lower()
       else:
        result += char

    return result


def vigenere_cipher(text, key, encrypt=False):
    ALPHABET = ',.:(_)-0123456789АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ'  # Пример заданного алфавита
    key = key.upper()
    key_indices = [ALPHABET.index(k) for k in key if k in ALPHABET]
    key_length = len(key_indices)
    result = []

    for i, char in enumerate(text):
        # Проверяем, содержится ли символ в ALPHABET
        if char.upper() in ALPHABET:
            text_index = ALPHABET.index(char.upper())
            key_index = key_indices[i % key_length]

            if encrypt:
                new_index = (text_index + key_index) % len(ALPHABET)
            else:
                new_index = (text_index - key_index) % len(ALPHABET)

            result.append(ALPHABET[new_index])

        elif char.isalpha() and char.upper() not in ALPHABET:
            continue
        else:
            result.append(char)

    return ''.join(result)


@app.route('/')
def home():
    return render_template("index.html")

@app.route('/delete_user/<username>')
def delete_user(username):
    secret_key = request.args.get('secret_key')
    if secret_key != SECRET_KEY_FOR_DELETION:
        return "Неверный секретный ключ", 403

    if username in users:
        del users[username]

        session['users'] = users
        return redirect(url_for('logout'))
    else:
        return "Пользователь не найден", 404


@app.route('/users')
def user_list():
    if 'username' in session:
        return render_template('users.html', users=users.keys())
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username not in users:
            users[username] = generate_password_hash(password)
            return redirect(url_for('login'))
    return render_template('register.html')






@app.route('/methods', methods=['GET', 'POST'])
def methods():
    result = ""
    method = ""
    if 'username' in session:
        username = session['username']
        if username not in history_encrypt:
            history_encrypt[username] = []

        if request.method == 'POST':
            text = request.form['text']
            key = request.form['key']
            method = request.form.get('method', 'vigenere')
            encrypt = request.form['action'] == 'encrypt'
            if method == 'caesar':
                shift = int(key) if key.isdigit() else 0
                result = caesar_cipher(text, shift, encrypt)
            elif method == 'vigenere':
                result = vigenere_cipher(text, key, encrypt)

            filtered_result = ''.join([char for char in result if char.upper() in ALPHABET])
            filtered_text = ''.join([char for char in text if char.upper() in ALPHABET])

            history_encrypt[username].append({
                'username': username,
                'text': filtered_text,
                'result': filtered_result,
                'method': method,
                'action': 'encrypt' if encrypt else 'decrypt',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })

        return render_template('methods.html', result=result, method=method,
                               encryption_history=history_encrypt[username])
    else:
        return redirect(url_for('login'))







@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_hash = users.get(username)
        if user_hash and check_password_hash(user_hash, password):
            session['username'] = username
            return redirect(url_for('title'))
    return render_template('login.html')


@app.route('/title')
def title():
    if 'username' in session:
        user_name = session['username']
        return render_template('title.html',username=user_name)
    else:
        return redirect(url_for('login'))


@app.route('/history_encrypt/<username>')
def encryption_history(username):
    if 'username' in session and username == session['username']:
        user_history = history_encrypt.get(username, [])
        for record in user_history:
            record['display_method'] = 'Цезарь' if record['method'] == 'caesar' else 'Виженер'
        return render_template('history_encrypt.html', history=user_history)
    else:
        return redirect(url_for('login'))









if __name__ == "__main__":
    app.run(debug=True)