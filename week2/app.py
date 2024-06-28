from flask import Flask, request, redirect, render_template, session, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import time
import itertools
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '46'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///work.db'
db = SQLAlchemy(app)
session_id_counter = 0
sessions = {}


ALPHABET = ',.:(_)-0123456789АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ'

class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f"User('{self.username}')"

class EncryptionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), db.ForeignKey('user.username'), nullable=False)
    text = db.Column(db.String(1000), nullable=False)
    result = db.Column(db.String(1000), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    action = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"EncryptionHistory('{self.username}', '{self.method}', '{self.timestamp}')"
@app.before_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')



@app.route('/delete_user/<username>')
def delete_user(username):
    secret_key = request.args.get('secret_key')
    if secret_key != app.config['SECRET_KEY']:
        return "Неверный секретный ключ", 403
    user = User.query.filter_by(username=username).first()
    if user:

        EncryptionHistory.query.filter_by(username=username).delete()

        db.session.delete(user)
        db.session.commit()
        return redirect(url_for('logout'))
    else:
        return "Пользователь не найден", 404

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user is None:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['username'] = username
            return redirect(url_for('title'))
    return render_template('login.html')

@app.route('/title')
def title():
    if 'username' in session:
        user_name = session['username']
        return render_template('title.html', username=user_name)
    else:
        return redirect(url_for('login'))

def vigenere_cipher(text, key, encrypt=False):
    key = key.upper()
    key_indices = [ALPHABET.index(k) for k in key if k in ALPHABET]
    key_length = len(key_indices)
    result = []

    for i, char in enumerate(text):
        if char.upper() in ALPHABET:
            text_index = ALPHABET.index(char.upper())
            key_index = key_indices[i % key_length]

            if encrypt:
                new_index = (text_index + key_index) % len(ALPHABET)
            else:
                new_index = (text_index - key_index) % len(ALPHABET)

            result.append(ALPHABET[new_index])
        else:
            result.append(char)

    return ''.join(result)

def caesar_cipher(text, shift, encrypt=True):
    result = ''
    alphabet_length = len(ALPHABET)

    for char in text:
        if char.upper() in ALPHABET:
            idx = ALPHABET.index(char.upper())
            if encrypt:
                idx = (idx + shift) % alphabet_length
            else:
                idx = (idx - shift) % alphabet_length
            result += ALPHABET[idx] if char.isupper() else ALPHABET[idx].lower()
        else:
            result += char

    return result

@app.route('/methods', methods=['GET', 'POST'])
def methods():
    result = ""
    filtered_result=""
    method = ""
    if 'username' in session:
        username = session['username']

        if request.method == 'POST':
            text = request.form['text']
            key = request.form['key']
            method = request.form.get('method', 'vigenere')
            encrypt = request.form['action'] == 'encrypt'
            filtered_text = ''.join([char for char in text if char.upper() in ALPHABET])
            if method == 'caesar':
                shift = int(key) if key.isdigit() else 0
                result = caesar_cipher(text, shift, encrypt)
            elif method == 'vigenere':
                result = vigenere_cipher(text, key, encrypt)
            filtered_result = ''.join([char for char in result if char.upper() in ALPHABET])



            new_history = EncryptionHistory(username=username, text=filtered_text,
                                            result=filtered_result, method=method,
                                            action='encrypt' if encrypt else 'decrypt')
            db.session.add(new_history)
            db.session.commit()


        user_history = EncryptionHistory.query.filter_by(username=username).all()
        return render_template('methods.html', result=filtered_result, method=method,
                               encryption_history=user_history)
    else:
        return redirect(url_for('login'))

@app.route('/history_encrypt/<username>')
def history_encrypt(username):
    if 'username' in session and username == session['username']:
        user_history = EncryptionHistory.query.filter_by(username=username).all()
        for record in user_history:
            record.display_method = 'Цезарь' if record.method == 'caesar' else 'Виженер'
        return render_template('history_encrypt.html', history=user_history)
    else:
        return redirect(url_for('login'))

@app.route('/users')
def users():
    if 'username' in session:
        users = User.query.all()
        return render_template('users.html', users=[user.username for user in users])
    else:
        return redirect(url_for('login'))


@app.route('/hack_caesar', methods=['GET'])
def hack_caesar_form():
    # Получение списка пользователей из базы данных
    users = User.query.with_entities(User.username).all()
    return render_template('hack_caesar.html', users=[user.username for user in users])

@app.route('/hack_caesar', methods=['POST'])
def hack_caesar():
    data = request.form
    user_id = data['user_id']
    data_in = data['data_in']
    keyword = data['keyword']


    user = User.query.filter_by(username=user_id).first()
    if user and len(data_in) <= 1000:
        data_in_filtered = ''.join([c for c in data_in.upper() if c in ALPHABET])
        possible_results = []


        for shift in range(len(ALPHABET)):
            decrypted_text = caesar_cipher(data_in_filtered, shift, encrypt=False)
            if keyword.upper() in decrypted_text:
                possible_results.append({'shift': shift, 'decrypted_text': decrypted_text})


                hack_entry = EncryptionHistory(
                    username=user.username,
                    text=data_in,
                    result=','.join([res['decrypted_text'] for res in possible_results]),
                    method='caesar',
                    action='hack',

                )
                db.session.add(hack_entry)
                db.session.commit()
        return render_template('result_hack1.html', results=possible_results, username=user.username)
    else:
        return jsonify({"message": "Invalid input"}), 400


@app.route('/hack_vigenere', methods=['GET'])
def hack_vigenere_form():
    # Получение списка пользователей из базы данных
    users = User.query.with_entities(User.username).all()
    return render_template('hack_vigenere.html', users=[user.username for user in users])

@app.route('/hack_vigenere', methods=['POST'])
def hack_vigenere():
    global session_id_counter
    data = request.form
    user_id = data['user_id']
    data_in = data['data_in']
    keyword = data['keyword']
    parent_id = data.get('parent_id')

    # Проверка наличия пользователя в базе данных
    user = User.query.filter_by(username=user_id).first()
    if user and len(data_in) <= 1000:
        data_in_filtered = ''.join([c for c in data_in.upper() if c in ALPHABET])
        possible_results = []
        start_time = time.time()

        # Оптимизированный взлом шифра Виженера
        key_lengths = range(1, min(4, len(data_in_filtered) + 1))  # Ограничение длины ключа для оптимизации

        def generate_vigenere_keys():
            for key_length in key_lengths:
                for key_tuple in itertools.product(ALPHABET, repeat=key_length):
                    yield ''.join(key_tuple)

        for key in generate_vigenere_keys():
            decrypted_text = vigenere_cipher(data_in_filtered, key, encrypt=False)
            if keyword.upper() in decrypted_text:  # Проверка на ключевое слово
                possible_results.append({'key': key, 'decrypted_text': decrypted_text})
                if len(possible_results) >= 10:  # Ограничение количества результатов для экономии памяти
                    break

        if user and len(data_in) <= 1000:


            # Запись результатов в базу данных
                for result in possible_results:
                    history_entry = EncryptionHistory(
                        username=user.username,
                        text=data_in,
                        result=result['decrypted_text'],
                        method='Vigenere',
                        action='hack'
                    )
                    db.session.add(history_entry)

                db.session.commit()
        return render_template('result_hack.html', results=possible_results, username=user.username)
    else:
        return jsonify({"message": "Invalid input"}), 400

if __name__ == '__main__':
    app.run(debug=True)
