import pytest
from app import app, db, User, caesar_cipher, vigenere_cipher

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
    client = app.test_client()

    with app.app_context():
        db.create_all()
        yield client
        db.drop_all()
def test_caesar_encryption(client):
    original_text = 'ТТЕСТСЛОЖНЫЙ'
    shift = 3
    encrypted_text = caesar_cipher(original_text, shift, encrypt=True)
    assert encrypted_text != original_text
    assert caesar_cipher(encrypted_text, shift, encrypt=False) == original_text

def test_vigenere_encryption(client):
    original_text = 'ТТЕСТ1'
    key = 'ТКЛЮЧ'
    encrypted_text = vigenere_cipher(original_text, key, encrypt=True)
    assert encrypted_text != original_text
    assert vigenere_cipher(encrypted_text, key, encrypt=False) == original_text

def test_register(client):
    response = client.post('/register', data=dict(
        username='testuser',
        password='test1'
    ), follow_redirects=True)
    assert response.status_code == 200
    assert User.query.filter_by(username='testuser').first() is not None
