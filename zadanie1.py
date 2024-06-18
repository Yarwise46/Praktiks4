def encrypt_word(word, key):
    result = ''
    for lett, k in zip(word, key):
        shift = alp[k.lower()]
        nev_lett = 65 + (ord(lett) - 65 + shift) % 26
        result += chr(nev_lett)
    return result


def decrypt_word(word, key):
    result = ''
    for lett, k in zip(word, key):
        shift = alp[k.lower()]
        nev_lett = 65 + (ord(lett) - 65 - shift) % 26
        result += chr(nev_lett)
    return result


def adeq(word, key):
    size_word = len(word)
    while len(key) < size_word:
        key += key
    return key



alp = {}
start, end = ord('a'), ord('z') + 1
for i in range(start, end):
    alp[chr(i)] = i - start

print('Что будем делать?(0 - зашифровывать;1 - расшифровывать)')
act = int(input())
word = input('Введите слово:  ')
key = input('ключ:  ')
nev_key = adeq(word, key)

if act == 0:
    print('Зашифрованное слово:', encrypt_word(word, nev_key))
else:
    print('Расшифрованное слово:', decrypt_word(word, nev_key))
