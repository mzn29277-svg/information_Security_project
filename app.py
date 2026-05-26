from flask import Flask, render_template, request, jsonify
import secrets
import string
import hashlib
import hmac
import base64
import math
import re
import requests as req
import os
from datetime import datetime

app = Flask(__name__)

# ── PASSWORD GENERATOR ────────────────────────────────────────────────
def generate_password(length=16, use_upper=True, use_lower=True,
                       use_nums=True, use_syms=True, exclude_ambiguous=False):
    charset = ''
    guaranteed = []

    upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ' if exclude_ambiguous else string.ascii_uppercase
    lower = 'abcdefghjkmnpqrstuvwxyz'  if exclude_ambiguous else string.ascii_lowercase
    nums  = '23456789'                  if exclude_ambiguous else string.digits
    syms  = '!@#$%^&*_+-=?'

    if use_upper: charset += upper;  guaranteed.append(secrets.choice(upper))
    if use_lower: charset += lower;  guaranteed.append(secrets.choice(lower))
    if use_nums:  charset += nums;   guaranteed.append(secrets.choice(nums))
    if use_syms:  charset += syms;   guaranteed.append(secrets.choice(syms))

    if not charset:
        return None, 'Select at least one character type'

    pw = guaranteed[:]
    while len(pw) < length:
        pw.append(secrets.choice(charset))

    # Secure shuffle using secrets
    pw_list = list(pw)
    for i in range(len(pw_list) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pw_list[i], pw_list[j] = pw_list[j], pw_list[i]

    return ''.join(pw_list), None

def analyze_strength(password):
    if not password:
        return {'score': 0, 'label': 'Empty', 'color': '#5a7a99', 'pct': 0, 'criteria': {}}

    criteria = {
        'length_8':   len(password) >= 8,
        'length_12':  len(password) >= 12,
        'length_16':  len(password) >= 16,
        'uppercase':  bool(re.search(r'[A-Z]', password)),
        'lowercase':  bool(re.search(r'[a-z]', password)),
        'numbers':    bool(re.search(r'[0-9]', password)),
        'symbols':    bool(re.search(r'[^A-Za-z0-9]', password)),
        'no_repeat':  not bool(re.search(r'(.)\1{2,}', password)),
        'no_sequence': not bool(re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|def)', password.lower())),
    }

    score = sum(criteria.values())
    entropy = calculate_entropy(password)

    # Weighted score
    if score <= 2:
        label, color, pct = 'Very Weak', '#ff4d6d', 12
    elif score <= 4:
        label, color, pct = 'Weak', '#ff7849', 28
    elif score <= 5:
        label, color, pct = 'Fair', '#ffc94d', 50
    elif score <= 6:
        label, color, pct = 'Strong', '#0084ff', 72
    elif score <= 7:
        label, color, pct = 'Very Strong', '#00d4aa', 88
    else:
        label, color, pct = 'Excellent', '#00f0c0', 100

    # Crack time estimate
    charset_size = 0
    if criteria['uppercase']: charset_size += 26
    if criteria['lowercase']: charset_size += 26
    if criteria['numbers']:   charset_size += 10
    if criteria['symbols']:   charset_size += 32

    combinations = max(charset_size, 1) ** len(password)
    # Assuming 10 billion guesses/sec
    seconds = combinations / 1e10
    crack_time = format_crack_time(seconds)

    return {
        'score': score, 'label': label, 'color': color,
        'pct': pct, 'criteria': criteria,
        'entropy': round(entropy, 1),
        'crack_time': crack_time,
        'length': len(password),
    }

def calculate_entropy(password):
    if not password:
        return 0
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^A-Za-z0-9]', password): charset += 32
    return len(password) * math.log2(max(charset, 2))

def format_crack_time(seconds):
    if seconds < 1:        return 'Instantly'
    if seconds < 60:       return f'{int(seconds)} seconds'
    if seconds < 3600:     return f'{int(seconds/60)} minutes'
    if seconds < 86400:    return f'{int(seconds/3600)} hours'
    if seconds < 2592000:  return f'{int(seconds/86400)} days'
    if seconds < 31536000: return f'{int(seconds/2592000)} months'
    years = seconds / 31536000
    if years < 1000:       return f'{int(years)} years'
    if years < 1e6:        return f'{years/1000:.1f}K years'
    if years < 1e9:        return f'{years/1e6:.1f}M years'
    return f'{years/1e9:.1f}B+ years'

# ── HASH ENGINE ───────────────────────────────────────────────────────
def generate_hash(text, algorithm):
    algos = {
        'md5':      hashlib.md5,
        'sha1':     hashlib.sha1,
        'sha224':   hashlib.sha224,
        'sha256':   hashlib.sha256,
        'sha384':   hashlib.sha384,
        'sha512':   hashlib.sha512,
        'sha3_256': hashlib.sha3_256,
        'sha3_512': hashlib.sha3_512,
        'blake2b':  hashlib.blake2b,
        'blake2s':  hashlib.blake2s,
    }
    fn = algos.get(algorithm.lower().replace('-','').replace('_','').replace(' ',''))
    if not fn:
        return None, f'Unknown algorithm: {algorithm}'
    data = text.encode('utf-8')
    h = fn(data).hexdigest()
    return h, None

def generate_all_hashes(text):
    data = text.encode('utf-8')
    return {
        'MD5':       hashlib.md5(data).hexdigest(),
        'SHA-1':     hashlib.sha1(data).hexdigest(),
        'SHA-256':   hashlib.sha256(data).hexdigest(),
        'SHA-384':   hashlib.sha384(data).hexdigest(),
        'SHA-512':   hashlib.sha512(data).hexdigest(),
        'SHA3-256':  hashlib.sha3_256(data).hexdigest(),
        'SHA3-512':  hashlib.sha3_512(data).hexdigest(),
        'BLAKE2b':   hashlib.blake2b(data).hexdigest(),
        'BLAKE2s':   hashlib.blake2s(data).hexdigest(),
    }

# ── ENCODING TOOLS ────────────────────────────────────────────────────
def encode_base64(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def decode_base64(text):
    try:
        return base64.b64decode(text.strip()).decode('utf-8'), None
    except Exception as e:
        return None, 'Invalid base64 string'

def encode_hex(text):
    return text.encode('utf-8').hex()

def decode_hex(text):
    try:
        return bytes.fromhex(text.strip()).decode('utf-8'), None
    except Exception as e:
        return None, 'Invalid hex string'

def encode_binary(text):
    return ' '.join(format(ord(c), '08b') for c in text)

def decode_binary(text):
    try:
        bits = text.replace(' ', '').replace('\n', '')
        if len(bits) % 8 != 0:
            return None, 'Binary length must be multiple of 8'
        chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
        return ''.join(chars), None
    except:
        return None, 'Invalid binary string'

def url_encode(text):
    import urllib.parse
    return urllib.parse.quote(text, safe='')

def url_decode(text):
    import urllib.parse
    try:
        return urllib.parse.unquote(text), None
    except:
        return None, 'Invalid URL encoded string'

# ── CIPHER ENGINE ─────────────────────────────────────────────────────
def caesar_cipher(text, shift, decode=False):
    if decode:
        shift = 26 - (shift % 26)
    result = []
    for ch in text:
        if 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)

def caesar_bruteforce(text):
    return [{'shift': i, 'text': caesar_cipher(text, i, decode=True)} for i in range(1, 26)]

def vigenere_cipher(text, key, decode=False):
    key = key.upper()
    result = []
    key_idx = 0
    for ch in text:
        if ch.isalpha():
            k = ord(key[key_idx % len(key)]) - ord('A')
            if decode: k = -k
            if ch.isupper():
                result.append(chr((ord(ch) - ord('A') + k) % 26 + ord('A')))
            else:
                result.append(chr((ord(ch) - ord('a') + k) % 26 + ord('a')))
            key_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

def atbash_cipher(text):
    result = []
    for ch in text:
        if 'a' <= ch <= 'z':
            result.append(chr(ord('z') - (ord(ch) - ord('a'))))
        elif 'A' <= ch <= 'Z':
            result.append(chr(ord('Z') - (ord(ch) - ord('A'))))
        else:
            result.append(ch)
    return ''.join(result)

def rot13(text):
    return caesar_cipher(text, 13)

def morse_encode(text):
    morse_map = {
        'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---',
        'K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-',
        'U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..',
        '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..',
        '9':'----.','.':'.-.-.-',',':'--..--','?':'..--..','!':'-.-.--','/':'-..-.','@':'.--.-.','&':'.-...','=':'-...-'
    }
    words = text.upper().split()
    encoded = []
    for word in words:
        letters = []
        for ch in word:
            if ch in morse_map:
                letters.append(morse_map[ch])
            else:
                letters.append('?')
        encoded.append(' '.join(letters))
    return ' / '.join(encoded)

def morse_decode(text):
    morse_rev = {
        '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J',
        '-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T',
        '..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
        '-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9',
        '.-.-.-':'.','--..--':',','..--..':'?','-.-.--':'!','-..-.':'/','.--.-.':'@','.-...':'&','-...-':'='
    }
    try:
        words = text.strip().split(' / ')
        result = []
        for word in words:
            letters = word.split()
            result.append(''.join(morse_rev.get(l, '?') for l in letters))
        return ' '.join(result), None
    except:
        return None, 'Invalid Morse code'

def generate_hmac(text, key, algorithm='sha256'):
    algos = {'sha256': hashlib.sha256, 'sha512': hashlib.sha512, 'sha1': hashlib.sha1}
    fn = algos.get(algorithm, hashlib.sha256)
    return hmac.new(key.encode('utf-8'), text.encode('utf-8'), fn).hexdigest()

# ── BREACH CHECKER ────────────────────────────────────────────────────
def check_breach(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    try:
        response = req.get(
            f'https://api.pwnedpasswords.com/range/{prefix}',
            headers={'User-Agent': 'CipherKit-Security-Toolkit'},
            timeout=8
        )
        if response.status_code != 200:
            return {'error': f'API error: {response.status_code}'}

        for line in response.text.splitlines():
            line_suffix, count = line.split(':')
            if line_suffix == suffix:
                return {
                    'pwned': True,
                    'count': int(count),
                    'count_formatted': f'{int(count):,}',
                    'hash_prefix': prefix,
                    'severity': 'critical' if int(count) > 100000 else 'high' if int(count) > 1000 else 'medium'
                }
        return {'pwned': False, 'count': 0, 'hash_prefix': prefix}
    except req.exceptions.Timeout:
        return {'error': 'Request timed out — check your connection'}
    except req.exceptions.ConnectionError:
        return {'error': 'Cannot connect to breach database — check your internet'}
    except Exception as e:
        return {'error': str(e)[:80]}

# ── NUMBER BASE CONVERTER ─────────────────────────────────────────────
def convert_number_base(value, from_base, to_base):
    try:
        decimal = int(str(value), from_base)
        bases = {2: bin, 8: oct, 10: str, 16: hex}
        if to_base in bases:
            result = bases[to_base](decimal)
            if to_base in (2, 8, 16):
                result = result[2:].upper() if to_base == 16 else result[2:]
        else:
            digits = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            if decimal == 0:
                result = '0'
            else:
                result = ''
                while decimal:
                    result = digits[decimal % to_base] + result
                    decimal //= to_base
        return {'decimal': int(str(value), from_base), 'result': result,
                'binary': bin(int(str(value), from_base))[2:],
                'octal':  oct(int(str(value), from_base))[2:],
                'hex':    hex(int(str(value), from_base))[2:].upper()}, None
    except Exception as e:
        return None, f'Invalid input: {str(e)}'

# ── ROUTES ────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/password/generate', methods=['POST'])
def api_gen_password():
    d = request.json or {}
    pw, err = generate_password(
        length=max(6, min(128, int(d.get('length', 16)))),
        use_upper=d.get('upper', True),
        use_lower=d.get('lower', True),
        use_nums=d.get('nums', True),
        use_syms=d.get('syms', True),
        exclude_ambiguous=d.get('exclude_ambiguous', False),
    )
    if err: return jsonify({'error': err}), 400
    strength = analyze_strength(pw)
    return jsonify({'password': pw, 'strength': strength})

@app.route('/api/password/strength', methods=['POST'])
def api_strength():
    d = request.json or {}
    pw = d.get('password', '')
    return jsonify(analyze_strength(pw))

@app.route('/api/hash/generate', methods=['POST'])
def api_hash():
    d = request.json or {}
    text = d.get('text', '')
    algo = d.get('algorithm', 'sha256')
    if not text: return jsonify({'error': 'Text required'}), 400
    if algo == 'all':
        return jsonify({'hashes': generate_all_hashes(text)})
    h, err = generate_hash(text, algo)
    if err: return jsonify({'error': err}), 400
    return jsonify({'hash': h, 'algorithm': algo, 'length': len(h)})

@app.route('/api/encode', methods=['POST'])
def api_encode():
    d = request.json or {}
    text = d.get('text', '')
    method = d.get('method', 'base64')
    action = d.get('action', 'encode')
    if not text: return jsonify({'error': 'Text required'}), 400
    try:
        if method == 'base64':
            result = encode_base64(text) if action == 'encode' else decode_base64(text)
        elif method == 'hex':
            result = (encode_hex(text), None) if action == 'encode' else decode_hex(text)
        elif method == 'binary':
            result = (encode_binary(text), None) if action == 'encode' else decode_binary(text)
        elif method == 'url':
            result = (url_encode(text), None) if action == 'encode' else url_decode(text)
        else:
            return jsonify({'error': 'Unknown method'}), 400

        if isinstance(result, tuple):
            out, err = result
            if err: return jsonify({'error': err}), 400
        else:
            out = result
        return jsonify({'result': out, 'method': method, 'action': action})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cipher', methods=['POST'])
def api_cipher():
    d = request.json or {}
    text = d.get('text', '')
    cipher = d.get('cipher', 'caesar')
    action = d.get('action', 'encode')
    if not text: return jsonify({'error': 'Text required'}), 400
    decode = action == 'decode'
    try:
        if cipher == 'caesar':
            shift = int(d.get('shift', 13))
            result = caesar_cipher(text, shift, decode)
            return jsonify({'result': result})
        elif cipher == 'caesar_brute':
            return jsonify({'results': caesar_bruteforce(text)})
        elif cipher == 'vigenere':
            key = d.get('key', 'KEY')
            if not key.isalpha(): return jsonify({'error': 'Vigenere key must be letters only'}), 400
            result = vigenere_cipher(text, key, decode)
            return jsonify({'result': result})
        elif cipher == 'atbash':
            return jsonify({'result': atbash_cipher(text)})
        elif cipher == 'rot13':
            return jsonify({'result': rot13(text)})
        elif cipher == 'morse':
            if action == 'encode':
                return jsonify({'result': morse_encode(text)})
            else:
                result, err = morse_decode(text)
                if err: return jsonify({'error': err}), 400
                return jsonify({'result': result})
        elif cipher == 'hmac':
            key = d.get('key', '')
            algo = d.get('hmac_algo', 'sha256')
            if not key: return jsonify({'error': 'HMAC key required'}), 400
            return jsonify({'result': generate_hmac(text, key, algo)})
        else:
            return jsonify({'error': 'Unknown cipher'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/breach', methods=['POST'])
def api_breach():
    d = request.json or {}
    pw = d.get('password', '')
    if not pw: return jsonify({'error': 'Password required'}), 400
    if len(pw) > 256: return jsonify({'error': 'Password too long'}), 400
    return jsonify(check_breach(pw))

@app.route('/api/convert', methods=['POST'])
def api_convert():
    d = request.json or {}
    value = str(d.get('value', ''))
    from_base = int(d.get('from_base', 10))
    to_base = int(d.get('to_base', 2))
    if not value: return jsonify({'error': 'Value required'}), 400
    result, err = convert_number_base(value, from_base, to_base)
    if err: return jsonify({'error': err}), 400
    return jsonify(result)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
