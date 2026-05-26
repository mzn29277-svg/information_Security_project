
# 🔐 CipherKit — Security Toolkit

A comprehensive, open-source security and cryptography toolkit built with **Flask** and deployed on **Vercel**. Perfect for students, educators, and security enthusiasts to learn about encryption, hashing, encoding, and password security.

**Live Demo:** https://cipher-kit.vercel.app/

---

## 🌟 Features

### 🔑 Password Tools
- **Password Generator** — Create strong, customizable passwords with:
  - Adjustable length (6-128 characters)
  - Options for uppercase, lowercase, numbers, symbols
  - Exclude ambiguous characters (0/O, l/1, etc.)
- **Strength Analyzer** — Real-time password strength evaluation with:
  - Strength score (0-10) with visual indicators
  - Entropy calculation
  - Crack time estimation (10 billion guesses/second)
  - Detailed criteria checks (length, character types, no repeats, etc.)
 
  - <img width="1895" height="899" alt="image" src="https://github.com/user-attachments/assets/f7ef410a-9544-400e-a8b7-0ccd87ca3718" />


### #️⃣ Hash Engine
Generate and compare hashes using multiple algorithms:
- **MD5, SHA-1, SHA-256, SHA-384, SHA-512**
- **SHA3-256, SHA3-512, BLAKE2b, BLAKE2s**
- Batch generate all hashes at once
- Copy-to-clipboard for quick sharing

- <img width="1895" height="906" alt="image" src="https://github.com/user-attachments/assets/4355681b-7f90-4b8d-b3ed-528bb28af01e" />


### 🔀 Encoding Tools
Encode and decode with various formats:
- **Base64** — Standard base64 encoding/decoding
- **Hex** — Convert text to hexadecimal and back
- **Binary** — 8-bit binary representation
- **URL Encoding** — Percent-encoding for URLs

- <img width="1898" height="898" alt="image" src="https://github.com/user-attachments/assets/192a78b4-73d3-45b8-b8ab-2a39e1359776" />


### 🔐 Cipher Suite
Classical and modern encryption methods:
- **Caesar Cipher** — Shift-based encryption with brute force attack tool
- **Vigenère Cipher** — Polyalphabetic substitution cipher
- **Atbash Cipher** — Simple substitution (reverse alphabet)
- **ROT13** — 13-character rotation
- **Morse Code** — Encode/decode Morse code
- **HMAC** — Hash-based message authentication (SHA-256, SHA-512, SHA-1)

- <img width="1901" height="921" alt="image" src="https://github.com/user-attachments/assets/87731fed-b76e-471c-ac29-13d3106c00f0" />


### 🔍 Breach Checker
- Check if a password has been compromised in known data breaches
- Uses the **Pwned Passwords API** by Troy Hunt (haveibeenpwned.com)
- Shows breach count and severity level
- Privacy-focused: only hash prefix is sent (k-anonymity model)

- <img width="1893" height="871" alt="image" src="https://github.com/user-attachments/assets/dfa3d7da-2e70-4410-b308-733ca7fb6c90" />


### 🔢 Number Base Converter
Convert between number systems:
- **Binary, Octal, Decimal, Hexadecimal** (and custom bases up to 36)
- View all representations simultaneously
- Educational tool for understanding number systems

- <img width="1899" height="866" alt="image" src="https://github.com/user-attachments/assets/cf7a7657-707a-46cf-b16d-ca72d3d49d86" />


### 🎨 Beautiful UI
- **Dark theme** with cyberpunk aesthetic
- **Responsive design** — Works on desktop, tablet, and mobile
- **Real-time updates** — Live strength meters, instant encoding
- **Smooth animations** — Polished interactions and transitions
- **Keyboard navigation** — Fast tab switching and shortcuts

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8+ 
- pip (Python package manager)
- Git (optional, for cloning)

### Local Installation

1. **Clone the repository** (or download the files):
```bash
git clone https://github.com/yourusername/cipherkit.git
cd cipherkit
```

2. **Create a virtual environment**:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Run the application**:
```bash
python app.py
```

5. **Open in browser**:
```
http://localhost:5000
```

---

## 📦 Project Structure

```
cipherkit/
├── app.py                    # Flask application with all backend logic
├── requirements.txt          # Python dependencies
├── vercel.json              # Vercel deployment configuration
├── templates/
│   └── index.html           # Frontend HTML/CSS/JavaScript
├── venv/                    # Virtual environment (local only)
└── README.md                # This file
```

### Key Files Explained

**`app.py`** — Main Flask backend
- Password generation and strength analysis
- Hash generation engine
- Encoding/decoding functions
- Cipher implementations
- Breach checking API integration
- Number base converter
- REST API endpoints

**`index.html`** — Complete frontend
- HTML5 markup with semantic structure
- Embedded CSS with custom design system
- Vanilla JavaScript (no frameworks required)
- Tab-based navigation for different tools
- Real-time form handling

**`requirements.txt`** — Dependencies
```
flask              # Web framework
requests           # HTTP library for breach checking
```

**`vercel.json`** — Vercel deployment config
```json
{
  "version": 2,
  "builds": [{"src": "app.py", "use": "@vercel/python"}],
  "routes": [{"src": "/(.*)", "dest": "app.py"}]
}
```

---

## 🔌 API Endpoints

All endpoints accept `POST` requests with JSON payloads:

### Password APIs
| Endpoint | Body | Response |
|----------|------|----------|
| `/api/password/generate` | `{length, upper, lower, nums, syms, exclude_ambiguous}` | `{password, strength}` |
| `/api/password/strength` | `{password}` | `{score, label, pct, criteria, entropy, crack_time}` |

### Hash APIs
| Endpoint | Body | Response |
|----------|------|----------|
| `/api/hash/generate` | `{text, algorithm}` | `{hash, algorithm, length}` |

### Encoding APIs
| Endpoint | Body | Response |
|----------|------|----------|
| `/api/encode` | `{text, method, action}` | `{result, method, action}` |

### Cipher APIs
| Endpoint | Body | Response |
|----------|------|----------|
| `/api/cipher` | `{text, cipher, action, ...}` | `{result}` or `{results}` |

### Breach Check
| Endpoint | Body | Response |
|----------|------|----------|
| `/api/breach` | `{password}` | `{pwned, count, severity}` or `{error}` |

### Number Converter
| Endpoint | Body | Response |
|----------|------|----------|
| `/api/convert` | `{value, from_base, to_base}` | `{decimal, result, binary, octal, hex}` |

---

## 🛠️ Development

### Running in Debug Mode
```bash
export FLASK_ENV=development  # or set FLASK_ENV=development on Windows
python app.py
```

### Customizing the UI
Edit `templates/index.html` to:
- Change colors in the `:root` CSS variables
- Modify the layout and structure
- Add new tool tabs

### Adding New Ciphers
1. Create a cipher function in `app.py` (e.g., `def my_cipher(text, key):`)
2. Add an endpoint to `/api/cipher` handler
3. Update the HTML UI with new form fields

---

## 🌐 Deployment

### Deploy to Vercel (Recommended)

1. **Create a Vercel account** at [vercel.com](https://vercel.com)

2. **Install Vercel CLI**:
```bash
npm install -g vercel
```

3. **Deploy**:
```bash
vercel --prod
```

4. **Your app is live!** Vercel will provide a production URL

### Deploy to Other Platforms

**Heroku:**
```bash
git push heroku main
```

**PythonAnywhere:**
- Upload files via web interface
- Configure WSGI file to point to `app.py`

**AWS/Azure/GCP:**
- Container deployment using Docker
- Simple Flask app runs on any Python host

---

## 📚 Educational Use Cases

### For Students
- Learn cryptography fundamentals
- Understand password security
- Explore hash functions and their properties
- Practice with encoding/decoding algorithms

### For Educators
- Teach cryptography concepts interactively
- Demonstrate real-world security tools
- Show how passwords are stored and validated
- Introduce API development with Flask

### For Security Professionals
- Quick reference for common algorithms
- Test password strength
- Check breach databases
- Educational lab environment

---

## 🔒 Security Notes

### What This Tool Does
✅ Client-side encryption demonstrations (for educational purposes)
✅ Password strength analysis
✅ Hash generation (informational)
✅ Breach checking via privacy-focused API

### What This Tool Does NOT Do
❌ Store any passwords or data
❌ Send sensitive data to external servers (except breach check)
❌ Use deprecated cryptographic algorithms for actual security
❌ Guarantee production-grade security

### Important Disclaimer
> **This is an educational tool, not a production security system.** 
> Do not rely on this for actual password storage or encryption.
> Use industry-standard libraries like `bcrypt`, `argon2`, or `cryptography`.

---

## 🧪 Testing

### Test Password Strength
Try these passwords to see strength variations:
- `abc` — Very weak
- `MyPass123` — Strong
- `MyP@ssw0rd!#Secure2024` — Excellent

### Test Breach Checker
Passwords from famous leaks (use with caution):
- `password123` — Extremely common
- `letmein` — Very common

### Test Ciphers
Caesar cipher with shift 3:
- `HELLO` → `KHOOR`
- `KHOOR` → `HELLO` (decode)

---

## 📄 License

This project is open source and available under the **MIT License**. Feel free to:
- ✅ Use for educational purposes
- ✅ Modify and improve
- ✅ Share with others
- ✅ Deploy your own version

See LICENSE file for details.

---

## 🤝 Contributing

Want to improve CipherKit? Contributions are welcome!

1. **Fork** the repository
2. **Create** a new branch: `git checkout -b feature/awesome-feature`
3. **Commit** changes: `git commit -m 'Add awesome feature'`
4. **Push** to branch: `git push origin feature/awesome-feature`
5. **Open** a Pull Request

### Ideas for Contribution
- [ ] Add RSA encryption demonstration
- [ ] Implement AES/DES symmetric encryption
- [ ] Add password strength history chart
- [ ] Create API documentation with Swagger
- [ ] Add unit tests
- [ ] Implement dark/light theme toggle
- [ ] Add internationalization (i18n)
- [ ] Create mobile app version

---

## 🐛 Bug Reports & Feedback

Found a bug? Have a feature request?
- **GitHub Issues:** Open an issue on the repository
- **Email:** [your-email@example.com]
- **Twitter:** [@yourhandle]

---

## 📚 Resources & References

- **Cryptography Basics:** [Crypto 101](https://www.crypto101.io/)
- **OWASP Password Guidelines:** [OWASP](https://cheatsheetseries.owasp.org/)
- **Pwned Passwords API:** [haveibeenpwned.com](https://haveibeenpwned.com/API/v3)
- **Flask Documentation:** [flask.palletsprojects.com](https://flask.palletsprojects.com/)
- **Python Hashlib:** [docs.python.org](https://docs.python.org/3/library/hashlib.html)

---

## 📊 Project Stats

- **Framework:** Flask (Python)
- **Frontend:** Vanilla HTML/CSS/JavaScript (no dependencies)
- **Backend:** Python 3.8+
- **Deployment:** Vercel Serverless
- **License:** MIT
- **Status:** Active & Maintained ✅

---

## 🎯 Roadmap

### v1.0 (Current)
- ✅ Password generator & strength analyzer
- ✅ Hash engine
- ✅ Encoding tools
- ✅ Cipher suite
- ✅ Breach checker
- ✅ Number converter

### v1.1 (Planned)
- 🔄 Unit tests & documentation
- 🔄 API documentation (Swagger)
- 🔄 Dark mode toggle
- 🔄 Mobile app

### v2.0 (Future)
- 🔄 RSA/ECC encryption
- 🔄 File encryption tool
- 🔄 QR code generator
- 🔄 Advanced analytics

---

## 💡 Pro Tips

1. **Copy to Clipboard** — Click any output box to copy (works on most tools)
2. **Tab Navigation** — Use number keys (1-8) to switch tabs quickly
3. **API Usage** — Integrate endpoints into your own projects
4. **Password Generation** — Exclude ambiguous characters for better readability
5. **HMAC Usage** — Use for verifying data integrity in APIs

---

## 🙌 Credits

Built with ❤️ for the cybersecurity community.

**Special Thanks To:**
- Troy Hunt for Pwned Passwords API
- Flask community for the amazing framework
- Vercel for free serverless hosting
- All contributors and testers

---

**Made with ❤️ | Open Source | Educational Purpose**

---

## ⭐ Show Your Support

If you found this useful, please:
- ⭐ **Star** this repository
- 🔀 **Fork** and contribute
- 📢 **Share** with others
- 💬 **Leave feedback**

---

**Questions?** Check the [documentation](#-getting-started) or open an issue! 🚀
