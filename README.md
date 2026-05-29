# 🔐 SecureLoginAudit

**CodeAlpha Cybersecurity Internship — Task 3**
**Intern:** Ramya Bhuvaneshwari J | Anand Institute of Higher Technology

---

## 📌 Project Overview
This project demonstrates the difference between a **vulnerable** and **secure** Python login system. It identifies common security flaws and fixes them using best practices.

---

## 🚨 Vulnerabilities Fixed

| Vulnerability | Fix Applied |
|---|---|
| SQL Injection | Parameterized queries |
| Plain-text passwords | bcrypt hashing |
| No input validation | Regex-based validation |
| Brute-force attacks | Account lockout (5 attempts) |

---

## 📁 Files
- `vulnerable_login.py` — Original insecure version
- `secure_login.py` — Fixed secure version
- `users.db` — SQLite database
- `screenshots/` — Test output screenshots

---

## ▶️ How to Run
```bash
pip install bcrypt
python secure_login.py
```

---

## 🛠️ Tech Stack
- Python 3
- SQLite3
- bcrypt
