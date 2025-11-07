# ===========================================================
# MedSync Backend (Flask)
# Fully working backend for signup, login, dashboards, upload
# ===========================================================
from flask_cors import CORS
CORS(app, supports_credentials=True)

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import os
import bcrypt
import jwt
import datetime

# -----------------------------
# App Config
# -----------------------------
app = Flask(__name__)
CORS(app)                        # ✅ Allows frontend → backend calls
app.config["SECRET_KEY"] = "medsyncsecret"
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -----------------------------
# Helper: DB Connection
# -----------------------------
def get_db():
    conn = sqlite3.connect("medsync.db")
    conn.row_factory = sqlite3.Row
    return conn


# -----------------------------
# Helper: Token Check
# -----------------------------
def check_token(req):
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None

    token = auth.split(" ")[1]
    try:
        decoded = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        return decoded
    except Exception:
        return None


# -----------------------------
# Initialize DB Tables
# -----------------------------
def setup_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            email TEXT UNIQUE,
            password BLOB,
            role TEXT,
            cid TEXT UNIQUE
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            original_name TEXT,
            patient_id INTEGER,
            hospital_id INTEGER,
            uploaded_at TEXT
        )
    """)

    conn.commit()
    conn.close()

# ✅ Create tables on import (gunicorn on Render won’t hit __main__)
setup_db()


# ===========================================================
# ✅ API ROUTES
# ===========================================================

# -----------------------------
# ✅ Root / Health Check
# -----------------------------
@app.route("/")
def root():
    return jsonify({"service": "MedSync backend", "ok": True})

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


# -----------------------------
# ✅ SIGNUP
# -----------------------------
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.json or {}
    username = data.get("username")
    email = data.get("email")
    pwd = data.get("password") or ""
    role = data.get("role")

    if not username or not email or not pwd:
        return jsonify({"error": "Missing fields"}), 400

    if role not in ["patient", "hospital"]:
        return jsonify({"error": "Invalid role"}), 400

    password = pwd.encode()
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())

    # CID example: CID-ABCD1234
    import random, string
    cid = "CID-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (username, email, password, role, cid) VALUES (?, ?, ?, ?, ?)",
            (username, email, hashed, role, cid)
        )
        conn.commit()
        return jsonify({"message": "Account created", "cid": cid})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists"}), 400

# ✅ Alias to match frontend (/api/auth/signup)
@app.route("/api/auth/signup", methods=["POST"])
def signup_alias():
    return signup()


# -----------------------------
# ✅ LOGIN
# -----------------------------
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    email = data.get("email")
    pwd = data.get("password") or ""

    if not email or not pwd:
        return jsonify({"error": "Missing email or password"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=?", (email,))
    user = c.fetchone()

    if not user or not bcrypt.checkpw(pwd.encode(), user["password"]):
        return jsonify({"error": "Invalid credentials"}), 400

    token = jwt.encode({
        "id": user["id"],
        "role": user["role"],
        "username": user["username"],
        "cid": user["cid"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }, app.config["SECRET_KEY"], algorithm="HS256")

    return jsonify({
        "token": token,
        "role": user["role"],
        "username": user["username"],
        "cid": user["cid"]
    })

# ✅ Alias to match frontend (/api/auth/login)
@app.route("/api/auth/login", methods=["POST"])
def login_alias():
    return login()


# ===========================================================
# ✅ PATIENT ROUTES
# ===========================================================
@app.route("/api/patient/reports")
def patient_reports():
    user = check_token(request)
    if not user or user["role"] != "patient":
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT reports.*, users.username AS hospital_name
        FROM reports
        JOIN users ON users.id = reports.hospital_id
        WHERE patient_id=?
        ORDER BY uploaded_at DESC
    """, (user["id"],))

    data = [dict(row) for row in c.fetchall()]
    return jsonify(data)


# ===========================================================
# ✅ HOSPITAL ROUTES
# ===========================================================

# FIND PATIENT BY CID
@app.route("/api/hospital/find_patient")
def find_patient():
    user = check_token(request)
    if not user or user["role"] != "hospital":
        return jsonify({"error": "Unauthorized"}), 401

    cid = request.args.get("cid")
    if not cid:
        return jsonify({"error": "Missing CID"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, cid FROM users WHERE cid=?", (cid,))
    patient = c.fetchone()

    if not patient:
        return jsonify({"error": "Patient not found"}), 404

    return jsonify(dict(patient))


# UPLOAD REPORT
@app.route("/api/hospital/upload", methods=["POST"])
def upload_report():
    user = check_token(request)
    if not user or user["role"] != "hospital":
        return jsonify({"error": "Unauthorized"}), 401

    if "report_file" not in request.files:
        return jsonify({"error": "Missing file"}), 400

    f = request.files["report_file"]
    patient_id = request.form.get("patient_id")
    if not patient_id:
        return jsonify({"error": "Missing patient_id"}), 400

    filename = f"{datetime.datetime.utcnow().timestamp()}_{f.filename}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    f.save(filepath)

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO reports (filename, original_name, patient_id, hospital_id, uploaded_at)
        VALUES (?, ?, ?, ?, ?)
    """, (filename, f.filename, patient_id, user["id"], datetime.datetime.utcnow().isoformat()))

    conn.commit()

    return jsonify({"message": "Uploaded"})


# HOSPITAL VIEW OWN UPLOADS
@app.route("/api/hospital/reports")
def hospital_reports():
    user = check_token(request)
    if not user or user["role"] != "hospital":
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT reports.*, users.cid AS patient_cid
        FROM reports
        JOIN users ON users.id = reports.patient_id
        WHERE hospital_id=?
        ORDER BY uploaded_at DESC
    """, (user["id"],))

    data = [dict(row) for row in c.fetchall()]
    return jsonify(data)


# ===========================================================
# ✅ DOWNLOAD REPORT
# ===========================================================
@app.route("/download/<filename>")
def download(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)


# ===========================================================
# ✅ START SERVER (local dev only)
# ===========================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
