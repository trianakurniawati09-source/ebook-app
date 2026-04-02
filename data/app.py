import os
import csv
import sqlite3
import hashlib
from datetime import datetime, UTC
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "app.db")
BOOK_PATH = os.path.join(BASE_DIR, "books", "buku.pdf")
CSV_PATH = os.path.join(BASE_DIR, "users.csv")

app = Flask(__name__)
app.secret_key = "ganti_dengan_secret_key_yang_sangat_aman"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            active_device_id TEXT,
            active_login_at TEXT,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def import_users_from_csv():
    if not os.path.exists(CSV_PATH):
        print("users.csv tidak ditemukan")
        return

    conn = get_db()
    cur = conn.cursor()

    imported = 0
    skipped = 0

    with open(CSV_PATH, "r", encoding="utf-8-sig", newline="") as f:
        sample = f.read(2048)
        f.seek(0)

        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;")
            delimiter = dialect.delimiter
        except Exception:
            delimiter = ","

        print("Delimiter terdeteksi:", repr(delimiter))

        reader = csv.DictReader(f, delimiter=delimiter)
        print("HEADER CSV:", reader.fieldnames)

        for row in reader:
            clean_row = {}
            for k, v in row.items():
                key = (k or "").strip()
                val = (v or "").strip()
                clean_row[key] = val

            email = clean_row.get("Email", "").strip().lower()
            nama = clean_row.get("Nama Lengkap", "").strip()

            print("IMPORT EMAIL:", email)

            if not email:
                skipped += 1
                continue

            cur.execute("SELECT id FROM users WHERE username = ?", (email,))
            if cur.fetchone():
                skipped += 1
                continue

            cur.execute("""
                INSERT INTO users (email, username, password_hash, created_at)
                VALUES (?, ?, ?, ?)
            """, (
                email,
                email,
                generate_password_hash("bukuajarM1K"),
                datetime.now(UTC).isoformat()
            ))
            imported += 1

    conn.commit()
    conn.close()
    print(f"Import user selesai. imported={imported}, skipped={skipped}")


def make_device_id():
    user_agent = request.headers.get("User-Agent", "")
    accept_lang = request.headers.get("Accept-Language", "")
    raw = f"{user_agent}|{accept_lang}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
        user = cur.fetchone()
        conn.close()

        if not user:
            session.clear()
            return redirect(url_for("login"))

        current_device_id = make_device_id()
        if user["active_device_id"] != current_device_id:
            session.clear()
            flash("Akun ini sedang aktif di device lain.", "error")
            return redirect(url_for("login"))

        return view_func(*args, **kwargs)
    return wrapper


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""

        print("LOGIN COBA:", username)

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if not user:
            conn.close()
            flash("Username/email tidak ditemukan.", "error")
            return render_template("login.html")

        if not check_password_hash(user["password_hash"], password):
            conn.close()
            flash("Password salah.", "error")
            return render_template("login.html")

        current_device_id = make_device_id()

        if not user["active_device_id"]:
            cur.execute("""
                UPDATE users
                SET active_device_id = ?, active_login_at = ?
                WHERE id = ?
            """, (
                current_device_id,
                datetime.now(UTC).isoformat(),
                user["id"]
            ))
            conn.commit()
        elif user["active_device_id"] != current_device_id:
            conn.close()
            flash("Akun ini sudah login di device lain.", "error")
            return render_template("login.html")

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        conn.close()

        return redirect(url_for("preview"))

    return render_template("login.html")


@app.route("/debug-users")
def debug_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, email, username, created_at FROM users ORDER BY id ASC LIMIT 20")
    rows = cur.fetchall()
    conn.close()

    output = ["DAFTAR USER:"]
    for row in rows:
        output.append(f'{row["id"]} | {row["email"]} | {row["username"]}')
    return "<br>".join(output)


@app.route("/logout")
@login_required
def logout():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE users
        SET active_device_id = NULL, active_login_at = NULL
        WHERE id = ?
    """, (session["user_id"],))
    conn.commit()
    conn.close()

    session.clear()
    flash("Berhasil logout.", "success")
    return redirect(url_for("login"))


@app.route("/preview")
@login_required
def preview():
    return render_template("preview.html", username=session.get("username"))


@app.route("/book")
@login_required
def book():
    if not os.path.exists(BOOK_PATH):
        abort(404, description="File buku tidak ditemukan.")

    return send_file(
        BOOK_PATH,
        mimetype="application/pdf",
        as_attachment=False,
        download_name="buku.pdf"
    )


if __name__ == "__main__":
    init_db()
    import_users_from_csv()
    app.run(host="0.0.0.0", port=5000, debug=True)