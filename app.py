import os, io, json, secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, request, send_file, jsonify,
                   render_template, redirect, url_for, session)
from werkzeug.security import generate_password_hash, check_password_hash
import fitz
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from PIL import Image

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"

BASE       = os.path.dirname(os.path.abspath(__file__))
DATA_DIR   = "/data" if os.path.isdir("/data") else BASE
USERS_FILE = os.path.join(DATA_DIR, "users.json")
LOG_FILE   = os.path.join(DATA_DIR, "activity.log")
HIST_FILE  = os.path.join(DATA_DIR, "history.json")

# ── Helpers ───────────────────────────────────────────────────────────────────
def load_json(path, default):
    if not os.path.exists(path): return default
    with open(path, encoding="utf-8") as f:
        try: return json.load(f)
        except: return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)

def load_users(): return load_json(USERS_FILE, {})
def save_users(u): save_json(USERS_FILE, u)

def log_event(event_type, username, detail=""):
    log = load_json(LOG_FILE, [])
    log.insert(0, {"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                   "type": event_type, "username": username, "detail": detail})
    save_json(LOG_FILE, log[:200])

def log_conversion(username, filename, pages, dpi, has_hidden):
    hist = load_json(HIST_FILE, [])
    hist.insert(0, {
        "ts":         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "username":   username,
        "filename":   filename,
        "pages":      pages,
        "dpi":        dpi,
        "has_hidden": has_hidden
    })
    save_json(HIST_FILE, hist[:500])

def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if "username" not in session: return redirect(url_for("login"))
        return f(*a, **kw)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a, **kw):
        if "username" not in session: return redirect(url_for("login"))
        if not load_users().get(session["username"], {}).get("is_admin"):
            return jsonify({"error": "Sin permisos"}), 403
        return f(*a, **kw)
    return d

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return redirect(url_for("tool") if "username" in session else url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session: return redirect(url_for("tool"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        users = load_users()
        user  = users.get(username)
        if user and check_password_hash(user["password"], password):
            session.permanent = True
            session["username"] = username
            session["name"]     = user.get("name", username)
            session["is_admin"] = user.get("is_admin", False)
            log_event("login_ok", username)
            return redirect(url_for("tool"))
        log_event("login_fail", username or "desconocido")
        error = "Usuario o contraseña incorrectos"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/tool")
@login_required
def tool():
    users = load_users()
    theme = users.get(session["username"], {}).get("theme", "light")
    return render_template("tool.html",
                           name=session.get("name", ""),
                           is_admin=session.get("is_admin", False),
                           username=session.get("username", ""),
                           theme=theme)

@app.route("/set-theme", methods=["POST"])
@login_required
def set_theme():
    data = request.get_json()
    theme = data.get("theme", "light")
    if theme not in ("light", "dark"): return jsonify({"ok": False}), 400
    users = load_users()
    if session["username"] in users:
        users[session["username"]]["theme"] = theme
        save_users(users)
    return jsonify({"ok": True})

# ── Admin API ─────────────────────────────────────────────────────────────────
@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_list_users():
    users = load_users()
    return jsonify([{"username": u, "name": d.get("name", u),
                     "is_admin": d.get("is_admin", False)}
                    for u, d in users.items()])

@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    data     = request.get_json()
    username = (data.get("username") or "").strip().lower()
    name     = (data.get("name") or "").strip()
    password = (data.get("password") or "").strip()
    is_admin = bool(data.get("is_admin", False))
    if not username or not password or not name:
        return jsonify({"error": "Todos los campos son requeridos"}), 400
    if len(password) < 8:
        return jsonify({"error": "Contraseña mínimo 8 caracteres"}), 400
    users = load_users()
    if username in users:
        return jsonify({"error": f"El usuario '{username}' ya existe"}), 400
    users[username] = {"name": name,
                       "password": generate_password_hash(password, method="pbkdf2:sha256:600000"),
                       "is_admin": is_admin}
    save_users(users)
    log_event("user_created", session["username"], detail=username)
    return jsonify({"ok": True})

@app.route("/admin/users/<username>", methods=["DELETE"])
@admin_required
def admin_delete_user(username):
    if username == session["username"]:
        return jsonify({"error": "No puedes eliminarte a ti mismo"}), 400
    users = load_users()
    if username not in users:
        return jsonify({"error": "Usuario no encontrado"}), 404
    del users[username]
    save_users(users)
    log_event("user_deleted", session["username"], detail=username)
    return jsonify({"ok": True})

@app.route("/admin/users/<username>/password", methods=["POST"])
@admin_required
def admin_change_password(username):
    data = request.get_json()
    password = (data.get("password") or "").strip()
    if len(password) < 8: return jsonify({"error": "Mínimo 8 caracteres"}), 400
    users = load_users()
    if username not in users: return jsonify({"error": "Usuario no encontrado"}), 404
    users[username]["password"] = generate_password_hash(password, method="pbkdf2:sha256:600000")
    save_users(users)
    return jsonify({"ok": True})

@app.route("/admin/log")
@admin_required
def admin_log():
    return jsonify(load_json(LOG_FILE, []))

@app.route("/admin/history")
@admin_required
def admin_history():
    return jsonify(load_json(HIST_FILE, []))

# ── PDF convert ───────────────────────────────────────────────────────────────
@app.route("/convert", methods=["POST"])
@login_required
def convert():
    if "pdf" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["pdf"]
    if not f.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Solo se aceptan archivos PDF"}), 400

    dpi         = max(72, min(300, int(request.form.get("dpi", 150))))
    hidden_mode = request.form.get("hidden_mode", "same")   # same | per_page
    hidden_text = request.form.get("hidden_text", "").strip()

    doc = fitz.open(stream=f.read(), filetype="pdf")
    total_pages = len(doc)

    # Build per-page text list
    if not hidden_text:
        page_texts = [""] * total_pages
    elif hidden_mode == "per_page":
        # User explicitly separated blocks with ---
        blocks = [t.strip() for t in hidden_text.split("---")]
        # If only one block provided, auto-split by paragraphs across pages
        if len(blocks) == 1:
            paragraphs = [p.strip() for p in hidden_text.split("\n\n") if p.strip()]
            if len(paragraphs) >= total_pages:
                # Distribute paragraphs evenly across pages
                per = max(1, len(paragraphs) // total_pages)
                blocks = [" ".join(paragraphs[i*per:(i+1)*per]) for i in range(total_pages)]
            else:
                # Repeat cycling through available paragraphs
                blocks = [paragraphs[i % len(paragraphs)] for i in range(total_pages)]
        page_texts = [blocks[i] if i < len(blocks) else "" for i in range(total_pages)]
    else:
        # same mode: same text on every page
        page_texts = [hidden_text] * total_pages

    out = io.BytesIO()
    c   = canvas.Canvas(out)
    mat = fitz.Matrix(dpi / 72.0, dpi / 72.0)

    for i, page in enumerate(doc):
        pix  = page.get_pixmap(matrix=mat, alpha=False)
        img  = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        pt_w = pix.width  * 72.0 / dpi
        pt_h = pix.height * 72.0 / dpi
        c.setPageSize((pt_w, pt_h))

        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=92)
        buf.seek(0)
        c.drawImage(ImageReader(buf), 0, 0, width=pt_w, height=pt_h)

        page_hidden = page_texts[i]

        if page_hidden:
            c.saveState()
            c.setFont("Helvetica", 8)
            to = c.beginText(10, pt_h - 10)
            to.setTextRenderMode(3)
            line = ""
            for word in page_hidden.split():
                test = (line + " " + word).strip()
                if c.stringWidth(test, "Helvetica", 8) < pt_w - 20:
                    line = test
                else:
                    to.textLine(line); line = word
            if line: to.textLine(line)
            c.drawText(to)
            c.restoreState()

        c.showPage()

    doc.close(); c.save(); out.seek(0)

    log_conversion(session["username"], f.filename, total_pages, dpi, bool(hidden_text))

    name = os.path.splitext(f.filename)[0]
    return send_file(out, mimetype="application/pdf",
                     as_attachment=True, download_name=f"{name}_redacted.pdf")

# ── PDF extract ───────────────────────────────────────────────────────────────
@app.route("/extract", methods=["POST"])
@login_required
def extract():
    if "pdf" not in request.files: return jsonify({"error": "No file"}), 400
    try:
        doc  = fitz.open(stream=request.files["pdf"].read(), filetype="pdf")
        text = ""
        for i, page in enumerate(doc):
            t = page.get_text().strip()
            if t: text += f"[Página {i+1}]\n{t}\n\n"
        doc.close()
        if not text:
            return jsonify({"text": "", "message": "Sin texto — el PDF ya es imagen pura"})
        return jsonify({"text": text.strip(), "chars": len(text)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── CLI ───────────────────────────────────────────────────────────────────────
@app.cli.command("create-user")
def create_user_cmd():
    import getpass
    username = input("Username: ").strip().lower()
    name     = input("Nombre: ").strip()
    password = getpass.getpass("Password: ")
    confirm  = getpass.getpass("Confirmar: ")
    if password != confirm: print("No coinciden."); return
    if len(password) < 8:  print("Mínimo 8 caracteres."); return
    users = load_users()
    users[username] = {"name": name,
                       "password": generate_password_hash(password, method="pbkdf2:sha256:600000"),
                       "is_admin": True}
    save_users(users)
    log_event("user_created", "cli", detail=username)
    print(f"✓ Admin '{username}' creado.")

if __name__ == "__main__":
    import webbrowser, threading
    if not os.path.exists(USERS_FILE) or not load_users():
        print("\n  ⚠  Sin usuarios. Crea uno con:  python -m flask --app app create-user\n")
    threading.Timer(1.2, lambda: webbrowser.open("http://localhost:7860")).start()
    print("  ✓ RedactPDF en http://localhost:7860\n")
    app.run(host="0.0.0.0", port=7860, debug=False)
