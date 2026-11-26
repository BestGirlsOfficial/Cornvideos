import os, sqlite3, secrets, uuid
from datetime import date, timedelta
from functools import wraps
from flask import (Flask, g, request, session, redirect, url_for, render_template,
                   flash, abort, send_from_directory)
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("DATA_DIR", os.path.join(BASE, "data"))
UPLOADS = os.path.join(DATA, "uploads")
os.makedirs(UPLOADS, exist_ok=True)

def secret_key():
    p = os.path.join(DATA, "secret.key")
    if not os.path.exists(p):
        with open(p, "w") as f: f.write(secrets.token_hex(32))
        os.chmod(p, 0o600)
    return open(p).read()

app = Flask(__name__)
app.config.update(SECRET_KEY=secret_key(), MAX_CONTENT_LENGTH=500 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT UNIQUE COLLATE NOCASE NOT NULL,
  pw TEXT NOT NULL, birth TEXT NOT NULL, is_admin INTEGER DEFAULT 0, banned INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS videos(id INTEGER PRIMARY KEY, title TEXT NOT NULL, descr TEXT DEFAULT '',
  file TEXT NOT NULL, status TEXT NOT NULL, submitter INTEGER REFERENCES users(id),
  created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS likes(user INTEGER, video INTEGER, PRIMARY KEY(user, video));
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, user INTEGER, video INTEGER, body TEXT,
  created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS follows(follower INTEGER, followed INTEGER, PRIMARY KEY(follower, followed));
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, user INTEGER, video INTEGER, reason TEXT,
  created TEXT DEFAULT CURRENT_TIMESTAMP);
"""

def db():
    if "db" not in g:
        g.db = sqlite3.connect(os.path.join(DATA, "site.db"))
        g.db.row_factory = sqlite3.Row
    return g.db

def q(sql, *args): return db().execute(sql, args).fetchall()
def one(sql, *args): return db().execute(sql, args).fetchone()
def run(sql, *args):
    cur = db().execute(sql, args); db().commit(); return cur

@app.teardown_appcontext
def close(_):
    if "db" in g: g.db.close()

with sqlite3.connect(os.path.join(DATA, "site.db")) as c:
    c.executescript(SCHEMA)

@app.before_request
def guard():
    g.user = one("SELECT * FROM users WHERE id=? AND banned=0", session.get("uid"))
    if request.method == "POST":
        token = session.get("csrf", "")
        if not token or not secrets.compare_digest(token.encode(), request.form.get("csrf", "").encode()):
            abort(400)

@app.context_processor
def inject():
    if "csrf" not in session: session["csrf"] = secrets.token_hex(16)
    return {"user": g.get("user"), "csrf": session["csrf"]}

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "same-origin"
    r.headers["RTA"] = "RTA-5042-1996-1400-1577-RTA"  # felnőtt tartalom jelölése szűrőknek
    return r

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user: return redirect(url_for("login"))
        return f(*a, **k)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user or not g.user["is_admin"]: abort(403)
        return f(*a, **k)
    return w

def video_or_404(vid, public=True):
    v = one("SELECT * FROM videos WHERE id=?", vid)
    if not v or (public and v["status"] != "published" and not g.user["is_admin"]): abort(404)
    return v

def adult(birth):
    t = date.today()
    return t.year - birth.year - ((t.month, t.day) < (birth.month, birth.day)) >= 18

@app.route("/regisztracio", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name, pw = request.form.get("name", "").strip(), request.form.get("pw", "")
        try: birth = date.fromisoformat(request.form.get("birth", ""))
        except ValueError: birth = None
        if not (3 <= len(name) <= 30) or len(pw) < 10:
            flash("A név 3–30, a jelszó legalább 10 karakter legyen.")
        elif not birth or not adult(birth) or not request.form.get("terms"):
            flash("Az oldal csak 18 éven felülieknek érhető el, és el kell fogadni a szabályokat.")
        else:
            try:
                uid = run("INSERT INTO users(name,pw,birth) VALUES(?,?,?)",
                          name, generate_password_hash(pw), birth.isoformat()).lastrowid
            except sqlite3.IntegrityError:
                flash("Ez a név már foglalt.")
            else:
                session.clear(); session["uid"] = uid
                return redirect(url_for("feed"))
    return render_template("auth.html", register=True)

@app.route("/belepes", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = one("SELECT * FROM users WHERE name=?", request.form.get("name", "").strip())
        if u and not u["banned"] and check_password_hash(u["pw"], request.form.get("pw", "")):
            session.clear(); session["uid"] = u["id"]
            return redirect(url_for("feed"))
        flash("Hibás név vagy jelszó.")
    return render_template("auth.html", register=False)

@app.post("/kilepes")
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/szabalyzat")
def rules(): return render_template("rules.html")

LIST = """SELECT v.*, (SELECT COUNT(*) FROM likes WHERE video=v.id) likes,
 (SELECT COUNT(*) FROM comments WHERE video=v.id) ncomments FROM videos v WHERE status='published'"""

@app.route("/")
@login_required
def feed():
    return render_template("feed.html", title="Legfrissebb videók", videos=q(LIST + " ORDER BY v.id DESC"))

@app.route("/video/<int:vid>")
@login_required
def watch(vid):
    v = video_or_404(vid)
    return render_template("watch.html", v=v,
        likes=one("SELECT COUNT(*) n FROM likes WHERE video=?", vid)["n"],
        liked=one("SELECT 1 FROM likes WHERE video=? AND user=?", vid, g.user["id"]),
        comments=q("SELECT c.*, u.name FROM comments c JOIN users u ON u.id=c.user WHERE video=? ORDER BY c.id", vid),
        submitter=one("SELECT * FROM users WHERE id=?", v["submitter"]))

@app.route("/media/<int:vid>")
@login_required
def media(vid):
    v = video_or_404(vid)  # a függő videót csak az admin érheti el
    r = send_from_directory(UPLOADS, v["file"], conditional=True)
    r.headers["Cache-Control"] = "private, no-store"
    return r

@app.post("/video/<int:vid>/like")
@login_required
def like(vid):
    video_or_404(vid)
    if not run("DELETE FROM likes WHERE user=? AND video=?", g.user["id"], vid).rowcount:
        run("INSERT INTO likes VALUES(?,?)", g.user["id"], vid)
    return redirect(url_for("watch", vid=vid))

@app.post("/video/<int:vid>/komment")
@login_required
def comment(vid):
    video_or_404(vid)
    body = request.form.get("body", "").strip()[:1000]
    if body: run("INSERT INTO comments(user,video,body) VALUES(?,?,?)", g.user["id"], vid, body)
    return redirect(url_for("watch", vid=vid))

@app.post("/komment/<int:cid>/torles")
@login_required
def delete_comment(cid):
    c = one("SELECT * FROM comments WHERE id=?", cid) or abort(404)
    if c["user"] != g.user["id"] and not g.user["is_admin"]: abort(403)
    run("DELETE FROM comments WHERE id=?", cid)
    return redirect(url_for("watch", vid=c["video"]))

@app.post("/video/<int:vid>/bejelentes")
@login_required
def report(vid):
    video_or_404(vid)
    reason = request.form.get("reason")
    if reason not in ("consent", "minor", "other"): abort(400)
    run("INSERT INTO reports(user,video,reason) VALUES(?,?,?)", g.user["id"], vid, reason)
    if reason != "other":  # súlyos bejelentés: azonnal lekerül az átnézésig
        run("UPDATE videos SET status='hidden' WHERE id=?", vid)
    flash("Köszönjük, a bejelentést az admin megkapta.")
    return redirect(url_for("feed"))

@app.route("/profil/<int:uid>")
@login_required
def profile(uid):
    p = one("SELECT * FROM users WHERE id=?", uid) or abort(404)
    return render_template("profile.html", p=p,
        followers=one("SELECT COUNT(*) n FROM follows WHERE followed=?", uid)["n"],
        following=one("SELECT 1 FROM follows WHERE follower=? AND followed=?", g.user["id"], uid),
        videos=q(LIST + " AND v.submitter=? ORDER BY v.id DESC", uid),
        mine=q("SELECT * FROM videos WHERE submitter=? ORDER BY id DESC", uid) if uid == g.user["id"] else [])

@app.post("/profil/<int:uid>/kovetes")
@login_required
def follow(uid):
    one("SELECT 1 FROM users WHERE id=?", uid) or abort(404)
    if uid != g.user["id"] and not run("DELETE FROM follows WHERE follower=? AND followed=?", g.user["id"], uid).rowcount:
        run("INSERT INTO follows VALUES(?,?)", g.user["id"], uid)
    return redirect(url_for("profile", uid=uid))

@app.route("/kovetett")
@login_required
def followed():
    return render_template("feed.html", title="Követett beküldők videói", videos=q(
        LIST + " AND v.submitter IN (SELECT followed FROM follows WHERE follower=?) ORDER BY v.id DESC", g.user["id"]))

def video_type(head):
    if head[4:8] == b"ftyp": return ".mp4"
    if head[:4] == b"\x1a\x45\xdf\xa3": return ".webm"

@app.route("/feltoltes", methods=["GET", "POST"])
@login_required
def upload():
    """Felhasználónál beküldés (függőben), adminnál is először függő: közzététel az igazolás után."""
    if request.method == "POST":
        f, title = request.files.get("file"), request.form.get("title", "").strip()[:120]
        head = f.stream.read(12) if f else b""
        ext = video_type(head)
        if not title or not ext:
            flash("Adj címet, és MP4 vagy WebM videót válassz.")
        elif not (request.form.get("age_ok") and request.form.get("consent_ok")):
            flash("Mindkét nyilatkozat kötelező.")
        else:
            f.stream.seek(0)
            name = uuid.uuid4().hex + ext
            f.save(os.path.join(UPLOADS, name))
            run("INSERT INTO videos(title,descr,file,status,submitter) VALUES(?,?,?,'pending',?)",
                title, request.form.get("descr", "").strip()[:2000], name, g.user["id"])
            flash("Beérkezett. A videó az admin jóváhagyásáig nem látható.")
            return redirect(url_for("admin" if g.user["is_admin"] else "feed"))
    return render_template("upload.html")

@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html",
        videos=q("""SELECT v.*, u.name, (SELECT group_concat(reason, ', ') FROM reports WHERE video=v.id) reports
                    FROM videos v JOIN users u ON u.id=v.submitter
                    ORDER BY (reports IS NULL), (status='published'), v.id DESC"""),
        users=q("SELECT * FROM users WHERE is_admin=0 ORDER BY name"))

@app.route("/admin/video/<int:vid>", methods=["GET", "POST"])
@admin_required
def edit(vid):
    v = video_or_404(vid, public=False)
    if request.method == "POST":
        action = request.form.get("action")
        if action == "delete":
            run("DELETE FROM videos WHERE id=?", vid)
            for t in ("likes", "comments", "reports"):
                run(f"DELETE FROM {t} WHERE video=?", vid)
            try: os.remove(os.path.join(UPLOADS, v["file"]))
            except FileNotFoundError: pass
            return redirect(url_for("admin"))
        status = {"publish": "published", "hide": "hidden"}.get(action, v["status"])
        if action == "publish" and not request.form.get("verified"):
            flash("Közzététel előtt igazold, hogy ellenőrizted az életkort és a hozzájárulást.")
        else:
            run("UPDATE videos SET title=?, descr=?, status=? WHERE id=?",
                request.form.get("title", "").strip()[:120] or v["title"],
                request.form.get("descr", "").strip()[:2000], status, vid)
            if action == "publish": run("DELETE FROM reports WHERE video=?", vid)
            flash("Mentve.")
            return redirect(url_for("admin"))
    return render_template("edit.html", v=v)

@app.post("/admin/tiltas/<int:uid>")
@admin_required
def ban(uid):
    run("UPDATE users SET banned=1-banned WHERE id=? AND is_admin=0", uid)
    return redirect(url_for("admin"))

@app.cli.command("admin")
def make_admin():
    """Admin fiók létrehozása: flask --app app admin"""
    import getpass
    name, pw = input("Admin név: ").strip(), getpass.getpass("Jelszó (min. 10): ")
    if not name or len(pw) < 10: raise SystemExit("Túl rövid.")
    run("INSERT INTO users(name,pw,birth,is_admin) VALUES(?,?,'1970-01-01',1)", name, generate_password_hash(pw))
    print("Kész.")

if __name__ == "__main__":
    app.run()
