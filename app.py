import hmac
import os
import posixpath
import re
import secrets
import shlex
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, render_template, request, session


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "").lower() in {"1", "true", "yes"},
)
DB = os.environ.get("DB_PATH", "/data/progress.sqlite3")
FLAG = os.environ.get("FINAL_FLAG", "CTF{robintech_access_audit_complete}")

# A virtual, read-only Linux filesystem. Every entry is fictional evidence.
def file(body, mode='-rw-r-----', owner='root', group='security'):
    return dict(body=body,mode=mode,owner=owner,group=group)
def directory(mode='drwxr-x---',owner='root',group='security'):
    return dict(body=None,mode=mode,owner=owner,group=group)

def base():
    return {'/':directory('drwxr-xr-x'),'/home':directory('drwxr-xr-x'),'/home/analyst':directory('drwxr-xr-x','analyst','security'),'/srv':directory('drwxr-xr-x'),'/etc':directory('drwxr-xr-x'),'/var':directory('drwxr-xr-x'),'/var/log':directory('drwxr-xr-x'),'/opt':directory('drwxr-xr-x'),'/opt/robintech':directory('drwxr-xr-x'),'/etc/robintech':directory(),'/var/log/robintech':directory()}

def make(extra):
    d=base();d.update(extra);return d

CASES=[
 dict(
     title='The Phantom Reader',
     category='DAC',
     story=(
         'Ladesh tampaknya telah membaca deployment key rahasia tanpa mempunyai hak aksesnya. '
         'Laporan SOC menyalahkan world-readable permissions, tetapi bukti awal '
         'tidak mendukung teori tersebut. Rekonstruksi jalur akses yang sebenarnya.'
     ),
     question=(
         'Group mana yang memberikan akses kepada pembaca tidak sah, dan octal mode '
         'apa yang harus digunakan key jika HANYA pemiliknya yang boleh read/write? '
         'Format: group|mode'
     ),
     hint=(
         'Mulai dari incident index. Gunakan cat untuk membaca daftar user, lalu '
         'bandingkan owner, group, dan permission dari key dengan hasil identitas '
         'tersangka.'
     ),
     answers=['deploy|600'],
     fs=make({
         '/home/analyst/README.txt': file(
             'Incident 01: start with /var/log/robintech/incident-index.txt',
             '-rw-r--r--'
         ),
         '/var/log/robintech/incident-index.txt': file(
             'INC-041: access to /srv/robintech/releases/deploy.key by user ladesh. '
             'Related: /etc/robintech/users.txt, /srv/robintech/releases/'
         ),
         '/etc/robintech/users.txt': file(
             'dev01: groups=devteam\n'
             'ladesh: groups=contractors,deploy\n'
             'auditor: groups=audit'
         ),
         '/srv/robintech': directory(),
         '/srv/robintech/releases': directory('drwxr-x---', 'root', 'deploy'),
         '/srv/robintech/releases/deploy.key': file(
             'REDACTED - deployment signing material',
             '-rw-rw----',
             'root',
             'deploy'
         ),
         '/var/log/robintech/access.log': file(
             '11:32 ladesh berhasil membuka /srv/robintech/releases/deploy.key'
         )
     }),
     users={
         'ladesh': ['contractors', 'deploy'],
         'dev01': ['devteam'],
         'auditor': ['audit']
     }
 ),
 dict(
     title='The Complain Mode Decoy',
     category='MAC',
     story=(
         'Sebuah protected service mengubah authentication log. Tim mengira AppArmor '
         'sedang enforcing policy karena ada deny rule. Hubungkan profile status, '
         'policy, dan audit events untuk menemukan kegagalan sebenarnya.'
     ),
     question=(
         'Berikan AppArmor profile path, mode saat ini yang mengizinkan violation, '
         'dan mode yang harus digunakan agar violation diblokir. '
         'Format: profile|current|required'
     ),
     hint=(
         'Deny rule bukan bukti bahwa policy sedang aktif. Bandingkan status profile '
         'dengan audit event untuk membedakan complain dan enforce.'
     ),
     answers=['/usr/local/bin/logsync|complain|enforce'],
     fs=make({
         '/home/analyst/README.txt': file(
             'INC-063: logsync wrote /var/log/auth.log. '
             'Read /etc/robintech/services.txt and audit artifacts.'
         ),
         '/etc/robintech/services.txt': file(
             'auth-log writer: /usr/local/bin/logsync\n'
             'Expected security: deny write to /var/log/**'
         ),
         '/etc/apparmor.d': directory(),
         '/etc/apparmor.d/usr.local.bin.logsync': file(
             '/usr/local/bin/logsync {\n'
             '  /var/log/** r,\n'
             '  deny /var/log/** w,\n'
             '  /tmp/** rw,\n'
             '}'
         ),
         '/var/log/robintech/apparmor.log': file(
             'apparmor="ALLOWED" operation="open" '
             'profile="/usr/local/bin/logsync" '
             'name="/var/log/auth.log" requested_mask="w"'
         ),
         '/etc/robintech/apparmor-status.txt': file(
             'apparmor module is loaded\n'
             '/usr/local/bin/logsync (complain)\n'
             '/usr/bin/backup-agent (enforce)'
         )
     }),
     users={}
 ),
 dict(title='The Hidden Privilege',category='RBAC',
story=(
    "Setelah berhasil menelusuri beberapa aktivitas mencurigakan "
    "Ladesh, tim keamanan RobinTech menemukan adanya perubahan "
    "hak akses pada salah satu akun internal. Akun tersebut "
    "seharusnya hanya digunakan untuk audit dan membaca system "
    "logs, tetapi diduga memiliki administrative privileges. "
    "Investigasi user, group membership, dan konfigurasi sudoers "
    "untuk menemukan sumber kesalahan akses."
),
question=(
    "Identifikasi username yang memiliki hak akses berlebihan "
    "dan group yang menyebabkan user tersebut memperoleh "
    "administrative privileges. "
    "Format: username|group"
),
hint=(
    "Periksa role policy, lalu gunakan id <user> untuk membandingkan "
    "group membership. Gunakan sudo -l untuk memeriksa rule yang "
    "memberikan administrative privileges."
),
answers=["audit01|sudo"],

fs=make({
    '/home/analyst/README.txt': file(
        'INC-074: Tim keamanan RobinTech mendeteksi perubahan hak akses '
        'mencurigakan pada akun internal setelah aktivitas Ladesh.\n'
        'Mulai investigasi dari /etc/robintech/role-policy.txt.'
    ),

    '/etc/robintech/role-policy.txt': file(
        '[ROBINTECH ACCESS POLICY]\n'
        'admin: unrestricted administrative access\n'
        'developer: development tools only\n'
        'auditor: read-only access to system logs\n'
        'Auditor tidak diperbolehkan memiliki unrestricted sudo access.'
    ),

    '/etc/robintech/users.txt': file(
        'admin01 groups: admin\n'
        'dev01 groups: developer\n'
        'audit01 groups: auditor, sudo'
    ),

    '/etc/group': file(
        'admin:x:1001:admin01\n'
        'developer:x:1002:dev01\n'
        'auditor:x:1003:audit01\n'
        'sudo:x:27:audit01'
    ),

    '/etc/sudoers.d': directory('drwxr-xr-x'),

    '/etc/sudoers.d/robintech-roles': file(
        '%admin ALL=(ALL:ALL) ALL\n'
        '%developer ALL=(root) /usr/bin/git\n'
        '%auditor ALL=(root) NOPASSWD: /bin/cat /var/log/syslog, '
        '/bin/cat /var/log/auth.log\n'
        '%sudo ALL=(ALL:ALL) ALL'
    ),

    '/var/log/robintech/sudo.log': file(
        'audit01 : COMMAND=/usr/bin/apt update ; USER=root\n'
        'audit01 : COMMAND=/usr/bin/systemctl restart nginx ; USER=root'
    )
}),users={
    'admin01': ['admin'],
    'dev01': ['developer'],
    'audit01': ['auditor', 'sudo']
}),
]

def conn():
    Path(DB).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB, timeout=10)
    db.execute(
        "CREATE TABLE IF NOT EXISTS players "
        "(id TEXT PRIMARY KEY, progress INTEGER NOT NULL DEFAULT 0)"
    )
    return db

def player():
    pid = session.get("pid")
    if not pid:
        pid = secrets.token_urlsafe(24)
        session["pid"] = pid
    with conn() as db:
        db.execute("INSERT OR IGNORE INTO players (id,progress) VALUES (?,0)", (pid,))
        progress = db.execute(
            "SELECT progress FROM players WHERE id=?", (pid,)
        ).fetchone()[0]
    return pid, progress

def csrf_ok():
    return hmac.compare_digest(str(request.headers.get('X-CSRF-Token','')),str(session.get('csrf','')))

def render_listing(fs,path,long=False,all_files=False):
    if path not in fs:return f'ls: cannot access {path}: No such file or directory'
    if fs[path]['body'] is not None:
        paths=[path]
    else:
        paths=[p for p in fs if posixpath.dirname(p)==path and (all_files or not posixpath.basename(p).startswith('.'))]
        paths.sort()
    if not paths:return '(empty directory)'
    return '\n'.join((f"{fs[p]['mode']} 1 {fs[p]['owner']} {fs[p]['group']} 1024 Nov 23 01:00 {posixpath.basename(p) or '/'}" if long else posixpath.basename(p) or '/') for p in paths)

def terminal_output(case,raw):
    fs=case['fs'];cwd='/home/analyst'
    if not raw or len(raw)>240 or any(x in raw for x in '\n\r\x00;|&`$<>(){}\\'):
        return 'Unsupported syntax. This is a read-only forensic simulator.'
    try: args=shlex.split(raw)
    except ValueError:return 'Invalid quoting.'
    if not args:return ''
    cmd=args[0]
    if cmd=='help':return 'Read-only commands: help, pwd, whoami, id [user], ls [-la|-l|-ld] [path], cat <file>, stat <path>, find <path> [-name pattern], grep [-n|-i] <text> <file>, aa-status, sudo -l [-U user], clear\nTip: begin with pwd, ls, and README.txt. Paths may be relative to /home/analyst.'
    if cmd=='pwd' and len(args)==1:return cwd
    if cmd=='whoami' and len(args)==1:return 'analyst'
    if cmd=='id' and len(args)<=2:
        user=args[1] if len(args)==2 else 'analyst'
        groups=case['users'].get(user,['security'] if user=='analyst' else [])
        return f'uid=1001({user}) groups='+','.join(groups) if groups else f'id: {user}: no such user'
    if cmd=='clear' and len(args)==1:return ''
    if cmd=='aa-status' and len(args)==1:
        return fs.get('/etc/robintech/apparmor-status.txt',{}).get('body') or 'apparmor module is loaded; no profile status in this case'
    if cmd=='sudo' and args[1:2]==['-l']:
        user=args[3] if len(args)==4 and args[2]=='-U' else 'analyst' if len(args)==2 else None
        if user is None:return 'usage: sudo -l [-U user]'
        groups=case['users'].get(user,[])
        rules=[f['body'] for p,f in fs.items() if p.startswith('/etc/sudoers.d/') and f['body'] and any('%'+g+' ' in f['body'] for g in groups)]
        return '\n'.join(rules) if rules else f'User {user} has no matching sudo policy in this case.'
    def path_of(p):return posixpath.normpath(p if p.startswith('/') else posixpath.join(cwd,p))
    if cmd=='ls':
        flags='';paths=[]
        for a in args[1:]:
            if a.startswith('-'):flags+=a[1:]
            else:paths.append(path_of(a))
        if any(c not in 'lad' for c in flags):return 'ls: unsupported option'
        paths=paths or [cwd]
        return '\n'.join((p+':\n' if len(paths)>1 else '')+ (f"{fs[p]['mode']} 1 {fs[p]['owner']} {fs[p]['group']} 1024 Nov 23 01:00 {p}" if 'd' in flags and p in fs else render_listing(fs,p,'l' in flags,'a' in flags)) for p in paths)
    if cmd in ('cat','stat') and len(args)==2:
        p=path_of(args[1]);node=fs.get(p)
        if not node:return f'{cmd}: {p}: No such file or directory'
        if cmd=='cat':return node['body'] if node['body'] is not None else f'cat: {p}: Is a directory'
        perm=node['mode'];bits=lambda s:sum(v for c,v in [('r',4),('w',2),('x',1)] if c in s)
        octal=''.join(str(bits(perm[i:i+3])) for i in (1,4,7))
        return f'File: {p}\nAccess: ({octal}/{perm})\nUid: {node["owner"]}\nGid: {node["group"]}'
    if cmd=='find' and len(args) in (2,4):
        root=path_of(args[1]);pattern=args[3] if len(args)==4 and args[2]=='-name' else None
        if len(args)==4 and pattern is None:return 'usage: find <path> [-name pattern]'
        if root not in fs:return f'find: {root}: No such file or directory'
        import fnmatch
        paths=[p for p in fs if (p==root or p.startswith(root.rstrip('/')+'/')) and (pattern is None or fnmatch.fnmatch(posixpath.basename(p),pattern))]
        return '\n'.join(sorted(paths)[:80]) or '(no matches)'
    if cmd=='grep' and len(args) in (3,4):
        opts=args[1] if len(args)==4 else ''
        if opts not in ('','-i','-n'):return 'usage: grep [-n|-i] <text> <file>'
        needle=args[-2];p=path_of(args[-1]);node=fs.get(p)
        if not node or node['body'] is None:return f'grep: {p}: No such file'
        out=[]
        for i,line in enumerate(node['body'].splitlines(),1):
            if (needle.lower() in line.lower() if opts=='-i' else needle in line):out.append((str(i)+':' if opts=='-n' else '')+line)
        return '\n'.join(out) or '(no matches)'
    return f'{cmd}: unsupported command. Type help for available commands.'

@app.get('/')
def home():
    player()
    if 'csrf' not in session:session['csrf']=secrets.token_urlsafe(24)
    return render_template('index.html',csrf=session['csrf'])
@app.get('/api/state')
def state():
    _,progress=player()
    if progress>=len(CASES):return jsonify(done=True,progress=progress,total=len(CASES),flag=FLAG)
    c=CASES[progress]
    return jsonify(done=False,progress=progress,total=len(CASES),challenge={k:c[k] for k in ('title','category','story','question','hint')})
@app.post('/api/terminal')
def terminal():
    if not csrf_ok():return jsonify(error='CSRF invalid'),403
    _,progress=player()
    if progress>=len(CASES):return jsonify(output='All incidents resolved.')
    raw=(request.get_json(silent=True) or {}).get('command','')
    if not isinstance(raw,str):return jsonify(error='Invalid command'),400
    if raw.strip()=='clear':return jsonify(clear=True,output='')
    return jsonify(output=terminal_output(CASES[progress],raw.strip()))
@app.post('/api/answer')
def answer():
    if not csrf_ok():
        return jsonify(error="CSRF invalid"), 403

    pid, progress = player()
    if progress >= len(CASES):
        return jsonify(correct=True, done=True)

    guess = (request.get_json(silent=True) or {}).get("answer", "")
    if not isinstance(guess, str):
        return jsonify(error="Invalid answer"), 400

    if len(guess) > 300:
        return jsonify(error="Answer is too long"), 400

    def norm(value):
        return re.sub(r"\s+", "", value.strip()).lower()
    valid = any(
        hmac.compare_digest(norm(guess), norm(answer))
        for answer in CASES[progress]["answers"]
    )
    if not valid:
        return jsonify(
            correct=False,
            message="Belum tepat. Incident ini masih terbuka—investigasi lebih lanjut lalu coba lagi.",
            progress=progress,
        )

    with conn() as db:
        db.execute(
            "UPDATE players SET progress=? WHERE id=? AND progress=?",
            (progress + 1, pid, progress),
        )
    return jsonify(
        correct=True,
        done=progress + 1 == len(CASES),
        message="Evidence terverifikasi. Incident berikutnya terbuka.",
    )
@app.get('/health')
def health():return 'ok'
if __name__=='__main__':app.run(host='0.0.0.0',port=8080)
