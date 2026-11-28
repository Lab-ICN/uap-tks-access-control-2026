# RobinTech — Operation Access Breach

Five **Hard** Linux access-control investigations with an ICN-inspired sky-blue/glass UI, dark/light toggle, and a simulated **read-only** forensic console. This is a standalone Flask application, **not** a CTFd theme or CTFd plugin. The reference visual design is [Lab-ICN/icn-ctfd-theme](https://github.com/Lab-ICN/icn-ctfd-theme) (Apache-2.0); this project uses independently authored CSS/HTML rather than copying their theme assets.

## Start

```bash
cp .env.example .env
# edit SECRET_KEY and FINAL_FLAG in .env
# e.g. python -c 'import secrets; print(secrets.token_hex(32))'
docker compose up --build -d
```

Open http://localhost:8080. Compose binds only to localhost by default; change port binding if deploying behind a reverse proxy. The SQLite progress database persists in a Docker volume and browser session identifies each player. Clearing cookies resets the player identity (not their old database row).

## Gameplay

- Five sequential cases; each wrong answer leaves the current case unchanged.
- Server validates answers and reveals `FINAL_FLAG` only after all five cases.
- Commands: `help`, `pwd`, `whoami`, `id [user]`, `ls [-l|-la|-ld] [path]`, `cat <file>`, `stat <path>`, `find <path> [-name pattern]`, `grep [-n|-i] <text> <file>`, `aa-status`, `sudo -l [-U user]`, `clear`.
- The terminal uses an in-memory fictional filesystem. **No user input is passed to a real shell**; filesystem and sudo rules are simulated and read-only.
- To customize cases, see `CASES` in `app.py`. `answers` are server-side only; the API does not expose them.

## Deployment notes

The app has no account registration, per-user authentication, rate limiting or scoreboard. For a real competitive event, add authentication and rate limiting, configure HTTPS and secure cookies, and use a secret `FINAL_FLAG`. The app is suitable for a classroom demonstration or isolated lab as shipped. AppArmor rules are *evidence*, not actual kernel-enforced AppArmor policies.
