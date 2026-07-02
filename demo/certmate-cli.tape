# CertMate CLI — full SSL certificate lifecycle from the terminal.
# Recorded with VHS (https://github.com/charmbracelet/vhs):  vhs demo/certmate-cli.tape
# The issuance is REAL: DNS-01 via Cloudflare against Let's Encrypt (staging).
Output "demo/certmate-cli.gif"
Output "demo/certmate-cli.mp4"

Set Shell bash
Set FontSize 18
Set Width 1240
Set Height 760
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 32ms
Set Framerate 18

# --- hidden setup: activate a prepared venv, point the CLI at a CertMate ---
# (deps are pre-installed; only certmate-cli + certmate-sdk install on-camera,
#  so the visible `pip install` is real yet fast.)
Hide
Type "export VIRTUAL_ENV_DISABLE_PROMPT=1" Enter
Type "source /tmp/certmate-demo-rec/bin/activate" Enter
Sleep 700ms
Type "export CERTMATE_URL=http://localhost:18899" Enter
Type "PS1='\[\e[38;5;141m\]$\[\e[0m\] '" Enter
Type "clear" Enter
Sleep 700ms
Show

# --- it's a real package: one pip install away ---
Type "# CertMate — the full SSL certificate lifecycle, from your terminal" Enter
Sleep 900ms
Type "pip install certmate-cli 2>&1 | tail -n1" Enter
Sleep 4s

# --- point it at your CertMate ---
Type "certmate health" Enter
Sleep 2400ms

# --- issue a REAL certificate over DNS-01, and wait for it ---
Type "# issue a real cert over DNS-01 (Cloudflare) and block until it is live" Enter
Sleep 900ms
Type "certmate cert create demo.certmate.org --dns cloudflare --wait" Enter
Sleep 30s

# --- it's really there ---
Type "certmate cert ls" Enter
Sleep 2400ms
Type "certmate cert info demo.certmate.org" Enter
Sleep 2800ms

# --- every action is written to a tamper-evident audit chain ---
Type "# every lifecycle action lands in a tamper-evident, signed audit chain" Enter
Sleep 900ms
Type "certmate audit verify" Enter
Sleep 2600ms
Sleep 1200ms
