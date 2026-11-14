#!/usr/bin/env bash
# Nullvault: instalação inicial por usuário, sem alterar cofres existentes.
set -Eeuo pipefail
umask 077
fail() { printf 'Erro: %s\n' "$*" >&2; exit 1; }
[[ "$(uname -s)" == Linux ]] || fail 'Execute em Linux.'
command -v python3 >/dev/null || fail 'Python 3 não encontrado.'
python3 -c 'import sys; sys.exit(sys.version_info < (3,10))' || fail 'É necessário Python 3.10+.'
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE="$SCRIPT_DIR/Nullvouts.py"
[[ -f "$SOURCE" ]] || fail 'Coloque install.sh junto de Nullvouts.py.'
APP_DIR="$HOME/.local/share/nullvault"
BIN_DIR="$HOME/.local/bin"
LAUNCHER="$BIN_DIR/nullvault"
# Não modifica instalações anteriores ou dados de usuário.
[[ ! -e "$APP_DIR" && ! -L "$APP_DIR" ]] || fail "Já existe $APP_DIR; instalação cancelada para proteger os dados."
[[ ! -e "$LAUNCHER" && ! -L "$LAUNCHER" ]] || fail "Já existe $LAUNCHER; instalação cancelada para não sobrescrever o comando."
python3 -c 'import tkinter' || fail 'Tkinter ausente. No Debian: sudo apt install python3-tk'
python3 -m venv --help >/dev/null 2>&1 || fail 'Instale python3-venv.'
mkdir -p "$BIN_DIR"
mkdir -m 700 "$APP_DIR"
trap 'printf "Instalação interrompida. Confira %s antes de tentar novamente.\n" "$APP_DIR" >&2' ERR
cp -- "$SOURCE" "$APP_DIR/Nullvouts.py"
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/python" -m pip install --disable-pip-version-check 'cryptography'
cat > "$LAUNCHER" <<LAUNCH
#!/usr/bin/env bash
exec "$APP_DIR/.venv/bin/python" "$APP_DIR/Nullvouts.py" "\$@"
LAUNCH
chmod 700 "$LAUNCHER"
printf 'Instalado. Execute: %s\n' "$LAUNCHER"
printf 'Interface gráfica requer uma sessão gráfica Linux ou WSLg.\n'
