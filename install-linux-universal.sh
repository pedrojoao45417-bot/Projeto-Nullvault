#!/usr/bin/env bash
# Instalador do Nullvault para Linux (por usuário, sem sudo).
# Uso: bash install-linux-universal.sh
#   ou: bash install-linux-universal.sh --local /caminho/para/NuRoots.py
set -Eeuo pipefail
umask 077

erro() { printf 'Erro: %s\n' "$*" >&2; exit 1; }
aviso() { printf 'Aviso: %s\n' "$*" >&2; }
info() { printf '[Nullvault] %s\n' "$*"; }

[[ "$(uname -s)" == 'Linux' ]] || erro 'Este instalador é destinado ao Linux.'
[[ -n "${HOME:-}" && -d "$HOME" ]] || erro 'Pasta HOME inválida.'
command -v python3 >/dev/null 2>&1 || erro 'Instale o Python 3.10 ou superior.'
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || erro 'O Nullvault exige Python 3.10 ou superior.'

REPOSITORIO='https://github.com/JotaCyberKiK/Projeto-Nullvault.git'
PASTA_BASE="$HOME/.local/opt"
DESTINO="$PASTA_BASE/nullvault"
PASTA_BIN="$HOME/.local/bin"
ATALHO="$PASTA_BIN/nullvault"

# Não substitui programas nem cofres de uma instalação existente.
[[ ! -e "$DESTINO" && ! -L "$DESTINO" ]] \
  || erro "A pasta $DESTINO já existe. Instalação cancelada para preservar dados."
[[ ! -e "$ATALHO" && ! -L "$ATALHO" ]] \
  || erro "O comando $ATALHO já existe. Instalação cancelada."

MODO="${1:---github}"
case "$MODO" in
  --github)
    [[ $# -eq 0 || $# -eq 1 ]] || erro 'Uso: bash install-linux-universal.sh [--github]'
    command -v git >/dev/null 2>&1 || erro 'Instale o Git para baixar o projeto do GitHub.'
    ;;
  --local)
    [[ $# -eq 2 && -f "$2" && "$2" == *.py ]] \
      || erro 'Uso: bash install-linux-universal.sh --local /caminho/programa.py'
    ;;
  *) erro 'Modo inválido. Use --github ou --local /caminho/programa.py.' ;;
esac

mkdir -p -- "$PASTA_BASE" "$PASTA_BIN"
TEMP="$(mktemp -d "$PASTA_BASE/.nullvault-instalacao.XXXXXXXX")" \
  || erro 'Não foi possível criar pasta temporária.'
trap 'rm -rf -- "$TEMP"' EXIT
FONTE="$TEMP/app"

if [[ "$MODO" == --github ]]; then
  info 'Baixando o código do GitHub...'
  git clone --depth 1 "$REPOSITORIO" "$FONTE" \
    || erro 'Não foi possível clonar o repositório. Se ele for privado, autentique o Git antes.'

  if [[ -f "$FONTE/Nullvouts.py" ]]; then
    PRINCIPAL='Nullvouts.py'
  elif [[ -f "$FONTE/NuRoots.py" ]]; then
    PRINCIPAL='NuRoots.py'
  else
    erro 'Não encontrei Nullvouts.py nem NuRoots.py na raiz do repositório.'
  fi
else
  mkdir -p -- "$FONTE"
  PRINCIPAL="$(basename -- "$2")"
  cp -- "$2" "$FONTE/$PRINCIPAL"
  info 'Usando o arquivo Python local.'
fi

if ! python3 -c 'import tkinter' >/dev/null 2>&1; then
  aviso 'Tkinter não foi encontrado. Instale o pacote correspondente à sua distribuição para usar a interface gráfica.'
fi

info 'Criando ambiente virtual isolado...'
python3 -m venv "$FONTE/.venv" \
  || erro 'Falha ao criar venv. Instale o módulo venv do Python na sua distribuição.'

info 'Instalando dependências Python...'
if [[ -f "$FONTE/requirements.txt" ]]; then
  "$FONTE/.venv/bin/python" -m pip install -r "$FONTE/requirements.txt" \
    || erro 'Falha ao instalar requirements.txt.'
else
  "$FONTE/.venv/bin/python" -m pip install cryptography \
    || erro 'Falha ao instalar a biblioteca cryptography.'
fi

# O programa trabalha a partir da própria pasta de instalação.
# Nunca limpe ou substitua essa pasta sem inspecionar cofre.dat e cofre.bak.
printf -v DESTINO_ESC '%q' "$DESTINO"
printf -v PRINCIPAL_ESC '%q' "$PRINCIPAL"
cat > "$TEMP/nullvault" <<EOF_LAUNCHER
#!/usr/bin/env bash
set -e
cd $DESTINO_ESC
exec $DESTINO_ESC/.venv/bin/python $DESTINO_ESC/$PRINCIPAL_ESC "\$@"
EOF_LAUNCHER

mv -- "$FONTE" "$DESTINO"
cp -- "$TEMP/nullvault" "$ATALHO"
chmod 700 "$ATALHO"

info "Instalado em: $DESTINO"
info 'Para abrir: ~/.local/bin/nullvault'
info 'Para modo terminal: ~/.local/bin/nullvault --cli'
info 'Para usar só "nullvault", adicione ~/.local/bin ao PATH, se necessário.'
info 'Importante: o aplicativo pode gravar cofres na pasta de instalação; preserve-a em futuras atualizações.'
