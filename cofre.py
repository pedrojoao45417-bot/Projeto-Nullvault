import base64
import calendar
import ctypes
import getpass
import hashlib
import hmac
import json
import math
import os
import secrets
import stat
import string
import subprocess
import sys
import threading
import time
import warnings
import zlib
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

if getattr(sys, "frozen", False):
    PASTA = os.path.dirname(sys.executable)
else:
    PASTA = os.path.dirname(os.path.abspath(__file__))
os.chdir(PASTA)

ARQUIVO = "cofre.dat"
BACKUP = "cofre.bak"
ESTADO = "tentativas.json"
LOG = "auditoria.log"
NOME_PADRAO_KEYFILE = "nullvouts.key"
MAX_TENTATIVAS = 5
SIMBOLOS = "!@#$%&*-_+="

TAM_MIN_MESTRA = 12
TEMPO_TELA = 15          # segundos que um segredo fica visível ou no clipboard
TEMPO_INATIVO = 300      # segundos sem uso até bloquear a sessão
MIN_PALAVRAS_IDEAL = 7776
ENTRADAS_NA_TELA = 15
BLOCO_PREENCHIMENTO = 1024   # o tamanho do cofre cifrado é sempre múltiplo disto
SEM_SYMLINK = getattr(os, "O_NOFOLLOW", 0)
PALAVRAS_FRASE = 6
MIN_BITS_SENHA = 60
TAM_KEYFILE = 64
TAM_MAX_KEYFILE = 1024 * 1024  # limite de 1 MB para evitar travamento / DoS na leitura

# Formato do arquivo:
# Versões 1..3: MAGIC(4) | versão(1) | log2(n)(1) | salt(16) | nonce(12) | cifrado
# Versão 4 (Multi-Slot Envelope Encryption com Scrypt em todos os fatores de senha):
#   MAGIC(4) | versão=4(1) | log2(n)(1) | flags(1) | salt_scrypt(16) | salt_s2(16) | num_slots(1) |
#   slots(num_slots * 60) | nonce_dados(12) | cifrado
# O cabeçalho inteiro (MAGIC..slots) é autenticado pelo AES-GCM como dado associado (AAD).
MAGIC = b"NVLT"
VERSAO = 4
VERSOES_LEITURA = (1, 2, 3, 4)
# N_LOG2_ATUAL = 19 exige ~512 MB de RAM por tentativa no Scrypt (alta resistência anti-GPU).
N_LOG2_ATUAL = 19
N_LOG2_MIN, N_LOG2_MAX = 14, 22
N_LOG2_LEGADO = 15
TAM_SALT = 16
TAM_NONCE = 12
TAM_TAG = 16
TAM_CAB_V3 = len(MAGIC) + 2 + TAM_SALT
TAM_CAB_V4_FIXO = len(MAGIC) + 3 + TAM_SALT + TAM_SALT + 1  # 40 bytes antes dos slots
TAM_SLOT_V4 = TAM_NONCE + 32 + TAM_TAG                      # 60 bytes por slot

FLAG_TEM_KEYFILE = 0x01
FLAG_TEM_SEGUNDA_SENHA = 0x02

GENESE = "0" * 64
FORMATO_TEMPO = "%Y-%m-%dT%H:%M:%SZ"
EVENTOS = {
    "cofre_criado", "cofre_migrado", "cofre_invalido", "abertura_ok",
    "abertura_recuperacao", "senha_errada", "tentativa_bloqueada",
    "item_adicionado", "item_sobrescrito", "item_visto", "item_apagado",
    "senha_trocada", "senha_gerada", "sessao_bloqueada", "sessao_desbloqueada",
    "desbloqueio_falhou", "auditoria_consultada", "saida",
    "alerta_rollback", "alerta_lista_palavras",
}
# Só estes eventos acontecem sem o cofre aberto, portanto sem selo imediato.
SEM_SELO_PERMITIDO = {"senha_errada", "tentativa_bloqueada", "cofre_invalido"}


class Bloqueio(Exception):
    """Sessão bloqueada por inatividade; a operação em curso é descartada."""


# --------------------------------------------------- proteção de memória e SO

def proteger_processo():
    """Desativa core dumps, impede ptrace no Linux e tenta travar páginas na RAM."""
    if os.name != "nt":
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass
        if sys.platform.startswith("linux"):
            try:
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                libc.prctl(4, 0, 0, 0, 0)
                libc.mlockall(3)
            except Exception:
                pass


def trancar_buffer(buf):
    """Trava um bytearray na memória física (impede ida ao swap/pagefile)."""
    if not isinstance(buf, bytearray) or len(buf) == 0:
        return
    try:
        ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
        if os.name == "nt":
            ctypes.windll.kernel32.VirtualLock(ctypes.byref(ptr), ctypes.c_size_t(len(buf)))
        else:
            libc_name = "libc.dylib" if sys.platform == "darwin" else "libc.so.6"
            libc = ctypes.CDLL(libc_name, use_errno=True)
            libc.mlock(ctypes.byref(ptr), ctypes.c_size_t(len(buf)))
    except Exception:
        pass


def destrancar_buffer(buf):
    """Libera a trava de memória física de um bytearray."""
    if not isinstance(buf, bytearray) or len(buf) == 0:
        return
    try:
        ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
        if os.name == "nt":
            ctypes.windll.kernel32.VirtualUnlock(ctypes.byref(ptr), ctypes.c_size_t(len(buf)))
        else:
            libc_name = "libc.dylib" if sys.platform == "darwin" else "libc.so.6"
            libc = ctypes.CDLL(libc_name, use_errno=True)
            libc.munlock(ctypes.byref(ptr), ctypes.c_size_t(len(buf)))
    except Exception:
        pass


def apagar_buffer(buffer):
    """Zera um bytearray in-place e libera sua trava de memória física."""
    if buffer is None:
        return
    if isinstance(buffer, bytearray):
        n = len(buffer)
        if n > 0:
            try:
                ptr = (ctypes.c_char * n).from_buffer(buffer)
                ctypes.memset(ctypes.byref(ptr), 0, n)
            except Exception:
                for i in range(n):
                    buffer[i] = 0
            destrancar_buffer(buffer)


def apagar_bytes_efemeros(dados):
    """Sobrescreve o buffer interno de um objeto bytes ou bytearray recém-criado
    no CPython. Nunca deve ser chamado em literais curtos (tamanho <= 1)."""
    if dados is None:
        return
    if isinstance(dados, bytearray):
        apagar_buffer(dados)
        return
    if (sys.implementation.name != "cpython"
            or not isinstance(dados, bytes)
            or len(dados) <= 1):
        return
    try:
        offset = sys.getsizeof(b"") - 1
        ctypes.memset(id(dados) + offset, 0, len(dados))
    except Exception:
        pass


# ------------------------------------------- detecção de pendrive e arquivos

def detectar_pendrives():
    """Detecta unidades removíveis (pendrives) conectadas no Windows e no Linux."""
    unidades = []
    if os.name == "nt":
        try:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(2, 26):
                if bitmask & (1 << i):
                    letra = f"{chr(65 + i)}:\\"
                    tipo = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(letra))
                    if tipo == 2 and os.path.isdir(letra):
                        unidades.append(letra)
            if not unidades:
                for i in range(3, 26):
                    if bitmask & (1 << i):
                        letra = f"{chr(65 + i)}:\\"
                        if os.path.isdir(letra):
                            unidades.append(letra)
        except Exception:
            pass
    else:
        usuario = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
        bases = [
            f"/media/{usuario}",
            f"/run/media/{usuario}",
            "/media",
            "/mnt",
        ]
        vistos = set()
        for base in bases:
            if not os.path.isdir(base):
                continue
            try:
                for item in sorted(os.listdir(base)):
                    caminho = os.path.join(base, item)
                    if os.path.isdir(caminho) and not os.path.islink(caminho):
                        real = os.path.realpath(caminho)
                        if real not in vistos and os.access(caminho, os.W_OK):
                            vistos.add(real)
                            unidades.append(caminho)
            except OSError:
                continue
    return unidades


def encontrar_keyfile_em_pendrive():
    """Se houver um pendrive conectado contendo 'nullvouts.key', devolve o caminho."""
    for unidade in detectar_pendrives():
        candidato = os.path.join(unidade, NOME_PADRAO_KEYFILE)
        if os.path.isfile(candidato) and not os.path.islink(candidato):
            return candidato
    return None


def normalizar_caminho_keyfile(caminho_informado, para_criacao=False):
    """Normaliza o caminho informado pelo usuário para evitar erros de diretório
    (ex.: informar apenas 'E:\\') ou gravação acidental na pasta local quando há pendrive."""
    if not caminho_informado:
        raise ValueError("Informe o caminho da Keyfile.")
    limpo = os.path.expanduser(caminho_informado.strip().strip('"').strip("'"))
    if not limpo:
        raise ValueError("Informe o caminho da Keyfile.")

    if os.name == "nt" and len(limpo) == 2 and limpo[1] == ":" and limpo[0].isalpha():
        limpo = limpo + "\\"

    if os.path.isdir(limpo) or limpo.endswith(("\\", "/")):
        limpo = os.path.join(limpo, NOME_PADRAO_KEYFILE)
    elif not os.path.dirname(limpo):
        pendrives = detectar_pendrives()
        if pendrives:
            if para_criacao:
                limpo = os.path.join(pendrives[0], limpo)
            else:
                for p in pendrives:
                    cand = os.path.join(p, limpo)
                    if os.path.isfile(cand):
                        return os.path.abspath(cand)
                limpo = os.path.join(pendrives[0], limpo)

    return os.path.abspath(limpo)


def restringir_permissoes(caminho, fd=None):
    """Garante permissão restrita ao proprietário (0600 no POSIX, ACL no Windows)."""
    if os.name != "nt":
        if fd is not None:
            try:
                os.fchmod(fd, 0o600)
            except OSError:
                pass
        else:
            try:
                os.chmod(caminho, 0o600)
            except OSError:
                pass
    else:
        usuario = os.environ.get("USERNAME")
        if not usuario:
            return
        try:
            dominio = os.environ.get("USERDOMAIN")
            alvo = f"{dominio}\\{usuario}" if dominio else usuario
            subprocess.run(
                ["icacls", caminho, "/inheritance:r", "/grant:r", f"{alvo}:(F)"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            pass


def escrever_seguro(caminho, dados):
    """Grava de forma atômica usando arquivo temporário imprevisível com O_EXCL,
    permissão restrita e fsync tolerante a sistemas FAT32/exFAT."""
    caminho_abs = os.path.abspath(caminho)
    diretorio = os.path.dirname(caminho_abs) or "."
    base = os.path.basename(caminho_abs)
    if not base or os.path.isdir(caminho_abs):
        raise IsADirectoryError(f"O caminho '{caminho}' é uma pasta, não um arquivo.")
    if not os.path.isdir(diretorio):
        raise FileNotFoundError(f"A pasta ou unidade '{diretorio}' não existe ou não está conectada.")

    temporario = os.path.join(diretorio, f"nvlt_{secrets.token_hex(6)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | SEM_SYMLINK
    try:
        fd = os.open(temporario, flags, 0o600)
    except OSError:
        fd = os.open(temporario, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)

    try:
        restringir_permissoes(temporario, fd)
        with os.fdopen(fd, "wb") as f:
            f.write(dados)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(temporario, caminho_abs)
        if os.name == "nt":
            restringir_permissoes(caminho_abs)
    except BaseException:
        try:
            if os.path.exists(temporario):
                os.remove(temporario)
        except OSError:
            pass
        raise
    if os.name != "nt":
        try:
            dfd = os.open(diretorio, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass


def anexar_seguro(caminho, dados):
    """Acrescenta ao final do arquivo, com permissão restrita e fsync."""
    novo = not os.path.exists(caminho)
    fd = os.open(caminho,
                 os.O_WRONLY | os.O_CREAT | os.O_APPEND | SEM_SYMLINK, 0o600)
    restringir_permissoes(caminho, fd)
    with os.fdopen(fd, "ab") as f:
        f.write(dados)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    if os.name == "nt" and novo:
        restringir_permissoes(caminho)


def apagar_seguro(caminho):
    """Sobrescreve e remove. Em SSD ou sistemas com journaling não é garantia."""
    if not os.path.exists(caminho):
        return
    try:
        tamanho = os.path.getsize(caminho)
        with open(caminho, "r+b") as f:
            f.write(os.urandom(tamanho))
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
    except OSError:
        pass
    try:
        os.remove(caminho)
    except OSError:
        pass


# ------------------------ proteção de estado no SO (DPAPI / guarda local)

def _caminho_guarda_so():
    id_cofre = hashlib.sha256(os.path.abspath(ARQUIVO).encode()).hexdigest()[:16]
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        pasta = os.path.join(base, "NVLTGuard")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
        pasta = os.path.join(base, "nvlt_guard")
    try:
        os.makedirs(pasta, mode=0o700, exist_ok=True)
        if os.name != "nt":
            os.chmod(pasta, 0o700)
    except OSError:
        return None
    return os.path.join(pasta, f"guard_{id_cofre}.dat")


def _dpapi_proteger(dados_bytes):
    if os.name != "nt":
        return dados_bytes
    try:
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD),
                        ("pbData", ctypes.POINTER(ctypes.c_char))]

        buf = ctypes.create_string_buffer(dados_bytes, len(dados_bytes))
        blob_in = DATA_BLOB(len(dados_bytes), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None, 0x1, ctypes.byref(blob_out)
        )
        if not ok:
            return dados_bytes
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    except Exception:
        return dados_bytes


def _dpapi_desproteger(dados_bytes):
    if os.name != "nt":
        return dados_bytes
    try:
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD),
                        ("pbData", ctypes.POINTER(ctypes.c_char))]

        buf = ctypes.create_string_buffer(dados_bytes, len(dados_bytes))
        blob_in = DATA_BLOB(len(dados_bytes), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0x1, ctypes.byref(blob_out)
        )
        if not ok:
            return dados_bytes
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    except Exception:
        return dados_bytes


def ler_guarda_so():
    caminho = _caminho_guarda_so()
    if not caminho or not os.path.exists(caminho):
        return None
    try:
        with open(caminho, "rb") as f:
            bruto = _dpapi_desproteger(f.read())
        return json.loads(bruto.decode("utf-8"))
    except Exception:
        return {"adulterado": True}


def salvar_guarda_so(dados_dict):
    caminho = _caminho_guarda_so()
    if not caminho:
        return
    try:
        atual = ler_guarda_so() or {}
        if "adulterado" in atual:
            atual = {}
        atual.update(dados_dict)
        bruto = json.dumps(atual, separators=(",", ":"), sort_keys=True).encode("utf-8")
        escrever_seguro(caminho, _dpapi_proteger(bruto))
    except Exception:
        pass


def registrar_ancora_guarda(ancora):
    if not ancora:
        return
    salvar_guarda_so({"ancora_seq": int(ancora["seq"]), "ancora_h": str(ancora["h"])})


def verificar_rollback_so(meta):
    guarda = ler_guarda_so()
    if not guarda or "ancora_seq" not in guarda:
        return True, ""
    ancora = meta.get("ancora")
    seq_guarda = int(guarda.get("ancora_seq", -1))
    h_guarda = str(guarda.get("ancora_h", ""))
    if ancora is None:
        if seq_guarda >= 0:
            return False, (f"o sistema já viu o cofre na sequência {seq_guarda}, "
                           "mas o cofre aberto não possui âncora (possível rollback!).")
        return True, ""
    seq_atual = int(ancora.get("seq", -1))
    if seq_atual < seq_guarda:
        return False, (f"regressão detectada! O cofre aberto está na entrada {seq_atual}, "
                       f"mas já esteve na entrada {seq_guarda} (possível restauração de cópia antiga).")
    if seq_atual == seq_guarda and str(ancora.get("h", "")) != h_guarda:
        return False, ("a âncora do cofre diverge do último registro salvo no sistema "
                       "para a mesma sequência.")
    return True, ""


# ----------------------------------------------------------- lista de palavras
# Listas de palavras integradas diretamente no código (38.504 palavras únicas
# combinando wordlist_pt-br.txt, wordlist_de.txt, wordlist_de_8k.txt,
# wordlist_fr.txt, wordlist_it.txt e wordlist_ca.txt), comprimidas com zlib+base85
# e protegidas por verificação de integridade SHA-256 fixa. Dispensa pasta externa.

HASH_PALAVRAS_EMBUTIDAS = "1d996ab3e8a950f53990b31a77ad823a2edb3ac47af6b966b482370a623fed7f"

PALAVRAS_EMBUTIDAS_B85 = (
    "c-l;z*@EjV&#ceCyL23q&}~Cr3|`&2`b|A0_rFh6V#W+Yj9!-Yl}c*=Tb3=ANn4%twyaA}#-9x4WfR`9z2`;nfac@CGXGS;mOslK"
    "hYfSNJ4T@`p#Kd5wRJJn0d`X?4@d`W<2?1W1KHFr`L@|H+rMdVvb-&jT!G^-{@Ur2mq5&ryzJF@WMj8|da95nv)zHR*uB_$x3@aK"
    ")o5rowz0k@uCu_D<UOt5#CFdV!h{+yz*$61Ox;sJG0tQ+ILs}*>@eg1o|xuG$ei*<k)-Xl7*cM*je9-dva2H%eGkc{)|S#?dNm9O"
    "<Kq&=p6oQ5;IX_KDZ;d1I=F2>d4`ACR$$USH8c5QMliYD?Pps?Fym=Bl<7y^p32FiEynRun$Ly0d(N}~d3~naGP)U}dPZ42)0Uog"
    "I3hsm3odO?7S9p2^K`1O#WB2=uzxKVZatXD_{%ZABKxmM`<1qbnLHU`-E6MgaEQ8nu*vr?GLxymys60Zu`jeEF`LoG!_GA8+!vaB"
    "rkZlM-3Vv_7!6;GtL7`MJs^Pu{hC$Zj8yFRGW-qSi9-LbyIbY9+ykkTZK2S%*&S;M=BzN|A&4^BqC*KA_$pzMdobnuVu&Cex5ZxF"
    "l(z9u#&-l6%+n2NUm~uuyy!tCJzat&y_{<pMOJE)Oev$g0_x2&tlnBKbe~G+tWz==27n#aGwEUoQ#16ir9RYk2~zIvW0N8M>YPp>"
    "-jYeBl*N$3a|zGH(e9>800lo8`)Mt$wuq9i?#^{|XKf;p{@VX<qIJ9<`JoDWkNr)S==yC+e1JCAmL5(+*=&hHp{0Bn$4QipAbD90"
    "#n6GZ8lS|MX)MiUH6enN?N;3~Cfc~U(=^(VI%^o;Jzxn`W)7FiaW#cw=^w$G++B{@XofMTyP4U9VM0tF=^0@|b{w;59$=&m)65Wi"
    "idJ;w_0>U2=*WdCI2fXi+3Wj-i<vV8X4>fybv7|v+L@P&q2iDCQb_9EEJKd>Z~+}tp7BMqvK-rFUcoejW9^YzpTnCm?AwA&5R(JH"
    "FAHaRj<3Tw_@*A>VKR-P7||<_L30%-t(i9$QC|)>rk<2UZy}EQYz9iI51D2yD>;ut;~+N^kaQFKh1Gb5`)M-~jw6Q=YQ^B+^4frd"
    "k@=s7Cl$><3gVw-+&?w!0@H36(}OuYa{jwCgMT^1)xXiyKtD4D%%A1$qM3Szi{w*dB!N*%AI7=QOmO15NNo{qh5@M4PN<@5!fwrY"
    "yr<oa=~u;ZlfYW7+)c=aeKCZe+7Nf^;vr_@`~R5o$2DUzgsr0}&fb)j_WkZaa}H;Rccxl)KAQ6}g;ZZI#t|Je#~|VD+8xMIj-EDh"
    "vT6)4L*`e6)T+;tDmNLr+Zu7r@E!NGVob%MQYm5X0X8B?Kqq2#XyRe}BN-g$5pGAoWvsU74m;(5Q^{!16C<@*OHQRyd~4m%w8ez|"
    "W{))jApL=GZ_d`l9B6+>_>Zrs;|efZz8Dq!+UgqcN@j91gY%f`Bp4Z@AFXL>cuFs!X{=MLQWpiO&a^!-7gN4zLblOiN*`ey4%2SQ"
    "fHO0M3CV7fofGP2TbsHKCjlsksDjzNoCsAvskMkTg>5BcuceiAVS`aEy(E$*?Tpo8>^O0lIWL#fF4nkLN!dx>Z`(E$`1M7L(SR_k"
    "AF@D`X$k03?#x{-?i!Q(0NL~as_9|BQ9Idm!wY?V(%nE*d$NhpE`$mB=)pO`MrBUGh>TK8br%;?{<v^ThOi~r?5v7qV^CSQO3Cj@"
    "S=$-$SIWL%Q#IWnvU=0>akhI};{@7_@NVXp;+aMJhc1k|SNoVq2C8J(%T{lDF0;y>crM4B4VmjGOlF+en=-2?LK7(Q`rhoeIda6H"
    "XLtg<Si03_yGB_H+Y($hGZhSnW0ETvR2Gb*?+)A@BV||Zxof(;{zu=LGeyI!_-;l(|84aaBZRpA$Jnj>?q=SVrrUni`tTLa-i^Lf"
    "J<;%cen6$#PZ&7ma|v)T*SDYrMp$}juNdaQfUl7@!)_P=9*6khf*KwL$1NGCk%62TRQk9h)F$9zwiUY9@F-}_XoACSw6I}HF^qjs"
    "yC4z8z&I@Y2eM^q6vU2%8Fo;eOci{ACTNzLBCG~{>=+nZ0F{*(6_SuLg*lCC2KPC1IWoqP`&}Z`c-S2Fl;(uQe0(za%66mHz*>Si"
    "FLW?RGAAj5u?iBOl%8X;Np*5h8B0x4COx1(IBX*OVmqXR#8(6T(TOf7$OhbIGrljuM6k)VKo*$b&hQjIC>)9|HN3R!z_SNl%;hj6"
    "+08jnF~#**p)}3AhmLzvvz{YWHz-h+XjA}XkSK2VWKgI~A~_Ay9|1*3RZwD?I;T?dJG{Iz>tU0r#}bGKG;cvM@HG>ASoiRC+U(Su"
    "Gt`_5N}n1*+=@29z8sUgWi)~8Z*~Eko&ewT5B|RvYf8Z=J6bcKZGEMP=BxT6LA(r4c*S^qYjRBNCZY#SY=(aMJpX@2u`sxa%6gNM"
    "eBV(Z1&0B}{=T!)1#E%DH5uaAT`GIFC9xNT<GmtWCQxKm!evtUHLu8_du6B)<S@@++nhuW%=Un87>eZ2T_Y@jmf`i#yEVFdy@Ww^"
    "2NC?4n~_4Umyi%c$DP_ci=Se$fiLi<RyP9;O4Udn+8*D~c3X#Qu`335gz936s;w3^b=;N!=W^Vf+7uhYIRa4;vnd`@reJJAO-;bI"
    "<_qL_XxgXfrxaKWUbDO-<fnSW2U?s9O4yRt#9=t?iyRFqVleZ$BkU*bri&r5$YriNitZSCcvqH3apJDa2~NDM1|;ra0cS!E$Lx?c"
    "xQ~y+(aj-H>7NNvaHg^vD8Gq^p$FI#y0P#GGv#)MxV!r5={Rc44JY>u;PcM<tvX2vt|>VeXo6;F70tNLj<AArir1ImPCQE&D%G5q"
    "DkgW-%?R^YP`DqVH9i;sAD%8wP!bb<0kqG@@=3_AM|vvn4^J%~i9!33wD?U-A?t+=z?mpQ3{4z}(Z|CbWFq>(L|UiO7F*y>dxlXP"
    "FylD(%L|&!BfjOaL{#10FtC^kI7~>$$+X=$$g64!v=@KPBYOo^OxSPvV(g)qUfxP%IF~So?-IGph0n+>vOnc!Fm(hoB8qLKfIoA1"
    "_z|!IH(?9!HFDUJ-Dks){qv>43Q%;Jk$r;v<|k`7`ncUt052QpTkV>|q~;nQo(X_=x*T5!gqHW9&rPa^Fh6%OVD}T5_*r%XnfY<*"
    "KaS_ekxP-GkPNOCF$1KMH@dC>6KboAjZlL)X7Ae!6c1fcbO6;9gCk`c_CUdScp-Q~HZ1_YNLf;Rw-I_^c@Xp<4DEgn1S*W#pD3}$"
    "MiW4cVn~!o=sIq%s0NSjXa_m=H?pJgKtF%X@w*Vlt8))2Wsj*L<L|J?!#)o?N$x$Q&p(%27S#wO+5)o8ZVfPYdD)&YkA(;x%8#H3"
    "RN0d%+t1~V?<TP|q2Y8aO!J<M@lR$yPo&s0X^U!p3V9JUqgo<Jq+Tt0dI{rc)fO0FH?^DO#)MDAz{cX!vB<Y}O`lI|c0$GUoEjVn"
    "Kikx}728X$-iMq(t}_xzfF)T7RsZRU-!tQ3gCx@d*gkrSxDPSzj(^uO)zgCr^OZ@QWP^~^%-|q!pvKHwA5btKl;8w>9d<mNWk=SR"
    "FxX9NGtJB}oJ2$$oRA%_zxE_39=1#oPB;MU>dw;Ba~m_9m_nC-mPGfPh$=Qwz2sTyuE4WvErw)Z{Z|a-LuY$>4Q=*SOig1d1qIiF"
    "p&@v-IN^bGhM{dtCd|nJ7=I=f1|(HK0h8u+v;jj67{)=MsY$sY#8HBip-3BFqt#XebNb0RS1dIN>S~5I*|OKEo=l9MG)GnGp3LB<"
    "HelFt?8HCbi^18O#UoEctAWJgIo*UE${NYUZeIh+XODaO81a#shjw$y+K5qdG6xQ9X)_spPKiTQh?)tKY|mkDPU`ca-A$a9uZ-?7"
    "K>|cj47S9_OzEYPdwGLr0(&doLwc2&75ON(tXV|U$=8sSo%9gZ_7|I9S;gXc<dnBsx1IH|L)A7W;B;5EsG>=5R%)5)?W8znY%<=f"
    "h`6Lkp31K%L*!&C(2{A`wzS!|)bDVTmM}2`1L9@O{Ov^GwV+!-2eeWmj|MhD^KLyWTZsa2-xrKH*+LC<Qnf(3Yev4J!(@7$gpLwy"
    "H*Lq!T_$nH&<}HSz_vM5W3<Xmn&`y7X!X;wBoCI01@bwNLjp+z;U4Ba%m_l53ws1?Yj|y!g<}?Txm>ZfE85mC<_xAspv$2<NWO9)"
    "`a|RSNor1>d{5m(ANA#pp9w0VFIJtt7FHg<7KlduIV%^zkp-Jc)uO&wxA|h-X3}mKw%@+eun)pZaRI8RPmzEX>+HJys+zZa)zM5-"
    "U<sz1(jdgx`gGJM$<;FlkgP=87t48~1K`^R?f(lY@ipR@5ll0Zv4K+Zg>afw<u)PPl=1N<f;TP*PJsiXqkJJazI`O<`<uO%@9*jU"
    "t(NxP@(l-;QNi*%^Y^WozI!%RZ~110?Ypy*^{qwDIWm9GH1fAlVL#{&n@&p^4pz%H@Apm6mkVrC32p5DZObYNvr!1zEyCrF%M+`e"
    "i5tkoQ(OxldvY))BO6NK#&+?B(mv^w0(Q#bNc_$$t5Fl~cx}!iddTJ-zX{GmW9XWgZOl%-ImCX&x2J$+3{Mf3lp8)_JH9(#-?2HD"
    "vXa0_F=%OGk`h3y!sD_y!dv+TW|4oyBqF&bGI>jOMXeA#FQhOhlMTh-FwBA{Iw=X;&2@L1Gm3H$(j|IBYzcAz8vW+OWCHS-HH#LI"
    "OeQKV){tR*bf3f6ZWpB@CPq49NJ+hVTRp~XD;sxPYzZ4LdorMH;lnoQ#zIH%wo*O0Zp1a2rDRu{#7ahxRofiD*_EA44#w$LXQT3&"
    "Ydwi&lz?P-g)tkHJugCURMlN$@T3xs+kHqa+|ukGJE$F!&2@@2)LEn5FaU{iLAE2+%NG2kU+ysJi|&}dFl?s70cI;EpQ$+7;%Lbw"
    "t2moiZvctO%?lh8o{oVg!~%xbHaG8R0wv5Tfbe$hj%C<{5Z$C1PeQ#sBArK2W$TgMZoOOp5cPvysmVM|b|68_zcA=KTtbr`zz!`o"
    "IK`JMM>DQT$jmF8aPXSI#x|IaAlksEW_L=Irj2FyNof^XbH*+EWa`A!Rx^&0!e@jNtpG*JV*H%Imq_4gfsl#qi?F+;FqkfeDBScW"
    "AdB25GcLAx6AQiFyQcy>xvp4W_p-r8@68<H*}iA@(l+qM8IbL}zUTqp9uv1I#4GTEMq~(7kj18LV_-xnnnYTSfRCSe8r{ByHt!bn"
    "(L%4rxh2zP`pgbQ32rI8IL6H6MrgrsRh{qyI+mQMw{7>X_hgb&uIpNjhT`~y1aym;kPY@V>^O%opbkey2IEZDwsmQX+cumr_OK@G"
    "k>e2~&SV_f@LJxc1DMrlaG8zMa(DZrOt_C~kp3`ZT6Ab=i=lK+Uj`!ZWOVbsgQD8&!)<;}wW(m*Je%IL7#1karmk2iOnur}-%yFY"
    "e%TNE?JBRuVB0xnC;YyBDtbdBmJ}x%3TT!h3jAamQ_soB{_PTaGwBk8Y1UT@22VPSK_j1PRksWM<E_)N9fq0E_Rc{ULo&n=2iL<%"
    "7E?b#!=H?&1{<q4+cDK5Rq}D?l-qW&C$(vEw{cu|V=rs7Ixfh-0Y#18x-}_2x?8Mw*Nz|?X^0a`*jq%1sSe!212KDa?|gA*>MAh$"
    "$n(~pR#v(vixcanzJWC8?jSwK`uXGzcK9dL2g9>>)i>?%I2c{8f6pQ5Zf5W$-wj26>oYmBgExPk1#Wklw0aURR<rQ$Js5H_9Ky|h"
    "SlJpYooMzUN(GI4bMA(BJB8(96wi1h4;q7(IovRZ+T{_93TIFYgC^}=_}LNhP#~1fD2}o?b&s(VvVlOR2S*RKlg59h7_!B<?}=+*"
    "2}Sfw_E9%G_zNe5kUTBu&+JA{*|Uf+X|cgkf86jso(2kc`{Eduup5u?euTN(`(<*Rr%g^S8t2D*G80uNANLn6WK5~LKs5yHo)Yd}"
    "DxIM6-jO)_a<|jHn$p21GkijLXQbJc*nTYp?5F@j6WmxU)Zmc}+3^&|TV4@cVJlBas>QB{p_|%6&jzweT<vmW2XptF0^md1(_Z~?"
    "6#4Gy_U?k;eUNK{?R-N(%mq%yDKi`2T{XLFW~X8%O`A;&58ev$KG426zvp7=?>n7QM|fiOsm}C=75$y-EIXT|b3*2k6Q*Bii#U#D"
    "j#8VG&C5~iGr$sP_ah?ntaJCV|NX`;>4X$e48(!fzjMZFznK&=Sc3wMbSS*r*dnhmvP!Jq?@80G-KW3z#2)N~WY|QNKB>DNlQps3"
    "i|Kouo)*@;UktfP#U8>vn|>Tgh2jlo`ip>+=`{jcZDOk<I0v!8&0Tj~c9O!advux%P0XJ%Zkzpj4Py>dtaa^Pv)Qj2%szFx`^wPH"
    "j*I9P5SCh#-nsBIsS@>a-|p4D9q}rP9bsISoS5IWM#ow1oilzrm6;1$@4jLXCm(=hbdpm$rB$IX?OH^U^S+>xO=O2%XrqSR2`ruN"
    "6w&Ujkcn*Q@1ADvyLSn8pRAZ*M=h|g7xQg~@|mg+-!+jXlfAAlH;d}E-o47ZCG>=}+H!L(uzbJ!K*e4iZbob&SMlKjn9vP;e`V4D"
    "*pp3~HVML%4UWr(_bb3&NVaw7rE!&lO_aT|nXz+JZ)dtEnw<FQTWUH=E$6pJ!%4}+TRT3YEH3TRq`-_%R~KgwCrzfrKJf=HNUS##"
    "EWyJ~@6AL<P{LP$6^;E}9cLYmmDL=<04U$Lb33*dGf#2$Jg1)bC75PRfeLZ(eVpFjyLYJeJ|}D{${ua2A4~h-aG=^ue6fBhrar*0"
    "MF;UGb7WoLn2h!DedZa-JUl}IFMGP*;K=0!ddTqSaL{P~ectIBMb~o#Yo%d}@v(I8AQjF)2%n8<ap8CySMbU;>np4_7n(D1mIZUv"
    ";$$#3ytb9YtY&a!oSX39utQHysMkFpUuFmBj;TBHPUHhJ+gZ8ARz*SeExNf^jBHty*}|x&$#{pOOxdQpgXN}sIpw<HQ{u`Zi)(Yl"
    "(!CFTHA=>$tk!6Uv;-9FEt<;8KsKQTB!hIqvU+G1s`HlBt_;w{$0=PKcTXNCW+=yQC!&q$8r3~e^$pq|3-v-<qa_HBus)69yW5rJ"
    "Z?KsOUnkDVaizxnJ2B*Pez${VN0uEKm%}D(d_{Bi8&?Ctf-{G21l&9oV}EH6XMa|!&);H(%OfSN_li?oA}zkRSCWrwm6UyJsig1A"
    ";|4)-iOo=fKEW49B#Ea`hU+gVj_NfuN90U-#6`PuUHdF?+p~D;Qy%`t>#k?HZg!T(mLepRm*TSw0_88Ra~9v@EKjTI;AN)j?I|vH"
    "mblmnHe<E@E9^H@55eMUfW7GoAdEvF%hUEuFDJ6BW+Y+8><P5(=Vi%mX<-vil(>{+`D5_zwA~~GC75imD~0k5%5A*zJjhgBNiEk7"
    "-DDUZg^VzhiBcQBp)?uGCm}9zk9Fds2ebWuOoP$NO7S(;Vrg9B7OT)g<dv=n*iaIDY|iNhVEAPPp|B-g^4&WCMMo4S!AoZDA=m;^"
    "U|1s{^6svjt&9u#;%u!OB<9_|_!2EOH;0a-yaG{l;sJlG?+G+`7qrg8l6ygyE_sS%stbk&=)<_hhixZNtPBa6!!H8-u@zmuLL6%8"
    "xO{W{wQ!YU((V%c_L(msMf)AsW6O2DwtSDGTdpNM`g(2gW!e&#XiHq86}pP9+q9F(i0tcDZQ1e_CSQT#Hd?tZ(w5zq#>&*<@4>Y2"
    "lA>$xIfj;<&KMVMCpu(t75ZSU0LMh>#JP-#(rC+dCAUaKQQ;-I9~Fz)lDLiuIvTEXfsWwk3ip!&9Q?;MS={o9N$}agY|Ka)H;%$l"
    "stG-8ozU=Zv>1OLiyFXYdm2m`*N2SwkTHiw$6(4mMxl&VVd{+-t2DDoX+Hvtnw!iV<1csX!=>(CQa6J?x(HFSEeS{mE^*nTObPQ1"
    "+}%2+{QYqpV(i0b_+hpSFBj^K{^GI5DzA#k;A}e!tc90%T$-Ouw48VH*}oDOj?24w^w73HUv}vrEm;BZHRB1-u#QF^_l|`hf$rR5"
    "j+?@To5IC6fs1>nuK^eL(@7oW;j!_U6Omy|e9CnvSj>=Ui<`hg=i%TCukI2Ndor~b-vurlPbnT=j~praesEzXB<kZ?lXC+U=0M`7"
    "PRzbTX*}MU=6AeVc`dpKjLtUY{??6%^NBsoR&(ZP|GF5r+_(W;bPPM<7>#d<YrMsyBIVmTm@vUwpVw4Nf3-!;gTC3Bf(SUs2a^KB"
    "J!>ysj3IQDp8br27`{$ejMeyJhAJj$iMX(*KIvB9j=`t;C-Zi9>Y2Mzpv@<8eojbe41JEj?8i+mI*M*112%-LV?kAvVJ<Ez`;rT5"
    "S%o{xrT^m~ip0eMY^E4)wu|$4B~Gvx=3vMP<%31pN%1Q3PnQTmYWBLAJeg4A|HWF$WZENa!b|p*m*RWL<;Ry(%8zyUU+3%BmH2Cs"
    "`|IIQhqKFvo6_aF#a!kDjQ;fT?j4u|D;SOILm_jsx$ZX=Qf1l4Q}@b7XJva+)K;#cisth6lIEL34Qx*c@(+^>GZHaxuQ0t?jCn6U"
    "9sTyK=)JHr8@B-8s48G4L~)2;py9(SqeAvD>1#b*jMG!)in8PY(~S0~mhkplGw-D{&x>stflWS<_nwN2ll^FAPq8FcU*8Ok@3cJ("
    "3}9~**f%R_+K)-v6`hQ)cbPfyq3V8nC;9CSWPyEm`|!H|duqL;>Kl*~^KR&29DpP-;f5z|ViEyoOPcLsR`i_jN*W0GMnv&j=Zz2J"
    "2G~+r@d4GhRlzs=uH;3E8P}`c4oQY5<+X~*Xe#pFbaNcco~vs=B?qKHd+4T@$)Q;R0bR6k!weO-xdt}m*aX_;dz%e;LebRC!bP-&"
    "iTUkhnn&n&<(R>{`p~G5g(5NKvS|i18!;zwWtu5E%G(!-fCAc7*{6M17V0O^&VAcRK*Db39MYYX=1{e0L|b&%i`yFjVU83YDTa#b"
    "B?#AW>s0wfROI)R-PK>vU+G)SJMLFZhMlkX+X~oQ9jzO=SN?X-GJ|?0hE#=^6OHGM`Uw1hwzRG##_6$I3Xq(;i}o|KLmjqe;qLwR"
    "fq^&m4l*9S-@e8+kw&f3bL>cVAj~e2w@(Vc-_3`>#jtWZ8DFaxL#4k5?j!v94%|f634}KO#%B$;`(|N9`83~Bp6GS-x6TRMf|Zkr"
    "S1mT{&LB0|(jXqMT~Ex=Z&zQVMj8h{1$Nx*bGNL5aa^vh3E_h!7Ofn5C*$2LMp})F0&gD}7xXZ?)io|t1BbEs3&n(w(-uG6YBz%m"
    "su4Hm-rk;lUt6i%FntgALUtbC;|nXzc;(YVaIkSOfj%_QuHIfabakLU=vHdlg2_7j;=9+AN~#HvC6l?2HL%-avj;UX!H*zA9AUNx"
    "%fkN#yZ4RNkmk3!1l;6+`L+YHNr-R~!(%3KC$Mo?u<31rJH|V{?^r(62b+$&C#RJ~cF2wot+F?7RtYk`ibFG+x<$smU6Udqc>8F="
    "WQKFsa6Nhe>2zFd6*feLekH&(Y<VuGPVL0U2~P)WKD#$T9lG7TacgYB;Eg6Z!6TR$yR*zMz?Tc*MvG`SM@55ZH+vZV29T_YlZ)RX"
    "5hOzfkS7y&Xt7(dTX%qNOX&@blecqh|AQZJR_&X3UJ$Q^H3UoZrU{V4+<{Cx6oaf3bEXShFxk;oSL3R~QbKIWQ0Qd5Hr4!!NsA{c"
    "niobVXg^{C1#<VZfX%C-&8wo#SBodu4}zfGtHZkv?gN6mlN`3jt2z&BrjyVN6RJgHaA<A>OiZ}X*sMtTB1Man0p3j(&4v<|J<Q$a"
    "v>OKSbeJbmmmGeA9!3`tdy>uDk<I&%0*Wf(#AxA*urWZe0o8Qu4oN*Z8po5va81jX<k>fk0Lh48E*Hh~M3yvP{{d(_lez3IR-SAJ"
    "O`t%ZTLr2;)ne)kpW^IlN)9+gFkz1zjs41iBOHA0glxd+UwtWNk2=jWhvta`aD+W!Gn*GpdqTdzVr{wk8I;B|C|*r;gJ&8%DOt`g"
    "?(8zo?1T%55tXx9%nIy<h&Fgvwo53xygVaso{%@s$6LOHV74C%-fR*5Z4vO@!+J|P+;lPJk2&B(HKa8k+7QqucU@#!VKUT$+2<-+"
    "oTX@98*M(lAPAFtq*qLvSA_(Z?TAnVdfF3Gb-%G_FtH7-J##|4p<ar*(ph6|vGLww%e}E(-eUiIBCDUxyV7lENm7ho7izn2V1YIh"
    "`bb>wZ+m2Mj>Aq&>x|9HenZWj)ZGqjFbEg-Uskx9*ASaG=L8ubF0$)P6py9F%>cc*F-_%i{3KK}HCBBuz12M^Ut3+4yr3ak49XRq"
    "M|Tn$ugXk1pyc(<!Qu(Hkma|_Sio1knP3Qrh+K24p>fu(S;22Ei~qQ-DHy=iz`9+T8#d_!#M*c)OyH*x_4em#8*hoUtBE(SU<;kb"
    "9LH^c)PP~^Hvd9DHR4Tvd&Z2tYLPqaV%UTUN4Ni$?iZ9lj(nvD8dsBy4<<rHWxzya`xVXZ*F9P&$>3!Uzc#+DRg25lC%l=d!Pvqj"
    "kmw<T9B5ao9L*)1Zvjq)L&*)rds3fI72`7JVWtVDhifDs|8c%^a($0T&nsYPMlGJ-foYdhzdZLpn|v`5D$+gk6%A0G>AJcJ)MrEv"
    "lP>NPOf#lH$KY?MZaZ`0?1+5r(Trn!+k^JWCvZaxv^Qt74vr^H<|jpislRq155sl?1zors3g8Tlct5~g3&xeg>q`^t{I<av)2(IZ"
    "qmxJ+v#KU)^+U`CQs>B*!!9!OrWZ5qNglka2=i@*;fBS<=4Dhtwr{$7e|Zum#sg8$>lVoNp%@;wn9PF(mdQL#ZTrpm*tMTVZR(Iy"
    "07jq3U>%@opP#kR)~|%Gbjc3$p~e#+O^a8}C=b8=#TkY6$;`dmr_gA1#^ca40D>9GaiiNDtJj{7cpdKW!+M7w);m^)bAgqEIh5Ww"
    "c734r9?VE4#jncySQ*_XNGb|!NmvtBB93@b?~ty@0qMg@J#=#TesMWaKJ`L?>|eJj+74baJ-mr=Fh@SDQ5>ie2V=;Aa(2+E=6sDW"
    "`_{0-hWg>Nga@b24jSVT@0}ckKpi`{w8%q(NB!^&_o1da3E6z7mF&HfTGOG^L?7E9&~DckYsT6w*bM{7P<;3R7g+376)NDf-f`hl"
    "O!%*kgLIfH9d8F|PNapCylZeqYdYBWn$(vf#2C}F<UpItVKbse$ae{CZV}FxpeNIzQb3Pmb_dcuGP4NK=Cs>P^PIRti!G0U9zcqb"
    "QIoqNGOfp3VUQhy6wu5RN8tsYL+_t1fi_1HaRG5MG>PMvd8r+d9)~Z9&MEYY9qn$?Y*RC}?s-^j9IU4wvqR!1bDHwtf%KUganh=M"
    "sz(R<sc7ckzJ@4TbOwoQkw+iS56Zm&FN156haQgWoJpQk-!kD4)rWQ+H(oGqs2tt5gSwTs?#tobK2G=bzI+xsMb~_<d%icJ1mdDE"
    ">}dwb|KreZ!gd!aae%g4vP?)esp;!2Tw<jF1-_jp&Y`n?5kHkUVHkdihi^m$=)O?c9kJS9e<j*bkH_`<i;LIY=Y2c(nmS#vb9$=N"
    "AG^AvCv=mp(5J1wuv5DEZLjn@T_La~wBd_>c`bkSe8w)5I2WuKzKCJI$9Z0mNV&SunUr*2HWNf(_F4K~j|W3l-`N74?Md~ow$eEa"
    "qoZmxhU#OkLf3VTLl~2RdI%K~L%|QT0iK7L<cYtIuYr}O0eYTzG1PzoQmhmFRgIk^KVdxSd*LFpIEOk6Q5G!{)q5OF#kK1J^-WtC"
    "Jh)t1a<F_GPIfXmu-nD-fQHqu*N-TVF-%}+ocKn25yPgD7=%;r@!suZR`yR}s_~UB3?JWsOT5R_sQ1P1#rD}{Xow(Ql8=^%2_KBh"
    "I-#<JSIr24C9s7DE!h~uqAwAmUltK3%iYFDFnmDr(R`Tv$2gLyR5_Nz=^kNnOozkM*}RQB;pvR%m~^1+DcO#8J;A+Ny+#Y(F#ghb"
    "XHU!p&FFwk=qL8eKDwIL0&`%yEc}6PUA@|xl`cWSc4nX(-;S_pZ^BG>c&!uVi?PjYVavrhIC@{dnpq#t%vfBJgBd<(XHlZy@@5}Q"
    "OeY{;(0jc<*u6B~y)@pvG%m1Zwuu(bW_ABjAYLr!KSM?P8}Azq|3G8{O?uo++7lewv1GxR6AWV=#Z<0$CV2w&6A<Y>xsRyC>$v-T"
    "_0XBj^<r?&c+K|Yb&(NIVvg%cOqg@I7>7q3j0cNR;}QSZ7=C^12o4`{CTcu<fKe#HIMIi>Cc~d3#^ZHa#1A0G!^gtL!+lT~=F4Xs"
    "@fwdfVl^IdUS>Sve2f^TUXyX)#(y!m4Lu&6xrT5!BA;y#a*hF}+Y811_{R#+#BBVGNQb@rK}MY**A#~z`58}&_UVl*VG45?E1>QQ"
    "<Um=+s|g&R8h&wr0}(zyH5iX{vKydL#G<2H$bX!}qQ%CutrPIfg7IKQc(6z{>1L>=n?2xJ6Df)K$vv@V`E!C}rVHz_c?QC9-2CSY"
    "F$3^X>dE*Z&Sb{RJ~&tm6U``eTd)#3&eDpZdJmtK1!+Bpe|IvDXl6$=v*T)JM;v_}$17aoe<PEL_I7ZLX&iCha56q#IF9Z5m}rTI"
    "Uxg6TsE(^e9#@Mz;?$uS4jGC$jP>&CJFjB88Ma}@@g5Ii_1P|AcF<^xhnw<*_@rZ5y3yH-vs#n6K01y&iQzEQuyPD6ffc-RC-Hj("
    "vl%0G{~lnXBl?%@@894U&WKwG6R9HK)%P1Q$;`LG$NC4`<%7X*wVA%seI<W{f(1&49G;<%n4zOiOmeeZ<><piuXc&a2J|Qx+xsb}"
    "$-EC|!!6jVlz)UU=|F`LLo~i&IsE?Q_{TNe@#FXTPW>`~6J4kF6+xBEsf17eao~){LQX%dc+#3ruCf~|;7|iYA!_6{KrqKKN9w1o"
    "djPSN&vIdR;7^!|uwmDdDU#y!`y_&oU2}kwW!2^M?+H#W>72YjaxO<m1+AtDq!pe#b8sfzjn$-tTYzUMOvVHgj^X?yP{{%JKw_1s"
    "IeATX2_|1Qo6#{+03kJmh&?muV!~};!F`A`*|j+*%~o;hXmZ<Pu&2$=R8``B<>?2LPrA^_BvaHb{Q}2zV#EgrA}3I)8YdlGb8j>L"
    "sGtNP>*ML13?HdK*~>c9xj2~DJcSPF6s6qo#KI)#Z)c8;5HXA}C-bk<=WI^D#&xp0bo!;O)0<2un@p$g<oTa0CzH05N!yw27eAYM"
    "Zl|3r0iAwn>|`c)`n|E!hg(m-H|EvWGxF37B;^wG@jd~bU4FcPCTfo~{CIQX%>JO$q1_y_3p1Y%P4QH}V=U|e3B(fJY=SZxM_f))"
    "tHXy1PTwIu8RO46x*{x2hSo{hqB?zr<&3B4&R8Bly%BnH#^jW&IS2Ro&k^fxCyNXxYYZp*hm&&NNl4aCR`X9fjm;(O3sUlo2CBAc"
    "`xe$H(I94?Xcssdzq1J1dF64QGupwd>0*1+<MMVGY*Jz7i?Pk7T>K*u4yFHOdi4*Bc|XibezK;{qG6C<JfVH~9MG>CC9hq5C;^Q>"
    "$-sd6p-1!X<Oi|x$!wSb^2pM{$B&o`<h!C*eJTWBthRrcZ+|)mxjsXu3_n8|`beYys6S2O^f@j2`FIiM^GVD~Kc6|c8{4dnn|@~_"
    "GJsp!iV>$7y(s+5&P_i(Q=b<zGb_+C=#Afg3G~*FphFqFU^1~b()j(~%_G%-*;#?V@v|C3Cobjo#ve@t>|(OUeB=GmIcAH|s+-Vm"
    "+z9Y*6`<L$g|U$gcXUAFS5pFPf_{tCVoLH5a&jluyC3y}G3?M{11a6rY=JO2V7HfHdIwH>JniGeN8*MLjMn(YeA!{w;YRDXqB`{^"
    "Y|dGf)SXu|gvSNj$4qkQJ}6B|)=8gO5;AY*H=8)L3q$GNT~rdjw<v>3`AnVh##72bh7yz7+oUGL?h5c+AjJOUF@Qk%c;5Miz>Ozb"
    "MfH)-r>zQ~I-%W-l=QQ>jGr{kXK~d&$?l}&h3i~`9zf(YOg+~r7|FC5dbe2%qo6#!RP--${8GkVLzH%x6Qn`qSEqKUFh6l*955SX"
    "S%G9qkmzMX`z#RR*9xirnppx8AD?~BL5v?E4lW$&>QosAfNpw;QS^s~s7IFhyvam}9~r+En*Y~gD)D^N(}Nh5a)+VBzBmLtaj0ut"
    "objJ~#P{r|<njBPw)?%g<!>hU3raVW0$SiO^Jrm{p;Ao)ZQX2ttU!0HziwxnWj0KB|BZNW^x;iU`vJu;0E$j8yWRA_8g?s9a<iZi"
    "q(G9tL+sNZ;*Pf6?Tn<Eb2EoZR3>jfO?ZmXnDjI-kW5J`lfiu0g-BhV+qd(wL1<RnRg6(un?G`Mg-k@)SR_WH)4Ngt2ZC-)3ZRa="
    "+L4mj9oz0Nv+o@jet>99fw;QE@w(9jf5PFM9*&Ie#$z{Tbo@=s2jZ{zMD{<HrW@^YXC&J_Q0+Im%zksH*<-xgZx#yst!}oj0|-jc"
    "ox!EJyJ*@5O#rc#rG$xXK{)sL5_cEHshr9RLF0wl0>Zch6-sJ%$YM&1E%%_bCGf{gq<z;DSHesY7yZ)&=nj~vV&_<MgPT?tMA(qO"
    "aqj~0P+rmbEei_6P0?Ve`-pV%QXnA|i)KeRpFA;K#%|1)MTi%q$(#e3V)*rE{U(F#>QoXYyqReGm&8yRny##YKDK;YJnXf_^0{e0"
    "_2%=h0taqO<gK~kG)sl%p}Be6%8ZMmc_a~(3ttf=+*^1!fB`*iM}aq*W4l@0wCg+C%}L!NCpRXyW*p3>$k8pW5$wvD<x{g@YBzpZ"
    "5R5&#&~>KP=Fo~7!mHgJY`E;$4bgv|=`?M%!TLpu2H3*nbno^_Q`3L7ZgHma7KbWti-*zX>hchw6O+!SV|*s$V?)L@hQa0muvzP9"
    "Iiygtw$XC6aMB_=HKJzO^iZ5|NBnW}?Z!zk6{Z!)iFmC<>#$KWK3@$Jj+cGO!8oR<Isc^Z=F?n;sFS}2-sqC;ua&ka!WOL{8j7pF"
    "rOV_l9hy&T(Y;zr;XZ7iSI4f`<;^_9;u-a+Bap_(V?&6cA?o;uV64!`V+q7#=r`>L+aK5ACqBy(`k<N*%f$mxb}X9>`)+^5&`guz"
    "2ypP$jYqdLUGZ2hlO4O`=?;3@l74k~_&t!9s4@pF^PmkJiH|&@O&%6_$1G7>6Ep_4Bd?}7aV1@7rA5a^zU@#<9fatp+~YemuES09"
    "zyt1wM;*kMMe5O=pB`V<<D0tk-kq_Y?KfM2I(nqqvz--r*T4G;OiX3Ei?DmX&{<}=xjeN;4;=wNAY~VOi!g3su~RRmLkX41VrNv*"
    "b<SG|#f}QoodtJgXRt@K-HpEco$edkng)x!-Xq!GY#gRx@JEf+dZ8FR54Y?;cc=NG_Q$e!fT|p~T9tLrbJ&X#G=JmJ?~M|SVi=CV"
    "P7lkc;s2G0(T}JnKHES(58e+H)`tQ8Wbh=;#P6x-VDa6ktMNSwtzj_aj?E+epzwy3emxe^ZO*37_ePf<q>s28MSo@y^M1JpjJKPF"
    "(CNN;fbhn?3zWpYDFu_sw+`76!4cuyqILYmMR;f{+6-b^3-nC%#Jt}yV|TWCvX|b5UH<XcU@>eUz#zDX@4rq4aWj5A8xi8|Grtkk"
    "O1{t%`*c${QJYS;uG4eC(_83bXb>kY{v;Ib_awd3eiDN>%TWT0+cP-`edNp*Bqv{gQkJZ}37SpFvvbgRJ(>8uCSf1i>gURo4&Bi?"
    "KeZxMJ_Dhn$0=`muk8T7bvbl0T3?;OsFrv~P0(#g=i@cmNjro{?A(ibXhO;)ih{mB$y&!7<^lZ?)$A)p+xOEgfR2t#CP8qj3W~a#"
    "5Wi_%or9HSHKWZ?b+yE)hnru*xg|U3to8(}W5}VzKO%1_2n}>1?Q&vqXfbwZ4`8^g?lXGqxe_eA0;n_nF?jKdKxS-Fo?%g*Skz+5"
    "JUzv$K4M0s;_i|XPwY(Opy4g~qPMYw&oC3Oe^4zXu&m;h9x<A(P1vCkkpGhi*u6Gm3##-%9X!&DpoyUNm+TOw!`Pnm3n<mmgO>Bi"
    "k=aKkstVa6UH|CY3<)-VPY_HC2A2^&hdt`u-&=Yv{?v)x;Kua4zDz?ydPci?`X}ze5Fou!kdwDd!G?pj<A}*sFahV{bucq{RP|xg"
    "uDr~W{@}#BJvY52j{Tqnv^9Q9uVrzCi0R<N?dBCl5-;+IY3+}(4@dZl&x*%*#PIlz8GNSg5f;rBnPPj*VT=~wXEG+<q0u@ryUI5%"
    "_uqI!DnL<WJ^3T_lQv?Y1SHM^S)hm-W{#qSi?7LTIO)c7ag(91PRXs8*kBx!-j4%_>ac<LE_BaN2N))X?4JxGU$21N=0w$&6J0=a"
    "ybOz1SPU;gr|&ttRPMf0^hRFeDZ!A@c#lWS9E$Kfq62y{DQ(d>HuAKgxh9rC5_{}G1?ZZaPjCj~h!AfZ9ZtLL;f&<moJiziVmJ6x"
    "wqzO|eM>pqZ8`$2EhRsVcjJXlQAP$m`+no?UQzeIO@D&A>E$dPv=MWqKN)(67*fi%KG2*vI0h|-Za9aniOb~W4kQLo)j6xf*`Zl%"
    "xbzm~7fvn~4ZF$j6oK8~V&Pr>5)3YWzsQU&Lh9|bJ3TI`2zB8~)S-BJPN0MIU^haiaAOw$?gPF&oR*aD!9+d^|1wkwl_yJ)U<xFW"
    "CvCe##}krDHhl5Y=Z)R2No#;x(nNo^=8}oGZEjo-q^p)56vxq#3FVU<@rMd8AIJW&;L|QTR9UJkP1;E^jZOS}zFdsri)Vgr3C%fi"
    "3rYXa(8YTgX;8@z`xu+i8E-lZR)SG{?Pd=vgjMY1Td{#ZX6y+apMCC|$3LAaDMn&T=((x+*%UM3V4yHqPtfn?!w<SjBY#h(a~xNL"
    "wt$Q|Tcc>#U=P#Ge6a$i$2sELH-30zCS8bUx(2g>Ns)YQx8l-@mqXZuzxk1JfmOlOn29D<;3xeRJ+KK`)6m~qrx?-Be69w}46cX8"
    "*%1=(Si)91dvcTFS)_X~RC~OS1fxSrH|_k;7mpZQ50^0W=a5Io)%W6sq+l8h>G+8<Glb4IkwA8i<`ltxuCe&2&7NuKM;(-gjvU~M"
    "6UCtUMl+*r*qfiBoxmh+!rjBeF`_yN<$~1VRJJqu1&3&;K`=_AdryrgREUPfB+*D!$CYU=F^uUaE{?ldJDyWjRET(X2<Gyk6MMoM"
    "IctL`2-ewtV$Th8%<d8o90SUi8<gV<^~#4Vgzk+@8Iz}sy!Zl8gPfED27mw@EH(kn=wXC%@PI#hBymQcVaAj=2?8oQ78NEX2~JYn"
    "{P^O8N)J7ep_~%{k^v`1gnxd*E|?Zf2V;<gX~EcK^N9X0n%zIQx_>Fk<KH#D{tHEs<6weNbEp1sGdwPH|38KhIR+pxSX?6@Obf;?"
    "q00NPnb3;)4@+@L?=j&nM)se?lHkOsPcb;;=!7s021RLtJKiVSk&dz5_%(}Y`XA4fSAnlDm{CLK<jgI{4nn^17bIb}QI(r-8p|@H"
    "I@nAJul@e)t&$0SF<{zEy{;$*>E=aeQC335pvLGWF-Ew&UR3d~x*kWge85`Q)rL)n-^4ijwIWONs-KEY_+3f<ZlZkOt5asmCK`rp"
    "pw`430{TqmtUyi<$8<C&rsp|5M4s3`(Zh2zugn0ElgrsE6!W3%D~8|(*yW)!<6<sr?;OEsT%3%K!~D;y^w|}J0Q8%U@dmH}i7{sY"
    "D?kSP^V+}^4ADMD<MW;-T9uu!Q{zwXE9EE6;K|zq6Itb-z&U}55>yk0HYoW;p<c3AchCC02~^>}G&>+Bt%BxnHq^3yf=1R@h!Xt("
    "I^K!3GC-Cic}^+{676O4sW2Gq-9j|{hPkjYub&Sec2Ul>kx9&s+SRn_k~%=+V6Rg5E9Hev!b#0%sG{5B73JV?-WenEUcF8k2O%an"
    "r-g>XsX~FvM5y@KwaflP<&8sTH~wjPvp$hy3ylM3H)$kLLS}r0XFV~^m%=H3x({{BQ}H8(I>$7v_~iQ3CVjTdn9!ETg=DO<QkiQ^"
    "iNw$-^jOsrm;&=<k^gK6;%6{|!O4YJQHTUy2hP<3sJaxmB7S3MViKBZTvHOGhls==7AjY!gj#U|6oVdaV|O#pX{K_mH^!1tIeYUS"
    "{Vjx(w+ex7bI78`7QbKs6hvdEcmh7uYJ{}yM(5Xa4r~<VR=f_IEuE0;nk@^CWhF-zALwNHusrtuMfR5;_O-e?xG5{(XVW(h7~ZT0"
    "bG&d;1_urqimD6`&s}vM*?|g2X(lF{Y4(%8!gLrY3^XtvteF({NZfgX`*8%vz@;P8kIpyi(Mf$q=L0(**!_WQVq~@pawm(OGa?fx"
    "L0=-f>5-XRcAa$p{0WAy?fm=6h=Aax%8fU0CapuWzx;1eTi2p-*1ukufayn*Eg%JAJv_C}pAQG9!1)EU>3rYnkC+G2!<fV%W41W`"
    "0}dF~(x!f|&)$|Vjh)-FFASz)o`lnO|K^9-jhWE&hRr+qf^4Y3H}nuaaGzac$LYYbn|4!tkcWZ&Nz6LXI{`g?OB$HBSa#i5W8Ktg"
    "Cc#@uIvKMitqpFx!~+aK32T>TOU`t1rc+2V{+y@7eh1}}$Xp^QC70-W6SAr8D1}5;bqQnA9bN*685c#7<HSQSdvFr3FwGb~QWzc5"
    "-<o;BS@=P8^MvT6oPnH7T_H|Ix<@uv;067L+D0E&edcWHS9jACFv6CPn|g~gY6S-HSHZQ5p$x=P#$xj2Nn<Pwo^`8j;s_mXV<6si"
    "F9YhthELmp!wkMOrI=Ks;5H<=CdFz7swk2b4WUvjb%E_3!73XG^=2m@L#VN0I8nK*K2%e!C{_th{VPr6ZrDr@px92GT4mlbBKK7E"
    "(jMx{(Z;HOCW#iPJ*si>(1mCUCKL0w2psdK8bmgC201jGda>Bg>32<9i>SP=KY<U!k=9(3rr>qzTmBg9QkDMU!Il5NO<JKWrc|#e"
    "*Cz*E>q~dpCu~p($&-}o+06vEx5?10s?~de6=^+338jHo?k5YneJL+fLE;j3a4nb=NJZ&S)Hfci6eUKok^QNe!p%>3=77~Tn~Anb"
    "<O=ZBk}0teqDQWrW_S3G^sf2G3H^}7mwbG&Z^npFeTHsAg<?+$Y_6w`58LjP@kS@n0T6@jlr*nlOrTY4TK*7CKncq;y9I7u>aC$N"
    "3VYaViPwvaqPv0o=`SrnF&u^nz{x7T{n;GUu3qq#*5q`tJ<R%mRo$53@$3pz0!c`Dg0=|iYTlzWPRvVS3kTcBH}9NQly0^gN*J5t"
    ";e6X1l2KSRG~a>p3n&ZaCKUpp^%i_^U;SngSS^7C2SAo4pmc;-l;U?_WV)sEHfm8`xtZz-LQ852^As35PH|-Uk)4KiF+|z6n@qn_"
    "L1_|@2OW~Ag@0a8+$)})|Kf<)FsXWJ{eMv^g+nb>4>?cz3;iTh8zL<$!?k|9<yHOAQ?XFS`t8xAazNRXLo*?V?m~@bi}h{HHmflH"
    "*NmzLvY74$0=b-<lm^iPFyF15znYXS=;}B3K-I6-Mkld2Z<bl@`68O9gFnd|h25MB9#RwH`wN$ET--03`vt3^wei)hIG@EHn733f"
    "f>xgC5<m&#Vrg?;i-*JcI-JYFw4(ZmPi2KcGy@8LXjcwo>9QXBeN{3;ibpKF)`NkVCvrvMDf=Molh+VoXtS1`-9r&7ZRNp^8!zZj"
    "N<nc+P{4Qg{AClqEj+uMBWHH1HQ?&WeC@21O(0j@!qju7+Fj`V7;addj5)W?nI&xJ004mP*nHf(>VCH<B|1E8>8#fznk2<-44@gS"
    "t+y0lYo7tC<9??d`_P+U7&!&OnQtBD$BSkDrI%EnDXXEL2vvjQnIh=Z*6vZ`>1?p#Q1uHHd&)j>Ty<6k`8c+qR2KMSrU!I;i2QHa"
    "Vr57Y2jd9osG8K&;klxaQXO%8Qj9$_F%X3DX}W~<{3h%vY+~x+<k}j3p;L@Kc6U}EWvM9clPV-fP3q}Jbh4~cxrzqh&m-tR3gVxZ"
    "L?-?qEq<6MRF3o4p9JwS{K?Rwe`stTmVc5R?3sG~A@v{H;LrE6zoiBJ5U@o;2M;XYDo1wf@3V2Dr2c-pt$y6+In%=Xwv+NA256%f"
    "(t=6m4&Y^KyKg8Cv_2r?b|<1IX?WSEUDqWV*Cg~v?2TW7L9-$3S~B)<?O`5<lgM{dlGn3)21)1^b30=*Qw^N7YAmWW&-et{o}BA)"
    "zdVtvV#}Byn9F~5l|0RP#WR_4db+f{i8+Yruny34UJ+pJAolWfIyv$?T)@KyZ-X>WS+$El>_+{Z5L$Bcp{eF$g)PeHtixq_`je80"
    "Dvov5W>vj;xs|tHC#6&pHLf*RzXJ;lfJ&3LI?0ddSA1TIvki^5tjAso;OUm$4{U&i|6~qZb4Ofn1UvmwI9$?V>$k<(0^Ww5G$M;K"
    ")4!(t4SsY*OeK_>JBM@!fhoT<PS+Ik+)2&T+*7>uGr5m+ua?|NCde`~{cl<Z$4FkY8-C_umfOCMr1{XVC^71n9Cz>u-RzZxjF!Kh"
    "*UaH4Ep8#8&3w$HfMyJTWMPjaT)K3w%safo)xb7<^Sr!yJ`N1fmgsveR&XbNL;njCNfFFz`a0`vJ7{=|_RpCVQGdq~pFwqd^{jdM"
    "ta-_-dCjb`nZdnCQM>eLEtvy_dS&sRjf9|~R|V6$L1T(5igGSy056NA$b031XV4u3#x5*UG!_>`wb0m@z&56?qD1K}PT_870aR@z"
    "ll+AUaCqWmHsn*St$sV$_je@Zs;xx1C(|%=yChQIZ6I1pzZycXUP4by4jcR9EmOFUdx5oRz#%@_K<v@ODkasOjqc>TKge0?=6^86"
    "a&D_5S}mh)i;=d~e~0n+0(vLwhRxz{cr+T+z#!|^Zrb2PU7UuUpo|T@%?u<%HV_y|#X?Jq1<N*K!vN;OW+dqDkR*$HA(G;}Ipu=%"
    "8ywS`V1qpqy4e08gY<>Ly0X9@clf*P!-N4tfCmauH@HQKlwuy;h9A#gCWFz}<%~1nSeWn)o|K=UZlwn&C%Lhf!};jJB`n=ez72jd"
    "BG{lBMg_^x0i`_F@Ur5>0uj|V7)h+X>Q{Ss`eu(uN-L4qP=cw{sku@Sp}`6`QKHwNMDW6eQvE1B8!F&P?w+Q{^^T#J#04VOaNS(S"
    "gZ0wE0Zg9^8{XCsB%l*0;roHhBbgG76l2}TCKsH~930D>)FFu<wTrdA@kDQ&fb;YDD@swJO^f2dpPFo~Ug85K!<*CN#iODVIc_pC"
    "f@bi>f`AO51`m|c;ZuV{LVDz8U!?Ehg){AAqvAK}e3SM!xGp)idqwVF3i{Zdu6-e2%<|2ovs4LSy?yqy84|Q9b^CVBGek|Q0@%3O"
    "GT4mLHUirt!|NRMH+mWeR0m5Gm|Ro-G@bOS|6r7u*O3QRt)sJp%eI4A_i$w~ljCO)x4~0)H$Q7M!RMTKQt~#;GG`fa(P!{T-Ho|~"
    "W)KA+h9?nd+jY5^^k+piyU09jjyXeD&9!e_xZ)|;4dk$SnM+6(C``R<{teno#i_0>{Qege-<nfz*_5t15nash2aLubI@*tu{c$qP"
    "HY}P%>EQOrM1C+v54O05Uis8s$Iu4WM@WD34E}n3=r(wv6hMX?zF#CH(}%AR2~YcTr#^VE)oAy(28Q7-uGcU8lL%<IDEZEYF+gQ>"
    "mnVbGa8vBw%#HIigTBzY=p(RqU(NwjpzUpf|3Ku;w;4uUNtj56B#8&FMBIMgYzzI$`PW-u|63Pcq+BM$9dE&AYP%AU47GqdQ8#f`"
    "l;{x6c+^g-AmK0jH7{|FCp#W(VGGsV0Ako2Xv+cQW+S*s$EGc&_-e>mm}WSfpwvRcmdtd*X}N!0)}=y+V$?wrQ9b$q;>NeFWNA&L"
    "xoX-eP;OWKt*)CX#$>u^<r!`cEoPb_ymd$O;`jgz|0)${bHrOoM=HI5jG)m9vBP&a<xBXsyIx3`aM#z|SpWt{zz;}u`5v%v3qZh$"
    ")6IBe_$)mvK4JdY+yZz@z?>5#6MXYMMcDp_ctIAdJO?r9t~WIGijBi_{So9loQ!Mv&aK9YgPOY!O5#4=#50_a;k2Zz0P;eevT-{h"
    "_4xWn>TaHo^ocC#*@;Or1^TFVZG6&WeB?%#c~Yq4^O>l%r_Mo5*eJDUss3dCw;>p`##iP$@<QF}9r;P`@MJO5#4>51umU6?92cr8"
    "|N0mcsC97{%M>ClIlujx`CW~TUYDC%RHof%R~)(m(WmlHvZHG@|1cF?{o;dczTCFHxL+$&#=b;0DovZ)&FEY)t^jVwo4XDt=mkf="
    "(7{QUJr=-W$?+yZ4PZ$LPA!7iZg`++Y`#7ZvjaB72W;-^6P)nskYfv20{Oh{zEG*#>@@++X5ygwHvO50^Hn0Gn5g+Jz3IUb71y1G"
    "6qcs_6CU<K)7z-~&AGHBaFg=O3c{N|EQjb5V+Vhue#QsTY&MILEkBk3+dk~q)xu{x@0P{eW_yC}i)l9O23Mf}S_0F<+n?F~ZE~!;"
    "GrUK#dv^Rbz`MJ!IR<1f8V%EVwuo1~><*=+ZUe(8`9kSf;>hHAwT06(l0S2I^lnPO?*sh!LqE|rKk-4I_@GZT$B$+K!U|GIyMD(d"
    "-}}uXdA~)ii76M;QZW7U)BkMp#f0ayGeS%*ERG0NzXHSD+(`Fm75dwY(@9hH6;P#nLZs~;*!C1&NW#5+&nu;}heX`{ol$3drh@j2"
    "KCtJ*L5?fz5glxDm0q-80qdS^p`AKsf{mStZwOEDz~q34>TUgG;$|pe{pa2<j0jH0;Kgh>3%328!hGb2#0U4_hTSd~Eno{B5aF{A"
    "j}N<^b#(=cBiukqA#AbR1gk^klI3N&AR8Pc0=)z5g>;LDtl~SNFb>HGP*!xIIbu_?yk#SJ*~E8E$OhuO>#y`MDaxdTO5oEeD^G$T"
    "Bh1v`QlQO)ile?tTFq|(Ass_4D6D^i)Q(lo@}xQI-}aJlv!ywq9J;8O4YYPu^pLBW2Q&;WN5p4wy%i5QB^po3rxhSE&H(+Ud}U|5"
    "1id+32QDe<tKwSi)!$L=#mY*tyeb}Gi^W!{F7oQ~MGP0~uu=<fqu=O7NW*66Ve5=`OM{6BsL~l%N@wigzsg1jj?eG${XM#G{3BV6"
    "js6Osu7h!&oxO3XW@Wghty2~2RK+?~u})Q@#fJc_48@f#YEXWVU9{^r&kYJ!!wxNkeS0){FBS-IYV2)&o9>`L=9XZn^EYMjrhC0Z"
    "MSUkS^meciy!tJMsC(%<6U=4xjy9s7W7w1K*a(j`(D7!gCGXtbI>l@kreHkwh@)@5^A)CEULxq&oG<5+r%hq({j}rHLUFz;B0>rr"
    "3DTC{ZcA^M>)Q?T?P!{n0O8AD+_GmE?-pO(ERglDPRxfXW5Ap0es`BgN1nX91;e}3_w>S!fzcGSb2a6=x+TQBdk_L!F!sTa{T}Y$"
    "Z*MHaL`9F!q<RM$`*uws+wuqq)PjvL8Wum6ybufKTKp}tUmR%R+4PDZgZC7%u3j<3dC#uP$vo{@58H*GTrN*GS5tel)j;{-2h;#9"
    "<eIqh*23yP7y{v|1lW&THV<yvTQ_`|i!?+)dzv3t%$d&R|5Je^l-DSLyc+J-Re1fJc(RSjp)z!f@{c)dG@=%j5z?YrM~IfCJsEpy"
    "wmn?Fn`Mt~!qE-eenAN!&f<AhyGlCBx%g$`;A~}oDF4klDDf%9K0WDosZ{G1(d?V`CT$@YJjAt_x3#xvHf=T$sb^8~cQu%I6l~+a"
    "L~A_KvtEz%tp2fCAi`KbIBQ|!nF05yfgbkV4ZG!VzsmYr*=YW(HaPbR=WHH`hvs;C$lcb1M!FGu_psf1_LQUb5Q?qW?ZT+@sJ?D_"
    "KQYY10)|ZqGYsnOTs#Og3y5}FqiSc3hI&{}IxIvF>p_P{y~AaCP>`I7U-gQQX}=Jk+QV3*=nrN)$LithpkNLf^zjnOyT3p5ze`;`"
    "+<*@^;DdH{?88NTnAnF-Q>^^LNtBX45XAgEY1Pk>t~d`<=i#7wk1K^E2OI{}ORM(!6?Zifq+cEN;QwDB1$lI|TPd&(?c6#~!<}W~"
    "7LWq@3=cy3gHO3o?mgD5Xe`~Lsaqs<F2TZ3?A@bne^oNqb4(PjRmJ{iB&9h@xYE0axb9)gKYjrbmX5P~H0;Ck(EdY7^q(AnryuHI"
    "Hojj0EorJRZgPVFRvEeIs1?7(G#l)8xGjxnbt9VHI6Q|KuD0POq(x@{FAf+TNSFd^xMx#(iB%?ROea}5or81P+`&)8%IR6+={e#l"
    "sR;G}hab?>b`&RL@yUmtWcf^9Kl3x+D-YGII*#E~Gs?kvHLWu<{XY4=m>-`M^I2&yXQd`i>$^W=M?LxQKHa+3>8A52YtpGw(L)po"
    "lCE>LtBz2MD0ZFgTy?->O+0`*K{`i@<;LWfX@$oMge~gx#4~`98X84+n@Iewv1QUBioJ7lM|dVLHl}+co(4~iCa)hRuOIq{-)myp"
    "r;R%i6+z<hG=T-G-UUHEGnq=P>?IaiCe<*kpYtG}!~bTIp}Q&h_flE%3R&|1oL0Xzv8GrdOI{%p*!Hq?NVO7PpIH6q1YjQ&*p_b2"
    "L%N}iF=w*_IZ2et#%te39UoeGW&*ksI!EgH776EDm<gV3@YncrDSD2L0A$n6UwH7roBi8uI0RPpfsB$uNc<L>X>&<9D>2zg+rSHN"
    "$%5JLdKXK~uIEH2O2F~+=+*y@7EsW|1zh}z#RY5)a>8j7g~_jz0Dnkv=@q`NM58QGR>j4^tS1%oCfuAAgW~Kr9|Y7$Iq-B`Zq}g_"
    "Eku(@%4ITcU@+B;v)FY+3}loS<1e35+ac`irFWRk7{(lMIFmi1=M(#QQ%mKS&ZfaI@jt@}TEs|Fn^<qs!w;s}z_+*6Mb4knfz#Gj"
    "o+h)|*|tQs4n0*f8ItiKW)RDCbCYRm=izc|;r8VaU(pX+<m>@S!_hK!CF`^L6Q3w0hA{PW4FXqMvp3`d=T88dj1Whs(#%)9Kva7d"
    "5_ONhIGGP&_z9>v+dJHF7U|y2iyXqQFzd{u8JFH^-+7G!5yz)e*oUj&h(CGj$DIZ|9~Gf?RJt^JO=4pe;N!i4YP6Y#8~P4E>V+zo"
    "ZbXL_goM75qG?lRJ+GXp5T{7^>~43m>E?%`o@gQ*jGYr+f1GdwQ1T|C>rWgdAPMhYl6`4oD1XE}@%Geq`9!_XZBT8$7A|#)*^+5D"
    "3|zN5-nMtJow#-u>nFM~zgX;i{ViUKLqV7f8{gVgTvLEUXg%*9E{;s+=lH<#XncSUAQ;Gs)~~?BQI~GIgtzV)gSZIL<0DGXVRJgE"
    "N_kcyc#{c#<eLU3jAD4Zp^0fuHI`SzbVv5K10tH$i5K(w#mxOeyLzSY#e5xH`BYD_UpxwHXn`Xb3#pf;q2#RXQ2_e!xuFF{kR6Tf"
    "rKzN=pq0qtI~)1a1x%EWenkvA=5R$>c!gU3T5$8vF3mKfznH&H3hnC88h6uVh@#{GP#|#(f69nY(G>_=oCX?>`IA51`L73}-=Ysl"
    "f|8pF<c4|b%d^xMqlR8-uxjJ?8Yb+N%7kyn%mg0zGgI_&v{nyz&>@r7xba%@7C@s(Z>FQK<fh?R+QoE)lkg;S6j(YP<r)2OGJJK?"
    "FMN!)PGNl|b$W6xhQdw1yumaXi2w>Cd$(>Pn_e#u;;+oViiEw}8zr3i8@gVphoGcPTy4kXR7ec0b_r~`xmjg9QY-8jOnNK^JnFEQ"
    "k&*z(;AL*icVF3mEHFceEjc^95--fAPQ@>Ch}mqhvv~+sV={z4<Y_K06>Chw7LGma&kOBtSH|R5w2@rm3yXd*7I*|hbIR70UO{z&"
    "6|jl+pR2>t*zz0V*xhgQyIR0q*}vxIuiSKyY9d;^Ao&}j9EUSE9RF}FFz<V9nsmRsLn%P#des%OK<O+xtcwJw?z6haBC6J?eRI4b"
    "O#M?(p>rSif?=@7vU%94bEqPEx}pn!p3B`FGaecz<E^q6=LKGs)>==RcthKM>1Z!B0lMF0#C66v0M36-Cbl(SoSK`!h%kpe+W)xL"
    "zh2?nWk2Y&Bc}h8$>Hg=)Eyrc0(V(O)d;e-+zmMGA`FX}{Unf2=M?<PO;=GJlEW3kNukVN!UUNpJN~gz#+a+{P|c(Y<vsif2b5P1"
    "R`+IgX512wfv@zHy!sTWnU1&3M&>EPH^|jap>wj19-yf1`hx}bo{{H!!_drIS@k<KKn9eK1ZUPS5Jj<2ad{doh)nU)*~;2(MkLN@"
    "DJA$I<_C}0uNElz=|XtY!81oMfrgRu2m(w@bn=sLecHcQS~I^*S+jRa^+wCR8XJ(vkgnr5+bbSvO_?(Wd3RmyRMzg=QajB%U&zHy"
    "gCmA(!PtV3?1+S9%M4X{cUn_>M=xjb1KE~Y)8(FmDAp1@dQnDQ!ibl&8xGTCz^{t$!1c)q5B>SM0iM;1A%X1FJS+&a!H#ZL<v$U}"
    "@02^mqgfsx$(<RQvQPG9f4*mL0EttY{=3}7kEwelZyy*Owz|R7L$fa;u6i&<)A;=Mf560Kn{$}Zv$+B;O8xp;)5O)3mWwWznafS8"
    "lk<VL=KKvv&L<Ob5TWhR-SqSdl!(6ZgUr;wYbY|wc{16wSdfop^X4B<uB<${viixD)pCjZAS>5FR$fzCxf8N-C1mwhhH3@}nmJ{p"
    "Ur{<<DuPK(?r!;A2i`7BFd4d=QqA3ct-FC(<q>Rw5zqzio#O0`;_Q85pgNuIs3H>sdfLy46T$dUHy=c`Xv#(>$LIGP$z<n{a&QXu"
    "*P%mrbYHv?<Ba@H!g+N-LB`cNN24SMN_j?E6P4ZResH=UoK*42j=#W8PUlq1**FimainfrG-K4GE2hfE##C(5v>TdX1lXAElVKgq"
    "AaUYUVBe`52>s5EEcA@Y;K}EdwuO$MmAl186o0S<Q-?9!55vc<F%*dN3V^uXP|zIV9Ec)l@VdARSoCj8!0--%nBfeZrtuZ5{_2Xl"
    "DCz0$-J}l@_K7z=;JNasf*)l=g*|{DOzib+(uFsRH6K9Rcs|>JB}2sKzgw-m?E=LQ=aF=xUsN|;1TKMzRQ=}fmeMx~7VN)FfQF~T"
    "b}T<^nag&8`^7jO9)_PoHM<d84NCs2=OJ4qOr_@Q0}oHA&R5OBJ|aam5Dh~C$OmiAKH|2a`fZ{5O{~lzCxc_OAU_2Fk}8d}Hb-q;"
    "M`$-{k6ZWxJHb<N+?W#BTgQcf!&!_JhaKFWD-DDT#}od^pSJC{af2kN+y-?#=p3W`iju1T*t-_)hpctEAvmgT?oN8w6^n^ajui<T"
    "V7Xs8iC!1hi2)7dRc9mbc6bqLhrS&#UYVZN_$lvXeij3-qM6wOr3qDj!Y0^yKm~P;+ZgV@m^n~a{RXR%?o@9<lj#m<O|;%v@uO8$"
    "E0Hz!0qV-vg<Z_Bqs3KC%$AF>eb6HKeoOpK>?{ZAj-UvGG)SEG>-4Lacf@o%4(vsEM~T1qtlS=iuE1f+=iWW`gBhfZ?`T;9EJI+K"
    "Q8R;cth^n#*0lMxM>s$Q7Hi8j#nFe#GHE3XY&g>YsuM-Inv{=AKR&KwhL)uF@kOPZ3Mw$51bvXEE@6q{@UY%eJ=Lx;(*{-8VH+zV"
    "2!P7p(gBU0pn^R0_B24Yp58sEmUt8RV|_5>=BelUg!D+k0BE$&;S-#bp%`8k81*GVSF`V52o<?2gCoC_a{Ua3l(Qdxf?@JnB@!la"
    "AfF->aw5VEt(fiKN^Us!S+CQcdez6tcT>D*JYdhQdInJ0?W%sn3=HT232XrovTgR&Z46J{F?G8Q=xMtXJ5GK3#UKH>+*aO=TzNr="
    "d($F>O3nnca=^B<J&$vh&9AyW2}*Zm9#rF8c8%?@s^i#%&Q8UpIKed}ru=b4sax5$D2}i=yvxT*sCqT+lArMb_I#D!Ujbev7{xM2"
    "@~}@4p2p=(I6qk=@Tah6S7S>~=%gZFK7yw^!Tz${rL;%g?D75k;`Sd$!0YDX;o%}<3e16aXVF?{=`6+`i<7M_KDD+mJDJ+@#Sqb("
    "WH|RHa2xUYI?!fQ>er%rYc2`~&<S{eB~gE)BkQi<ZdVI`b{r>lQH^5Vt8O1t7y8FZXaR>aXOob`9(`hWpV(c6JBNL%=fRbEaP>S`"
    "Wx2UMO|A!|z`R_{pARGr%xNq8Wf`#ge}_g&QVc?SXJG`ey#wp1uZijY3+zxncXtQlb~r%J`RZLdq3B}3gY~q!@4Ryu3@*Ek-rN^M"
    "-RpAnYL^-TMhT$RhzWbQ!kzan*SecHP<0ybW$hOt2jIf#o}AFzSCHy;K)tee<6OO$%gJp~%n>f=oMJo{?K;95$?C@g7Z={O#XHQo"
    "1mB#N2P0~$0HA%c@NHaz`AHXJzgrad+m}PkT*0e@*C_FKbvjI(!6=Fv(bvdXTLN5U?fR^i_w@gmI<v*rS*BT^zjvuvNG6elKLm>7"
    "tKZa9t@ZDdu4bNRXl^Fb>?0>JH-x@NpuyzG(^kSs_mJWn_X3A*4?1;CFK>g1^!4MeNj>&W%(XDZEBkc#vJ9BP^pyhhbTcIB&=r%w"
    "+i3o0<emklhvC5~rMOo!vXF+kHC)q<IL<A;tzQm5LKJQ(Fx&iwGwhwVx82FmaR)#{6cZLaxF3&F=YLEI=ATiGgfWL2&?BOr?tpe<"
    "^B#SLMAuNkEr|0`+<uS9r<vYY|7(P@g=xF>?S=txzz1M`B&<Nsj^)e-kufyF+a5Eg!Qlg@=>c_iEpEmBuH!UUL&q(2FwL=A9QVcB"
    "$zrIj16TL)gA0pCD39BQ`^&-D%Y55smqQGjOJeNx_J3&oyZDwUzD4r$0_}BSs|2RqXt#BWQe0{|La#@GESzD07%*ei-y}CW1#5Dz"
    "a;#;GtXq9))l3-HJJaG6SMvCr!BKtvf~olIW`Jp5bD-5%Ozw~G6vOB7J*Jl=>$^Kt;TDX8`tFgq@7s+pm6v1d4(N!<&S2g~qFo~M"
    "IadiT`UZrM2)WfefDv)@%BzDoQv`l;;Y8@w%3zN3W?H%#SLpL@+@~*Sm~kGS64GP6ydF1W+p&UyafzN~x_$SARmkg9aWy)J^A#0N"
    "Oa$ZPd66b)J-FMvdc`HKPd7s+e4Kp8eRH=~#G})_9`?U^2=z-Afg6{1CWTk%Uv^~ObU2*mQ60QZx-rbp&_2UnnD#J!hqK6$mTwOu"
    "M+e$PEL1H0*?1fD+n|TZ6@ixs#aXLOPGbrP)BNR}9U1BpYTbF)`rW}Xlu3ra+sa@Zo9oVqD@Db;d`@HLHuIc9OuNlotd|c>#k|Ah"
    "ZEx};{EOl0x^w1=PVKsL<cd(DZ@sdImCL&oLVHjgVu^Nt-Hqxhe^`9G0dYAOp_q?SejrTa^&-BMm#e;zYFJ*eaulO@Xsn`9#PXKO"
    "{EItM1GM>DcsevFb4#8I4N5EXr4--|vQZO{{|0VQT+_@WHm}H6Hg(G@d(QH5kM{B<Az=;e7HZqJrhWB%`jx{YSJRiz+lp5tn!Y(S"
    "e+}@6EkJ?&b<2IRO;}#efET@iXI`%wF{<{kdf0rO&Lp-x3vXG=%U-cVTVBzWU+z6!j`1BajOUXGH#9Wc@XZN?lm<xY3p=HH@5!gr"
    "0%oZky=vD|2}gpyz{OL)(ygDYCdRzeDf)1F(1&ClqJCKI6Ci}0LdiMLYw8?H7|dqC+c~!T#B4XFU>t!tEU-sr0jUoJq&~dHMC_d4"
    "8~@o)8AC0t*w1LR?Ydg~47JOzW>$U@hdStPYTx!ddv=uGCPE@AUzoH2oE)CF*Ek~-gHwu}8;671VYhj=Nk<dj^`pLmR_D^IFp=Z{"
    "H0FbPuVSE6uU;6(6tULqiJ5+mwr#Jb2JWwRGu;f;uh#Bu*?QWGlh!ievM$sKrLM)~cz{h3rPO>?QOssz&%XwqB{<tBJG!&{iX6P6"
    "9&-b-aNUs|@#5`dcc6~n>0yM|NyRTj1X!aZKbe7@?9zFaK@!fBBPdCXJ&Y8RuYnC<;^}H}dZ0Xg+$SXG&loUIPU{4Yr}HEJw}RPj"
    "OyOS+k0Mdc#mWKXpxp{?Y=fZ=?|hNCoCwhJHOa!;#^RTarMb`bu_RzCK58tEE>UkOc(*N%8~Dx+N?tbixBkjm=-El5%6n`dBYAYV"
    "EuNm0cF=va!xr2C8Ye0Puxfj5z9ify04<iEt^l6pa~)R{CkVPIeo9g}(9ks+Q@ibPf6|h01>~6S=@qW&4N4Ju)3*CE*?kA6aFku*"
    "K%@JvsD#Nf=yrSjg7}>lcXry1)(E<VxxIQNuh8^+vm^T2Zm@m{H7V^cuLd1{>~Z(lQ3I{<b%X7F-LA;{UL*cBoYQIsShJYAtmDrx"
    "814<jP&LNN(Q1d??#M(G+U?Fk(ycLp^79*=O;OYOUDZ1Op*=!O?!YUk6L)#--S6pBzwTsTVLg(?9D>I=gK{cg{2ZtFbPz~jHJqVr"
    "c6qDpL$k{c4ZklN(YWJARN>W5@uV|e?G#??=&F`u5nIbX1TQ`WNAxe0d7K~Z6dvsq{Qvzb+Mi<^-u3+LM}7l$s9pZK{eI-<2jLe2"
    "lJv3A3$TC=h1aM0DOXfi^uQnJDVj0KWEZFnNI&taK7p^2xM0YJ5`bqW$+Q|ez+es@#f-s}(7k-nyG%9HfjlEYF0RV4dhJ?y5?KA("
    "ulf~V^|l?~Sx$jiy)5QQjMH>s?T^?dW!j)Sl$Z>Vm?Rzj2dE<u9-%(%hM9a#u1cWQ&DKL#otp2h4tm)JF-Tty_3I1GFNz|4VdNO|"
    "$g28zmEa7t^O;k2VY3>VexUg58aa@_SE7|o6Fz6GWhXnEVzArc9ucPSEzShMj~&(F<HO2NtdBVQs|o&PUtW<TugDU=xgBVVH!AeR"
    "E&A%i;;NU%R=xtPOPx!n9iR3&O2CTXnFD~g8W-J}-d!NwS<`JqOw=zS)K}E;ig`#)zk_7W`Km8H`nh)Xt`m?zd78hdHi9*o!8f)&"
    "_12%-k{>?_w-j}@r?WlKM<#-7BgK)%$%>_Bo7zv3;YABe3-9NO;^7`|-_32oq?=(XRJlsWRRq5j_x+TbS&78;ASCaKW>YM1v8rYl"
    "iRaJ~w)?oT7{deFL-ra0p}UV-TtSNKN1@{q$fj=RTG;L*gzbVIC^I|jNYx$G4WF+|1S&|x;0mz7?ZoQy7~PybfNa1Xc~E?h&zEWO"
    "lAO3N_f{{!YFzaYk`ZnfW7249MGL@zXJ*wh{Rj3fJY=RIaCw%$(Ep1n<rz#3Q40gTK!VwBOu<lt2eah=W0V{&OjrH)_wc222IxUH"
    "(;KYGbP=@8P<{X|=GE@%-(BH56_4$_>I~_=iw9QljkCj)aJcAF5d$Xyw+*1`XkWPgx%T~W3IPm{P7O&X)w9zMJ9R~JX+_lB1}KXG"
    "E3y3rPd({;N-3Z;`<D+N`j;hy^e+^)DW{54x41qDw>9k0E{ceV{%}9o{ZzL5;$wfXc|PF64i$xaH~rDKY>@StdfK_c)zhk0-PsAz"
    "n>m#Ws5x6t-vrC@wmU(ITWFo5?{2oC&nAK{^GybMv?{AdIjSrK$&d~5bnQe2M|4cxJ(4BH3S^6K5rGaQt8DSGMZ6={&W_BTngP%T"
    "Nv1fXbs%zf(92Gk26a-)F?#nYdiU+VXh;Lt^6Q+ScizNyPR+Y72y|ZzKsGI2k;U9!miXsvAii-LFKjo4`DJrrx%sf)&)tzyJLv9g"
    "-QrmdOd+JwOtJQwOfh*mnlHx)bBF6tEwcqAAV;6$s~!j0V7gItc>i*>)nK6OoAQ<JuJ12w?tL?L_U*2XyKAH5KFKw6&3;f&><)G|"
    "7zbsT?CzZf8IW7fnLArCoeP=WX;wcsdbv5E04k*y_f2ByGr)Sp_+^sQ3ck2Eub(`WQzYDrqRw=ua~#k;tsJ1A$U)m+FJT~)wT=K>"
    "z^1pRIvC6M6*!!5NcPtU%W`D?ic&e*eR2t~{h}j|gd?}Z>Il>P7-zd*srKsI+MW9gU1KFZS>?x%2dgu$_VrG~c6buo^}V=G^PJ+-"
    "H=D#@$9_6!r=<I^p>wh!nhj3<6-gw8bW!KSJ;E8?+4)eXY{?3p?U(Mb&M3=)$IYnXpZ12zN+8+=VeQ#1Dx-Uz*14M8`SNCfYi;Z9"
    "nJ<$HWhVBgMaCbGM*h=h!Crv#Yp|$$^uM^!`4=}f|F{G2$EyV~x`;9G6M}I*NV_S)j9i;1{Tn*ymmXpb9A!C6)U4=JWW;$;NhlxC"
    "{ziKA76hVKI0NTD(Ik7b+|5|gm^Wb5B6+hcs++T3uxfKu@}XxwrktmzX6S+{nq~0RMW1;>U-1^jf0fjX3{izX$j>BKKZT^IZ=1Ct"
    "Boblhwjs0w37TzEpz>y)Ad<ojqL(1BnaJ%~>D_lo!mpiMZ$gE-Yn%`ez<v-#{W>$KHd6-t>et|TB2kC4Sf?(trQ-?I9%inYKndm`"
    "kB{_4ns`U6_c)Hj;oFSCln$r<Y}QAdv&5o{kU0mB;=mSoSwDxq#%&||MX~0!zaZ^~!(dHPsl!J7Ye{|`f8@jQXJ>!teH;PgRT{0%"
    "k(y7$;3LX*KPXFeGCiPuG04~I9H~^;IztGw&ekDvmCRJvHS2aebT`Goek2<cy-M2Z3Q>lrJ&W2Z<y)y*m3Y=I>RYAyxmTOH9XKdq"
    "QA6~WR}e*CX>_%GiPAtS*<Q(;+Hu&~FPQ1oXMK)y0NWSM?<8VpZXd!wPYB7TQ8e<dQ6PTIAv^*|Y;)Ue(`l>WF3ehJ+C_(6*1OQd"
    "nwvo*TL;CQ2>H>55U0sbvo^hihbfNpWjYzqGog4}aTvwE7f0Ilw2|KPL9K6&QlrmOcZ)Npqq!+JvQ}>bMs@j;^^QIt_YR<3Bu-!O"
    "a<2rU&m-{Jl6!y-*cPFYhHKi*le`O`FKXG9XVV0XA?GCqYXxgXA%C)TKEwCNHL6IOX6`s5|7}iV+CP>&LVD+<AJOTW;nWX^u?^*j"
    "z<6uhS=z#thAm-MLmRM}>Uq!2+1GzM_D&Oj08g1I340UhE)0OvTVS_1WnPl34N+w1iaD$%f|gf!GxlJl0tjDprvZF95x%!HCvS@n"
    "%ub~qE&_T_C{!Px^l&fVjIHh2fF}$->ETS*)uzkp6Vo3NJ>Qwj%~dni8sU!FGkBrq{<?6R3|lceg}&-0re=eU=^#=Zcm*?u(HUT+"
    "v&NfDFwT;0bDcj9%9tTQPg}3EIZd#HE|J+KFuSa07qV?~WHGQ4%-rd_kW6%8KITz#LLSGQ7E4nzvr_cSDAsB$hH%JbDDbBNx+?@m"
    "0f;Mh8d)HwgAOfk2`4UrMZ;k=lQa0qc)f9vCK$4R;WTt$mC!C6)#A$L>q}T_nkl5EN7*kuY;Xl=PAlD^hXm0?ATVnG=J09Nc#&2{"
    "=j6NiLR`CktkoH}R)+<4Gln$ZCN3EM?*%Z|uMkSdlaIoLMC*Czo8CEPjYP?hxdvjEi6!$2d?dA+jxqQonvCm3G|RDc9rQct65GH+"
    "5Av;xjdS|3&p+t>P;Ngu9GWc(YQO`{?SW&Br-@&?1>XiL__h##<dF|p9k=bNtlMZ467f|3F~m$)OlNC7@{NUtu;rhr84bJB1QU*r"
    "6rqT#!Gu3Y3QG}WwZ#??h!sk5bJD09+fErFd0c>=uD_8`XM`iu9ezKpI+H<~`?Qud-3+mUvl+P*{oBqnS7W-d216=#B$x<Kdz9!u"
    "_vmN`egbTI8k&7coz98QQ$iU;?Jn~T%wS03?uk#bqR={b?%@e3<(+W@Nz#CfB)y94JX|jZ*w__=#X&k&7b{<~4Pc~C$B%10->Cyu"
    "xxYWqD`c^rx6t3ikSPZX3vNM+CQ|}C?-p}7P$J!2)r7qUm&uu<xgZdx4DA2iL*db)YFNAt=!p1r{G8mY@b+j%uGOHf7o!ooT9=u+"
    "{F(^&m5zsjIC7=i`lpBI*XCj6Rfv{vS%WzMTQp3rTmx<&Fv<4LW@m)`65)?UG%ZpV=8i{=;Q+>-Yj@uEd-QNGHaU#dXzepqvQ3w+"
    "u}NC1q}&Y93`qw)Cn}m(B|CMz01!0W`+{o<XvPwtg0CCt^H5OrQiPHc=giP$SJ4<H>rOU$de2j9ejc&Hg<9P%E60pR2UVxn%{UOR"
    "K|tqBt@gc^=*wz##T16y{xt<!L%YI8eE3aF=jtyaZwB*8jDY8ay8&*DVmgR8UKs9Wi<@nANnx_&z_L<M;;Oao(F*Pgu7|BHD)gxz"
    "9-hIK?=am<;A;xcjya6<U-r#JG!LiZ<&NQ$+~~{Ebm5)T=|1X25-CixLHidCuRvhJaf^x|ft!IUg7a&77*5LQ{3=luPd*o|H)luj"
    "@ethZjDC2jEG7o_(}I%Cv|vupjZVb7&M}ia{d^N<i(qw^{C#svo`Q42;;ho#6-)-$_J_G+sC`*8Y@7~mHq9h?F5yCqljqU-O#4@1"
    "GC8=H>+m^xVb9?Q_YB;oN0?PlZB7ZubLd<dHClbXl1raS%(?J!iWxV#!F_=AZ~#k8NzR3~e{z%F7)caY&DhgqAM%z0ovtMZ*qBRb"
    "Vrp;y7~5R$dLSmWqE9@Z)21#-*Qf)gz;a_Z(>*r8Z7^GR-ivW$qK3M~<p?!LP~T&&MVfzFQ73%r?Yt}3mcsMRtHyy|HlBLe7w8P#"
    "^5;g!Y>Q&mi@MN=yx%9+wB4Tvo15wUPR%52=+`K4dsLo#J^|yD?d8_Gr`Ll+4EEq8=+b_8=6)hG8$`E^rL$YgzZQX9BhbntMK0+U"
    "eV}Iwr!HgeH^XH0jNaolMXhq1czOBAjxP{%>hpCM#jAWr_=9ssytsuPj1%@MQNLg8vw^os3$T8TAyeE3C;pFgjuCXw?tblzhH|o}"
    "f=olen!20h$I;MiaAj)I#W%(Vfo(-y^QHXx&c0S`iU0^0YwLQx(V5ft@V+x0<U+o{5t7(@cLSG1;K4A~4)7cm#+h=3g<P8h`HeLd"
    "Ps#-wwXgXvB8lOBkWyi2{CKJ&hJmFePjwo%+`(qGP3vmwXXw&x#z3qK{3#GynQ4}<?+dS(p@=(~C^T2(R>%_p(He6jz|-31f@x7O"
    "&0A~9+cjQDv|e9Rpw!*_8lCLu<VN@6()&@Vdz*mbXG-0hjo*V@vEQ6751_g$CSOVHMVs*Df3OGGkm`34#zhbpch7|ngJ;8+SCJRh"
    "@#2(FNUmJPewR)AfdfhRMH{%he=)#DMC|Q^ygh_}Mt_2LVyK3nL^cm7mu(P-kLF@#Msd&)!V$tJ_J%$@3?CEZFZ7Kk%x1Ms=}@vn"
    "aELOu&F&@!`2PlTOf=!FQ}N}2mor9mI{-?(>NmF{I8038I!kaH3_rjJgZm$C7V1`n7O+A`VJmCEt?c-@;otV>5Rf|=Xbs8Io{_NX"
    "Tds4yjd)ff{9xmSS#?g(iUnstLmQQLWIN2W{0i~z3lSLJfy&<NlSDIl&C%1SM^^wwPsLN)Z8@@3w`q6spG<w&H(Icu1DVWukR^|X"
    "VxE3lmOmU<Wd^LAzC>nv(SaFS$#O(*4<H{CI?8voxy*Rssy-^Z4cT|k8Uj%gE!Qc8!p@nf(FF72!t^X9-;)%W;~!VS(-z5~0T^lv"
    "YlGq8ofx$c?b&p84)UUl%rHE*Ge#id@SAM~CIWeNidL_kgtoj!JXXDOGO$>J1JwuTH8)ezzA{z`uyG{Q-EaW0f)*DVgii^(#!71W"
    "fS;x|Jix~WVv6-O>lvdK8wgnfk7!<qV*t>0BOCA!6KGSVo49Tp1Us8Gu+S${N*ctl-_A5fiUv67&ZfBVy3w9R)VF>`L%XL?ENvtl"
    "t^lX$X-(Z|)m_Mg$Oy?wm>NtDBmz2^yb-4wi*=8M^IvmBUyR0cGa8&EII{uO)Gm4QCq@e)uEL03=*?D9ng{#Kl1q0Ouue_V6Iuar"
    "cP(I4$cLS*5Nx{q4@;cUkJebWUmSPjBb;K)EGJWck3W0=XaE0XE-^OlX2hjHrK=EUHh^+*Z&K(ciD`)*SC^3kto*~7<X2{60p#%I"
    "=K69tF9-8-t9@nHnHK`_gr4W-*H-p`TbTnXl9xm=Vd6pP<w(9db(l#xyO0RC6D2`xqv%^rE0hFIO4*Xi+MaRfJgAxZW=izOirusX"
    "oZ#7Pr`cVzM_x9IkvvM6Fj3^)3;FC+fKPd)P4igCa9I6q%R7C}m>)SLZ>MI?Tr+2`nZwmwqoQ-Zn(Hxd02T;{{P#yPLR9?~fDc!)"
    "bz18AfOwofA3m!XOtkhBvFg>_IR)mx0zR#@f_yt4kz?n>N*~3DvGy{teJe%+B*a9we(G8AbTjttC$je(<9`F$PaoK;EzlfTw+VTf"
    "H&B~{Ef@?e-~r}!=HMb~uWh=uw&@Qnt_5f87Q#G(sRoY-r^O_|*hOyvq08(%pRT$5J_9&fXMRnAw&oa}oeL(}%NW6K(AISJqa-2S"
    "!vGgcyE~Iu*MN?O<J#)vGHx~e^_y99GzKvq*Up%-iz$oqhn0<`DbD_K4Ui9wEt1UdD}YtI&6G8GMwjX`?d;2E=JmO|BKJzf$x6K<"
    "K}CzZrq%rFap0nnU!0<5A3O`>@JbtD`3bKvlY?;cZARt3*jUeg+Y7dELjwYB4{IKFeV#4Aj@L>;hf5cFX|M=uVSI$CePRbJU)icN"
    "6eWN#i<<~|YcK)0*nP|wwe;#6(;8v_$H?I?ne^5UcYYJlXL4jd5K8qk2Il!@T;0W0<4}HQ9Uc^V+F~0;#)UCa-wn<Zz9yOcgV7~S"
    "HqHjsV>VHRQ_Md_*oG2h!H>u(LPZhu3Km-NVEE>2Fx`hW!6*n011#=rW^gOB!uQg*xGxiAl=6OMbueHz;PVPG<%F%UOc@j{Rb#C!"
    "aB&UtBn8<&5Q~xbc~x8(IXP@7nkW{vi{d5u0PaqdAH~tP5sEIr&Ir#EB}+H*Y9q4<NOxanq+?~US`#NLF0!c_lSEaCZV>cIv5(*w"
    "RweC;$booPY5*ayHWP#jH+X`9UX(zO0Bi10XZ=pov?L{<*-j1EtgS{+kXQxSNrzrmTv!|xY!xDfdoC0UCyQn0Va$wlqd}jkV&Pd9"
    "K@P8TR5}<cgU`SK>eL>o@Wf2Wb60caFcT)~pb94;gR(r4#3ZWE?qp+ej3?~_<78S4&wR_>nG02LZ%zl-hy<jgId7W-p|0-)ORSHH"
    "3eT*p_^O+Lv>wjm!<VZH6I!s@Wmt+R9Mf&;L^9tkp6?c4nk$D3L0dowpqY^}Gb3AbMzp3Vv#P=jw=j(@aXZgaNM?j@&XO>KnbX1C"
    "R^Z4S?3aTCfHPdFh<wkkNJz45QNo<17LA_e<=lNy4_}Cq4YW3Xydsy7TQDQHVAhS&8Hofl5(#ER5X=$<V7da>SBzc~VIXk2UayT*"
    "4CJPPpX39{P=IF5W=*mkxuSwAqQzDN64gW%VpS@cS?Z}f^faY^sE9EL#1$QvKiil+w<`W(Luh~YoDJ3_3e?4_1Xq{j7!e)PNi(Q?"
    ")n>G@!#}OS4?;wO)NFzL`q7e!B}hr0)Y)^gCa2}aYZgJXn`&x>>#t9<1lGMZ?XW{H>rq?js7{AXnVwNYIcOO@TdLOfTD!2DTzvdc"
    "*xzusr&r^%-jI{K%+Lz+vcj~icq_B`ZeeK=TVF0LzFb&*x$u6j4P!UdK`t8>Up6eB+__BMF}Pod>xISLL*qs2j2uxLM=IQHcmi15"
    "c{nInCWq&!IS5yp_QAM&H0+a)a`h5>JHX9ttFuuE)W9B035zavu1bm8nEQ%;x^1ww_aBUkeZRenHsf<~o-_|iv^&x6j<zJrzCl~4"
    "wo%=+>#q4+Y#}B-gApCmI{MGcBk7f@Rn4l)DhlHAG^t!3WiFS(<;Yx)&DC3I%EhlTf<<}pmnL)hn9w3WQDkEQ%T{jXMJuoyck7;_"
    ">txyiTU@p7s!WJQkATC5-7c6WgB?a&i<JRel+qMqTbe6)2f&B+)%UzvN!RHG!4SzVfp0T4ASW|6&!L}5#fzxEUikS!OP8DVBky78"
    "z>nxtL^hp0iBU#?RYn%R<rS4z-1InZrozleFj!EnA4?s*;WT2%ZxcWXP$Y7qU#odhhOt*xxkJg!jjuPM#b5(gccVu>37|F8P-FuR"
    "F6^<%RSQ?T^(Jx<%9&~Cpu9Jz-psDWi7U^;Du$TK+)^|doZo|?`RS!(#@e2^Qcw%!H^wzZSOPLOP@Z&NM$}I3bLd!kA_mAa?LBfi"
    "`v{bW?5EaF*8VZjX+PjO&Hv3l<>iF8GuiHJ0CtH*7j2@jaP3Lo(Z3}2Z$MUu+kMNnQ)b;|)4%9(2PEv%*LC0A>&(?UzlH!O&`h(z"
    "_8LZ5Q?Jz7#^?_Scc=82Z;)mmTeg?Dp6L(u$Wp{706eyYW<vo?<&)}f_bF$m59loaJIlpR?Ua}bQKfQOM5I)u=nS8o)4;xBVI|!w"
    "ne2_@PR=p=?`%7Dm44Sn#*Q^MYk7n>_ir-soB2W4!^2rG@#g-c`293ZGCR4x&3L%YRJp$4F)Iz8#?5*)rN6ad<tHyd2Bnd7%3PJU"
    "b3e$Q9HhxRo89fEbCIc+ncu0*C_YR9JNtv333aDp(Bnwj1~k0^PFQ*f)r7Iv|EN6H=r9P)zI%@53s`z(MgY}|7r!?HPD2B#9kMs)"
    "*JiU{o6UZ02H0VTUe>$NQ@1i`P6nmI9=iUp4=L&@!We;Ez1ioSKIRm4R4I4foXxy7oB7FMW~}U$tg0sRj#*dtow$w;v1i52utiJm"
    ")WY^A`uz3_ScRoAh^d8BN%UC+ltH+AbELmz#2XFKHieQMy+7@}{{*%hlbHgH=~MbIP3tB){PorT^!1e>hoPdCMXISZMxcCrn>gPT"
    "mDwn*^mSl1O8X&IO%Su@GgQ7PGt<L=B@R?SG+@;Jk^h6y8x6r`mEtJ~P3&rU3Rv^7s#$djo)B4no-!Syvu^Ga^3RvX<AE~x(Wi34"
    "(Vz!?jiw{3qnXxS_^WB(z|Zs?3DoxwoO>ibU{KF!E`d%FH*C3uzmlSIaKsqQ2X3^Yq#fP#7+u`?H;`C-bi$N)g_0!XE6vu>HCe&&"
    "A0Gxo(|;Cnk!IbQ<Nm#}Z1(gAYy#eNrCUIK(qWgV@^#k0%f<ZtKVQsGNG^pIJkh?2Aaqq$^DdE{$@ARgiEiBC2V|w|4V5nRPo~*`"
    "O^+1dWelp==`n9wB-lgLd<SM`opGmsfHoFpI4vdyaF{6UlR+Npf>v4<T^KV|kS=F1dMdC4gEJWH>hwYolt7i2_DQD=Kn6F>h4p*#"
    "q5rJJ)Cfw8wj^o$wpgdXDbVKH4+hJ~Bl-UU{C`MN01CLwN}{^3v~(UXBuNcTtJ>Hq>1}!dFRFO0>M2CC=;)0GB>{RQkk*nV*~^HV"
    "VmpOTeFjR;5>V61hw8vEdaBJgP~sKD=mNq3y>bwKPtPj+;dbm`HeDBi$##HsKan(Z8jnNxnkL*s6su?bLPz!eS=W?5!tktW&`Y{r"
    "p$T`=zs!1uFeY5P87;UIBIQIiX-#>KPGK~V1IoU?KC#{~UrehaIEs1u0%Vl~=j6X!1P)z-{sr=qRORi{1v}Ob-;ftmcZ`pz?Ra#2"
    "(W?mY;?PV{knF+nwduBk7-zR$<96#rmz!@&2&xD9SSH(DMp-m7>hM6TM;B$A{fWDEBIk6~l5kh|^@ADn^hL}woVvTzd1}~r>iRE;"
    "Px|uD`p){pDgM!VM3@}l&lVv?!5#X>$7qY&?f<50o?>(rV!$zJ88?_Q!2l$>T9>s&T6y7GA3PhiSQyN2WbkjVSkO0M0>{p|t%jS="
    "D3X&6(Ucwd>8f%rjAQv+w+VlBHIs5b@#y?<E)6`0?HS2AUA+e;vgzdho|ve6XG?f<jU@^WfAv6S;K$k9&}}$wu9;kpPx-A6zV&Qo"
    "f+`!{89o#BH>TR@6JRXq!~%^n`NNZe(QY4z&D7JI3961?)5!FrYmkE~)Indm_>z7!ZVh)oT`#l;e$=qHX|%X0P~GpQgEoEcE;54K"
    "zGSNEsh<x=gJVe85?^-&qOpd?`u}NsK&w_<Gr$Uz6+#=bbqAv;c)-~7V|3C5r>gkFXo%Z9Aq-Rwn8V3|6aA7Wm_?O{7-}}%#c{~Z"
    "+HEorjcYQ^hTU+RU7>A{F6$=Zs{<~B%`%>2agn`+rZ9l3hJ%qgqrAVOk^p`(CKKB+g#5=-BvKQUDU1Ky5Xf)F|1JBeh!{E6l!6Mf"
    "IqA1c_1fF+VNs8c29XY)7s^PppKMHlq^B^VZG}|n8Zf!9nz?D-w4F{=qseWZ_m+CRludVl`s|4oFPTIc6?xE<wu{!R3u?n`*Ithv"
    "G-)G5Ox{El*PV+Of`^WZgHg@Z`N{zlQ}pD|mv)8(qwOhfyWh_W$u6Ol+H5xB`b*dI!$oD%1`~Gw*Qc9FFsIdLxNX*Ljsk0InEl3t"
    "hnDFt<^kPw$reTfxG~)fE_5^|Py+@gqjkxIFDIzzjfW87_}tbfHpOWu4uQimV=~(Gu-$4y-;4;3c<7z4A>W9;r%a%eI2IPGBg=w9"
    "7dIm}YTusrOq|UkgX&)iAVJ+;^%l8BXSg#^?_3`SN<jb5y@No9-hf?-IsS229D|Mq$(=KAz%EW~S&upEfMT$b18AfzwQQ9wHd_#%"
    "SF%u`rX!{VD0q(F_@mmUhi8&7A7O>y6A{Zipz=FA(PoGHgtt2bzHWa(Dfc}w-{7+nbwzve1)yMvM)3+lcuj#hQ2xI7t-ivM-LHvz"
    "_b|_!J8rYX>S}1WIZ+<)%)yXpFFnhq_+Pq!X}f7P9JX<UIWjQ^voImqUr&a${bi4`=O^(y3FrzY#s)|DpG~WEYrc`?qB+X<wM~y3"
    "$tm5BX--&-9s0e5KsGH31b=qX_sEYen)^%dc<9t#(FR`rR85SIu8j_-=-L7v7F*C1ME{?hk%Zz1a?q9Z@d?i2(H)%gu<}^|47K@X"
    "*@D41uu8}As-f!CDc|N1)_S8Ybb8P;;(nTH#<5E{a+1)cY}gItb4Sb+cp0s$na|$cg(0viA*D(5q*{*YStH*LzQR0%DMCG89b^6^"
    "F$t47Z4-&n>tv&1Js2th7#cfAvT(0}+n4<nc8*(zS;nFFTZT21N2rf*P?1Lo=bAsb4kYdYim@BL)&%S_)yHQ2YU|ZOC0d@a1YrG%"
    "*yCXE*2$A>$rL}a2vxL)K34=JFiUf!FP>b%)zHy>UoqiNRLvtk;e)v~XoiQs90PlJ!h;_e_sd6oRUoEL-@)AegroY3d_tyRIzoD{"
    "m<#<H5r{{o;;dHQ!esl1^r*>PyV2PtAyBxTnfB92j+r)c=)tmVa{;-+RGyWIBOB)*B>ITy;Z&VXHPbQiGIyYciGxcu_O-AeJ>o)%"
    "7+qToOgB@_5I0U%2fmP6D#lw~+OSa1clgXhct-~zVnT$7!E}3ew!UDcKcH%82fO4zz0r2;Esu_b4y}hJ4`K&fwl}7msb<_#y<0ob"
    "YodV>tq(hZhgLubTOkKG(gHE6lsab1C^I_$!5w()#Ro72-r58xhAO{IHB7YcHlVSc$EQ2!+d8j(jsG+Vk2o!PwE`bARcX<0%r<N`"
    "Y($lcH|V|x<A`p_6weFwb>XKa80L@qH75)_`y5Os(t6q4%tU&{*otj*@@&x=2Y|PomL@?Jt4$+qcj>Iw7fgW_{I>F&5O~WeAiwM)"
    "MKO$(uiN~Zyo+YW?mS)(jKRtrA&`;l=0%@=9RHdE9fQHxkIhrdV=eZ9z2yOsbL)#eh(q%#$E;58h^Wp=v4gBqIM?>P?g8>SU&K3K"
    "QLDdstZO8UZ(7Q?HuMJ+%!<b30q!Th-9fSP);0-!1rJ^g70h!s(>#{=KjMMikAcN`!FRCdbQ~$WK#oLAkK}&haBv4De{{_=0HQw_"
    "yBSD~{WNi)mVZal7Wu&y7(iaUTx-T+W~MCTD<UzR860(bI9|~M*QhWxDomY5o0_MayR|66I>oBtKtRcWXH-Mo+<|K2-<WPD%(1Uy"
    "E3&e>mI&5cO`3IV9DqYM)dh}$Rx3vQi$bfGd_S1(72a`9nhzdl%prK;ELjg!|FgvKbQbdF>{>kQk0FnbdXz}rY%wPm^R!Pb<{WL>"
    "Z?F?*bCWnBrGw0FY+3-fk_sxO8^c}={pvopX%7)^M(0JoGz;5<VYF+p1$fY=n&04vp|5M(G~3iWeFJazTZtIPR^DJn|BMa|qWRVu"
    "3|{dI2<T~xJ}j~YRi;3vL&uGV`BooBC!$8*-Z*Ro=>uDxZv89N*R8&TqM@{KmIC%<f5TF8HddPXfUAeS55PA%lDjcQUPvSX9*iZ}"
    "3e#QhTC8MY2-p%p%^d$YTdBM4{wB|Zn)f-6#?I!UMluCbjV<fLh{iS1a0Dq({#<E$y1fiexA?>yo@>I`agyYqo4K`4fJ%80*yU%C"
    "$$vEotk81T-!%brG*>1%+4k6|8`!U@2IEjlHpQc|nc5?E9Rw}#vZX&yG`)4B&zutQKja7xF4gr$%I+Pr+BaV!3ok8sk9W5{%@6HW"
    "rzU-vWPBw0Ou*>ykq4i@-E{cE72?E>i2q+nFZS;SwQv@3YUVFpycR_(CY567bYEG2KBKcT2YO{c?Mzy)@(@E@Sp^J_0{t%qrzcB^"
    "7wGR`3R}REmG;7NlQ<+<W|F}Y(<<VoN$HFKHWZdFnS{g@3tUM?<;u(F_d<F=1hJ(5#oqD%bht!UZ!U>}WPLI`!R@+mDCV&Gz=Qm<"
    "=EW(MnQRMu=rx!@boWblT7qd}RAzNTgw;TeXL@j*xS230tM>Xe>59Fua$+->{tv5BzI|cIi}(8F<Cglh+AQNh1wLqVJifH%2btm5"
    "FYZu+#enI{y>R`i|CkgE-YH9}&&cZ>R_5uoX!1~JpK}j%M=ge9<H3~KI;bQoYJdjrIu;|VUB{}Vj>QL2ocHM@ym|E70Eb9bm&t6Q"
    "Ni@trUu+r7uOq+-P32(ifblt6)tOnKBCfrs0F{l6TqudHhyh>N;2gC6vyu%3swgFsJQ)c6)RdjaQ=&8|#MvdTuZe~cWyn{VfNW@Q"
    "h_IIFbU7`0o%oMYO<2mN{99^r4H2WrYIafMJWY5|5!UpyMowSkyVeAQP!HFF!y0u>3>uhq{A2Pdm~rQlcuo$*XLU8kXCZ5@!EDa("
    "XKo*Cl(12j<sV~%us9+_0X)kV`t~Z*EC!Wf_Ib0Afk{jSQ2by<O`!2spHo&IUMiG)j%K`J;*qoRvL@A^>CmuUb$UpAel&44qX2%g"
    "4+krC^&cZAo8}e=OqAVbakpk{g<RVtw-XCWQpo!i6HRr$I|(rj+@Yc9P|X_ZPImCv76-(Huc8H5bWZJ50#$UXhqqo?B<j;NCj|x%"
    "3KevRj1>%#KO$?6sBVXA+d;p<9ETY!2^Mn%%9wtCP*<LUVkJ=nsPJVaSsdh4?=>KGYEZYF;%&{!>ly(2?6_5rZj}+Zx=I%lwt{Qn"
    "1W{m5UUWDw*Qr-_H-=y@Gf_*$NJ9fcWtgeHS0-c$S$)3@46uW0!)BK)RQT$Fsa7Z4{fsApmHTA?Mo}?@)z}Pf5_E&s*`c;<s}Wu9"
    "m?MuX0w=$`1ubcujv4)#2TBBXNjewgNSK#u8VY<QgLNGOe^0%O(Yb?rnSo@)nGo(fnAcSQF_>tJ2L{p~;jlYNWZak(ywDYcZh}NF"
    "-l7|CG;VU!$MBWvtJj9u<ECfQ&l>pJedDP1xVNOQ^w^?>xo(tI6aIEe^>>Om{>HfXtIe6?X3$C8H#K7opXU#zehD;@I&KCVcaQR$"
    "tDR`x1QX5Rw^Uch4?7kxotp4jbU#B(j(mryX0}_0O!|axpR?&Av}BqwfSnWb)st!IiLBuPUEkCQ*~~o0O7+`FTL4wBU^Fp4eN1?M"
    "CHtnyTdbT1XsLYiDF-m$sB#m-Ne)amzU;?t?VTx##E&)of+S9pFoD~%INv4E$==JZsKOFLc20pQYz*!LbJ^r_uz2}|DrpjmTa4at"
    "8uM7}^CJIdoCGZdPBxB<)l6hgM1BC)eK8pjW9=&0!scvU7ec{XeQQL34VeOPu9R?*2gS)zAM&|54EQby@o8Uy4}$~O;bFBwu}+`w"
    "a3rbmmak^aE<JJ8%<a0n6uVvAdDg=try$bH+2;V|`^@C&Ob;xoexK||7}5J5`-A7AH4|kBN7lemehVwkbFnZjF?+hXN?aBnY7EQ)"
    "cG$_k)rns#E2vWkSCzolPNhS-2uKRKeRcZi^VG#FlzS+lydx53sQ4eg<3z}rl-nq?M=-2$&wW}0h}%9|r(2P@1ny8w6MU>KV78kp"
    "0JhY-pG*K;Qw}zq1o@wa4B4bSiyrh7lwJU$GiK^W(!ej1V>p$dv1H)8qu@3eqVbC8aK0KyvR)Hs9^kF<EOzNKfB9@mc-m%->>S+3"
    "I*$CyJ&#UcBNpk7MS8UQe_S!s>4si>Hjb#iY&Bcx!ozh8?ludn_Fnxq5QZ&%ZqD}H<p|w0)b8h-vEN~{<D*02@`}L8%2Nw%3WJZ3"
    "1*>&!_n6ot5a;A%=TSCw=-FN2Ym0Nh!Es6>uHaAE+%pZvE{pqnp*!DKsR53SzKFf1|8B8xAr%g=`PpuC2ri^CD~Tw?*_0Ue6JeMi"
    "p08+v1IcL)dj?pu$8hlKruLYwggxNtX0o|NZ|+Z+i@7~aIE^q<>|Tpm7`w><a!2yc=}(jkqO46d@ooU8NkZ$^P@RD-@G>gWoHlbv"
    "cE;^HkG74STz_1f&LBHfhpoD<bXfBY$Oc@wBpZ3wvhS^!VH9fls|3{998IzLTtSlbl7q~C4FhM3n>`47yES(=C`+agTKjct52iRS"
    "yzzp0Ie>2EWs8?J$sk|ZIQ18;R{CcvF_{okL7l3d=CG<~`H2lBgU$BoK@ZT1zqJ(ivJG~8&K5Pg@quw%CXhT02Un+Lpf_rMooA+p"
    "NjA6vHc#s%YS4p^nByN;16_B-Iq}t32E}Zl5xK_ij^M4n-DX>i@~qhzRdXm$LwH*jJ1TcvdU)Go_@)`PZqM{yN-$@)wdQ$1>kC%<"
    "D}^`xMYqs5=PkD(PW@6PO3>U!9P~qUg-VB)p^`Lm3go!yY0jW39VY&Q(X<-1rcrzOGc-m07vz8z$ex}#f=ShmE3Tg!wg#n6wWkC{"
    "1EE%Ra%=Ez%~&*Y_gqb4H{e_5I)Yn;8%5(b@TmIn0)yWa)f`&fk8B#;8#|}%a1h5o%U-><e`@`(C$BjRW<uWhG9*c+<sj;b8vi?`"
    "_B(hzj?4NEJaJ{4eZsEi3Jj2a@w8G8&T_!5{0XF;Q+PU6k|V`sz+oQ`UQ7r^nEmxETsC4K7Ril?SzhN&B9KC<UWk{yV+yLz0822T"
    "5lR)+#bM5%x^F3{28^`sd1Cp+ZN6*r!v4}#5ulldq8NC#7~JRtB;>`%5OD3r6wF7+%u}G!z5Gz+im9BiCS#idLw(uYDkb}(>0Rt&"
    "i|&RF*o1T!-7~$)rbmTfC<#F5l#0U@#|oEwuj|6_R~h`P(d4c3T1KbAHBqnf-qQ~%buMqsDFY7cO3tXU8Wl62REQn`TWN0#UkI$h"
    "*m@(N{;+mO2A>&gL{|?dlLy<h12z|eIMwa9e?k$Sd}wdZXoIH@%-;_t5rR+=wqJO?`PL-R`Wu4F#gqqN1z9i5hMJ6b;M&BU|8Zw9"
    "nn1l1Vz7+1Esj9a%J?j_m7Q&;H}~&qFe$JYTL95bEL(t3<|*(ta2AVcX0&Dd_S2a6lREr<W)Aq?PmOdiEO_3$U3v4YNR<7ox6kYc"
    "sNoHOeq()uOweSC)lIXcHv*^!P-ilyMgnE5D-P0z4b(cA(d6E7<zS#PT#TMMrZ=00gLV{rL}DZ$*3@r_PokGIM?Q;V9C()+8ZMAh"
    "KRi2n7ZYBT!q|%!KTUv+h#4DsynVkUWm7;Fymaxs1ati3DyX^I8!=@kjFt_6T~gCuIcPO>fDjm7-pu6Rp2@#`*AuXPXT`sX{oBuG"
    "jcysdoBhWmGx|YBjB{9bKHH7c&4ft}je4sc@>cGkOJo%caV^oBUlKuMbj}oC5Ek>qTUwAWg#w`&uA{c{Wkc9>zrjZBjku|<c3=(0"
    "rO?;IdD}NSkhl*zu&!>?;_Qfurq6=Oj*~ghyCG-JNJ?A$<s)uPwyK%v75#<)2piV6AU7D2pgFLEhpWL5kC9jx84Stb_MzyULg|_y"
    "rh)We4Vj1F33S`<(Xo3<_GTgVzF3mIB~$pnW#YZ<fYCz@n&C$kACw=l!5@Pn7Yr7-hyrS|xJbP4k&GzeNBl$&(`LQX^j3}0TiEQX"
    "g?5KtHoGu;LR962xmpv-9>C&#2mxt$@Dte0{L?9TZTmkYd<>Z)+8q~W$DQ3_VGm21F&op3IOrQ!Qs4+r!bKNr&E&vL4$LG9*|h?+"
    "h{mimXd_7UBUsbJFdI&&qKQ<q0i~G&y2CN>sdzpQhxX*W5Y)MW7)40W9G^!pm{(hOVxCq10>ES(>DB?LJDFxAeBDp}M1Rv7Sbt!+"
    "HEE{HD7!`t$N}<4p9>rfMv3Dd5@6FUN-Qh;GFjv5Wn)T!j(?d5Eo?Wv?O60+21?4l#ea9~{>au3e*DPdCe7^&Vpfsa9uqR+#XU2S"
    "t<pXV2v9g1<?I4rSP&e6D)5a!x1WOy-Zsdz1IZL?8%{PNa8lVNqYX+yZ6|eUJ4w}cI!f`Y58UE5yPesd;34VW$eyj)hepwE&E~Eh"
    "o73B=oI4~zz6)?d`&*DVw=*&6#%gA>#t}dm7VRt4Et5q%`=*m28L%po1K*DczmAD|Be`Z8uLt*~i(N1s+xlM=1LAP-ajTIAEQXd#"
    "I**kSJ*ahuoA@#2AYWjw7j6$ze8u9KT*Hp@SziBfgVzNBlY-fAod$A!W#OYxAz{(AFMJR>=+~EiR~3_>OWt-fg`BHj6jlA&$THo}"
    "=(f=Ct<qK1hr6yy?sA=Z0JUOJIwSCH2A`;)I?WNKiD>Tu*iH9P-GH;`wvnT|@agEF>e?Di+R#|3-gR}*6iy|#kfpou9Vs*!)*GG4"
    "mA4HG@;Mg%D_!`ebV1tSqVGvXk`1C#RlLNwpkM4-<DH<pFgyT*=u<Q5X&OGBkrOBWk}`HKxR!0bu-VcPNR~Gn;@H8)pkax<3qPXj"
    "KS9M+Vs@w~=ffS`86&9wcQ!Iuo$hbWN3?+R5nUfG=aeWLL4_*V^XZCB0!~WqG{F^twh{^%G>@N+hS%Kinj2o5=#p9@mz!I1q+i#z"
    "3<cP&I&4N-8|B_4s9LaEwK9ijezUMl<X9t~j!tvb+Z_O(rVi|;I}}IG-^NeeLY)7i_a-m&y;M~r;w7Vjvh>-ru?BWC+0>m`e~_1b"
    "$)54_4T4`79A>dgY&tp2au*;P6j-NzcUKn)J!2^Ck_`b|Hr84DK&!5p6VZJ8+x7OEAQj$aqMtkf>yebpjX;+b0XnnG-U}2@#>#hs"
    "$j#fe@vUzIX-{to<|7*)O7oM;kpi>vG!FmL<Oz~wxd8Gs1+N*ZK*^S92MuicQS}5iQxuH2iT6bMF9`*A>x{U|A}liocCF$T?JbCG"
    "hH7eq8hQm#C^La@KV?9X?KF$<8}gD?-Pr(SVI}k@A!w?VaGlX*{NoqOMSo9<cz%<zZr>Y-AW7G>MqB@!<P$I6S1mf|UXT#5Br=5_"
    "B1uZhe-=n0+HL+$rn^DDZRClDltFYxCI_1{U{kG6u|yPeV3<Fmiq!V%WCR7UwVDmm+8uYDLW+{Gowk~ECb{^xqybD9(oURo4vF{_"
    "5(<`J=*P^pe+(XwYW;UGC~UJ|4Ff$C+dxz^WP++=PM-4u$=E}E*_LKx+QrV+F2pE`Kv&hFC<yi-36ga+DC+|K(s%$=u><}{4*`A^"
    "vhOG~ZEatRxWbZcF6ZM9FaI3MpM&|!*2JGbT&i%$+3K8Svab7r6idx?)yV9FVwf{@haQum0Zcn|5$<7ZHf?s^p_h#=0$_oZ7>GG4"
    "g=T|oP*l|=UU#RlTChPpOcLZ94{Ha_)>Tp~aW5pePE<Z_NeQf=8VzWXC}%-Mu$q`ZQM@{d6VqJ57D`?I6?Y|5$MuRLsqQm%RyR+9"
    "1bh{1yV;!(&Cj_8vhcKeVM}7+kOsN|+0^EWEw$Y>{q(I4nD5ZQVx#0vf6-(n2im%eCI;~2p*t~jGb>9i5@i1xM-f6&)$$ywY$$*e"
    "M455uup}C{mX};uT|5ZsT;c#b#wsnYZVi|nk%1eKq4JSIK3PbpvEPWsW^-1Y36Fat4&4I77uFqmc@$ZuyYEYukbuQ^{TF?2q<ZPU"
    "ix!TX7w-z>NtZYmNsb>x`<;erEI<=QhdHhO0m9(?0U85tra#T}d)l-c#M=5P9gqQ=DPx&ScnCcZsPb~hTr`=U1|@DFwR)gF)BshN"
    "SkdJNem(Fi()r*QA`tH$NJj)O>q8Uo%3(<G10fp&pOdLgpFy$m#GhxgUbFYlZi?cE^g0A30^wFm{9puL*i%`KYL}s#)&Za{6^lEp"
    "K>)L-+rk!j8Ch|FRyR9tb{v*Svwr(t$;Fv6m>J5lKXDQ|z|PzvduEa~8(D?3b0{e#9)dGtaK<lY6uOMD(980jny7rVy9$c~<<%k&"
    "R#qgLOxE+Wg^l(>)nxL@@>%}}IcPG7sd4r_Bp7?Y_MlS$Rd!{nC7_*{c}_QH|LP5j);FK{Eb$`|cnweopEpWs^Y%*C@d<%!Y>*pm"
    "fXCZ(n>Oo)t7=bNT$_t)o5BuFXNxIfcH`Jwh?@(MeBQ`o=ZdE<0M=47odQ-nXkpnQaG_q<O)+~$-sn(q$!w&>RtAs)vvId2ihM%|"
    "#y`dmZO^*Sk!<?PVdHh{zg|WzXo#U@Y!Z01xLZVWato#tB`WVm@N@~=9$CCQ+jc7)!QDBwI~VrS*g+I$yZBYU(WBru8=xO~*PPL<"
    "MxM5)Wt;nejn`*jHjt<fL@xQ+ZgJud_rPrBWN+n2LfPXVRv1d_AUy{WKHS&2U*?)vJb{P@5CYn(9<3i{u!_gYM$DD?wF&BKeAtt8"
    "+dm(M(=Mq`%=ZTUSn)BE8;4u&!F@nsHnojxPgjH?!W_4bT`|*SB+rN4(Do1a7)Q3j@wBaKI$4)(8sTP#r*ko%PeZe@Q;=_!+xNku"
    "VE_qZawkBK+Hm}cIQy8X3z!a!%1ebfh@rEIK04;JT>V+RaLGs&Uic*n8VZ~`2JX7b!<0d$c;_P*N}IK6W~n;jPW377aY_wv8Vg@x"
    "FOn}jh+8_R5?RMM0|=?Q23G15GfBRP5<N_{q|F}hYvK*jV2F9OH`r#ro0;ck&vSEiYvZkjAZ#lhv;f_1U-TCf1}7_9AO&XdX-co*"
    "`Nqj`dU8euDw|I>xCCha(04H36wL-I<$1chJx}+gOggjgBQDOn=3HsyN^|>bWKPU+SZ`&QrpvD#92Sj=L`|?0dq&Z>u&kLTs6gA>"
    "{=CVe_9j~;dv?ivcMsahQc}|!>FCWvOK(m`Zyq;#^Kjpx-tS<K-;%KeH1T(gMQ?wK0pn)yCW&thiP-z@7FalEwmz~W`;JEJIKSP?"
    "yvYi-Lh_rtc!T+PTXbNBx-a>7lk|Jk+W(e~bE{29O>!bxJcd)0j!jcEZZDfNs?XW<Z)SkvDn=dR#wm#CWJm$%{)n(r7aa4A$qeo#"
    "Ex^FyNnE;3?90Gz#_qxzGV08%!Pr^8)nVTX5=jz|hv{<)bTHxF;p{jlS)s!|e(+3h`cdn}z<}3js?L6!X!+a3C4M2<O>Q;pQB?)@"
    "qqXpycy}90UW4JhHHep5(Z)!+c@t_&o)~YEaX+XgBYJSY0i>Nb83WwF{fXn^KO6^itB8V@JOQDkZX`DTBoSN0$7f<}_|DFSn1yfI"
    "+g!XS1D>IMqI9wNAUY7+>h?GH-D7$Jc})ge;9-%lnNEf<BzxRfZ0;<!9C|186M7#zcvBzU3^zBy%}sA})7m83ZrKVYS02njHttUe"
    "eysYT#2GC_4?vEKa#{y7o7U>wUx01_$*7eUml{MFvNwG@Gw8{hU?3YFTcIUO@Q?_RE>2}U!4PA^77DjegcKWUAVp2HEgicq0et{D"
    "=v%Zqxt$8r5eytCo1NV9@0~(TTs9r8>gJNjWP?1LT45t1)wzUYv^J4OP|o6yKY;>VR#EjkEx41ZgC<+?moS4t`#epv0ULzc>~FK9"
    "M&ditk{3P`rP#%6H{$6VA~zBWvK0L$AmKBc=?Tb|ej*dWSn_xT9e84rA<U^bF{I)Yp49-!kPVpO8b7>IT)eSTw3;gmVJzzM_0Pk?"
    "V@A<xoi56ZP@j*<HLKC0&tw-pYh22`t`pOe5oZ$r56}VWUoxrLa+KHs5!_*onNOkLFH8r@_Hex(3`+V0rcy{}gLc4LJO>xUS-`-P"
    "q)2d^nnj_GOGefdO3t8#&1x^D5W%=0fDyVI2r1)nCOSWmJBk}_9J%lyd<g3l@>Z=NKRCcHUZ@PfYht2am0up0;th8`zFPe8m4p>R"
    "(tjbh2<XNfYEKa)YkcvvQ#2dw<Lr5bXQRdIkaBoGp~Nn7@h);<7n$=BzSR=dGt`9-wFad$#<GB6t8fm@FIx-WY7H6}g2f%g0$t+K"
    "d<jAf6)R#jCSCv*|EM_LQXXKRwWVB&63Ej^%WhieCW}{lg~diej)}pV6or?(h1ae?Xtn@bt%hc+q1o(fv%_YGmo+amza~Qb(zd5S"
    "@s>y_zu$r$|Am}$z!n@&&blReima+s{>o#^#g(mk!>cg$FZyZ5s%q*)drP*&>9+bgDD|ZJhRMLlF6S1zIfXl92I^2<9Xl7Gzjy%c"
    "uPcmq<4gUXOmXpDOi>WkeKO64&~u{psRe{3=kIPq4PnJw?~<0Z+D-(%7n{2KtG;(3bjTcRf+^4jUe62NHPj=ybPgw#6)XaDL@5SX"
    "$=0v~=bm+$8WomFx(6sSdVhN;?t@)tTFZ-rXmP>CT$qvTu2#)Mm>5^r)?JA^dH1WY0tSAZqo1hEpUAsU<j+U+BplXcg*91WufLo="
    "tL87UrLYDQ?LacMLZ?3hD!_RXPag#!Aa5z8-Sv%8nNPw*$tU)SN?WbB;+&&&eGp~^5o*+%W<s_%HmV8&4g_|DN$a-QQFixNoyy+5"
    "%MYd-Re$<I`FG}z07I{49{%nNODy9BDIj#+gtVPiT(MlOdN?!rLaTbv77}1xX;HoAu)7na-s#!=2z5?@wnp{|R_oW>z9%hAyULh`"
    "m`dl}DwDawe8Un@1V7LMJ)u5pf!T}<9reB(Snu0`{1_<804`(}!Z%=xqc&*X0<83yET$03>J@4*cFrD&(4lzvuG4qu|J)JMzam2J"
    "sMWEWD;!+$E7(#IMhzUr*h0I7{$>4#X}CT7@)_=#0`ra4Ob)Bw(WqYGRj=?Y@D9kwjiF&%-*)|N6(tZ+93$3e3NFI1kEcEO1Z3NP"
    "@l7O53Lt_Ee1f|~P8TIDzD^No`x%KnNn*2mzbz8Op=+J)l8-AWgK<pYyR(15KZbolxN1xRx3ULg-&9>|vh$?1J<rJo^$iJ$=`pne"
    "+cQD<j)Mec>5I-_5)ArdCikmC(Deq2A2Id|vUe9G?>hZ(4l6?r(<y)w_0JHC-m$e{sEBEwp=_E~#7Zr`Qzl7=yTNAc&sNS={5#yj"
    "%fW@;;gB6^Yq3VJh_xD^hnycVRMJFmT$9T)xjcE0ZnXnB9Y;FrnmFY13%e!e0!#to0m$OpZkF65aXS>5PB^C{G_t+zY)xA-kKiEj"
    "F2YNra^)&>jYG?U*vQ_U8K|C8@AO4zVfUF@&B<2MtPgQvn6lS6tEv`jvG|7Fpfnas%mLBe=)HMpyKsAc@!ffVil@Ih95-(n=waa?"
    "G@|U^0mV2@6kLvYoL|XGYGig!OYnaUJZ<dVH8Di##Q)P;wo7j7QI7+o>+@ct|KD3ec7YLX31u_fN>!u$`3MTrc>(pQc;e2N3WF-P"
    "MQdkKxh}iwG+1HW5tm&FjfF(@TA_MT0QAsifmw?yv|c@&U^Dd?QVx$Hpgkag#o5R7pcX2e_ZX_T7HVuQRDJci5kQA%#aw+BFX52c"
    "umvPz3vDuSAhn^>;3Yj5%6MD(V{QQP@KrVexh^DB-)*bCMIG$-6s>kUXaSup8L>N|jhO3(T>%aZ)lT?nZ_x+c3m@t&Tu2^7<EUj`"
    "E>7K`Tu~iJm)a5eDyX*FY_)~TPMWP;R$ZvDpt9;*wC`gHpA9zm*-d9oKd5bHTh*dvP|m->E19ur7sYW;rq!UT(x1dML)QNgfV+5a"
    "##=L@@<)TBzV=)E;C6tdW-NMlfPWjdHb-!Cs9M<zGE>ODvEMl$R3yST&j)0y@WpqxjWrl$2d3&bI%^S8vVV7!d?~E^e{f?4tCeRc"
    "n|%mNq1mCA6=eF3Imdb3m&!U@(Ed2yLV-oicT=>;gx#g&Yey1LYl=6!D__LkgxaaSE(BFl9gp~7V4)Y6xUbz{Ex9|qUIbB7m3+f|"
    "K;}ykaW-@{IyCF+n%Z<OfpxFgyKjGWmg=3`U)`r<oo%bmOs{jA#kYi_+Ts}VXAHhr0>?C3psZol%NK;A+NSD^Z2UwBRsQ(CHZ$%N"
    "h*v~NFU`pTdSg*_8hl$Qs(x2+2Bg3OqDyvCVXL#CQZ*4Q1rQi(6i?qfVy2ev_!8abgt(n~*(b0CH@fPJQJuZ%&YG}OuBUqq9S~6R"
    "%n8P5wE6Hu9Cq38<AJrP-RD?Ucf|P{6kXECD$sqSd&1EXevu(=x4wBMkdx-@Xms%1y?AGu?#K8*GUNd6Nt$b6LmF?60xdmRpoMMM"
    "_x0=aHHuPHcYB2+T7oY6HA-;xn=d}%62bPUAEH>&Q8-2!ms+W<ae6hn-z3dhPmwsI6zQ_<*Zk|WNFYLk!|Jjm(`x9T=PavMLx}Sp"
    "<d{s4cB8d}Rs+sgc^n(5V<=FU0w`2cn0>Y<MpiQpblYO&)2a=wHGWQB+2&gPeex>#8zLM2;l^HH#rP)K-vuIbY;KP87Ez8+w&_h="
    "^sY!0euht`ni31w0vy(@0X9<;G~Q}$yP7)*l@xBte6v^05m~7UZ2Sr+<jtWyM<ng_lcykJQnLoC?6(Huwq%Tu)ecrZAX<6A1SJxi"
    "edH|==p=18->?E(viX;(ZI>72vPno5U{hUnSSLIF$Yh@&JCuyyNgt9CR}MCz^No1FlmELbx{f&4P>+@-3_2ZCFtrBP0tovHnn?Se"
    "ocf(6wA*Lrp+3_Ah#2YGUD0-uzB>_nGDWM9dAsvw*V1Oy@#*R)9sDi6YMosGs;aiBG3B4%fr+~5%6#DOu|hCiqwK~=<m6f0ycml1"
    "C>LSi?!>1C!B9^=P<FbM<Bjgyp}c7hV<a=s6OBdLIyoWLjjht*8bhBDYBU{T{>N09*93H|f4Pt=rCBMBN<j~*AGlUtJwa=L{bPX!"
    "9-*f7jH-_|dVKLN#3^a5OWq9~Ai$``_0AcpP$kKgFB(A{;Q5hFlL6lg4vRf<?;<gk$I}|!)M>A#WNqct5?twb$4J=%tmKu8PNZle"
    "^>jqeWYCr9)$$7mL;xRC-1EhSQPDo#j<iQ2x<i{yI+Oy@Vtdep@26|wNl~AKbP{<-;^ck8K-$GgeLu%E@u!(Ne-wf9(B<NRg<p-u"
    "M1OL+N}YuodcGW~mkaTHrP*<PIrx|Tr&G~(?TQQ@Q4&Fz%}H^loDQwA3LOm3T33I6z+ys#1UAj51kmh`vqd+FFUXZ&xq#q3mK8yZ"
    "&;xKTH{M_l?AY%fl{@uYXTs1Fp!%cB)zHaM3`#~{$cWB{fS4amdW0Uy`vys-<cN?&boXN29f%HgS6zv)s?p%-Aue<-cXpSD;g5U8"
    "PxOi(8-8Le`e@QPz<zy-{&Nx9u8P)-g4d<HHH84}m8~yP$+KLw_a$N@$(=SzMy*gYU13M5tt!E`{b#|*D|dcHZ7zA51GAM`PkDt$"
    "Afv=UWyF}+t@feR8|}J4y=@HBY+hY<Fg8h{R`KfEv8`o%*PJYU_3*@EhQ(B=A3qRTd5lildU7^Ls54h(2HNV399Cg|0>=;D%{i=F"
    "_%MtumKRWy&Gq>!Ojlb?=}C|&L&iMJDx4xKTX48g^zs{EkqL7fNY3uS<Vf&nDi}i#wXd{@af#^uDhAu_bW4t(ZhklvPPT>BR!gU9"
    "Xph{;1Kz>hS-V<ZvwoZS3WQ2bvs`%6sZWYe8%VUY44zD#2RI4{!4^1mPlRbp>^AXvCW3$J#TW3ga^H=%TA?k>dZ^V@)AO128RuaB"
    "VZ~8#tPz+kaF3sO$3H;N@&|mJx3oL`%pxjp^Zr^eI3WqWQ(YHN&iMX#P2bMEZ(T<i_!I5yXL`A$exhRh<QMhlXLD8m*@`U|m)B1T"
    "hhxD>BGp&u&RYN};iZBgLw6`rw#^jd8kUbW3_{<kYA>o)G~A6B1j6RvZWW!582ivo7i(UQ#f90Ih#CTO_d%&4TS}&c;_}{H-djR`"
    "f*EV*4@A&PlINt1)(KQor=Q<YglAZ?ib&>2LU#V;IaJv|l=FzAwWF48Ip}OyZ(UnIP2E)KFgFaMn)xpkp)-wvD{*^Dpz{F`Hz#IT"
    "?-7n>y!s#Y2|PE$5oW|;pQ8Qm?zdxt?X!cG&nu1E_!L8!yVJ{t4{#cskez0?`!>3m(=pJMC%|r-9Vv5}m8YGNTfg_6K!wU&2V9zm"
    "h|yrE_lI@A(Hg|}FnMB@GSx!Tj5ee5_+So^{4b60v@51XLM8^u9j-5utp5IM)rVBq6o@NsRDpP%848$p4oY%zyREda!{#$gzKjLG"
    "buD+m9`=vP9vl<n)KN%P^tDHE$s9iCUiqyB`UV`!^2w@shcn0C;5T0I?+^^ejZR9ih586%oOCj!JFxC{EX;v;?i6(Qs)h0|Yn_%G"
    "sXm2IgpL0+$g(mjTD8`gTq-NM)<M~eqYN~G9>i_q#mZk`B~_9CRt9YDN(VYZFV%oxJaW9S9`V(jDshS|c<$Ci5I9Uufdym@pYEwg"
    "jUfzS5i7rjKo5f=&TX0jvjVL#tnz`z$`2Y==FrZ2pyP(bz14qMps^BL?R&2LFtO^(2D{BMy2kmG7^-yDMN=@w*UFesDR13+Ic^M%"
    "e~9<HRd%^MEqgYlh(Iz6D=!h&P&_AHEy;eB9C~~*^@OeVr^nJk8=$|FK*e19h;-s&=(=@>|8X<5n(+uIhEZrRmHE?PJT*B}Or*}}"
    "p-=Y-XNo~@Fh52ug+`y?EIsp%hcQh(bCkka4)>=gwNf&bLq)GDLB+vj*VmB6F9r|kwokfnD&)y{i4a=gFmxbi!*!#b1*MVeg(_g$"
    "-Itt5WgO_tK05<an+~W)y*9-}craAOmOM0A_P;PjswQb$Fm8}d5A0C0$pDi)KsK%LZIs$=)B#mem_ovdaBB?2t$9u{uvwi0iz)R|"
    "7fD1n8C@~2{dJT7^@RA>^Tc0v2n343uLJ&#>FjT^RZrW0qlfs77VM?y05_Q5s1Lt6Ek-_17UP;R(Dta3zh1`tW_F%oXwAQ|uK6uq"
    "GyIka^{!68{wM@yG1EO^{5!Rqkv`G?ea5(M^xX0jqh8EGKWc!WBk+mk*C%S>C$i077OYRYT2a}4I>Vot9WOx=tOuH$kQ%d4%UWIp"
    "14SE|*;|&`dzM*ya9LQ<RK)Vvm)4&HPEqPpM*i^116)zn4Bp|c&iwqq)5m7Z-0NSpIj{eAlt=c3gyn^h7u!`1W$&;7GUC$k0QQBl"
    "M0`Q9uS*yMSP=0Ba?llC$v7m9Xfva%$o&2*WHUdr1L!Ag1GJFTD=+d#m;=$5Oag&|D-UvM0KOKw_^hkUgL)b|5ItV2fyv0$t+3r_"
    "efyL{_tvzJmsJ-krKhlcmbq9sfCK2&Z@vax4)SvO4Yc1^MC_XEJKphG)vB8dN|<^)UBTTAhe72!W(JcX8E&L<IFbGiM#!=xb4f{{"
    "2|%unPMw_M>R44rimR|I@6kj_FdG6qOA~eeRYxWtrnpi6nX6J!Q9CJ`LF!T24p1vkO7dixl}}eVBGK4W&h)mT$<P3rCy&8aKL%S}"
    "NDKfx@>r2^t7C3>;zM$17w%Yc|H{<gPRr4!5&~Lk?yljTdt;!LD=`%&kY07*X<ID-%PxWeTPTTkk8JLd&z<YV!fYi9*F}!(*7!VC"
    "m`q3P`2cnG|EE9)Jhk2|U@$NRqgk$)aG|UjOWMqrbAw}Yjs#kibj_Q$?5$yU2mWi%eCUTBTCG7pIO|`AhlB*cV5jR=+sHc|er)`b"
    "CODy#n~#@#y0l3aiY^;^1tkXA1LAakt5@kWbejy;Q%55xz+p{=p>aoHL<NXPKm3nN90qO%vZ|1VqB9r$m<we?5_C+8M7yni_%lEk"
    "jRx%Ky`W6ZHzZOU?05AA6gZvg>n^1!Q7orp#yZ8z)y*I6u72~g>YWb(G{?P}HXBh2rAzqQDv5a_szZRx`h&^FKw{p1oTHufvfjmr"
    "5S71|wsg0@5C6)o``0M6g9-mZ(H-SMBVny|=$(UTfnt2x)~KK?b&4{%e5ncynxGk4MA7gzf>1&7^X%%+y4J#ZZ_zh|qRQQZc+Az;"
    "rdCOf6{!J7pn9;vxo~0HT9CCfAe%PKi@nfU{{Xr;?d&H*sAPpo$7R*EEb5919q^zTDmx1~CO84<akAu@L(wJtL9v9C5WwffB|9}7"
    "3YUDaU0%M`dk(6yEZ+qCO%KRnaM9imd)0$zTW5fd01DeUh2zh%EfB2xoO@t4<y>blrr0KTw3G7`Zs<`}1<8;NxO$;y3!K2w0}N6P"
    ")=E|-E3B7I$>iORRGCB-Nliy}d2IunUZJe$C-Dqg+jAF?1Zq80biHNeA<N25(?NAoTgv>a&-ezjas*NIm*k)t7WB6aD|#{P$?z?O"
    "sO@wPI>po}&>2B-aXMFY5(l8g)TH<hix7V@@z&1mjTnA&I#KHA@dQ*LmVAS1I4vArxz8vZTe-(@n=2=|NObh0%zvx9j=~2YE0_93"
    "qu2=wt>((pq9)SOl=kE)&|sK<@n@arj$!0di%ep7hCWF*)>qGa3r8~rd3OVJd{Vj(j0=OXuKKITDt&Qv@84FEEA+jCYPvZFDVlj#"
    "`GCA2hDkP8hf_KoV(C}(0~fcV*Yd{!QBgNpr!R=^*A09mu1v%+NsaLmRL{+C-Abw$+JWTGicE-)U%eM%QOE$E#rZ`rwxEbtE~gCI"
    "?X-uh9=b{dTS1!N(KKR1NWjGhG4^n=ity|=dlKyARc~AAR+c}+72T5|8*siC-h_#JrHI`AGT<{FACqY=MtnVH(-hFFnH&)M+_^Gm"
    "3u!Zu)WfB4M4FHa0e+0%4*8n{HW=oZaL%m5(d=8q{_q3_CIuGffH)W7%Sq6iGr`j|86qw(XR4kbufDDiSeHQ07indKVodKKlPOWN"
    "Kg}+hFY}1Ou@l<NhclM;)lb5~65y=UL!ukg&0vM#^kPP^;n@{58;)Yc=9Nr$Lp8VnFAMI43lm>G5)<kc%82J>zZoAutHVEfN)Y2W"
    "hJU2{WA`7|6)uVih-+exyQT+Zf>J_>Nx%SXJ+S1)l^BwNYIF+HN-g6?lQt2dY$8;qGzgj<)NO{{E>TSAe#S!R3%9%0lmcyF3Q0PX"
    "SW)s#Tib+se60NFDcS0)|Eq87ul`wgfNt2X+{IsY7az){y0s#q3Lrx)kqT^qm-V5MJ3=x;0;5)L-4D9BaSYr8O6XUB#+aAIbTXs>"
    "TVb6k4682AF|D;n_8xvr{v5%z5`W)k6cde?;Wq|9fPC{HSp9YjwCn%J)R}H8&obTm|2oSoMMV?vC6H(7(QoE8EBF3}!<rTPzNc8j"
    "iv9N&^?A}uIuR=y-fSM1Pv*S@&=^l9l*9DfMLxU1V}vitak$CY@e*!(DAEvIAfOYT__bm3I(tCQwFJ>OZE=2|0eFWx$+Y`So30@E"
    "+gU=fV4I`4gJGi9s(P(TY1bWZ(GrjXnvry>cT7?eD#^{YfV-~+7%*RUt5P9rwO{q1R93bMCXkNRp=X}MBDEyJxyo?k5J&;e=*r7u"
    "p%n^l4m8N10*iTp-RdNuukgXx@9~Z=hkCqeG6u!jQ=JJanao7nV7?&0cSaj+phQt*Wu>vO(uOO=pa`?9+c-)tKsdD+O8KBmWMP<>"
    "W`Re(Rx5vSpnUB%AMeE$T@Z%f#S>#nq$Xs86|pc=mMj=ZQJzTZaDI2f4E9)P9Rz9}gevsH?(ZDx&}^y#HE38#x`E&;0ooLT!O^x!"
    "6Cdh}!RuncB$+C(9vuQ0x`)+u7q^MqFHpO@+ti0)#aO=T>IYIoba+-{#*vt?2$CTiD$vj?E+Uhu*o+2c@IW$<0@TRCP%7axb`V2T"
    "4MRyD>@d)g@?w@KR(gDNo45E3-Is6>xH#%NsP{o&2`Z_C%twK|)WCk|4wZb!*0^%OV7R#-mLzBl<pZ~_{=y^Ld{M<*;tfR2Yo0J9"
    ">R?hv)dN9(LY!ai4rO4roRaAxArBEqALN{9`G(>WchmLkD2`M@{<d##3^U{$xmh5eWJQ=}{OFW4zg1-<e{y#kbO)7Dl7};*x*>h%"
    "u8-&!3x9U#&n7wAIT$BS`gPj5EKv+*uLEU*GFG+<xREmH`VnQEq8lA|Zf8uYq4A(p7M2)Bp*XzXGT(kh*y+?k_(`;sGLT1e=RDMC"
    "10p|2f}Jg{ft>USglk9FX|prn6ZC&b6`kB+6;fw+>bT-q!0Mfo{rA}}AWwEOacpPwhY!vV2AZS4y?Hq&=Z~Zv7cuoF?3}q7I_76^"
    "Ms_DH_4BcC*KC5wY+EN`^I+m*nT_Q{wj6}3X)>r$2xitcxYZW3jfXz#yk-JZKp3VC3vNa!xHXt-n4V3?$(&mM90>m<9QLtTxafn4"
    "D6|=R_qPVyLJe>NQFtX&KIG6<4e5iK--C(YOpuxIqEeZosY!}?#Z2dV1(N7pU{>e`wMv63xLPI>m9xsT2@fUML&{lU$(GeNnY+kK"
    "wmeRHEZHQP&Sq(1XNl>dhet#<C~5y(a9;~d58WepEHA?I$}+S%z1GDa7+o>C{)&(TYqD=E(OI!>;g>=T-`*M*J#=IriaWD#>?p1f"
    "SX`(O%s@H>ebvs1bJ%CP05YWxTR;ihHbTtqBcQNoOemU6*J8x7iNjo6JjxaF>+sDv>}7e2QQnq2gql%G>Lh$2i8ZQva0UFq0xWbj"
    "$hcnf6}(dbif=Mft<7WhyRY0bjDpo9F*gvy?aDLV4^EbIZ36n=VnuRcwoG!c-B7xh6DSTXU#e26k(RTGc#$m)i<{mjJ(+YeUz9LK"
    "DmGHFy>0ZJ<7@B!t|fqWgm&_w2JxXo-NfNbggLJul>J??-8)3z{X5B!ES3km3{V^yl>LDcF&uA{o6X9dfkJm}7(FV)=s|}9F=xnb"
    "=#GDofJS@{Qu08cp0Lms9fbc-XDd*dJ4l5iTR#({gUtAYNXVbW7RhF!B}hCiB2*{zNWU!6Jhb)x(CJ*QyNOAQVF(5`E_0B#Va}Jw"
    "9-NeU=#=dwbhSd+zh+({c<7ovOGv>flM;bZ;%Td%qoEIk#)(E5(31iW?f*YGuQ2Hg0~xZ36i61;GRQ+`3Ni1xlyZPZ#(=*ZmHg%W"
    "KrpiX(yP>hEag=xwWc%dYdXWe(%1@Qn&xEEp%AIECN(2^41j({j8=gjy7;eSuGn>(Fri?3+Z?2=S_-c?FQ18fcO8{{Nc{gSuUC0d"
    "?kcH1#SF+bUDps*H=;vVnpcYHbZqI(jkJeW#6^Cg>y@}tbag!HW{^(}6Th^<9Jqk03QzP^PB{FgST!q2P{RagYI80%-6a(4M2~d`"
    "!NC{Ta)g|Xf_a#E)YXg&Y<rDDfssrfJIqC*haQ?!wM^VAnNY74bJbrqTitIZ%_1kI^#$w)5mCKQjoh4bDi<Im-cOL$?$q3OQykW)"
    "3WvL+sckXQ=W<uN%m#zDGieU^Ko|nF|M+Y(bODrdgCt^HEihF`htp#Ca>!)l*PNNI3YVK79;1EuHCllDLXy0|Lmn~q7DK2E^6sF@"
    "|1IfCJpS~|vj#lo5=^m9kzJaWKaJ@hk`t{02UZl+3?Lkyr#I0ATQKQlWbT(u`iUw%qBGz+L^h|nL?U0cyr~8S&RFSUbNUs*1KdoK"
    "ggHTC=qG&T;!V1`gZaq!hX`A?LNy=~(@ok~Z1)7E2Pe!$84pa{?@FyXds%htW-`CrT73AV(PJjSFI4qNAX^3LTf%H=MWQL$Xb(wg"
    "#(>|Dd+2bAs+*3dP#?rR%)IQ)E52MCG6`7r)6mW>FEJh=Pev!(#B`e=`*Rs5qr>rl14n|*vB5=GZYJj@Fuw~!CSj*fp3^YIYER}3"
    "!P^Piz~Nl}B-D)Duu1fG?JPZf%n=ws_7@@0qRoR=oMhGky8q9}q0Z54F<(<MynkQyt)!=$6s1gnYcSHOzYGVoA#C`FDut>7TXkg&"
    "suEE>Qm@RNACj9Wl4M15yGgVCskdJ}tTgc|sX`BJ)E0wU>xqSCzTPNB_2v_xlktiF$!rS^g&1{B^)@RD-*j&RHB9w3J0dG+|LajX"
    "e<|Rk!ekT^jo0f_;oy*k28P<VjTW_fPNaR*#^;+h!V(214A$u;Guswzs><TVwF8(9T0Dsmw*&R9H3V^Q`VDQsRsj9zHR|SGPP?x*"
    "MRIMJ)Oq9OWb!{w)n#(!6GrDGJ~Vq}9EfxgQB77S5*xZiQH{7JW>HDzGp0bBtpv5`2>*nJn~Y~C<YKT^-K|NW7-oyAm8x~s>9xtw"
    "xy;f?sNTHZ_|PTZNhtV|IM@T0K*EE^+VumpqCC+fRrZP>2>*u4hh~~}S1hpqV=%{w?m#@)Y;*$CT61eK7)8JCvo?uon(tJNqpv4c"
    "GbC$kh~yPRX{4%GDp(_Gx?UM-L>Zo&iGif!Y@@ov1Gkz{@uT+e%BG-VM7>I7Y9q=Am*yt!Z*~3J4}P$!`>5lW$!RR^KG@-fl4ZzP"
    "cxdldbgD4ikI}xY0<L<D{pUnq;}*K^aVwrr4;BPvR26S%qaCWWAFNFb-fsZ#MRiuoQUrTsDQTJL!Q-WqzC>_l9k$6Sa6<z96+={W"
    "N^v;7{rs>rk_qI{gmD+lA-Ww5IshuC0HfKjxS9)mEP=|g5zkzTQFaV>f@2F;@wb|_2cGthP5q))vmb*Km;&nHpuP@5Tri^~(qwO_"
    "0UC|eXk2azL~jk+40uMSPMTk&5{p$2EsTkhi~H*%x|0ta=LTeeV)OZJ`5F+PGfbbW92UjQ)q>E(_|tvg=Ny}SVw~~Wf-3GGMd=gW"
    ">E}JWqw<33bN2D06T0sz*nc?Qn~~cvX@!bN`r8kObu%mE96inPBxqh(Qv1=^%5;WMz$jHrg-(Zb$Vsp86j9|rkPXw+g+N>up3=$}"
    "T^GFzrO5LhSyHD(7HATc!xyc2c}G`I)l8yWxicZP-YbyD6IRn?u-XPyBO`3q>((2hs3eRjSd*fhMNmaCrcmN&0)tV4&aiBz@sSJ}"
    "=%&`{*6LwR_wkLS^tG;#MdxsX$>tI?Lor#>Vn~K;Ku?k5lK({Q{s^S@Sy$6(M?yR_r(~o{smkhivt%}8wLvka&G)rd(U~ZE_IoiT"
    "LpD@k=PO|%VIU*_Nz4vK+L{*f)qn`?oQ2&6^EDItDr<K-Q#NF6yj!zpL+Ig!W*$H?$Os$b0Eb}modsCIYFdF}E#mCGq0AM!tjmT|"
    "@kN2;1)kaHQoPoLC=+lM%#o&!k8?nV22NuWYS%;=%*f7|xaDp`*k7%Bx}%mGYQ;SnvO%_ZXfT=Ko2X9Uf=)2#4?8mU_)-ItSCVoi"
    "nPioaOe`lOGpAd~b{fIZ6s$V%o8?$bfike^jc#JXPz<^mRJ0KImaVR)9xO{>I?)<c6w4b{3n!4obiNtQuW$rrPM&5P0&00-;!J7-"
    "E^^O&Le<k<dP|2V*C#U|*w9>Apn@fkLA_$BwAy&GUgG@p=8RDJpzcl1>fIs(>EKx9GtAU8QHs5oY&dl_@P-+N!}``$5!_gO5@>ps"
    "xmpR8g%?`f;WDT)iOB$Rk2poV2UM_`-qVRz*oo%s#U0o)YQpo|CiCf0Ww%7kKWIigVy|A<$gj;W2AG*c7Z{Db#E?)MHCurF5y`fV"
    "Vj3TqaV9AQnnO-*g*K|?>7_=F@!e5)>rr~c5|~bG!BjA}0PC+d-Yz-ZX*Sjf@f-0M!XDq<&ZKJ&Fy4!miPzh=ip7-OwdYM&D{v2O"
    "ZVjgHHMp^v@%NnPh8g>w!t-d3#EsJ~9qPt}LZGSSL@MW`?rGt|f}dKN48x_s<z&*yP#)*}<gx^w3a)H0Hk|dGt(a=BcvZr9emg7H"
    ">gdt?0qC<F3`Qk;Bm5nF7~h<s6Bo1xEP?4n>+cb@>P+OMsnI_56#D(2mtDe9C!^zBPN){`1Q$=OqH{jRbRr(M`gUAfJ;L^EknP8~"
    "(}W094yK++no4A#LC3eu8L1!>oD8Fx#z*=FV^^KFE)2s7<0>_W{;s#f32j$rt&6fTG$#lhW(Tv)yDYybm4zn@jq34X=8R}Eyojgc"
    "Nnvue)j6A2*%f2;GE>dmyC(x*3S;pGv)06}*$RWV`+`vd>Af=%$+hCXRyS&K#h6ZPX2QVeDUfg8zFmU*KTJEhbTale=~j&~>~njQ"
    "16Yf7T732;kUW92&K}r}4+usc>TL?QAPg!kV%&4X5i%WK0BmrNFk}bHiFWa(HH;G>_t17+Sc5gD6EUZkMGc!V8(JvabB{SdXTCT*"
    "s0sJ0PQ`(>otVtLL&E{(feIn-C&B2-In3As3rRCufo8```G>aL-n22|{$c2Ne!_!zlX4?$;`m(*_H_JagEiNS3&GH;ml;|)F%Irn"
    "ot{IRT*mN69A1rfgk`7M=;Ys3!ux;<Gy+7fU(?0Sk2vS&HTivEb2xOJeM|;7(_$NEUA;0InD9=gvsSk1;c#BlpXm~Cx6!{a{Ac5A"
    "JsPb+`wwJeGUQO!`Y{ZiFdGCM$b1ilyNkD(Q)};b<bE1H{k%JkvXd;EI!CVVc8oSXTkIap>tw=Z=CwjPj>*i_82^|WoRc|!f1>JX"
    "lIGx^#rVo`L1DMc)fL)~4X4q#JESAqPL!GJm}3m%W{hS;7kLQPkk1luB-J^xAc2H@>z)<{+<H#PfoM11xeIQEi8SW+Kahb??D3V)"
    "&tzL2R~$hOp8(l_Uw;g?jLD2m|FP<>haf2zx}yA}eT&VMvU9T>LYUA!O;rG47Gm1V#@vYBJOnE@XR}}lOeZ!NTjQm6VYBv3R%`2_"
    "5U@DGZeIR3gHKT+Z>};oCyZVIH87Vi@yus1G&8qsr?VrLN$*>ByxijQq^05fbnLP-Nf(EpxVKVmbbAP3(rRqML=eSUX++{iOMbqC"
    "72MaZ)4KcBsEH=D9)3o}m`+?zrUhdQRF_)|>Yz1=<%8kDPcu)9%uxqJVYn0+!5_t)+|6y~&E3q+eak%>zPoes?nyLAV|DjDy4))j"
    "=g#`~L@pVFJzxp6wnuYXTD%H$){yc5r#RpLBgQ&jW+ZPO%yocJtp@q>V2WBEIjjs)GgfBJ1fKe`oas#RFAHo!w?C7Sp?o1;k}wKD"
    "H#dqCzl`2Ww2RR!PC%PwDPTP@1w%0rqZwPV81so=_mmR_&!}b3vvxgGe8+fgG8Fx%M+#4bAREb?=kU<yB~`YECb%kWeh4#{7y_bL"
    "xQzf}kDS+L&7}3>=6Ev1Rfw5-ECHeK9+>U4Y-{Oc2yNA>#)&N$?C8p63Y6QGS9>QG@}@?w>bXjITn{^{bev=DN&h#9{Qrg|<powV"
    "tJ8OKF+zcpn~nV4mv#ISggJR3Eq9mWeJR#wMq2g@rz2q8gzSl@tHsa)?o`}evzO3!P1sow6oj(DBhX!om(;I4`s1Bvu0fkCV+l+-"
    "7~;R@W(~KVdxWa0S%q06ANFdOG@WfQVRNEgvICu?n=q6c;TKFcmG4VnSPSFXQ-i%bMSJcvcrc+8)Ye*Px9ExYaf!xZA2%0}-34aX"
    "h3gYTAq={g-(92k(e4c2y1UBmbqO$mFDtvWPn4~m+^|n1LBKT_8_1sS!C7VHJQZ8_`x3~6%*?42MtXer@Ti1cf9Y|ZV4gPEE^hV2"
    "B}&NTuDSnX!g_M4oZM}>oSYkMaXI2MXUc&kEV@^o%<A0iE-gKIS_g)2C7sw#=F|zt0^W5!nJ~%S6u86fwYZc|F56h7-|jSsB-{HL"
    "R+pOYD7dQ^WMeY84Tqt0b(fRQOV38T(p{o@y|`QKEfT<M)1Y0j>{>C^)FZ{NEhLww=6+KcIo{lNc29VEOnCapCnTe1^)SajrUqwJ"
    "9UA1gA0js9K$#hC9KEgpDBLqFUJx%9?4HZvuIgAcErMC;d%?xbZp7VV*}d2x<}i|@N1}`!Yy${b(<(XzIZm_z7kID*b84i23g2Kz"
    "i{sz?Ufi%DKj&u7TH3?{LOBA^!oL>Y?ElaaK-iO*Ou3n`1=?Li>wpeIcDpgBDcR~d%$eGE&l!(sc#r%K?6iXrD*}hJ^~fIJAN3M|"
    "YV|1Ms2)auvc+`Kb3?t>EI{IvQ1^p!_26#81|6aaf`U5ws<$ArUXy`hOFP3^56esf$2fx8T6K9rAMBk}Esn8Y!@G}A&FXyoS5HqA"
    "!+v9_mGLY+8B5Sy9?xtkX^l@+{EetN;4z(jD-qpsdv&!fEW_)-vqCS#$L2Y)E+A1IkS<q@Vc>tEpqIA_PT^{YRT$zHKeB&BG!Sn-"
    "K7(`{3Aa&VHHc&+PS9w8y=GBXioNaXp_a~|WIrwh3;<8^o~#%~GR76(hESUGhK!MBkbCS@SG{;B+7Zh;dz}}%SB>;;oW%uHfEuT="
    "fo~{()fR9fMwEc+&iN9UPHe$oyrJw(VBrefJy>ha2jQ}WdYdi**;oxDl!qOsvIuOdF9F3)^)S_I00F5wkw0;lY_N%)WN(Ztn{UcZ"
    ")cLsFb`~0&i9FHv#=a~UQO*5#CJDRKdS4{FA#)W+*`-3e|H_6+C9iXfuA*u^clXsh{o@>_DUEjBeSmtqdFKgnL1g2;EgA*xY@&!}"
    "1C}ciUX7tn<0R$?1+_vGuQsP*wDU%7_8?Al2sV!5!Ss{U6QE)WpQUbA@AW<5%`pNE`2_zP9?$G;k=&d>LZ@P?k)M(k%*HR@&UA)="
    "f{hQ7g2b9(QBTol2SY^^qvRE;>IiA-B(q5ybGxYPfA{jPpu}fSfpidXfdfbeRWpx9c*7(QhVCp6jeDKBqduC3?vVJ5e5hI++zy^l"
    "_+YPOLf!*ZlMhVzZf&MH)}=EZ1b;5<az1tIWD@#0p>)(zKP50?hW5#YAyFNJ5@MqMYMk=)(Gmfw|I@`vGpQR@Q(<gd=>`mdfL!qA"
    "njlipb-$<9KRNLH<WkX-OGT4TF953z9O7QlQ*r>GI^gou3nkDUDkEIOHegCRPZ@p5^HsO-C)8p}+*Z!}1vZ#DMzPAA1V6Pvg%~)v"
    "9nkpUsdq8%2@Kl18K=hfi$5D_#6IlP&iKKJiIi^P$|vt~J#{(f@)FMR>NC7@z7?m6P6JJP*qis_V88KA`(*oaGNg=Jqo;4}JQp7v"
    "G~(u&cWwSCB<*UNH$w>sRniJ<C)0zGXS_H1L<kxbJz}{_n=)XJ5yt;qoWp~J9C{8IklTY);rRN5tp>=&K`68}42=&gy_W$bgZ$(D"
    "rU|>u9SekFqQ?ZGj@5zqgy$mJjX=}a7t7zMI$v_`o3Dnu-2Z+d479{(H3v+_8Sx~gqzeDk(dQ>QtfwWn*^5m^Cy1XZy&*EBYN011"
    "O^X2yo$7xg?fj_?t4YwN7U+h{GhrZGaE=(!Cq-w%1|=Yy&bA2VIO3U*5IG^g7o}SAu;r;km>P~fXFK*4RhRxuyT<-3`-o`c{>e#H"
    "(E;d2>yv9{&xC!lJ+ZnoL1(X@2y1`p!ADUvhDkEDouMO=Pi`qZb^YL}qmWMt_*`*C%v9BBF~VH+4i9w;PCd`$iYaG<p7nS6)q74)"
    "N%<;<8ElPvpJawkYiGkppt;0T5)GbJZ;no?V~G=1>`AnM%7hphywjQq8lamfPf2`yR&tf6>TOb&ai3Lp@#G&*);}vjR>Ag*^}r55"
    ")znWwNVc$>#>cR#Tz}!eN;@0sqP*(#<mLG1?1eYEUM>(E=Pse4fmURPcQO((2&8}(IAAiS|3@4dH$U|@x#-n7;7JpRS(e$KymtLW"
    "h}4|6rJI_aiEo+g5S$tdgz{Ed)P7dH8U%y>s165Z+-~bQ5i`nyks-|#=k#2-;ZJC{F%V%BT8}W0%)XHK)B#{gC6MKQg47QxSJj0)"
    "(c%wi#?gaS*Ju4u3P1MXlMHj{q84Jzc87AT3Hu~!uOt{!BM~!70hne?0q5s1%DD4$_{#9pA`Ao)NIjXWx;bzcO%StkM1yltZzu(~"
    "!YBv?=vwVUeHmnq`Z}~I`Sin+0z!S)oJTOAHjyA^oy}rw-tUo#QG+!>2Lzw)Ee68ApL!<pIox6n4;zLj2+u(Ts6S&)>7N|ymUAj<"
    "LmStVDj_1VmD~n8$ni?Qb>@wpgoLU{4Jy0j6^r2M>g`Q2@=0=eW~2KnV_f%rhL{c^=e%L?LHISUp^jz8+OJnnoSg&`KSiZq5~->N"
    "X3(V2FHTbBDA)W1s{IqRQ1#Sd=}9{FNJP6`$dU4~nU6kH19g~Mgm1UWgW-n6e>?{X-<(O!nc9eHy9CH>wMp)Yc}elfMfE37C_Z@y"
    "@ySbv&v>QpIVkrHZyHf)cr2MIWKf&!^4L8z(z=#56(D%Z(d?&15(q5O(i;!Z9T3GgT%nN}T*{bmCs6%PsPshqlL4q|d|r*+73IHK"
    "F<;BCD)dYJ%4{Nyd|Ojvj0r;@x&}Mp%FW!D?(uv9fAlWMlkmdwOLy}p(dTP24_VE;^B|^Gqm9my?xfTD0IH~j!lNoDUs}3*=|()}"
    "*I$uT?Dr}YtIS#^=u1=6NxoWFc<He=XjAmI{F<#3%(@zjC<fmOaq$dZ%qs!1UJ(5vl*|w@B#gwOyfoVFd<A7K1twX0_V<A8^srR%"
    "MNuwa!dSj*%7N0;^hxinIHcTOn&7KcVmd*am;x&}+gE{7QBs9ojHM^lgPkzD%@4BdJxGtX)R(bC|62&Go)#5c`M74MMswCTMXMp<"
    "8dPYt=lb%wCE&0H1*W}uqd?5fNRqZ4>n0j;2yyB^T|^V3jXdShzF1+7m$obqc2?3~dQeP0>?(-DH{R<7usJGv@%q<`%_dQ2ujbtp"
    "mYrPNDPUdZI{KX}t}qox8A`m6#`|Id@QTtnRBVPto4j~m>$Onw#!lo%*c?hT4dSt-<<SYB<pQ0>cQz2STx*d1(xCdK$7Nm!SetR+"
    "%J`&|jHEYtM7aZ~mv|=0B&zO=zciwLrI)O)N&uIjNy!$8T%Y7n$>)C4D<SS3Xn@*fA+rfFUn+3&mWFV4!Jo-A)hMAt-d<R5GKsN<"
    "=*)@#$$LFB_e#4$)h~~s80tY(?1-_7a${1*6KTRP-6|%0q;29(%N*eTR?X;N5^!--sf9_x0+}A^KIo*H#=i3JuW~>uqzasdDzkg}"
    "&0UH*qa;`jTl!(8^hKf0Nk+Kh__DCJm&CBWGS6JSEOX_h@ruZySDD28C;82<%omT!yz~IiB=@UIvsU3=l-pd@L?XHDm3hP$kOY~@"
    "NSL?q1>FcxBfq$CDpl^6zBsV*$~-bVLEaL#|1xCSTNg)yE?iWXeJ9Rl`2}vG7$7hc&~GACA3?^fy+JHB76!Uw4;a{Cwm<Pt6<|#^"
    "%0p}dt$DumoR>UF2~yIZFpKD}q~Kj_fz<%LWj7n~HJDHtI6>iA$=Ma@pcB*{g_vrgTT$LX0*FlZv{B3p<@Z|@aT*hq%2KZM2ohhd"
    "a1$lpdNejrHuda>Xt$bjVI99BH-%})x`srrqTA1tD#S(dPbPh%PTMGn{-RFng3!t$MomuPm4OLb5}V-qKT-CznfBrtpck!Nk>J5e"
    "C8co!_cD!5*p$zOTga$)x|CAwLv{5l%)Tb5%_+pR)b_TKCU<nhQ9v_aEVgOl&V}2_5GV~tUX{^?q=R>X+~BpT7lNrL)&1QG>a;bp"
    "ed$Eyi-wp>$g(xdvRaqw8d+%|>)p>8y>u~n63$V-bT@dC3jbQL^-8ANwh*em)K^7O0bCuNRoBD7m#Axm65?)n;ig-F>i2IaRvuz9"
    "lLD2M)$4XbJ<=@Pac^uWtFTr*N&C{`v*?W$xYEj2zhNbm949bg&GsncmhCKXYUwfpVe#dJiEnM#gAN=w1Hjd(Am-1QzcwK;=rEON"
    "Y}!nmiFM`8C^2f$YPoT`PRvZN4pW<TR6`{+TBOkn#J1PO*&70@q^62#M83TA4ERJH{4h2f*cr(PoxeJ>V8FBP7_u)4{Q0v&DN`k4"
    "aL`N$|A0#Hzv<nLst=&Q)w@#u>zlND>#~xNYETh2Bv|P|>zmLugf0oCsjjlB<I?GzNtCf|J2fHNW|%-xYj0AnaT4_9!@vz@5Jp`="
    "7LByj=IyKQ8c)>dT#;ox>BbvkV$|x_U2kK&oS*%Rkuf`j8Mn5mz_dl8<X@87EP54D^X12NUX8}EA;szyF_bLi7ZGWT8^%U+)+k`U"
    "J}UTPcHqfCXW;OEG=V}|^0xeGxoVb%g*q)%uC??lOM2V#+hMYyifUI;;9+v}OOr38&`!Fcxv4#xutLeZi8O{`i{5S)Lno`=E}WG1"
    "l)IxZ3xh2%a!Us!MK_0-acq<9zL!Okz8d~#vVg5h+?7xVEL5ftg3RZObg86=wu&cJv1_y!Z74U?jkKXYyYaZigg=q*oHdI1yfvH^"
    "s8!n;3Q5Y7VmW>lj`8bY2z66=GEm3Ni!FkocuN4(YtYJ$2bW_fD%Zyxj5Ev}k2$DThzCnNz*mq(R_c=8zj_hqp#})R$?bnbZ5jtE"
    "MU_K>0!Vz`%Mt@$NDO=p_qa^yUu<5!G>=!^80}ZZbppn<H}FEZIdlhbH@2?Dph|QbZv#(6z?G28_b*-(5v{1Q!Tr)CAH%#8=k`jn"
    "XZ|pHm=cwyl-Mmw$_&VyPy!2Ip5DJk_n?l8*`m%bUVeRj6oz%tW4AL>lTil=RKaylCpR%Oyekq4MVn#PoC)feRt}><Gtk&hn_R_A"
    "9VaY-=|nUd@0+aJrIUe+$t>T3ZWyB0QFH`ZUR>b4DCVbDpw_YyzK5m9%nT6ueq#8vUoVl0GTWSBUW^-nBNA7<TR9g4_U&u?Y^2FW"
    "Hyw=xzLR{H&Zg?>4Z#VLT?wG*OQyP3$_hPVmPH(#xY{iyla^PO&sPhM6?BZl+kjnb*>tsO9X=4MQ<?CYM1q*~A<=jY=S2vb9z&S4"
    "n9Ba$MA5l(&ugNiad$KxN-PpC|BB2y0Zl+Q)vo-Cz%)^%MZQ9?N4zCD6>sv@xu}hCQS4x%1f5OQ>LQan#BpHDIT#z^Ft5-KcQWHC"
    "G6!;^uxdyrG9lA^2BH-gF~0;+8=g?I7yN_C*--Fk`*o%WLxW<m{c;6kT}Z!;6>gzAJ|Tk*GuGIl-FET?nwr1L2}F8xs^}tf#tmhM"
    "geXEuS<BZ3TiE7$=Zcs`=rg`>;hjk?-8WPuuu+J3p#~P$Jg#xY_pkz`xLk7RyPy_V-g5o%=^7}m5jt+>=s6>iJH#<7LB|R9M1pLE"
    "FI;lnL_!3R4S49Ylfj_>6|EP}KupE~s4TUu3u#7zytO?oXr|8fw=M|QV45)nW}ukj1jTdGsJ!o50?>Vn5cD@;eQOD6)lER@xY3x@"
    "<>P+?m;Ktp#9x123|9ym4o)MG?Mf!L@V}ABEt0mKlq7A`@#chX91{X<F*_f)$Ut^C3UPB~Z8&=@rkNH<UDu?aqAId4Zrk>Y=>tlM"
    "m~eo2h`1|O3W{L>q~lH^?H%Illi~<qG@`nwFZj;E9#1ukkU~AV*midtzTzruG~H+6=%mmb?*H(_v+42^?>z$*U<I5bLO`P>>CI)T"
    "xA42UL+DZCgeeepJaclm7In7){rhlX9%@Yo2FBSp54~zqgP|LBSOy6)+*{B2{mSuzNjE(gxh`(0N1@dpo;t0IGkA8)PS43;s=4|O"
    "(vxC2Is{!}HU5(vQqJ#){AL5Cbz%kX{<5B{nvkSDoLYw)Cf?x#R-5j2w_CM`qHP@hqU2D}j&neu<E{)|4kB<QXU!44!a)Wf(P$km"
    "`-g}6VyN?nv*(~=Iozb`*ikhCB-^1Q`s?zav-NLrq54~Nc-DAWL8kuF1}#ujNQOU3x5PQG%XiV66JowI)H6>+q_1OtE3#ii(W8ze"
    "tz6FxO&-XxK<4!^(f_oFF&U42(yvzQv}`6<etB7QO&8r_1W>;4TBGs&4t=G4@+fRhUB37<zY4~44@ia_aOz^|C8D5R*hUs|CQS@u"
    "M4hS^X{LN+$Q`NxtDGiG+zI)eq`5n7?)0t#Yv~0YVF~EgZHB#{Xw%(vF<9*gzyadSbKM|;xHI^iNZ}Fsv)WH24o;*$O?pvrG1{A~"
    "oykBHO2nW<6pATsK*oYY!^Q@t9t2FIu=G$_)Pnx1b25|s{_v__GU#0(7{yiNuS88x8OO67$`7O}PKLndwbDAkG^2+vaJx}eArTp>"
    "!=&#U1vnSpt@SJRqW#ydIQb_qES<%1&L=Qu^?px;y(7g)%xR8BYa&8vVf2EUnWl)n6sA{qn!jiz6UnQkv6Y8nL@5Rgw9;nn&9%uH"
    "Ona3icVW^8^hNrxyDVr#P_iYl)qi}g2TB3g{Y~5SbL6W>cf3WuY7=bb9^%S7G;6A2D`8}ikbJJqNH`geiBcje&xQx0ATw{0=S}S1"
    "nh8wGa40dT5LK1IRHOPemk-^RHOR1C)ZX>VVWLSl+-LJZ;KU|?9NnGZtlcR+yH^L0@UuqvxvIbF1lSL<ene2;sm%NCsydPSvD>N*"
    "T7~p=jonGh-KpQ*P<EPw?&hGot?aH--BqeDdW$_6InW)Zo^?eR`9{zv;_9u*LPp~5Ie25jnD182WK8c7Wly_>TnB{-aP`m`ur&=o"
    "q$%cs!;*+m0%d<lLdDPO(uANkAO)bRXsdhHaT5{zqtg{Fz~(O!*F7#^lg;2nbzhs@$tHKQ>7c~Wr>2AL>6NFd0TR)jW}?$fhr0t?"
    "ZINb&oA^K1#J}trKg@b!3Pv-l$-Jn*f1W|7&x^+En_V~bj>P(4uJ+I*U(zGye0P#e66nZ|>}T0>m@`uh?t4P{pa5EOm0*Lq-kC}N"
    "7#mbX1sxco^uGDmgLPvICL6Jna9kN|d2@ywxEi@?02hHq2p!Plld)+q)*=)cZDz~)*G4iy*3+5Vh*(VHgOPgvJ?U=f*bWQu9|!ou"
    "5g!=h_MxQD%pyDJ$0y0q5?_TD#f&-#abIgysMS=2-A85CwE#+ud#Ze)dU5R+*<d)TW?dBT$-S#nN@Iq6#Vl!|eniq<SGH;8e4>Ep"
    "$`l8f*me<lLrIaeJ3y(M;?RIF5aI2?Rc~=~TTjGe(8+i-lkagw(VQH(6PtU6?C_q$bG8wRvD!nG7ra;QZ>(H>TYZN^Kpw@|m7Y3l"
    "9;H~XrfSZ3aA)<YFE%q*KgqRPikZMYQ{G&#w_nWs!lRCNbd!10p#y={NQceYvHAMQYSCV62=y|KU~qF=Fa?j8Rber8(cfI6Haa_r"
    "XCiZjDezRUMi#|*B5cw@Y+M41%b8XuR`9_{21XvMZO!!d$RAmeJiT(~T*srSDTTqepc#msFmw+iR&F?TtGYD(<6UAX(+^$9@4$#)"
    "Oy*9bP>|ObXrsdggwDsszu1wNNOkonv`(`nqa6ZODhoBLm}iDD0U!V1za%@Ut^=@GuCCsZ%I`{9(YiSDtu`Pk<^Q}8Gf_iGU<pho"
    "p86FGO0}RFGDo3mI->?;Lj_nb^xdj8(;Dx;HNa{Y)AZvlc0fZHZgoxihG@Zjby_ln$h_zSP~i9O9NpcAb6ZA~VDc2&%5&%0nB$wg"
    "=!+|3*K^CO3qE&c_F&dP+>Eu!+#fnwHjx`UU@~BeNs~54!<ib+#C5*Ok$9c@&yt6zBH90$9qu~%@L0!;Yz;~+Q+Q^lldN=3hx71o"
    "79Or+hx6}n#!Vo_=Iobwe!POdau)}>7~-oL!o=`rRMvxV|9NRDQ#QX0h_!-W3<FRitdgy|dSNzJ5Vc&0+S{O4dsi<;X(b5IiO-d%"
    "%|$VnaA;1rHiP^~x>B=x_QKoeqJLP`!?UX=4|9-y0a)bo_<2qEm+T*h`B#s~G<3r4!)_neI+7Lbi3Uh3B4Sr{8`8=f=JkZ{s_G5>"
    "$gAA$2Gkg}tUTNWV7J>YI}K|lOuSw{a~N}#?3ys38ZWMu1gY4p1hNuF-o{=fPF$4WR9KcZc}jhiSi1{A5?6x8&Bm42&nG>!a=i}K"
    ">2=^0Z}|!EY~1i|+_LpBx2~f2Ih@PGZVyu>umsZ^I>6`$`SiRJFS4Q`Z#WgAgEtgDy;qK4cDRl`4-oXG{3LI7dneOak>Ex7nNX@)"
    ")uYr2l)~zDlj>y>;1;MF33J$h8e<(r@yqn0TGg1)23F+r1*r>b)iZOeA5RzH1#iv)*6Y?g{B`if=%#vih#sh3XO*ftE-^E7=6${E"
    "1wgf|_5RDsqQw1*c<|y5xq4MtH#p?w-D5Lh4$yo+3=YK@WHK)(!}WS63Gb48>{3+kUPKcDP{w<bz`yF{5s?MTi$Ignb<GLthggcM"
    "v=}wVw5&cM=SO7ci>$)t=8?USPDhL;&6Ocem8{fDpz0T0i_W7k|C&tmx7TnhrBTOFM3O1y?y)A!ljfo$1(1@ZGxhN45kOy6=~dq>"
    "I@HP<c%^mG-E;M8)k(>fLjg&O3+<Ohuu4=|`$yJ~XognP-D=o_)myiql_*8+PULug%Fv9I;f8~ltE6sg&YR}vto2~CV@;1--4_co"
    "fDS5tn`1JumZmpJgHilElb?RzqdHSgf{D^`R!V-<tWIGd_%r|=FL<6AXz^)hP8#lb-h{-mNvYi$Ve4`YxjI<K0F=IiU9CDCG2bZ>"
    "RwzS+N=6N9IL~Ke=Ik4~7(D;s_8Wqow-s#bogL?4KWC<nU_v#VB`YN5Vp5l*aqvMy!z8_ar~n_gRUfxK%-e>h%DUYls;7aMlL-}q"
    "Jh=M_#8(Ace98@W=k<E)1wF5Pfm!&#49+9b(eO25LuUvk)lsa8?6?bPK_{b}7Yrc#tC}kE5{4}q&kZWyu9~+ld`C2{9z~9;#l^1!"
    "bEM<!hHyZw;$Rn?{gOd>oKyzgc<Fl0B#0tf2eUVXhO9iIxem4F<Hb$r$*9p8Ja{+Zm%Ve{ViC=*P)MF`MkbMnpvEal$(=yj7q?f#"
    "W(&RDki1MiIHE9+7lln_0dumrJ-E884XWjE&Qvz`DR`7SuC}a$b5^TQ!>oG!7DKY8gJZMD#m8908A!Zexu7CJnA(6vwh859hiLzG"
    "?B@GVh|vb5L1_B};t;c#F}%aZdzhj&=2I?{@h2hh9@+5gu0mW@MWz-EhF0Uxnfphf`eWEL{-RSJY{-ni1VI5O*_9dW%8Wm|QXy#a"
    "J)B>ENE#LrwLcQ->rF&sgF!h%u22&Bqa_o8P6ba;^YPjAwEg-ie)$qcL1P2;g9&-{Y3gD>QA<C*3cr57Y0f7$z5luCv71e2ZPp(O"
    "p@<5uPy$JWrlkXNNyz(GFf(w0*~|_M(b=YBTnjA#ddajK9}vxOK|8105P`wu60n@O1{3<Kx@NkK_;WZ`6YDS&QOKxgrW9gUB;JU#"
    "i!Uewls9hmZ#w4##bp%Ks9Vx|KryBUYIS7OtD>ox*-Ya@K3q*4imM(=mcv&<cO~_-oi*u`{JK`VR0-sj`}rWYn#2H@iEk&yRg(G)"
    "gzT!(%WB3Eytdh@2?w!DJF+OuNa1$l^Q0ul4e8t4a$oL*MuSD*OJ;$n%kMi}r171sR|_LC_o(DcKn_U73_g$$cW3@R6WM!q8h8LH"
    "+$l?UzfowW5zG5(KQ>c*uv3Nd&j<$amj`DX=b4~kzi>ZT3>D~(Zq=5I5W8gKof<UhT8-99Ht0msR_5w&3=yS4x;&OnNFNG2&n^HB"
    "*cPj5@H4U6r1ZEe3uJ&)%D=8*T6$KPDF+$1GM>#wCO&U^m=W9+-t1TiMl+KG{E6-LCsqUv-AE-C^1aytYOc2QXgs!qBZWGSP_<#k"
    "xu46pIczLJO{~~<z#4gx<-${m@YJ3U`6kXq^XahrUi`#Ll0R!RO-4EKLRO{lC7R^X%k}t04q=nSkRTqdQALHfz{3iK=5SqHjgS`u"
    "Shw57za`*q<v;ve=lI3#p&tqo&RGXg40dgLMm?X5(`UW1EC)mUwN(o|{e^WKCF$9Z6WBowa<1l(i6ACtgTERTX1#M_QcR1G(u%AP"
    "r?)pygqLK9rebx*#sy$8u4AhsmcLFdPPT4~%hkF@C$NU8HCq$9xoH(TUK`4l=4AC<5-|$s5*$9(=1&R+(-uK*DuF8!_5;!1BSP#r"
    "Zn{Szf>Mt(?A$~RhCuWd+1~kdXEDb%qLS!Fdms+=!=-=yPC~8T=q@(;l#LG6{fVZcTbu<1scu@K5H*kK48c&QDcVTDjr7~>$7ai$"
    "`<00rZiyKk_=tukgFhZ2kvO|M9|dVNLb9%Spims~;_|L5MFJfj0VrA%kN7_PolJlIMTsgdXA|7;={5Tj*aHXXzNWDEv&B(Dp(*}T"
    "03=z)u*T;W-wrwJCq`1MT$fOHw^FVV-0SJ}mBvD1wl8+kpDmw=Gl@E05*4XLhhJPVi(McGOPUk+e+-RyNnyALI92Jei=CA`0H7I$"
    "F%sc!YFB3YKWt|N<ghhd=RG1Qk4m{NIp{CNt>hR37Wdf2J@y1Qu_Xs>0sf3m#SETgHyI^*kK$Bv7hfVXS%4GP3-I<p3nrb6Gl5+O"
    "m<Y8;0|jwppy6<@Tb`z=xoj6C8cclQAz^VC_^#QMNY%rUlEgoQOHQN<g8w!i3>Q7);5=jN1<cOA?yT=TM-5Z1VLtL9id|36weB``"
    "VwlUPxf}+p?96t>8}25{a2*;RDF}(zIP-2eFgiwhqSg20MhdP4<C6SGD^>m+uRoXJKer8k&XO;_d_6;`nUdfUtDD{GuKc|~NX$3R"
    "y^|a5w@<diG$31fgBEDD4Jd`_O{Cx0^K+^j7frW?cRjXKz!S^>vi%d&jFgV1DN={=G^6RBb}>`K$hZcapXtN~b3}=6zbzmIG-EY5"
    "FWLpNm}Ucou|>PtqTSR3@~f@b{R@xW2h+`jzP-9cH{GHIYn}{+Ap9+!^f88)IRfP`3`M-IgauvNpq8e$c19fTBx^@76R#O<oG^yk"
    "+D?pbw0#pOA5C)#C+OWr(cuU*4d0~U>Yc*ScwS3rq2$4>!4OuH#ni6o&;xieWmwf*!<yT&=JE1u)z<*qET&7qHB?WqRaeoL%juSr"
    "HP<z;c*3hYTuu%iZ3er)yCcC7z(Ct@T58nVJiwFSd6#2x=+ect&Ev+#p1aY7c#C-?jJ2E|8=Y+9F)E{N&YsQ@uM{*7tDB|6ZAh|*"
    "RzuhsHz%3fO~L*Ab}@AW+M)q%-ZzGEPP*QB85zdbS~RY$1$D|ry=v|?TcZz=TuMU;D9g#DVDJlKn|3@}?&eK%m^ENIu?3S(rW%_~"
    "My={GQ)?C>595sM*;CNgJvwdO!T8|bV64#G#J0b%^A{^0V)}_#{zLhj-;5yJSD(8J#(p8J`^5vaJ(`l;4aI&gtL$Dh*)L;tiQUuP"
    "&`fd5HE+)lD#^~`$^POp<fb;$dAAq4hZ}A;ce=gZS-(^ES>`w9fcSjb-`$@~Z6<8-c?8%E_ckPnBt_-GYP`EYgTu|<Y=TyJcN^TD"
    "Se*-K!n;)+fKGYn3^RH(t)ym8p7?gsrISrPv|C9ht|xQq<iKiFx-b^+WXhxzmhL3(yd4YDwsh)aKU=*XjUJeS3Hv3!ld;>ngPt|}"
    "px(M^=us~`it5dagk1u9|1rso?%9g*_(bUPF3#h&$^9AdC5B$Tc_F7u%B_&_d-&E#$L`6Ow`YWj0Cu<M-k#xYza=35#8ZEU_7g87"
    "3LM?>&ypkiho{6qFFpqL06uYsg;K|6G)6wiaS|j`_Y0%N0CXTI*XHFDvp>cXgW(!^@|SV(FK;KTC#GP++!o*Y8zx!R`OAM&|48ja"
    "dHYaezq3t}e_xMYzF7J)9MgHo&BH4Vt{PuT`Z-SWv&Wl`@fT1fEL{+@vgt^~maehtGa1TXx+c>G#YkRE%ZV9O6-;`yWb+F>0>xqi"
    "3y0~trjGzEuP;nw0U=#U`w4r1!hoj<X+B%JFM4|({3zolb5l{~<i6_qWRR7zCFG$^(7w%<wA`kn@LS@Y+l@Qj*(l*Cn}_Tv6K_R-"
    "U>KtnvSS=aGa;i%)}rpu*(WDoQv=l%rS*d96*cZ$BI^uAx~{a+L`i5OfJ8$j@cI(bX&t^c%x<_-AuLXTFC!(^>jk3L#WMN7lBjxu"
    "d((M$bsNTHCLkNCVOW`?>Jv?x$Lr#f!9z=PYcOBpMe!)wz&2RzYSj$gpmwsjOnRYV0%PRFGrWSmpJ=Pyy62azQqFZjQS`9ZftIhR"
    "Y<}O)V1JyJ1!-O29rMiJ6EpY3O0AcnlBetficq0BPkNiBso_UPITXW`D;EpR-2uu~xsz&h0)G`es5M2S)JZL-6OKTHCId&|i*hk%"
    "x;R*7he%B7dvWb4WWCP@`bk&l-I3Y-QY~B#B;>SfygM)I+E9>_ZS;3<BaAzW9F61Dh={c~cW=zbQ(LVaTf|#jju1Zl`KY#RD>+~@"
    "P_#>TQuKTpA_aPAR%^PzxG11Mk||*rXuKaB@Y|f5v#3!7H4`IjFk0r(%?Qsa;<XQuX{|0uKqWW=#x<r<!ds%;>&?vg%=Us?B}N-?"
    "ubFh)GEmpGB|Tha^dDm-ukDE0fldS4UaVeAa#k_;OXsFx=yxWP;Efz@s~sn&8mq<vmzhSsHP&S(C>3cIJRy)kE>RH**G@&=DUbU?"
    "GqYb(;3HkZ)t@wB0t~bNHUXL-IF+n`nG7kWRE(W+yKh8u-x!!AcWt|?>CR|B?f<i+S#vZQF$fi|MyK6w@Atd}?8Xw`wBP$a0{>$K"
    "oH#@ZkU=^`8sFXD)$w(qBmiNwyUNTVPXmHtf_Qh<VFmum{vzsK`>Mr^p;DTJ^a-74bT?{U5`qO7wF6JGtkcSAH;r`d?i##BD7aYL"
    "PR7V5F_fN^qDO6_)9n_8EXEakB294jC|yVy=#dz7o(#<<y*s3cEZmaDpn9D71d?jlc>!kVABII?Ook#e?x*3q4d27Com!puV-1Ry"
    "=k95cp_39iVLtJn0_O0CYC;J=@R-POn?-^7F41;>zaAYiHsh|!<}Dyi6}v$7fWkIO1_&!qx|tL(y=QSYUsU2J&3t%h%IQ3)zh0)2"
    "nKf}+E&}<?Zg*z4Tl6;tW@8b!!Od)JOH}0!D5!e9Wb;5u;u%CU1O;Mnl>{qLl`wnonA1%}>gp)7L#d#vPhieF32McFT~!$_UqG|r"
    "{8ZPT-DFJ|VOD3Gh2L!N?Y_zx<2>z<KS*%)eShLSjsc%pPZ!PSCmC^PLg4LFKM)>op>OP&X01GDBsK#nK*nCqb2c3F>V0I8MInhY"
    "MuV)744h3@AVo6HlT<ou&_D$ygnVzv_L!75P>{o|*lEvPS26s7Ga4J7W*-|D$DBH||CV`V!a%e+ux_;B?~kRPZm}_}2M2UO4(8Wk"
    "<SGqF(z2(Qy?K|lLw7X-XyND=ZE}hrvQd^dhl8E6Ne^@|Ls4XBjO!_)n8^@4lf*Mo%=kn>W}hru3fiV4)|04K)7DQyJ7cLDf(^=M"
    "ztK#$;ckn=)J2^guWVr$!feV%n7DF<QH(n%7d6J4nenEV7)1~3bW__Ro+aG(Civ{39EyA04cO34VcU5S;D<AT3@@4PDpoInB@i3g"
    "n%fevo|uB6NEPQs(PbWB5DAjJWPdnzHIls4X1WBB!NvRbLL72591E&}O;HMqP7G3aG_JEsM%x+bwm{%a9Q}kAID*NcVK>;P22nno"
    "qKC7Ef?3_nR+eN11E^5>&B={i-<W!5Q!AnER-OnE|F&F6Pw!)AOGOgit(u`6T*%FpyD=%s-i6M{nE-6G+lW0ltVT;|OKh?5q>^ZX"
    "b|^M7<-NIpcs)Be+Hx^`RlC5hnZVxHXeXjgYb_|wv7F9RLjcY=oYZ-Z5=mAc^#d7cG251SXT01!@)pXjMuvIcA!svf%&}C+6x~av"
    "adHU2qDLe-)(t%s&<*sq1d=_wSDb{>@6jLhh2!~NY|or_vzVcc%j$%Gj?-=(<VL}!%RcKZnZbaYrwBl-R&oXC#1V}3DO#N)ExB`N"
    "AKdL*Ssv6u;?ZNdURQ-O@Ubak$M8n<8j2489KsXcSz!PS_3RIiJi4T(2_#Ti%<vXw9y;-`!$f1|A<SS_!6HfaQJDPas{RL0!my*5"
    "IUvLPJ)*-DC1U(XF8&d!Kd1O#3{n2NziirzgZXbXhKEI?p6Z38%51kPpnms4z_7kbju|u=@;_|BsFa#f$<RF!?5o=QwL-yW`fEj*"
    "qpg^ffp5KJAN!dM$)r0syzwrwLRE?w%Ik@ZCE$L3EA7M(Ea3>I8gNb(Td&L6HYK<sMFTjM%lYl7UA;VAxjJhYAXTIC*g235R^-$m"
    "csZGLVhe^YS9eh!HgbN`6I7qf20QwEjMa1raJ(4@1I?HXwxYNv(lXJ2R;QoG#`PR$icztto`zSPx-F0mI-mziBqe8Ks_rLEO19r9"
    "NH_Vb0cAz7h%T{eB2p3kvFXN(Jic2?OB<q#LH6|s3V;^N67{jDP1QA+NyNq2G+sLq1|^)}9}MM*4y7`FbE{l^>vq$l6qERd&c>r>"
    "P~2RJ`HGYjA<J>qV^Tki2G|O2`?#AQNds(>D6E8x=h8O6mNwx6QHHY~Iw{3#z0%^cw8T?to8OlgxZti{XRF+>6YTafIUF7ixf8A{"
    "nZbD22RlWr&t#(N!5mTV$yRTDRW5~2c%imJ7E=Q3z%kO*yyjv(@`+(BeShUn*MuEyhpyXKr;Zb6u!zSHp?cA*#tLiQFwL>9NnN$J"
    "s8QQlqsStSSZiU&23U=>HD#fSPN+X|lUiUSEvz)cT4H0?Otw}xB}B!>FD`80AIt+U?86m8W(mrP$xN{!mz#2RQHi5gNL>@n4&T-L"
    "r!e-3l329DZ_kpmCNhwPRZ-HzbxeTjS=Nj9Dz!-Js!$L%Jn@NBPv>7LY(@${q;z4#T^)Y4^cR?mU9XpqgHVw*B<39+*EhRiRpVOv"
    "l{tj1P7dB}oVe!*ipM2Fnq5{`H<&@#34xQ2ju}XSC75g|0sX|#c8bTBz3YzJnIN6g(9eYG(V7%*rAgp%wz-G~0|_8JYoQ#jj}uTH"
    "QO?UaOS&$yiaOsu6`&g;WB7h+aKMO}2Uxf2qB`j%zBWS($f4~PA&wZ-|GAMRz?>NuO+c|41+D#RKm{x(QZ~gI-Nv+E_A)_5rMcH{"
    "QAgTYM<#Q(zPlkILFJ?k6JH*M>L=o;y}CvquGys>#yXxMO{V#KnDSwgp^jS$XT7FgePE)to73Tz{FO_fd*XJpU$+SF%~ibJlogFN"
    "Ndb|()1V?Qko_O%Z&=8`!}Zq(Y$gzhGcK8Q%WRQMbaUU3NG>F1G?UE@W7}N%Jc4P(>1`!u9F@~4wY?wC^0&`Az)-0g(kyjkA(`T="
    "t$H-loVU(d9P3W29)-pm8b}L=t^uKI7rp8#bR!O91K9?kPPF0Z=ux@}hX*P9;(^w_c%(J)C7|eQigaQEG0KS!!QuXYpQA$Jz?qK9"
    "BdHVo+K3n?3%Y};wDCEO$|^a^B#S3h0vsY;=q$D2N+I3->be-yX4O!WZ9>yoAOhr%Q_kttQxE9YqT=fMpD5|#p?=lPI_MHW_3`mY"
    "z!n*KAkAsQYCqszM|!miF^p3U)tfNYA#pgUGwuj=#I&+rZ4u|2uYwwg*l_RbJE5T4%z>t>>oCE3MAj##fNmtB<K~8XL<=yY(hR>5"
    "G8rq!)ZiQ;gH{M?vrf_BIg4NkOedcD4#jFZOda-(r{A{f0o#bCf3(v_Ru3jP)-AiNjuy$#9IrF~M~`o>xK1X#Iec0irk`j9yF^~I"
    "9#fBK-wwP!sA~rmjrnf1q#~j8zh7FI30M-I-xYLc#}d6Ho^Qja^7VG)Hey=GZC6p{wjiU(68K=nox1?zqUp$R`#xAVpH#(`!=r;a"
    "+F$}cc$IkLp}B3aiauCHA6K1Crn0hg8AWDjD?x^CH^>5&#%+aP&8yhYVk9Tj!s;gLMR3pApjZ#?Xia)GVCk-O9ukQ$DT5<DCZ`av"
    "%<TqZFsmP)v5zM+;0d!<Q#1#|e2U@l(A{eRgK|DRd>7DEj`d++(J79kN&15bNwpG;Rr2<?VZP!JZrU-)zyJo2Osz&rucXGLZ-<L`"
    "tQ>$E47(*yUW7#1LP<jqF5e=8O@xtyF5j}CFk<-X&TbTrSW8@mlA8nigIICge$uNUK{seKwNkf!&jG3^V(d`INAgBe?9rpG5TM!}"
    "C>#9X*e3^I;Dbva>9deG*rh=zkEr~uh=>z99Q9xvtmQBoqQOvVc>QsB;nByXh6hx-E{p{Xlk+SxN-Dl6WkiQq0ooKWov0W!TzEe|"
    "0tWM=Sq=B-Jvi_%$pyMWyVVsMS|N+e2P;|^Q=UdN!(fgxM>_rv#VtJDlQnUW4BfNcl_atr9B!(c9_&?5N|!oV?j3$tW8zEWn+Xok"
    "N(r#%4x5S2RO9aMNOsA?7LqVKha(0f|KaWA;er2%asNQ@0f0N*$7d#Xf1Y1CfKukU!i2-h2Va;ZA?$mPnbn91!(f$gcym_}rr6<+"
    "<9MS-YIKh>N9TCbuzzoFLJsdcvl8O_-5dA1C*{b=gmeO>un%ia^B*L?ZXXF^xx&0nRnb1Wb_d2f_J;x7q%O{Sadc+fhl41SI;>*I"
    "w8_lCmPPNXK`StRcy>u-mS61}LD8IzlTJLzbxq7gbp9ysC%1~xX$=8}WlxWZ3tBR5Kb)5;Trd{xJ0P!hIY|@^98wpeX9tVv1B;Rq"
    "G-0({s_I3Lk8gndy!8btFYhLcY3bnl<11mJJjm{wVWKqOVus)$t%n~#oQy__6B=TN#b`l)A|GRcCIu(Y+FQ7_S{4GYfytzAQ<M*p"
    "zbso%ku}NAdLNs<HksVQqfHVJ3(A!k!sBGYkCGvzxKBh*ETnKLDWDhzfC&@%P`cge*;J7)GWlLsS$~s)?}VwhZfXji6+lf1^nQ@$"
    "+(;}uu?Qs(-fyS=`|U51Sx^-&l0@QL6R0bIvxA~6w%H=_bv2bq%W*FYLtP*P_hCbs1Zqxoje{rEYd=ElQM`3L-#|(<cAbp*21C*{"
    "m)h1yIyQU?kDx<QJ1G6_tF4=|?5-6%ik!&-vH`8j0!4@Yp^1Dv^w3f9vyEjT;&yYV!gBVz`0Tg#Ygf}`$c7!D1uTwICkD=Aj@<x!"
    "WrET<YEdHMJ!?vb4>@QFu#Xg8W+^~6VDw3;>l6(;(KJ^ruISytiSUe|POnZMTzneZaDILj#&K)Q{U4J~h8)mcuN+wLgFbEoZ2@g~"
    ";MmQmMTFUD%?>w9hr{9wJ)E+KQ}&>dIy4$63sFC`A|mLfi{T$)Cf{A~5hn}KQXB}q3~VsgCi0d)7ifi`GAe26l#lO1arjP>)Z`?D"
    "g#qcu&)^ld?<Un!F;Fm}rY!wxoS@H(&VzM0#Xq?rPnTBTJ1$;0@jg-KlJ!LK234jeTJJ==%@&*}Dj6OJRWDPzPIBYCt5J#?>Q73O"
    "nUueYcclwb(2GT!7mGFrR_m$vFBWPJ#Ft8@&~^s&usa88?&>GguxM8;5?M?()p8+>9kS-YtjbS%Y&gREnMGTdlc-3FE{0}MX_-h*"
    "kw_5s2McoeO43VKRa!46tO{Jx!o3%Ui#uE-85V?m7leG5#3@390>s%6K=oLd4KhoP(^I7KP-PSpKIs<xys6+W!3ttB)S)hgqk$!1"
    "MNL7f#R*@d5lYp1?{#r`dHcS8FnF!DUQj(^n%tY3p58e1?lz?@S&k&@Kr)0vM(dl}O+?FPg(I6fO9F8^H?q2s)9n~`<ghQGV%cVQ"
    "kZ6I^{>I2o(cX8e3l+nqYiE6>B!{d=sh~&@rrv*id_}aH=J@*HS09vKiEn=i<@I2omFE2T@&em1Bb!4J)Vx);$3ssUOngdg#zdaf"
    "Ejsj9t{}NLI1~$#UyL9oCDelrjft3aQ=8n<0@+CN%>)XU=#_ym=p-M}3Qz|$hNoDJ9?o@AYtTmlM1Ig&0mVoW)SZ$^|MN&p%mYV|"
    "eLwN*xVv4JyzdHZP$eMt4_ciACk{=^3z8_IiqfI;i$?5I0}sOgpU5AHq^fu)X}DD@n)q1xSm8GjwaS_6pn{Bc=VOQ*QkbppbWb-k"
    "v*7Z;m^%AO%&NAys`BbCP))PH<PUAJjy<jcHc8t&0oUtlin|pNtHH?eYxLb(&JkhHt?1l#@gYWmi_c_qu(Id?qr6qZPO`)YB`)K$"
    "ttqcFDL%)!nzw_1!mdn^<WJeUhs1AlW@sSY7iJyPQ;Ptj#vs2Gfr+c6cgYF8Q3V|U3A0Ih<%AoFI)N{1(J<R9PdJcZEGl>AOu}jp"
    "<>CJ0+xt4;N>-Ix0??{Zk!p|MrZ%Pf+6E;t?_2^hqRoXX%;EUA1FP*nf9@^<v_Dyk(Y!QU3=NQ4ZxlXVTnk8n*7aCMOh3^YP<co~"
    "9nQ-mQC1K3bwbL3fnss^c!rr~OebQWDE!HYZfW@~+~Tt)+E#?t>qnqM;?pFB(<FscB+#z=@xkTg<f?TK6fRJlprBRB;}RX%e28ek"
    "I;kx%A{Asq6+o~zhmxul5<<EIt0^Bit!knZ8zSny>XkY!P{6J%uoNHMC>+r!HQ6eOph{D<IanlXR%905dLtR`gJhV)2pwvG8GuT<"
    "k4w1x(T7Yz05UCZ<-!)Az^RRxBoZR)+J?cOSirUJq^Dd|CsLl7UZ3n+P83lepfdxaDhm}+UqB9^de+VPDNxZtw5Vdep-S8t7uAiJ"
    "ZA51CJx?=hpsi<?7GZGS#x`tGfpsom5+~f|6jH^huG6)6bX+~VppQb3si;*HfnqDx4Hfxk!V|heJx^A&%~}8gLq@sNtkgd3bBcI`"
    "pp8uG9)d^<vPUP)7xi$p*%~a7Y8wgAIBp7->xrSj1WXJm)JWM@Pv3&Nk<@;h#><E$F6?g=ZDXzXY>v$GjIm<D*BOLYf2yAnG^=i="
    "n^j9d2b!r3axo5Ox8n{UYjHq)<p6a-m9;p*fF3q_*bG&*Uq`#)9rh_uG>4oyhb|bWc=g*t>4|fQFdF~NhByL1pDQ3igrro@K4}{q"
    "Zn5wuyoFf~fCUpqZaJOUf^p{4SJm!Pe8x80tFNhDb<0|NEJD>Dm9+=e=#I_0!e-s1qfvPKf4c5jv{$E5kz~4xkT(RurIwkbDB7;1"
    "<4(EthTFtKY_!b<kjTTW+-Q^)0VyX22Ne|$<0Olf3>?vah*<;hfPB^SX0%NV)#~BNO#NpjMN@LP@*U*MVP6mB7j5w2GYevL21-~0"
    "zgGTIf+;))b?##eAH4lIgbc;&7eBtTI4J+fbb!j#V4Kd+z%EKM4G;JP1ISoMsY6jdP-QGSc#y3Ojanp=wgeP^uK^jrpnG2(@ht4T"
    "7DUWWy3$VyvjJnWLnIX4!OE%5tcqp`E%xvs#KN)|qH>B(nG{OPpo1AKTMU{@I;2@%HYogEgSm01x(s(!0vV?0>WF$7uLvXqgt11p"
    "4g4eL2l>vXR~aTUsa6pgvZ5+pf`QJA0IkVzPcRB8Q@HkAn7nFZ2(yJ!Ff>SzCp6k@{!B`^-9iqvbcRxm-QRp2m_JZaff{eim@%W6"
    "y!-#b6bxmDW<a|?1TNk(F53Dio)l>^lnq2msFr@jSWS3@fy3W)PosZ-Nm(}O0e|seBuvGVuNST-!<>Dh=j?+NVwN;q*^nd4wEz{r"
    "5Ash16}pRRr2LWWv`OFaTA%$SbQ3Cx0q(3>O6*TYM|Y9RNBjN7QeTTUFGRI#HvzNCyQ<aBs`*jnidg-X&y!9Ubdvcx6RZAS5|>zE"
    "1Xt}l%+cmm7g3FQIT;L2i|n9lNXq46Gp`?n<%{6WOsVSki2z&RVu4W2c;#uLNq0QhU83vnO<RKX_c8jUbGF2Up#DDf@LvmN=Bt=j"
    "2ZAovWt9|0z%_fp-T?x#auZMIu@}>9*s8IGW)JNi>W9rCe_V{3eJ}+y(57rh$Iy)F#1>2r#Gu5&8<s#UAbe~N^~ED9Yl4<nCrG_5"
    "kPWI-<GI#7m<pmvfSX460!$M3maUWT{?bw}i0{olYG7V}ac;k)Vtf#QUDuZ>D&o-L>X8r`EGL83nR2_X6i?7m+!Hat7pcx14d^Yt"
    "2cWs8%~CA(u-NpfZ~e94G$9fJU@&g^X<!&EBOrlRB<MX;W+a9OCvsTL)*ZfV1D68vVo;LF9X4j`?~%!yBa=A?CF7uE9E6@nHfIIa"
    "Y*(9*noU=Un-Y-=T-Fr51`wnRxAX)XG}PWmg@PMa(fQ86WX5g|QAs!ttj3m%`x3}E(t5xh^BkQprW0E*I3zLQ1_w+M!woj}mZ_v3"
    "V!~5q5s@QM@E$V#5Jz;05}eeToz)BJ^};>L5I^JyNA!RkpH8)^jih=ZIWeJ;#+<1x5+edrka7T*3^p(f2a2|&0(;@`*#suv!h5yF"
    "`qnj!$+VgcpCyp64xgT{K1BfZ4C<CD$fzPX(m7Jqi8|f{bV#tBAQxa7m~(87Pt5>isOqPdpO|)6<p0mPH<jl~i+81Pif&d5C}E@o"
    "bilS1_^TVnD^mc#j&++?(p)L<R~G94n>a9$_(=GzVtmy?7W7Ym?utE!Km!aQ8LTKP6$7e^*Gg9-*bJfN;8*YQz_h?nCn~i$^p#dr"
    "aD;1zm6Kg1xRnO<s$-~t14g0pOCR<6+4nRRXJ4tJpXLl+1Tn!dDn;y0)U-|)W^a}_7g}`y$WzgZ)M7w%$js2w!9WU_QNL--FsWat"
    "<>HCR1*!@#AshAp>dVd2CcrR9Lx1C`K%mAa?%T44dG%&brj}X+VGl?kMrGDuGs?HyE#u{l`Jz$LHq(MBHu4RXH53|Ccr!JypJ)x!"
    "+zcqny~QX?nYeNPuHHH#hl7y<M}L4CFjL@;ATr(1nS`Xf(-Y`<UES1Cp4^L$<O0*Cw!G?HQa0*C4@1?*9O#K?aHU6ft0Z@80lGeP"
    "$?-1yZw_vMDvRTln(3;iI#&$4phJhqfyo1P70`_Ql1g>*6`;5Qq!)3dp%p7#_mKugn(Lc-4rhVl5eKietcCL(8SPag=$ii+#XOT_"
    "_59S=?6yQdlPITNFP#CcFE^Mk9nBSZEcp6H-{lv$szqVfRf2RT?Oes4<A8;$&SDf|y*9iUs=<oIiVel>$M=6Gtydim60>8XLx+ft"
    "Xx8<%c<?wGj}yfRH2zud1IO-~y9tzBniW?M5qS+1x>+rN(73&f!DEaaeUk{V^=>0XjZBO|<?6Ok7vV(-1-Y?ux!RD8$=IPdan}_c"
    "oJ31c8Ty)1WfZ!)1zqzS0icr^7(O72DLx*_G~3UEoXCfLaX5Ln6|@_2pR<|*QRm|(!z7PN{^}-^H@+(G^>EqAcb&N8GzYaB2&{+7"
    "=E}=)RqtAuCIcy=cO<f)AatlAoKf#G4bfF942wnY@r73N2g@T~Uj?Q|5?dyEhi2%i%R)vo@;V{gq%x1LNU^DwIwPotP$Xy?`5G|a"
    "A?R!2ty*SFwTzW&Au9qKHs1+0nYm@$&h{|dQ5w0eWQLs+d2O%izS6b?%9wVI@fk)Y-s)l}#j*D~4YA<M<*!{pBc=tL%0sM^uJA0r"
    "30eHA)MkmzhK?VuXNjm`EjqCvTA<3QqJs;%tW``goYA0|7M`5~vY`SW%5LF)r{P+I`KLiQP}n&zG@}frJO1kRbitDVrzas!M0Msa"
    ")WHz)jd6NpcB?1casN&)&Zgs}-XN+vUOTC~tl~jQiP1=j;Y1;ekXKOYk_$OnC_%Kgh2l{p2Ix-Ge>D6mA0_uULDc3Ht+&;;uJnm&"
    "+$_jIg`&SgFtlQZpuW$;g~7>`@`+LUn`Y-7GxoQ{RAH4Ty#brd2D0qU_20^4KoVZiMRiRS7(nt@@|VKM<FEp#q9vLQy&8w%@Mki`"
    "mqG|8)Id9fLG{0Ht^*1@ftbvLZ`rOpp{sieC;(Ue#9)v-f4?&nXJ8om2z8i33`OMqZd5$*{3fJ2uG&yxn)PnywD>eRfo2azHdGSc"
    ">>~&=bb}H-b_xXcn2iA-zHFh}s9KYECmp-9v^zB^X>TUmZ>Di??*Irfox?#(h7t3E63dQwkH8d+S_LsI9*C(1vV*4X-JL^jO5Q#w"
    "CfrRmOnMXYamS!eVW^(L^b?npId#55ChK~Bs=oc&w{b@4e>yo@EjgniI78HG%p#hW<wViHWoQ+>CsW1EVl}uJ=zD>cGajNiwLunC"
    "D0~eWj|O~Uf1jxc78nT$Fw3ew6B4G1Eo7*Q!Swj?{X?}T*wbpb9?>K|^n;V4^_w6Yw3u3{SsSw%9i@Gf$OGsSaH<klFa<*he(8Py"
    "h51(z_>~nkNo_VoS51SOhv2%zSS2l-CkM5`$2g<WM>P5f(TCNP?*feD`jyF1^R%_ae6=xQoYZQzm8lZ#>Udo9`DK&cW(M@I+JRbe"
    "7>d2)XqK)|7DDgGR01(T_FTsa&eU`#J>AdD!P?!xsKeNTshG=3M|VeaY(nHG3{ogbz>sF0iZ^A2laC%vwHpIZfGFKGvR3CSE+8Aw"
    "PNq9l4%{`^5={m#J($BAao=F9bDG#4GK%$`+CWFeJHb$NM>5T;(Ta?yn+_w2;;>iRfaSzBm~^7jEqel~^~wTJcJkfjB;Q@ovW2{x"
    "Nhh8P>ZB&a*tqEp^)-+p?cSy#R0;4Gnd;(|?Uyb&0scZCcDT~N2%);&w$d2T6*fyu5Zc)46hLBvpxZ)^FI((3LIXfo+7OlS|A;!X"
    "ZN+tEiN5c@G$25QZTYBit;N@0#f)^_!5|~mT79n+fKl?t2=kiEV=ZdQO87k~s4L+l_-i3DZmrY}RT7X6cv1&-kD%@js#jL)?hx+|"
    "@$L}s4zbg4cNpDoS2Dt>y8FRcF*~%H`m3JeRHyu&!($?_I|B6b6}Gr(bu<{UF$k&U)cCU=@8qb{!-#U()JvMx;xw;?LP4mqp#Tl4"
    ";8sR%0$I?|tulg`l;||)P$Tvl5>-YPm4QWVM2H|Z!o;?W?hWhI0d<6axYF}hNo6c5k(?jrf-v;7;wvf}%f)1KFOTIWcOZ0GH-{yr"
    "M|hKjI5Bgu_=JfR=nZksVpex{z3t08aI=QGvtaC<mo6s5);U8VsZa9pbYC%n`hL21)Isi2f82Eau+Un6bjDlPl|?>_C<U*%-0{eg"
    "s0u=()U}1ZyNS)3I`2H8<JelEgROJ1e<yk>j_t;xRpa24V1w?~8={P{1<8;Na;)b^p^Ks5K;w5^6DzS7(sY+Ycc_V(i#0?2=33cY"
    "wz-H<+G?V@&^FrSrqenF$@rydaX%XipdDFmVC&n>(QpB5{)kE%l1W9;D3FE@3njCe*QB?3EZO>PdGDZ}mKKwCQx8>JtOkL^xks!z"
    "rAHu%6Jqqi{;Y)*?eFDjuPDony8-}?KeI#ois8_$kW}bvcIawQ8@5D;-nuJI>pTlL@o!l8n~h&af5^VzK#hPA7=u&gfJdo|nJ*}>"
    "B_X)<!gD_y9MMhh|MVa*(eGXx>mEYSV6bV&jSHPAxi5xnzzReB?y+#k=L^wyKrO2t#2WiB0vk4)DHr=!)rd0|lPbu=lKcy&CCa!d"
    "VTU(31u0;Lki{*|uZSw2hAw?bvq}#81ZK7bf*_1pE>s*we@NDb?sT*C#s$AgpK2U+@56Lm0{I$p*e9&ZUjVN=&sTGkds&V6r=dll"
    "ir46DWDN>{sB+R+%`ht%mMP)~jiFnZ8yfBU=!4asaZ>XEX{$}}!n!CcNMc@rcpP^`idWu6HAbK46g^pT9^YG<k>WJ9sFL>deh*h("
    "if+6VH;bYhkWF`kZ51fIr${HcdU|~5lRkQ@S%<TPUNSj#u3iUvvZ;Kbo}E;)lW#CUIw>kA4=xI9iv1m(gZALWfX?=`=$eUAuofV?"
    "0dlCx-FdPwcAl)33bs)0fp~Fx%@eeK4)aNW{2b!!%^nc7%Rl7b4?<*tUGTD4_`)*@qKeE9@%wSiehOj#`Q=KzFqzKG`Z8kjI?9*u"
    "eq&wt>tKH!YJo!i^}_Ci)-SZ9ZXZJT(zMglsuPvHBdflgH3g)pEOuk{)j;OZW4tWuh)f@WBCwv;cm!xAkvIBp#x(~!3x{5_RnW!g"
    "fL$=D2BQ&?IW>jBb)0`h%Em{Ey-=v`X0>Dh>_9dY)74f6F?cYwo%k@FLvWx0D?#C;31F)<Ey5~)d9xOE#g?xPi7A&wJvIE5Q>w*;"
    "YRXr%<T&Y^IEpGl>|F^4aTUs&r|i8J$it9LlVM%WY$Vo80~o-%yDjfwX3zE>U^_KnwWZqZrgmcs?DqIl+46v%);q2Dn*wU!fI&A!"
    "a3xjl@Kd=!GN8FSYSu$Xo7Vz@Pw`+!L_jXHBXTTcRCZ+XBYQkAhQ!aLeRh5b2$Y!mFcWHm&dac9><~&xwtt1h%EjLzU>P?gW_Iz)"
    ")xn}XnEio}Y<fn7GV@9D@*}eHtaV_8xm$gYc<J1b4ITswv;ljFVsbzOY-@M5(nBkv<l^eS`Eb()*z}BVpVdBTk7}Z;_ezx|rPlP+"
    "fdcM%S(9@x!Pzm9W5)~VDG+Bg59>Qj-yCQ;)c1&ZCrq49HwqoBY)uE5tXv~n4%A9Tk{D<5YSo#<K%0j@s}qp7Rl$a}EvU0nFO@*E"
    "qqEuVmM?TLHd8`TR;aG62zP6CQ|k@W>Hr;!>1_>VHaPgl(nI?UeW%J{U5DdvC0mau3`dlOBZp&F!o=8^FhMwRDtwrRLZ8}-^J6<q"
    "-_A^8xkuY>NqvD8=3)JZwKuD_w7>sx%|=wZovvfjN=Wy+DP?%KS6AD+yM^8#&M_e^BW2jtb5E;v)+kH61LgL1e`d<o{^VfSp(jUO"
    "3U+ryyR&uAA1JNo?j+qgGH2v_EC(ODYY$DPRPEi8EDxSnK3sA4a=2mJS%np2@oxujaEfN!c9j`3yX!FA8cYs!Y2BTzdv^o3yVu)?"
    "6X+M$U#t`o#_bmV7Xt3$Sx6qT`EdRnd@u^h;r8Kh`*660Kca=F93C{s2Q}{qZ9=3i8ACSUk!39$yn}gYyI#aPZlkp`W1vnPUY0y~"
    "GE<Z~cDPs^*`d$PPCQtkpdTgp?xy~51w4wA?Qqx+Zs1R*<`35KuBoga<hfSuC;f#~6f^H`)am~XM^wW4Ccw|(I;Bw$auWXPL>26|"
    "^$2akAsoRt{#y9|xzJXhm(ypsd0GE8bzrioEzNXu2q=7lyj;w~Ot<?Z!hO8M-)eo21Lim<d<<$|!fm&e?r(I5{Ir!bMR-qJqSdnG"
    "!9(wc9tiM+Iwtq1=8`TLumrAQ!ToA=M-&f%9`O+9!MmSO7k`*`G5uovdGu-JD(AcogiJv90P069uOE>riEt;H9W9mvG03R@4-QTY"
    "bKR3yRwO_}m^ld@f+z&f=zGNU3#~D>fF<zK_BZg$X_O<6-09UE7LpSpN?DFCX1sMnS0#`fbbit*)jyG@9|&LgXa;?7D<7H-POUXc"
    ">l(pWX&AjOEVL%AMs<f>J?g4!gvkvvi^4|?PAAPab3Lw31}6g30#<krJ^1NV;Bm1)Trym#Q7a3*LDi^^n7D<nZs7gEr?Fp%dG&}8"
    "{HKAF8pDL@QGTt%g^HG`GDdRxM|%WTGw%6nkA&-21-)o>2DrR*N3Tc0_pOBEdaDyA)F~{4vl<Z2!*e~nckqtqq$FTu_h6oXNX!Y8"
    "Q_5z>g;+dulz#HJ-3gbUO%l=<w{0OgJg;j`?dH^O4MHJ8Vw8~tZ;ecC%}q&bE<~+SZd!AVYR#tw;95A$VH0XSqTKu-CCna7sR1bv"
    "Ur7@S)1Up{>^jC1rdy3~eHpKRC|^251Dhom<Q}a-M}FxMk8B>-Bb!IOt$D=TnnGrW-GvURO%up>odBn_^hovY9jai$#P*+7ZP49x"
    "32>nEzJw=xs2vBt$N|GV1@V;!a$!V!fb|BH+_r(A+!T|eq37u#fQ}PfF2*Ls>T-`TRtjIQk+Cp67=L9r8`(J!Vrp;gXLqaC9jd|L"
    "wf{H-UkXt70BL+=f6$tZ)g3nHpm%dorUosM8{TMkT{c`}M)kmqLBa@@2d2d&Q_SpJXD-0{-2|qDG9@8TXVB?6y?}f=V^Diyc=bLf"
    "*LshbyPcF1t#AQUyYm`Eoq4+~lb2_q;GIs>lX`HHLca@S?*aPauStB?W5Af>e_5&#^X2>BFFDTiF)bevUaS-T0t157-e3~UY{Sxx"
    "MwB6PVh2RfttEGNiFW{0$rH;?EZRt<4YcF*4aqx=P_iu@jy-fh`OvK$K6>vQotVt<d{~Ummmle|_>BW`FOEJ1XD#(mdSTQw8M47P"
    "cDvYZ)~)KH!Zm!p8(w;fT+EJh`(Nyuyh@Kb2GJTF9Ibh})}XjOa4<x%I2}P#c|<DCq-t)`3x8gGfi;!nHI>9EQ-NBGL|iF935gE^"
    "=!-ZB$eGM~4N#4A)p~{$Z%ml-8L`bNU|~>P*gp!JAZ#ES>d+R;00_}fGDYjhVf~3@_#>h*3cjjZ`)yMo0WU)~wb5p(E-HC191Q3{"
    "wL7|!v^qaM&`DleNl}8lqLLW=B(}x@j7V&!&gvj~gqRp1r}b&0XQ)U)3G8=JvbOOL_bqA7p~=T)=(7=*6v#C`#|$1=0{!U~m&Iv7"
    "3noa0Y~T~cv6K*aA<jAlE>;qZcsiVT&bZYTf7L)i_??6zw3Gh3E6&b@Q_z3G&6Moe9rq}4yR%_;^6yUm-O0Z@`FAHjV?xnKfNh?("
    "Np7$TA&O0^VYC+lf6vj|BX&Ct$&QzlDnAck#QuZa+*w@~(EW+=7a5@nta2I9ng-ywaby&%OJEsh98Yp}Cq;J(%KozA6)MWd9N{zv"
    "_igX<&4J3+%`}9&TVcP~dicFofz4w4VzE(&#YO=b7iXJG&hC=4yX5RHIlGOTbGt?6waC5Zgl~}>&7p4$K85%m{#^bI;@&wn2lKLR"
    "2eaoIc&WoagOrJUVZ5AzgTvWks<Y+S@uHV1E{4VBs5sG!)0;jM5m-l3Jrc0qn7kC1yb_lX4kO4fLDwW4P~aFTu^q1ytqU}n-mFJr"
    "PdMGIRhP}`B3YwIR*MkgR4kJXF?|V47h>Z9SxhOfA-G>mwmxO2x`6t$ny>`y)-Dvt>H;fRLanv#B-t3E)^jwYFmpn!24hd$d&ldt"
    "VqTt;rmK&uX}1j)){^GbPOe1h(vdR57l>|RGM{eT01{u20&_5{fxtXHMi8b839e?}4xi`W!mxTpgtu{oV|V&<uSodx8b;EUR)7%Y"
    ";-KUsaxz<Vy*Ph8hd(`3*<dTQa@E0h@viynI1wWUCb}=?-pR9VKb1Q{8~#pwy|!M=V0+6K*f<K*b`>PrjOu1!f=#bBq#}o=UK~D9"
    "Rcg6mUWkWVk6P?k;e*~5oy?K?K>t|N&xPq?2x@gunJr9+j%YGbv0OM>jB{#p$XjAiR9p7=tV#m1(RpJr$7URMF|J|F-)hI~ktu9#"
    "NMz2z<~`KC2#j-_6ByubCo!?og*ND@P82ceVqBn1Jn&ET^Z=%w9+811n8+4!1cwxItJ`SCn!BkMwLMzmXo%Yqn%xe%tq$mEJ(}o7"
    "T$+dA&HZM(UuIA$8*}v3qH$|3A8y`#+UVdlWT+L25wX#|gClu;fESO+#yOV<I>f$qXQ1CL1|6p!6n}K`<zZ{G)ICJ+9-?<I|D{eu"
    "I7c(VjSKtAiEZWN(I*pWuEju!uCK)kyJ-TH(FjI8c%FDt3Ql*A(X0JnO*v7GyECxItfV`zU-9FhA`2d&zMvYj8I!~;3ZJ#SV`XeQ"
    ">M37nhEAR5@(__o&I#{TbVrNz&*#GWlU@`%o)X+yg{&?-SqFWpO@94np>4-AKcAwiQ?m*^S8YRpNH-Hh+xcA63qb7MM4j)NFys?L"
    "k0x;3Ya*(VMF`oTdcGH@>07&;@(kwZKW>$kO<0!_fW3;P`fE!XtGqRWnV_p5qD(s8MWR#z%HX@qVUV2QO9{PpFs6D-ln7LY)xOr>"
    "7o*+xuVkqMGdJ>bXYn^nLN=&knM2Ao3`HqxU4IfKdFGs&fRvwTpPohZh3(fH&tm&Jdv7#*S2QnvsQz$UHz^Cx6YX{m6al91ISyJM"
    "-g6dhhD$Si@-|B5T!E-{o4ulL3hf26014a^=~fH}jk1{UOb#<mNxmZoPRNdxP^A#LiO>!>rYbUwWF-vII>oEVVpf0;-ra=@8_-Qt"
    "fXzB)5aN5cbmGa3$RWB)y@V-3UCb#cgVQ``+G`*m)(qT$kCsw9@%Yc%UOu0Y*&WMX=>=3}nQ!xSv}j~Z;x$YoZn`~i!m5$VzK(t5"
    "@I<RcRM-4uT_t;MKr%uOB-b7sS{GFjMrg>S*%5eUr$49DCv2MA2sETHqQ5in0YkkTh}kQ2oy0HuY?DEl{;)Huxvjj_f?WQ1%OZb1"
    "c8vd?$WM4ecgJ3`3!n{Xp_?GVW8@@R9mVy<Ak6E*5;mp8b4$t_(udEBT*pO(n}PD`X}0$%v(Fw}HE@kW=#vHl`&PogVmBnw>hxV%"
    "-VsnuS8qNU@rqUH>?wNYRDozHB7m0M1{3OV+wGRDTAc|i#1(NuM0*g!*>~|O^^qf=H?J~-SloO_!I)sUn5;{2Ov_@)hc~35Bvw4W"
    "2eTQffkj)rF5LjAi~jC5Q(}tM&FDpFQ`V^_Q*Ar~tgCm$sk^&h7(d+ov9qt2p+(htIJuqJ`_6$~&);~mc~S`o7SIwBXD7v^)O<&u"
    "XG;XvXSyl#gS`JZ_CJpF4`pTlaY%pt9h$<~S2`giL+S7%&4vmp426mQ1oGTP3b{1`KF;n|E|M9|TVWz(Ly7dBMb2qbeC{DjL}D;}"
    ";yAJaOBm?gs0l-VF|^W!gF;ycEhp$0LH03%2^*9Y^Z9`Z1B%lF7cLeYBFIdX^Wj`SA|W^^kPmhskij}>fsjIMC5e(4{~P|^|3;Kb"
    "ceA{*cUaO9&;$Odu}oCBGbeC^&+fNhs5ZQ8vtLk+85mHaN1?2IS98~F#Oq{=WnD)lK8y#mXL~bmT$;JYdg%3OXDsi#P4Ir?L?4FA"
    "jPEC<aC?|9Xoe09C}H!ceF7nA-g5yHh;xF@AU-o{&y3cy2QqX$t`g0;+MI{Y`PB|vCTerwuBlUWV2sVP$L11sy9U^d(%M~wVrNwN"
    "vYP&&-v(WKk6O{`!nzj<vi<FD=)0>*XH6{g2m*i=(?5hhzU!vAyD8Rwpwq&As}66|Zcvto!#GI!D0X8BBYEjE$C7#;e1EwA7^_uu"
    "c#MVf&{s5G&u4KaunQx)1ni*>Lt_5pF#O={kFB_+`ANj?hqlYDjvF0T%(GjbAKURae%K((9+634B9tWyF*cjQTsZ|Ss+u6&3~KGy"
    "I32tqU`}wi6I)HUP}zz56fqTGRYtfAY$@Rlk2fA`eDW25=pZxuKduILV+u9Kna|~isf{vz#eT%<?flh;Jpn7LUE0nc6d!-$<Hm#2"
    "mMcT-b=f1J`{lw5*Q?93;JpN1Y6oW5fL1_x^oa`5P}q)>#9Ooz5ndXMt$RQt#_ovwPD^<m2Q}J*26gzHA%30JO!yIT?BS+gU++#?"
    "F5iImZ8*UW(}Sba>k`fMx<nYRAjJ6!82j6{#ena;Ya}rdkVustbO{(n>pIll!MzT<u6m~gD511}U(xZ1FnVe!<kQ2S;Yjwn{NBnh"
    "=y3lQ&2`sBcVFgITuV2i0ohOhB@2rRD|?TtcjQ*K$5wBHt=u9qP>jWpw_=K|6Aqqr5aiC5#+r6(TUTSaRg2b6zC<n{yYWCU%Hd6*"
    "m1PHyR7ID7)tEy2pLucUMmMci@t$F<$E}1m`#9^wmw~dCqYSYWrb&MWaD_hK^RXlz(1R9(n#PHp>XKc^GV@BkXFQ1x%ddLHd{Vrd"
    "gCEl+;1#+KjnC);)tG~!*^vn9W925NVF{#K7Vj*A1Q%&sf{ZhgxbPX8|CN&?Yatdq`gp{a**acs!v_8RItV*GgXqhupcEMJ2gV^D"
    "+abEUIU7D^wEE2la0NIGv=V~h#$`k`7^f$Sv@1Lv@!wJCSPD0WCalm+M5$MNYOVOdS)tP_3pyHJ6rc2y%t%q?5@R(FW(zML0W_Q?"
    "wk{+*PgHJHL&}2>dW)iXv%Ea`ii&*E)f-XGiX>1DTYQ&Ij7gQS#iuF@I~s)zjl!<_qyrBK-lN(#R?>?{5(TZanblVaw--~2)-VmI"
    "Is_dq*nthTeDtk{;z@Ct6JL3a@b{x!8|g6WM2mOS0rXc$SXzfEHr#6!4zZPN3$)?D%VxCM;0R^}g!!;17o~h5bqni+k&`PWcb^21"
    "@Gbo4JPi($9p<xMP>uOwi26sx5#d~Oy10-~>SeV?Qlft?Oy-OC+L6j-zzXGPeb_zbanb?Cy3A}Oh06m@xNn#_aaO$K%mq-5IT&k)"
    "!V_R07B9S`bRfh^^sqmNRklx8B^*|NlP!H&U=#Dj{|_FmTx}{|N+@1LC|*RE5Fw-<u~9$iSOOfZb%b5_oMnyE>BWu;Qc=b1Y?PTH"
    "GbKZK(gWSYS_jk%@<J=Ea4}lBS1WXef_O2aW~`RmEe87gw8h`o|0DK(H~aXzQytdd*^ueofyJP?zGP{cHlW*#@60BfDViA~!-QAD"
    "uuu@C&1uNfNQa&opz+wYpd|a|fNbHy4Qrtt+z1nCwD~5JFdJ$p9je2sWJ7xqlUOlSs_h8B57I)g+nhx`kk2Y0o~utFHABo53}pa$"
    "R~N1qgNp}*HARFCi4xdd+p*rp_AYkWIj1?{SM&u>s_r=`>9D&Q<wyWa1cl;vH8Rfmoz?mY`KkRnG1RncQKVRQx6mrbr(4UB>cipf"
    "gBE62urx(1tS1z&Clscf<+!n0Q;vI~Op*gkLy;RLiZ!Y(O9$of<EE1-5W;;NL3cw1D1TIlqm|tXb~Gi~hZ&6-Vs?!6GGc+Q=$Jb~"
    "XP^T}o*xu%-b)A#$y1r|AdKcf8qL9)wFec&OTl{A9;Yvop}y?$RZOX`G?ea=+4n`D#vvgZyH;=zPjRpu>zC#a3kp3fr2@c=#gpKY"
    "A@Z;KHbdbJ#RKWKhaaF9SPOgh*1mSgV#>&{#35*54p@zsu|pmU040t_3u~w)GZAJOPJ3iia<E2!SEEDrd-mWSYRX@=u&2Y%+8?}u"
    "2;J>vv8L}=@aX-d!`Vb>u6(;WY1nT?iq~N=5kLnByCp*$77cM&HpF4!5Q1U4Tl2J)_yFyxkGo3717;8Q6P%AM*&s9Q2;mN(&G9(L"
    "*D~_e;1HZ<hEQg!9C8w*<wz+p=Y^O<C`#>$tV7aDsD{JT27%!Vk;^S|IW7)@R-5wa&Z%6G_8^X9m#ZXoUqbWaCf8-35@+j+i&yvR"
    "fL{Orx-C_MBj9u0e#YeRD*=aJFFA@!SroGFe6TflAU(!Roh0vxrX$V)2zx*%zX402wH>ci@AjjHU-g2pwFb7(cbHQ69V&+~N7}gD"
    "NAgBq_U!)K@pFCd@l8rhC(y%*GVJ|uqA(dQtb7&Ly2@}#9XB63EaPs9J$F5VYIJy9GMFG0*2kD7mEnEPBEi(Vkt3sJtU-G~w>n}u"
    "JZ>A@jx2frPe1_ZzK8YQ@lN1_|5`R$ic!5wF_|al`zCWZ@UsonffYTDvKT^@?Jydsp$iq(@w`|JJ~jxS>h|&sCznMPpwqRL?E6bH"
    "SYX^lN{h#i?A;eu<En4gSB@z!V&aB-WnRhKsfVRgOn5WCtcxvNE;41SE+2-jk{q|A)*@?-wJMMa4l?8RKz!XlSf|gJ@Ksq7qHMep"
    "cX$C^>*WzHABh1&O(X0ZWp(+1XMwUVUw;P=6BWJks<S}NgioGLdSZ0<NqC<r(~&YdJ25_yC$5E2!_RvOt8sC^vPLth4%6Y)195yX"
    "*-(?Q8+{=SW;Na&QyuCiy<loE-RR4x;#v!TF8?lrFTnd*;_Ou%QJoACf9f%Am=x}w$>Do484~_Pa3+^pFlf9SBZ~^C$@l!L*QX>j"
    "&bt0O6VvJw<kd&WbsQZURcW>%4x`f}!t-Z5oZ)_O?m+16Zj^{7G1g{5OE>GXVHi#;gD!ziPlVBe0h-xQETKJ|rn~!$8pnu@*0@6-"
    "rq*H=0d#oh2s$*JvJ9fD&)xzAg%Nc1k=F^sC%|e#K)x8?6P;L`;nCmu7^C(Z-cA;6#yBMHUfIHji{xzS^0=jlgI>8<E~XGDq|6v2"
    "65?!RWg(AReA^*v|L<k<D4`-Q7#N4E!Q`9_%{6Lv-mi2q&W0;quAz-(ETP*8ovLz8?pJE5lY4~OrPD(F6OOWJl(f)v5V}>vl#dRl"
    "o0`^{hI(v01&2RpatM61R=7VdCM*zHm%Y;oe&+Poh*dWiw8+)RsoebXa;I{Vww2X4_j|g4*@L0XWajsrL_kt2l$8)M{X*NZ%FefN"
    "zwxS2FsD7hHscR~<kaT6T~3Bu-saN9WV`B6wL9$min`9`;!rWu5Gaw|lzOAEdZ(~@tFY$g=#YsSZ{xOBjc}d|x~H|MQTen_PWvo*"
    "K`%3W?JTBzM)|5UfjU#_x?Maa1iR5-Lt4I~lhvX=z*Dtexm}2F_hf^66#Oz<TVmuT%n9ofHrHkQr$eC1y|M`fV<U#F;H4&Rh0<3Z"
    "t~tVSX$<R(Y?qJW@*t*P7#g3@@Q}P(-aM!rEYT<y7lGpPTAq+)4_E@zg*6zQJ}n5RmgrP?mf>;fWZR8KWHSB2{7)yxSF`CF5Sq?7"
    "p}lexEz<-H{o<T`7B`ILIbOCg!eF>XDX$v2BgUEXQde4oYwaIX%(<Z~Z%Mm1`kUEB#reqVPT&Pgp!+(w8jK5g`QtXKIF75!-)aw5"
    "9SL8|{n!>Mqo=_QCD6sePca4aPsj0#=b0wAC1>YE2WGpnX7gva<f21gYN_qE=X9s(n3S~~m@qD<ogF>E%3-=XXkr|q-En1YPvFLg"
    "wWIoPMW}iyXu{P~7Rx*W(}gt{`)pA-!4;#6t}a47tm8W)71`l}w<CXK2jj@s=RB_R^3a5`m0<SpsYFQK^9jC2cYWn>r8sJQp}N8$"
    "MWSj!DALz*pkerevpxpKS~zjMomc<5`qG>&jcba*eJ-tPojBhvE{89+(Q_Z!T(sfh{vpZPlM}ipH*sALAc3pfv7TC3aFX_9-+OfN"
    "nteKo{e4+2KD}9eDi#QXu4UfIkcb4pL3g4IR~vWSNW>Fb^JLUl^fCnCbUz~jPiE&JA9in2;@-NL>Q3Oy(KVbt0svztzEdqGO6z1U"
    "qsY9|V@=`LXfMkD+<2cp9b6Ft=Q8z!Nb<>i!~1WvKwQ+QxbvuYQh#_nY;`<hEXE<pIy?*?9)=_Os=7yD*RBp5+td<ij6Y_WoKGg3"
    "68oW3aFtQhi1F8GaWP_YZU*$A;L(<KGnFE-P}@BFo>06FF0O@+mM9trx0-IXup5o2n^qK^Mippd4!+y3y_tY(AFlBp$GA=#_;ih4"
    "*A%Jly~iyMDf_|AgO@cA%b5i30mYaCs_|nW&xSVXS-BYZxFR|kmPrODrH1xu1|fSq*mEP>c!(2PfC_C;!p&47CO`sheG9RkZBxU)"
    "Np~xV_alPEkbN-!92S5izz<~$YyOj{TLol-r#hUVi`DQVY8!m-ZPI2%hw2Nj%n1u&GUNbq&RoZpT8hCjs_}A4&yq>Xy>@%gnH2#("
    "@7dIPcDLgv9m3#M?88ru9>a%}#vd1gKg-$yYQo^W)}$w91tYa1EEJBFK&*ET5P<s1sw>j}U6T0^cUHrasD+rhN78NoyVc#6>_TGM"
    "0qm$8sI%ss(}Q<TMX|E-%Ex5p{BwahAjwp9ajeM9Ro?(vvcZA%%CPVZeSfq;72(w<$;L|i$Z>(e=9S(}<&f-PJ8II`*g*`Bze!?T"
    "IO#=OF?-#&Xo5)U#L(&vQAR>mU@;OtCll$*9?_%^Lo&s4HH)IwtM<uBx;sgCuCf8oK&qOU(-xGiYM#d498TH>t{Dv9G7zkR!$4yB"
    "IIicKgB_+3XK{rXaRzSezjpVFMP2%2p>MccYUOaSH#*`l_=p4FgU3PyEawgOkjBB5zQ2R^B_e2erZ^B=CYlYTXr-yCjB^CTh>=fs"
    "f%l6^7h;cS)TpDpk7=-NAK-%Vx5)Mid-y~6fi7Y9gBD`y@F%~_WJjz`3@*`0mIb-deA#L=Wsq4uZH}bt9$$lsH)+(JrQP;sUpjQY"
    "c>GY8zbqmONX3b#)k^wb-xc7^+2eN(@$vn)T6XdA+uzwR&1bKy23dgMTr+{Q#Wbo&!vTn)oR}d^^po%k`zwYk850aTa}ol@4}VIh"
    "4dN&=kV6?(#wM(nIpU+tXyPp91MQ}14YYgjXPI%B>SfRj-++ASe~s4vW&?U{!K;Qp4U;*h`=abfJ%R}}PRKxExAjYV6nT|y=?+xI"
    "L?_=w-@~W?YVid+08%*V1dkwFB_ESbwBtF!1ee(c`46`8W=&1_g#K>+0ai#*>yTt=wXa%&5varEu($~J)T~a}F9*7Xz-M=cNMd-q"
    "{eM3G07Q982WnD7x4H$FH!OF8d`q)vfRE`OtN=xG?y=AYBm)vieQ<J)t(Kb<nPg^2Cip<*OMXC;%W+P4qB})~Vz3>K6i$Z2N)tJ0"
    "DSYGkN*J@_k)3ckC?;DX>GS3Q>KP?%v!FL8c|fvWv8EN>)LQ=J9%Vi60TjrLjCnEj4pomQv?;zdN2XJ_awnBJ@$K8yqW%&R)Xk)T"
    "YSgmyWKKe?DpNvyF<U_*4u#&xOY)*rDs;hP_8x&Pkks%tqcH`BdAGTBnTf!JGt)3t80(^?EvV|HnQ@^tB-m);Et@We(Ax#@$}j-`"
    "vc1hZ*dW{uIteeShLCQ$1iVr(dl-b;!7L2l#f(=aDC5PgvAWzXdAI7Eczs;BT#QX>xeHO?qXy#@DWuR2B-6eG+NSPwX>&~NIJgER"
    ";~b5#cV?xfPr>b%3j|P!Q3nh96CX(8<LhEdI^0($!`<Il9T4wV!VGI@+fO*iy?e1I<?^Lm-jwj6TrPQ$&6qB<fy9UfN`r)y&|qi-"
    "lpK$n_V$oODPq0kw0Iz-%#Tn_`b?{`<w4oukzQam>;dGB-{%EusC&3Nt$$wv)(cZG{&Wt1?*7W1yhD5+5SDEC2~Qk^-45gXL7S0y"
    "XiEq{g;Pw+Zi==G^uxvX5yki6h0Dn_4zq~q%j05pl80U2iNhfnRH%n@_VG8pCL~SZs%|w*q7iA;-3AHwBo&^d_cLLDL~uZ|4aK-z"
    "KA(;$Sc55Gu`kakEfOLw$i;xKl(45QhP57`*{n8;wS!Sz0$<4m5VXby-T(83GIRkH5ze?)$?}Hki!aLKiy*%I!lIaNYA<+*V&b5*"
    "B8dvX%YloxwBF(<hWP<WrX;+^l~616ZJN1EU^%o}kpVvG3%Wv_3hKBf-6#yYZb)=l@ew#1L2N5FL@zhHII(xS!2MYu8<gDqLj_~T"
    "Iw1`b1xyzsfBzIL7cx$;1f~mRixz#2N(%ndknu{Gwd#Q&*bN}nEd07!__d&z?qv2#6096OH>L~i=+_ioT*^L{bz*Y|@ky}TP~yF<"
    "wLvLP8>z9~7B}x3J<6oy<MyysOx!SS(J*Z~RU@#4-E=V!$SwWP<z)+{osUpB{isiyXH&t@%xnzf18s3Pec9qpcerJn5y1$>=2ArW"
    "u<6w9h1PW#%O1&7_6x!|0(dN@PNXC1oTl+m+o1&OFewmTp{K$41lOX?MV2q`+{`le|7tYWJJxsi@%udoG@v+0lQCF#@HN`I-MzzZ"
    "QMtijYC=x!+Eo=`^~tx<Cmpy`5obsQ?+oCA8oEbczQ5g??%a_VQabkRT;3gK^~QRgGzVhyhZ?1)NdbrI%T3$5xW7fRlOP!iRL%-*"
    "#^G^?-l70ZH|S0ma=6#KGVE~Yhj>wtNFWgu2u(XdE~c0PJ#9#DNxmOW$-^mmQ1lOCV_{dqb_ej`O-(;8+JT3u^{8_PV)els;L?3$"
    "N6F3Rk!{LX-2ol$e-8IL9H#-S>Bwaoy(1H%>^Nn|X^r>`m3arc+VYriK++np1d_`~biId<k_N+9eQ={nboV4!a_Wwm@$&3{42GEm"
    "R^K=SnxThb4~F7I7G9@m#E}iv*$_)QdL2^)Ejc0<jS}M5!i0N34@kx@P_62A7-robbUPf-(>6{Uk(Rs<CU~1>Ynp1Osa_mf6rD!4"
    "Hd3Iu>$Z3vAzz}cYcEnPj)s~c{MjnUiG*s!-=(58ny}_d(xS+>DD2IJyhSN*F3jz)H;1jz5;rGg!*wI&5$h{7VR8@i$H;{Pzsmx}"
    "&t8)Ud2ltDeChaGy;_Y6H#FVknT@nooy6|GP#BE$aoLF*@$LRXcUkGgvXhKGS*JpA@Jcr;-wOlNp5v=m|J0*b>Q}E61GOF%w&$RG"
    "0Hb0t4rh*bxv!)N>EjSL$H;4XVxHBJXzx_{QjZx{?=ib_73mbvZm+u9tBb*O#OSfR3+g{kfggWG<$l~mh~97^9u(r?uZ%lg!JsG)"
    "`W}koz=!b^!O?DwXx;~(AFk{(5a?Bs8Nq&lno1JdgDSlQ2JopLSvnp1GX}WAVP;JMC{fUcP@GRmHbD;`PZyKZh2+fcmrmNeGutr-"
    "T&m>kPD1|uMrQq5<i}*3hJGu!A}mJ~J&D<^51oyfh5LpeF)^8K3vqIqSp1yeHGMHzRFy6<Qk`^gt06cneO#bmPGiBw3c=2LK=Fu|"
    "-6tX?A5*m#X;xc?k!I8%BwDv*anV8o-SI?+vaozQ$TNYczUD41)!KB^Lpp(>L3Nl|Z%c#ewm^g?(Eo|CwQfs<;x<!Hsd&Sxq~{9O"
    "M+(fLv8D^F8N5>Qo^-dzG^!H@{=bJNE$L<-n0`!<oGqb^D6r|4ZRX%=a|f_DtG}_@n{s!uh^a;^9UdK$G2{zvD?Y?BiypAR>oTb0"
    "W^6vfgW<4Lf1H|>Zq2>!WV*z4O=dV@9n#^)E5&uwP|yL2A??CaMC8t#I7yxy^bV~5OiA~<E1ocP9Up|^Rtt$XSb4D7Bd*$7eTA~7"
    ";25AuuJjTRf$DZ}nc6?%cc-!^WZkKxdju$^8YoY9m!vx#fxsWo@I%zmNM6hlgU?Yvg${Q@{IM9Ol@kw6c$q79s|Pg$!>EPj9^ReT"
    "XE<d(nYYK^VrnocQu-b7ct^<T86-bjrw)R#i#<$sN9Il1zn$B{bRow1hIjeC#)mRB;Lc*N@lxBkS-V-+am<cbBxVkqo$60X^pQMa"
    "-Xkk@{hAOIHIR!rr|QHUM%8{4%3X2cD6^IZLre?vYGLG`j#v33ItlfUvEOs*au04F7g~d{Ie4kVKdNP{c?u(#HM|^;fY8^@r14UR"
    "KjVrQ4@d@someq7W1Yz8>cG_Ol&C?i8M#^`SL>ClbwuJ*etVR&7{PE>sami)g~Kn#>qNao1`4x7rQ<6GD{Z(g27hYc*Erm|>QKJ>"
    "56ij*qp!FRm!03cc4=VN&~P*I>-E_5xcW5Rp8{q4pz(QR8YCWv;jsQ<$c6&^vF2uH8xtoOJfq_m*iE&nLupF%%sX*-=>Ce(b?Gt7"
    "qoV?6t<`FZ_nc`zF4UHC^}3>Hcrb43axuwF4~>3V`4KdZ3QT5@H4_M}bL62n!-+q`qom`cH948m!_|=63ON`oCxkkJuA<s>n{>Nz"
    "jhKrIdZ`7jdxhFu4aVN=XSNQ9-*a%`<qzva$#3O=J;2Hxs^G>1E<MRm?(`V!P{Op0c;MnC2xSVm@Uo^GTrgWW*wTg744nr@VFmsO"
    "ZZci_(<SWb686m4&SV?MVGa1jY-@t4LzwLf4|SH*kOC<VPf5%*xSTza&>?i*Jy*Al6Mq6QE-x3qXW8$DM}U*Vn+_A}J@93JO5FmM"
    "z;xkdPTq=f{eG7J$8;ff*>D!RM|wt|{j@x$%G-mCZ=QqVHo*xraS#j_`De6IFBi1e;tmX~Fns65!1kqw6OF~tfDKCfELZ~5h4zT8"
    "7o#=0Eq2@Mp>$}-5kmfYEdY(?%cIm+wicc2%frT(Tbc=chWSN$xtV!o3g*j$_LpZ16Pv61i{kR~DDveLelZ`^t)6V4l)ZM3dS1K3"
    "x!Z|*dyaB(^=A*TlWdPrm_#zV*?JWZGhSCgd9kpTUKHgxmJQR|g~be!;^>Glx;z+kus$5b;UKy^y|{}l)Lc2y>Ai1>aKCRJx4u7F"
    "lhO2Evn~DAJM^<dbgpNHaQS8*+(NUhkenU)DZ*ArVnZQitSB&iM?2k)ne&J(Z@?q7*)!b9b0?#QKu!^oGk5#!3>09ge^yPN)u^HW"
    "V?PxSx}!fa*8D@#{YjSsU;ZE~7bFCKN(|@z6qg_NA0{1(AqC)gIP*U4RzIto;E#tbpUQAQdeqM#gIDjJ!ewi)^lYp!2U)$klB`}E"
    ";T?@<AR!iWUbtM0ot)w1$8-rGLX$~*pl$uy{P$9N(6Xk5p(dh4N-#Na|EFWCFDuErS*32(%w^3Vj_IK5+L|2bbh;H1b6G#VBxvqy"
    "=5mA$g5i(l^fXk1!=9tsuld8LU7U5Ib?L$I0e2m%yUf`KIDp7d(pi+(1$Y{{PE}Y31oM$i?P&ZjthupWqp@AbH)b;{5#LD5jh(B+"
    "R*<OHM<+TVHb1`!6Y36ByQ!Bc@3aMDBhTVCH@BNh(zaZh4H(b}%xNQ%ce^c~)^9gATAP<cg|413$xI3pJf(_F>RH;BV$`+e2!dOM"
    "&DERzqO>ti*|JNe6TtJ0&28o8oqaG}NW@*wwsJ+gguSrl=$39zm@90D7h$%;Rdzc(zSs^AFhKmacs`gMVEy80!WK*IV*VeoLadx4"
    "BeIMYy9v%$7m#ht?w0yPd$7BW-Iq`iw>`Sl{pwP8Prcn0#U_?<xtJ7;KFl!1L*q%awH&71OE|vC3HDGE9X-6V{bO=4c35q(+IX0v"
    "Fd_FQQ1G?yl`bR-%yai^ptxTn#XZJ)dkpsWYqYmNL;X+bW_W)Vx1IYn?h-=~9fH^5Zf3u_TlUb>{`QE10m1H6pfpEy+w;=_$?@TQ"
    "eVIpJ#5j-k8~g8R_g6e3@G9kmIgSVWqPAx*e64JzZc-<c3{DCp@C5#2@a>9eiC$uNha_-_B1xi++6(o1C%T>2SIsy=eF<-!)ji_f"
    "v+YL=T++PqBJhV?wFS0>6W>#s%xtG^|8#uM@*7HbFZ(Y|-Ts>lxYp?k?gG0j;IVR`{=*6r>bfq0m-;gA0ijO|0FvDC3}i5ulQ0<p"
    "HfN(H#T$SyESIOl4JMDx8SIT?7teqNlgyB8@qm{Y2ijHhxT+Cv{1|({rOX%p(}+*(5r^c$AJ5{L8R5J>0_vqEo+*r3Lx_hIY6`*A"
    "V%(z~(NBhuU@=avXdFXIDU2KG5Q-U0w&fI#5(6SPsE7OS5QGSG4~=`daF|H}{!;z`KBAE<UmMJ!cB&NGVP9AS8Sx&)hAt`IHceMk"
    "9zt?_{oDql+4WhXY>LB*=Hs-rvDFIhp}~5KZ;0EnCo0@Vwm&r%MSQgwY+<E2-Zfjln0lEiF5AL*@gc5<!Tdw}KmxGYCP1sR&UAD)"
    "v4=AT6W{w0<Bs7NEQ4^<BGBW^gQc3o!<)nFAaSG_CSS~Es6Y;-cTM9=N{U0RFfI3gjQvD|uQ#VY+jDw_r2z`JUREWC+4D^;=`~~+"
    "yWq2I@ru5!N17rUpa+vcyd|O9)AhZ@TvbS-w%6ckl#nA}AO~T-|NRpzU}pcvRpaouA8v(llOgmMa;SHE@9ihbVJqw1KurQe-!Yg|"
    "3kSgkoE_-Yjw^|dSo!f~NudPB+m5rX9kG%oh635H%FtTSd*FI$dqk^OYVVGv9qRt2Q<}wU9;$Jb;M;AuQ-)zS-q7!iHT`xC*aJ`N"
    "J4aofn_I=!v(0=iDOqR|7|@3;SUKz5D_`87CAcsoIYvZoFd&8RaVmE*ht)@@DB|5?u^uC^evR1r60XU{ATAaCYW;f*qk8f>Nq5iP"
    "qZjBYM!Y?`gMPLBJ?(a91zG5n>4_52DaAeCWA-0Cp-xioDVPp=Z#_lt;#Yu$^@5k}*9+`jwRa5vJ$}$Ev{F%fVc6?~M-wD=)|f8D"
    "6R)QAYc;KxNDYaj6F6Z@y^P&j_iLN3U)yv(Zwl<o#bDrr(#C2g2lNY<iwT?iJ#;7+T~D0@n{%H@1WdjS+sO7aTNU)~)!}|M)7|%Y"
    "#f<pEa8F0c^D;#DQb&)B?Oto?yu~c^3QV8T3*ckiMS`(cKeUkjho-i(l1X>&mYoxqqMLyU^YDj<WE8TFep(#2nBjr{>1qDyb)C~|"
    "GpE;DPEIHZ!VWoqTDFWui3AX_Gb+M)RfIDt!08HbMg=%s%+GLCA7LrhoX=D*XElOY?c7cJnOb<$qWr_z#dp~PudsZV^U|~P3~@y{"
    "Jq$tKiQrZIMKOFMJLEZRH>c}lirozxpEUkw_BPZtyg0pWeR={sfr4?CY)cNZtJ8$O1lrVn0BCzIJttm}@#N^&5&5RWpl#Cs>RYEI"
    "lzDGGM=RT6Seg~n72LOO|4gc<z&~O*7yHg!U7YyU>;{msJk+ziIXCzoI)oryEkwUL03pgA+xxe_H#`)h^vTGNtULrY>3V}=uzoSv"
    "CCsII?3fw%>nWv4PO@vFq_P=h@#fwNw0em8{6h96k1RnblXCJddplmBHFcpuTQ?K<{GG`<KtS#s^#p3*2*$<(sw?{-esHo!4?2my"
    "asQ?kg4L)RE2QFQF7VcDCmtDs>B4$3e6~<4c;zY3+AP0=I8@}>H2hD3OjIrz;bh;1$Z;0}@c^RTW<=tVogluYAYk(%^D3smpAt%)"
    "xO|giGaZzl=^>(ihS6e9n~gWlTxKhFTGs5Drw-!*Cii5(cC&(%OU+AwY%O__Fh^y}PgVB(B#v5|$n1+{HmLM!o9>kEP<@0Yf&9dw"
    "Hg6`fQIcPz{!0f-v$re+p_dKV=7=p|Q|>4L)fl!|R#LNK8j5UC)ym#9$i5_yz1%M#dM^%bX2fY%HfHl@{she>#>=+Zi>i9ziJIdY"
    "p^BY1R{>ThbF4~E)MzfVewe*}$mC`c?wIgGlIZ@QWimk<z$v-R5p>IG(kuvjj3Y8Df}&VM2T>@(8k!6)b$xD<Q3yI~BQbZ)>R~+U"
    "_HB^7KiU3v{<8uU4HnNEi8eBD$K)gqh4gYx6&fB+m3tE@llUw)>TMqpR>p+|h(wfBGwTyO#)+BN<UkVFhmW%l9cLdk&K8&oqCBwT"
    "xsayfoa+)Z3~JXIsAUFTjL~>yXHF)UyG9w=GpGsK;AXHb>~;BZ96`4!$<sI`;45yED$=CA=T9?}KETI~Tl2$Y7H=hrRcy=@Oo7?h"
    "FAQ@^QFCL_qLFBEAUkufaRLD#2^teY!2oPb;b{cH;l~?dgt{Z4&xncF358^?#=;k3FFX4@$jv>fLwEV@8w2Kv7@Aajj0E9{9fB=~"
    "fOtE4-4j9K3Zx5+m?`?hpLOk?<FstRL!mqy&g|jV&?h|SNJB%`?8BQA_#ESo?1P&bk#B|_q=7#%;vIOf{Aami(8V_CSSAg>Jp;+7"
    "3-js1d}g*GIF+cE>GcM$`pcp#VzSQ@3RO=iOro+=e9T#I;fg#A3P7R5E<T)CZW>CIARBatVn^GF#*7WcyWHk*<PLUI0x(enk8&HW"
    "2P}aqdU~KiM6oK@t<2(6aOHkS!NO<Z@}+xXQ9F1CRh{+&4>dYxfzn!n=o_XVh|Rb^IRP)}q%1gS0#yOPrfiT(4>E$6AZp?362DS;"
    "4?=W@7HBoa87amMw8C?ncu0cr0Q-cpJ_QUsijUP458L(V1Dm}CoA!|#d*#L5fC)P9J;8dU?aNNM+EQ5hD1Pcem`tl-7|R}j3p^wh"
    "-YygGIX;!^_otAF?=?A&v5Q^aC}wM*&b%;AENn!T%szc#G^OX5IW|)M(5)7Be#@t*mD9D;hv318k1ks`Pi2EcaC!s5$T3v``@WO$"
    "CP8u8LB6NJS4e#?O0*d8aJ2$nWTVmn3ABoC&shHpIS+<Lx%IZ8z@D(81=>ATZO+NF!Ip0>+?#JW^L9XGJU<ET;KV-$Qo?=vgkjaN"
    "ifYPCnI{0Co1um>tmFVnlpcK(wH<loNbWq?AY}SAu|To$fGno2bgayZsxdW&#%9<JBLF{L4P3PMr!N{8Z$6dSd;)Eo`sRyT@#4+I"
    ">QGkSG%$m`A4<jk<1cart9UP@AZum9myFmE?jck#T-~F#S7dD<3$0qPdbJew2{(qW#Tm~-b^>|P(C0wn1S=RTAQ-(O7+tj5LbnO-"
    "sl(iFDPE04^!cP$8EQNGShESEvk+Q|tphD`w4vdEGbb;s2}&Y53gXZmo}T%5FQzsZC1{-ij35CUltk!@=Llx1nP0#MF^dJ{8_OQd"
    "X^-^Le&f;wBkzJxW?V(Vclf$LVgKFcvEqh6ahv6!i{Wxk+VwxWA1~%J8z`ZldKN=md!(gT%_Jg@vh3Ex3qZxmF;nV^!_K)A5SI>q"
    "H(yK%lCPhX&g4vh;c(><THBEtS0esRj*t%nNk&~|_puCjI@;vd5?vgvoFH#m+>)?!e{7iSP<cD-_Lbb2B6ABEHqE9s%jkK5qKxQ="
    "N8D8QfjLpaKceQ2*owLWuriG`{+O}j)cb|D7%4cS-5poM%ULTu^=ZWw4DV$a(Ws7!GKpOhQOCANLd7bvuM@-x)Cu`Q`*Sj&Hd>=P"
    "Aqf6Y)*Ic3@JoQcr#m+JzYxeLa6QsAsr-GYGH4mF{L+y8G76l)dW=vWbD;*A>J^#l6`AUFENVgqX*`FnKcXt(67Hj5gUuQVn>!RT"
    "qcP}cCf!Zda18f4S{zD%Qfv5r%5YCKd^=^rY1N5JgPU<fC-0`Az<4DDdTOgu8YijfR0i$BkAW6;GP0z)@1<nPw9~RIQ6S!`B7?Xy"
    "u$t8O9fu?T$d{6}x(VzEBjTqb+Go-go>DVxTG3(D&fUxLT<%b1`~;{f&3NMAnb2XbI-VR}oS?8jeHvywcN&AC6$(kVo8<N@>SK|E"
    "WeRH7;CSWmvc&Mg$_X2^Le<U;_GZS5ZU>Qc%6fcxtAiMlLonWzw-M^dy!bs)x?~OQpsU94lzce++|C$0%~>T&rVh=zB|I)0`h~?f"
    "45zgT?<z5MK&WihR3Bl_VN!UUc;P`0#chTGWGG?XT!}z3b#v&q2)@rRAyw`_WK4=sf(5%V8~E;Fi^uGHxJbmM@!@L1Kw^*}-sRzj"
    "t~}v>+@Kpkd`?9UPUWEII9x2$#}39&Zk7hmqYKEp!*&lcDsKOP()M*<zlm3Q5)YaT86dOSS{<wa3@*ct#`?tY^CrUdpXFm3c0;&p"
    "9y||@u+EtkYlK3imC!=c4k8z=YU{zN-hKW@D2LtI+U+Y%^f*~W8J>3z&pXHI5<OcjIndkH(~g#wFOctIQb7H$Ei)*S^hsuc5uyKv"
    "DZmiD*@o_}H46=Dk`^R_&MZ>Rl7oOIuw8{oFmp{{BTe80yyXpJbv3nuzT;vxb1K4<(S^>&rAASIXx3EVkD<#GT__dZJJ1$DF=F*u"
    "p!F>y>QoW<GPyTnqQ<~lbaikhlS98*jo<IT>a!-33F_VPy=Oel3es#@o1VCvMC~3xNJ5w&T<h5!_L_s*>}9j{+2lT!V0IE$oRa17"
    "Ai58{cp#z3IGPy+5Wk#JPu*D;bW{nlo0p5{Qyy^506@<QXTZ}DdCK3{0=XwZAtkw({5DC0S+a2twfvqF;0;ItxYL<(K%T#f3h0Z^"
    "zWhBM`kwG!(0r4DnbMmv*BrMkkvQ38Ma$)k#6nt2W7o4Sf3)J+kh#)yGIf%V+<hw5<HMTqWU#e5k}DD7=ra&15}j9efgWH>H6Ytm"
    "4FlNi*p|CL5>757+Z@o-HclIz7*QM7hXeHp*N<@b2)hqT<@(45n-OWhlPJW<xweuYD_OfrP>*0-HnpGt_*?lNVBHjP*5m*r-+4?1"
    "uou<g%KlsqCp|Q6r-uiQb#`=D3dg!ZFn7XlXzQ{Rh&dU(mVn~`x_zf4t%sBCh-^C|N=Kyr5y^K%S|1eG_3)!E;-GboVJ6VZtP+JB"
    "44-gTcYmnIhkE2s50ASO-1qrmh)!67A8z%8cs07|5-O~oR-N&gGvaYZJkDfFf}A-3?;Va4{yWJg**r8T+s%|J7OySBG%}A&*xdAQ"
    "wzH`_Zy^x})MDCX%0gk-B(+<3gvDdUlSWC~nhuaoM4?q;K_zB5--C5M-yPRI>e}wQw!1d%OK5gGAt`ri)9y6coddgXDFj2|&^wA)"
    "e~4&(Pq0CED7K#Aj>eE^?k@-7<qm46RYETR1QKt54~N}vPc+WG<DNX(T}#{!?!JaU8EcyGX$sulW)oOpJ~~0yIGBi#5!ctf|NF{S"
    "zV;qppw#Sxg!mEfhVqC9n#|doW4T-(F1$yg^E!B{3`~ag!q8rAyKbRwfv2&VcDo7)GxFwm({LZx=S}=I#P3dY@z6s<0=yg~0}^Nf"
    "nf#AT(1wy>0O2uBhdrv1+Q^B}F|Wm)YQ5|FW#ja@s9UxAh)Pi(*d`Dh?H5?f@vDwseL<4bzfwS`)fEvYLbU$i=^r=Bdce{4DR6ba"
    "l(gg330ZaE$3YK2$h>MF{Bcqu`n1+uLs~PHQKygZDt|<wQz*NK1DuBfbX+DFisNjvbluWSGDGThx8Pl6lM#8dSP&o^_JCpp<b@=>"
    "3!(&1bgdtc#roNl_zk9FpaSGv9`@jA#mmlKR*?ieCD$ZPL=P^ab3m&p>FTv1Au5s6t<eMu!AWI5v-twWTCstfi66aNa$$lAeJbA9"
    "qopsW3&1^)ToQ)*G=?$M!Ya+oMpN5K%4)C(HJ=cC0TS}2vYm}qR^YUzI})K17)-`9%uk!=uqT@Ab58h}?PKx4`zE23@~YZr9VW;|"
    "DF=cYCO)5N4~C-mIZV%>s-1SHWXXN-q||UQ3!kQ#t&3?k?4fyv`n1~qtjS>7tL=P~AygR7zR!5rV=h7%t1+~(r58vhaFSeD94H>H"
    "79MDGxTX14G>{C|v=`0L?a}FvpAjo(4H)V(%pFT;VoWD#6B+1M;WDi~G_koYfoN{<JL#VYo0h&rF(zOM+0PSC;LSvFf@V$LA{0EK"
    "*3x`fXu3i7u(y8<Un?tAkCMT39T0-~0z*_1AO!XyCA>|~XE3jq_46&z0ZTdT=iShOb+zug8M>8f{srMDsq=QAl17-??hOBHKzz2o"
    "mzNn5bK)LI6cSO$&b7BI_(Z0eLZX%>W5&$WKwi9QoF+W2`?Md9i59T|n{5&FtkoHzHj6ICe(#@Pw3;HU_OFr@oOcj9gzFMPT%EP6"
    "W2qUDad-UJ$kBCiGOf<DHC@gl_ar)CH50L#%rgaJKU4UfB7oYMG;^ib8VMHD5HU`hHHX`Lg)3{gAaqe$wRZ#BqjC8-!p9K_w`yez"
    "ywrBMMS<U3thXql8@<NFv|1hczU3&d+ZEJJ834oLnwa?ZoX}qy_H^f_6O3)_OO)GvakTd3vN>Fn_H_RQ6ObQ)_FFQ}K^^B1jx}74"
    "NbY@*FXiU^DgLzfjRiDs?-JoC_*tAp#g(YoV+)am(KRp_ml4TlG!ECL8ij+Q)dcMWfevb&h1nQB7iV^L9*!IIxfrZR9_ay%9!w49"
    "=7KpHXV`H48II4G1GJ}^?&weE_b|gWXEH7r!v)=m6@_CsfRTNFqlx?*Mdt4kRq!u@$6(gWilh2B>eb&REY?ug@G*Q&;VcT*-xRIj"
    "UtL-^+Jm&Fi&?{}GvRN9;HoHpX9Y1c>{CSZZ^Zg<#P_cw{P*{Z2RhA~LGm~!x9DtbP2i{$*hAefbq-Xq%F%u1L3gQBC<auol@7VA"
    "jH2&aM;4_kFT4-}qAUtzInc6S$6?p?9{8|>`mi!V={P6Ys9DvliZ4`up?+;hJlO;WLX{2JY<AGYy*qYE{+-m_d+`(=EXLDnMqKwo"
    "BV2eW1C)~IVFh$FHIx2xgtcF2?V|&ogx5QNh6JoG7By0_vcPa>+Ik<Z<HI8u#>qTtD2jO_Gy~C=;2G-E#*;oG*&m2#2Bu1~<tEV>"
    "C@~+CST=QW=~f^bB{T1okS}<3exNMe-{`$1<h3Oigv3!ILB){UEu0T%5>%uHD*3jEkReWTr1adcAwxIlZiNz2&<rZIehygBLfP&7"
    "QrStjlL0+#<FuzIHn6QjCjvg292`%zg)JbI-RSQmd`|W<*~`3`ZdTbF5>BrV8?48+-o@DVZfZrr_e=noZY3XbZW0l+7?L3yw7QSr"
    "pqA3YDXYoMSqU&S7f$K9yw(0DiCRG8y)a{&49!eRA5UM!bi5+i$S#_&c@!dM$Jv$~ue7rnBc@=110oZ3A`hGFG)_DV1CNwuQ;P!$"
    "Y!~Q2Sd$=_1du#0=k&`t%(}P7Er~vDjy07cFGuzjY5Ka76oD&%ec8hsFGg9^N(<pCjl-Lww6n<`OMH{@h0C#!r7SX84vHXKk5vjG"
    "p&YxNQdbklrCVYMo8AQXt+Aq9yg!vS{=`!Iq}~BZZ*1}YUrUrM54${)o|HUcLqvm$2hgAj0i!wY3#+G)Ah1Sf#3`MYC|VisNEKEO"
    "lAgwFx^pv${Qc<6LDQ|iNjS*S(#n8j0^eV6gwKzEfdCPm1IGJ*Eeg-7QKfsoL`$JP0}c4GiHOvO5DU>{DjORHn_DYwvgHp<x1pjc"
    "ff8;Swj0U4d0h>38?#w{AWQ|awZmPKoN6HzZ}Y3cX4s@KXRFwdFnmIgUzOf6vAx@ZSp%!l<|MS<4Q9n>4zDSno+>0xr!|Rrn4?bz"
    "f7j?^QZ1AS5>RcUo5~0Bet(d~j^*ywdq>)mkeacphV8C8ET!qhw?eqvsq6CYHfql{`k?o5wV>8B<4z`8*!l*O18sn_mKiyVkyx3F"
    ";nU6b{FSDiZQ*blioqdiwtGcCGHcSEZ+2?l-Xq*y@|s%QWCwewPdmorU;F<HCDSKWPwUsh4LPtIOMr6z@Yo5&8V`dCDN)Bkdw=jG"
    "*+kOez@JWx4$?=@<<($_qR{?N#$}deRM9n5Yp97m&ngIZD4taJf%QfN>dhS<Gv!IC{q@HFxfp$3!fz;7m39Q7A%=%__W)Z~0P9mp"
    "SN&pzm~4s-(x7Iy;zA6wRd$}OwZCi?XB+#&Li}drlQ@z%;fQ>%2X+pukV4ftRjXV0T3z^RrCF#E-s*MZ#1ff1^*NT@-ON?H7{uPI"
    "JlxxcT9cNbp0tGZWFt=Kc%M074ecK4(>~EixN&PfE6ZDMtHH&)wYPf!-hc<?xY>|hD()CJ4?TJ$bB~1Ww39tizFjAJ-mSn99&{&a"
    "XE>QWT<D~t-E|LFIzq1}erYB;(+dHXzUyV`_F%|8XPYMAU|?}P?OZ7L!&y0;Bg5e*X=n>LYX%epCiryfDJ*j3WQ#ogp#2m3?uicT"
    "r@b}dnD}*p{UPaoc+tw(L0k-vH-Dn3`Eg70!xf2%zmt4@=u(VskF@7PTP?Vh`T`j0)8?r3+}nh1J33PWgr=-8)I{oGduBSVXJ!EW"
    "^c^`6=h*|>XZG0e$%zliw8;irUc-`iw85};T5Z)AADL=CxvVb80sh>c?V>nPjze}Fvg42)heBU3A%@vNP$r&MV@QAW)NCyqr9^t&"
    "1e;EWYKvYB3tp<P6W)m((bqfF+svC+xzVz{%EmS=Xf<ggc|11PdyW&BsJ*I}bYInrxk8krBytz>f0z7)Src_zV#0P5lzaabP#oS1"
    "_q`;worSK6>YEitS;`t*zcr|$IL^LR1x_H-@^_NayXv2(2;O(_u7fU%hWaLfMSxUltY_6+!%&>8-&s8rRFFNM?5UydQc|{IRuC0t"
    "*hn`K{AMO3s$JsD+kgTF)k11|P7w7DnGR!8eK1v1{G?INZnv`c;&}aTQksM8-55bOC{#~nrR2Vf;N6QJH#5?o&1_J#NSPN&_}btZ"
    "YYDo>xfyYa0yWo~jQjLY_OTbw%0+Eg&Au->3X)Y={3vNwox#Yg4NY1#j-Bm1FSx*{Hq22xmRLNWz$1Z^$saZ46IYDa#lEaM#gJEP"
    ";tkxmGJkaru55v2#>3eo;Y@tBE21$)mXudE2lHmrge;-SWM<hy>`@R9_|!5F<Nz3Hw|Ti3`*o1$IxElue~dnepc|5tu%{;|0ZMaS"
    "7%5=p?Kg3=it`0sp}<TJkP)KYZ<7VnG4$L-$01*K#m0v&UZHwko{3Qe^giTb+=11)CD2C&CgX(%-OK3?qHE9od9DK+s4yw3sigGr"
    "o_0fYcH@0SC(_=Z91KB*HgwB@s0Sr(cc%xYKpQtx&g1CrC({8KKBR-#P1ijeutB>O14^mjm`py1h@PaGl#+YcoxEfvIeSo-J(kP$"
    "g^!ilbf%$X=OMF`oh!S^dCqA>`A{R9xVAZg;X+pJ6;LLdOJLjBU5n^66B1C@F_1W8>#T3h?uH`X?>a{0w4gpQXyN%tB=$@~q3CQ8"
    "XTIKTySs7heGO(TrrE%hL(Bk*sTI&Uj?O<bBR@<4K011&F~CP>J3*NxPV!GYbWLR<M@8EwyX<^2f<lGV+0U$g;|a2U{!ylUvM$F@"
    "kO(l4%cNp-eRpCkmQUsgtGpC3k#jnqj1-cIIzit)62@u3doMG7bck2s9_vACI76g&ciZPzmVbRb?DN|-UR!;BYo&^;%U`tqdUCMx"
    "@C1+r^r{HxEXJCQDz9MZpSFjJ%CY7{#A~mXgxOY)7zDeahw`*3w2S=ZxFDFZ`<Ftzs@>ieRwFkb;6kdUpf0ZmI6c^6j<_LZ2uOy|"
    "l*7ajXG;tgHjj}6$&d}0;X32Ecz6cNth_{MRwgh?@FnvJ)izmK6J&$U@Y(CvzJ(5CgUklak02Y+lu#}JO>BC1YA-ht29pA%>0Uf|"
    "oH%J&OxL&DTXAUY);~n5h`ynlvJXKLVP=I~f2b9CF<4U>1>ot88J?g4D0Jlsz$zzSbnjK)^y{JE8j!%`!ztoyo;0c|ciaA8R3JM#"
    "BI?(Rmx2q983&aI?NoVWQ?y`JAw-FgH-TBOFHc5U<@sdxH<4NFM0P~W69-Q>hr$k0kqhIS@`UYwsX7H2*@6vPp#w^qzX<1R#b2Jt"
    "ZpF))#qy)U9@?k%(ItVsG+B7qQ9u;mB;;ELT3Y15OvyJ9zLq6>eFA)Q%PoNgx`p>JkYFoIam5XXpczyr3;nF9H3yU^t(<@n^iUG~"
    "m21z&Vmz(33V$9D5^H_fQ--O<XKe+xha0?QVZUgw2KbvK$C~_sXMB*;*o7k->|_+D`s`D(EwJ7yu!;{x7W+(X@tNAPUJe}L6+%(>"
    "K9AtU#%jukVGFGNbnRH}SGNHxLS-FsfKn3LFgRJ+Gb$t$z|Hx!ak5l5a|3KaoxMQbBT^agiYZ*ajJ$3FhYs#Ztyx0`aJPyObLU0C"
    "2Q&>TUg8w^<DNDPNe7Qg=cq}Uq-(vC>fxxSOS+Oew?V6^weTRyK4X0@=|Zz%Gf*FPpUwh99ZpVbCsS+Ya6@TwYq(>9<<zn#S5?lZ"
    "7Pb%cvShXu`){9AGu-|$?I^o_v}b$97zwVz-&;{j#+*cSF(gAa6a(IvBttPMwcW^QfKy1z!{vY>WMS-BJa#OM9Vgwba8!BnLx4qc"
    "kr8D%kXQkxz!jUs>OdZYuv?R?Ir626*DNX&o+g~&$Q`U*mV>w*b*R%TekHIK7A+^`AY^PB^ICP|*%r|pDwcZ-r$P&ZM8xunKIhl~"
    "Mtd>>B41ywZuP~wT+!4k1@aa9M=}#OFC-QgB1CsX3&08rAM>1;?2Z^!TOe_&&3gpB`#`doFwSAYPVjU<PbZ6p3B`Lu#U-Fo$(y&V"
    "3Stg{J(Q%MB^Netg_rIVy1r)&RM&o15=-Yk&;%mdnW2_Wd#VTAapE=i5{F3(2S|!eEbye&q?L}6u#@P~P@P!=RPK{b_^bK#9MjQO"
    "%%L3><1h8;ujJ}a&~4^cGzy!<RZ2HW8#hTCH%Xh<c_wAe{g7yyEPSAPu-YJDIvqe<keIhYAwk5B1X^+!>hN`kgVICoIaE>)u6zmh"
    "0Q_gGBQ_1#Gr(!}{ieeUM*=*qENV>5woSGO&rqLMf1qplxmwdyB5+|YpW70!8SSRoc6Z>uIllX4N;{_^8`hd_cYCD?(Xo78Dvvn$"
    "did<v1cqe76wpA0H9d%s-lox{3kJ8WF->?tl?I5*k<3t*jSnA)I@pku{7{zSH4no%4fKIT9RQb3aW9_7=71#{1GsZ;B%gm3UfO5q"
    "pH|--r0R9;1L5I7b}%X(z@fbaL$<X#!anJj+7jT;c{5CSUTA$swOK*Fc}j95&ya-0KyIgRHpPz5pB(SJ|4hgpuODu;4jzIRsJcy{"
    "W*k}KWB}}V)$l;r+JyAT1`NHmF0>NGi!sq*0b-3_;m9BS#HXF{xsWK&5<|3vR(C7AZP`-UP0=e3uyZWe@UKR6yt6e?ZN$OQL>&!b"
    "qqwdd!#P&W3wJx4PybrxERg=Q;8~60#S|><oWVb4e?;7@$qDVlCy@@HL^{->1KpbBQE{dhpT7}?wpHe>rJ(sCFyT)6*5wyU+jUe6"
    "s}sXcn(kPzW-9T|&X*cnw+Fq^q~X#f7kSU^a5B}xTtSEx4qG18Et0RA3voD@I~~LA;CPWKLv@<7c*oeBlb(1UT2?rGA4))i45ZK+"
    "L;o}q-qH7rfAZjeW06cw;cBI7oWPpxEyz^=&du4r+(anBypFnpAJK;uKDje7mw?@<N<0x?^vE1wH!qPlY{tNDKOeHOa}ZE;F(kpZ"
    "nPz~y(l9t6$$MON>Uz){ctBscXXm{8tb)J}z9|6T4hQe@{IKU0;xBMKsrv#<M_RqWf#O7acPG$&31z|wSg)ro(7N9D1B>xva2j^6"
    "2*GsY`JbgHi&|@#CPNJfWiwzCizk~OJ<im-tn|f=TX%ivX;CP2?kpM6^cnCTb)_daXCP|jX$m`G<-J;&Ax|jQv@X^;5u>|TwoFp$"
    "9T?G2c>klbIW;MnrK1}Ld+rjEym;O@p)R@@a8YlzS{;*`3=T!j{#bNFJ~Jhn4Ypf!gt&VfTwq-%SL0jcFx^Xc_tL$_HNn}TF;!2)"
    "u^kcXzmguJtI=eOyOZu+sjl?_FSGXOJiuxsCF8U_h`tZOc0_IptiVVUl<u9IPSo>yYXHfcnJx<aaqp`3%)w=WKe%lS;3re;Z0FXC"
    "(8`xp5nj5W?k=di3+i6F@0lm#n?>>gBvbadY$6_1^M{Q{{yEIK<M6b@D9d_0HyL{vpJ9I5JUq6Fk!&wfoH^l*I5FsAkaxu&E3Tp?"
    "I|E8o&GOMe%=`P^-tRsaKH+dt^3p>0qQZo)s2i-ZyDpb#xQfri^<sKJD9Xh}x%h}nFV$anbL4&#K|-Q5sij7MD-o-#40Obs3gY`N"
    "-lcL-wY!hCFmAwh97OH1c8Sq(q}2aQ_BM%Aqlc*O8Y(yL1y6&EjE>sTsUUb9$N)V7@+kz8PX^i!?S6GzURn3*9$E4v_t%yV``=S|"
    "+-**$+j;RAV3;nk-ydsmn6UfZGw>PekAc8)#<*()05m?OVSt|cd>gQz?W^9WvOId=fciF1mq0@z%hKiq+?Un<6hc?*upBhM63#?b"
    "s@mx2F@Tu(abs^8B*L9QSTcwhjfMKSxq)Dk*oS9l!UD+2;IRW?wjrlx1;s!|KD=Z%5yK}opXiW%!=-+ZT@fZ9S`@e)AN~%jpMALf"
    ";3ndv9Hg6=1G1qnfwt?qJG_Vi+Mc089Em6c!?O<1YA6MKM9NMi$$s5k{YFRdTMNTdA6Xg9(%Ie`Dn-LH0N(1El=+|}BTdqw1A5|A"
    "`$dz+EoE_Pe8vr;3tZB@JuGZf9BDK2jCNRD9CREvRs@EZW+u?Z4BpcQQ2pW1sL+kw<Rmx9s3j^%Q{sX;Oz24DuQ3~0fgCqWhPxQN"
    "+a$alWVOdkuEDji<1lSk7&jlwmE0yT8;P@jAzE#6JcD|15gosm5sbgmB7x!=2slm*27_TwKj_fgO`v4_Ur}eer8>_m;s1S?G`PXL"
    "lbF}B1D&fss;9*H)?%p?<9QxrIZ$_5=C?I)1@qEkVEX3eM6JrST9xVTa)Ebf#qGd^647W%YH1*Lkm(TAOQPN8<JIQC2NoZe|Mo4c"
    ">Bpf1A%r#;FSmo!GYiJ_R2-3+y!IhRZ9%Yem}5>Ez#i@Ada;m+ix~}K)7!Q)Mg6B`p{CE;rX``Kw{)j>bf<T6rw_X3?dEED^ZvuU"
    "c_(1r?7M|h0`1?!E#$`YkVgJ?6}z>M_0~VICxf4I%k^6{aqY;DaPoo%E>YzsAtUTIU9BwHHZ?HOhXs)oTl8f3MJu@@8Wxaqg?abk"
    ">txqTnzZ;>_@LTqQ8_)^oskYIfRL6|iK~>EiOQz4sh;ZVq#!GZPXmQy9UE|ybC{{ak_3O2#F{v}Yn~O6%sd~NET7yhPqgX*I{@7!"
    "6)q9jEkX8IlNGAyujDL~?V$S=;19};$BzW~yyE3bm0ax=y~?`!@73E|Qn0mqkZ|2+k7=^E7ZkhOrs3Bs-=G%YnC<GqX_j}1u|$NF"
    "GW$Zq*6y)odX^>F^7HUFUmb!=d#Qb7%Z*I*UG5VB4_+LH;+sW|=hK<}<XB%&4gAN`S^dLN3!aNN%fw{0^7~kUZFOiq_7Fadc;Sr<"
    "-%Je3!DftjxYUD;pi6-#sEp}Vr@wqo_vKGo!hdco{X#Y97k^ABjfAcKppq`1pU#>*>UN2cs0B)A|H&SuvuYM}AgduF%hTgTzq{KC"
    "+&&C@aDFZ*fG!KI5Yr;avs+1eFx`|JRMR`K0$ez#VKZ&<@5wY{niIybnQZJ=W*A`mpe*gVeK~j9{O&y1UD~@#o41!PW*Bfkd!}Y;"
    "{>6^z%>A>er;*I)WuV)Kvp-yXm@e<ZIrQ}4HOLX4L{2a7r{^*Uit2%pczn=*LlHC;C?GJrIEt?oN-=ono2AO(d-8|x$@6|oF^<H;"
    "<{P%QY1>{?99}XX<y86)rj$WZ9(8z`dw7|9c-J(5o*uO2VV7z8F|?DzU&O$7!w+=33%Ucd=aAhdd-}DfFT1J3$<T+bj*QgEAaLL-"
    "oQIcihcx$9V|>0Ov+*kGuwPmwYwq|;I=pG}CwW1^b7+eHw?(0-J^bkkGkB}WI|b8iL-Q&AX-Go}{ki?||G2yZ*hKj2UW@*rZC6s*"
    "*1~0R?4bNTqy$go3jKvf2f#~`7ejQQfvO^UR#H<QKQ9T54kGbwrW?liU|O91quN57rn<}&3}4Ksg;q~4&QX}w)n%?H5}m8b&9FkZ"
    "0m#cMSD?I6Iiw%vX6(hVCGHg*{yebsxR~DZ%ic<)lpRmg{20k#wb~mUwgPF$v7ET+{~P}OH?gJEUNO*lpP-V#TGfdvF+aM13CN!x"
    "{)q_-+oyObk(ZziTk`CF`PJ5-nC{ZNYjzb7#Yh3&%QqQy*RI>(T6)mCG?oW0YNjAT-f^n+vof03#RFcYtJXYtOyLV{%|U)HP!dyr"
    "CV$*9Tb2*pN;3CkKF|}XGJ1Gp@IdI$%ysA;uOKf^REPA_j?2GFQT{{8>yU(65ZPN?Hx~6Uf^J$3JD?0$zEPbY%oT!diiJ0=4Hy!;"
    "g%VkOc{3O)%TlHCcJRc4s084|D0@DsMEFF|i14!Fa3!CXbt>Bzf@!W}QsoBS9Ihk{1RZxzQ!GCD0|ny4EqKvILjJR)Q84pn*e-_r"
    "ss;j%E;?XkvmAUR>P;#!ok=Mi2?c2-tMpj{(>Q6hYgJWUTjhf|uTN6EK3Pq&U%w@6pKl_!4q7#a+vVRR<c)&aZV(J^<f_yX3kn4G"
    "M`2P?H>#h`YsLq$cdzctbOZ#&-F=n>rDP+ao11~25ggLjAY#^*9Pak{=rzB|jIGgEZLXkO>fRdeR<<nljMCs;i*a#{(<Ql}f7H|M"
    "&r$i~pFjRld69i&?b8)aK)_GjQAeKS(vy1r^nEhFX$Zx!yVYkQ%qO+{`C}V8Y6kG6`oCJCE=8uh0;ly^?GCS+J#M7X4`}Nog%0MK"
    "QF<0ylg?Mhh5G!IX8M5X7V_V`5KU*I<Wc}P{{O6V7)F+{$yp^(4AsyKwl__033$@^x)HyABhCHhuD7!U21ouq4M%<+wq{GkZqwKL"
    "W3UaWq&M0nrWh4^&~C?MPtO|L?GyRmsnnek?{~68V0-t6!F8BEuRC~m&$=*!4XRYHwndgu#ru+(w`4ju$76HP&qQ26s4mI=%#41z"
    "t#pbqrs!`5^!`a*{HCLB>+JIwKi`h@Nc&oq2cGn(yGQrkUF5EoxYKM=Rt(^5-(4bFONdt6QIrtM0f+#HXo<8M4#oickhUleP0Rs@"
    "Ig;wef=*x83eZsx2Ar_JV3$J`Z25wDFnYXRL-g3V$gfkpZomQaq#-5z21<G~7paigjy<O&Lx-q>N(&s+^Pm7;P0~FkH9BDPUl;#b"
    "Y)bkhoiEBiuZ!!-c>BLM)lYg+BBQ=Vn9~{+CHvucPMpr4tQ^zR3~iM#1C=fs!vwIC6UDhQ&zT<gCf!&}8f~-ZtP@pr0@t3|UHN8b"
    "vXjI?aWi|^*^v{#qcJ6Uo2*dIT48oT;k^q4b0YU9SZBq%Lim#<M4;yiZ+z0Zl4$rLeO>WU6qK&M2N_%rGqV^Y1?9V_78Ge94T_B`"
    "V|%$4k%vz4LD|-hndr?QSmW<s<zdlf5m7w5ZaQN&VqJ!}+n;FJF=F3;r0xvx@b~6Vnm<?*Z7!b*+jv7dD;O4~u7c_<$&ewTqaj5U"
    "I(``Ct}`7#9^Hv7Z|4F0HLXBm6p~1_DcV3AQk8Wv6ace3gn-eu@c!a(Imn9T6%jo%_{yWCgBRR~-)}c`<Mh8yu}inqx4n2%M8p<p"
    "Y{C5E;Ci5RL9}D1VE({rg>0s2geAM9>Xe1DUQ|yOe5M%`Oi2lMUx!pDKv!tL_^U68!$>Cv`a3^IeopA&j{|Q>;hGg-W$7*4phTiM"
    "{Ac;fvv#1{(9U%<2{7RiV^~T;H`Wj1zmvK>h)K`M?)8~L_+$8kDz`!=WwcJmcshv_dz%-pfmef99)7u2aEj7GtrJ(w4Z=fAVszhs"
    "_-$KY8cA>f^B6H(8f<oEuhbs^X_z5&e@;_A%C`sE!pMux2%C2rujZJBC5@N-UK5+)@TX&0@{1y7RxIjB+%qy%$j!;2`1I<osO$b#"
    "i6wE`@U3;zV!(`sNrl~Zn#8sj12t%4JZ6szS`F^3tX=}NpU5>C^V`YDFBin9>B!X0b|Xw@=){dH$L7khxpKtBT88b~FYZV69vX}H"
    "qKk(%;v!UFhuEyU18q$Aqrc|n$tX|f#nXB5e7eu#AqGLE!|0k~kL2nH<*r}7$`UgSN(S@6!p>*F-PB!QCu)uqv$&`QkV}5hkObIX"
    "O&$5Zx~6vPNikDC*v*VIAiFwULbt2U%X1H>h{!<m1LvEq6O(N^WsQ)`yU*%8IyeyRgkBQn2j6Dc4idArk=&Np4XB2Jn>Io1i5cer"
    "Pe>WlhNIux)!>--mcU3sN8X+NJJuQfy8p~DPY8BSnPYutxZjyj6rAo9=1wejw^cU~yxd(RZX`R^W%t;P2t42~=<fCsQ{8Gf{8<-&"
    "XF2Y>>)Spcm;4|)o_rT3v?beL0KF>PQiZ%8lvvPm>;5j#3dICpS%u{2qWLQ_PNTR5FeNOW`301O%`gFZMc{MLWeVi#kY@*+tNwwP"
    "Z><eP35Eqnc|!)IK-pIdY^MI-bh@Ryd8ZRBiKO_Q{mEPBdgFoRN6gd|+~YHIdlbE18lWvGl%@u4G}}k^5sz$(4>v-AW^oTH#lr>u"
    "U>*K&wm-COJfu)Eh@v7I4FN5Xgx>jYlJW;fH{<bVQk5%}_st|ub`jm6-L!~CDD|7FsrRx6plq&s=R|aalGdunH-lFGSBk3i*oex#"
    "22M%7Ae1JbG_};(C#NnFN$Zj%luX(el4yR6m8V!2qpFOQ8Q`cO3XHUx$Q3hr`D5B3_<$0FVI>BF-CsLaRFkTfPn8?$f)2%;EMdl2"
    "@7^=0_wKI>RSwsG>?YQKyaCzF2^M0yu&xPUear@?Qn!B7<yKwnA_vfv0q_Nn%hf4f^|%ed|CGM<0~o5^>B4<Cvjg^3s#Evm@aD<B"
    "v9tsPAs0yOb`>G@Oaf|70=U7yfsVi?5e@;l#?*j)p1L7x6u9w-t)==b)CYAuH&)9znHEgIv1M<I2{tbEOrpRp*y`dT6R*aq6RI}L"
    "rm$XNrh01jS=mvn&kA8REX>aakh~}4DS`uH&W2L;<|*TD5Xu6XG|M7FnJP*m-gelntX7&2ChT7+xCo?WW@W<7=EKIrro(O~^sw21"
    "cT$R+$TzNIxsc2X-JnFDR@dGCf;G{urzuv+;hu%+WpkBKYcXPn=gL9-ySw+;*=6++Qr*e=-A#Yb%-@~)yEC6&ExJauKIm%IW-6P5"
    "PJphiqB1E(IR%TUqcBMSa70G4%`72CAyF*y1RePK#>w>Q6^za0g@%%PlE-H?FH7f1lUv;*H=2IaLoo$>@TqaMac+hP-{5`XpiROd"
    "!6+Gx?W%^59WXFdzVME)D6K;`q({5yp8U|ez1waE(fD9~v``h}-lyGu(HlH;ReDHtaPTN^&<P>NcM}!9Kz}R48oPr{3+x>mjLVY2"
    "8(cmfjow(4iqv%M(yGV6=2dU|t=`CO6495-1@aBOiV(A<@R%-)zgMW%TdG}`1TCt>*v^gzs;=Aw7G-tP7Iv7p6D+C`p)E}21Uo<g"
    ")d5tzSRgoAu!C1{8Yd9P9Vn86@`vgzs4tD3L9T|I;c<EW!c>2&{xr$Shz@_G>j^!u_nmYBim7c-V+GULOc%SrE9{eptJ->F?XH`@"
    "&<%=XFV}Q)H;C$b+Z=yp`MSU>=i4`DDNQ3nGe_z+4MPZ@h*Itwb$nx9(>50%V+glwgZ^B|=<TPPYVV?P3ez;cxUOyY&dyJZeuoYf"
    "B{HHvwS2I{;LvAh&6}t?A@b+uI=5}kXf~Qe$w%;QCd1ggu4pV-8(p?5)P}cQq!BV0wauQ}>wyc}(8gr6<(SnrXX_vQA6cPwO?$d3"
    "aQe~^NFH4A72Tlx@gq_pn9|ieQC|`mwV&{xE025+>1`Il((}tw;1&W8is_ynaX}@}+l+ypjPlMfbTxE<U^^Qk0hGQ+vDT@oonzwG"
    "-MjT~Mu>*~LP5KyIWFvrkJBZQo<O#B7T1ESTVQavG_hkFx?pq&qZ`K5v+gRWOU0T!NLX9A*c<mE-JJ*f!L2KE`+Z{%v2|}r1{S(9"
    "k9Gl+bN@HpfA?QzKdpcAUKc>B8S=fOXjka1i-v|o0hE5O`)mztUny4)^fb21tt9y0V!PE}89%pyfRV<--=>5K>qt-&f;!lzJCW`O"
    "Y{fK3ptEV;dVYCFRg81GXPNXY=kBuM=B1IibWC^5_GY^9kEKj}l)?1@-yZPg0pA^fy3j_(ijK06=?_HvV0ywOG5?qH&%tHvpa*te"
    "?#Tij@*5|ALFjlm9@0zNWRI83zAOmr{+H!2=<i{tY5Fm=)5Bkct|w27rivG<d#;6xDo$23C$wb<n*)Lg6jPho2X+Reg{B(1VdSTy"
    "v)8nAq_N}W1PmvBWF*JsV{Erji&(V5@Gw}n=*{hFzy?M{&6|5ImZOUXZhL^qZb_0R0eH<^=66+fn~XgYqXr(PmjtTbba#=bNKJCj"
    "Om(K)_v92xpoHeL&_fs8{rA(mW@7M-%`~JDg1BFs{o7_7y$ESwGdGpQxUtOs37e)4vt1JIC7I73`R(Xvi^~RfPo_~%C)WMV;a+2q"
    "Vh5ug?C7)?o^X~VdNCBh-S^uQZ?4@BuH6r=-4Cwa$CUURf)XJyJd7<y^5eRW1CauU;Z9$)8>Uf*HU09j@(Z=m_*n6(EV9-6-D0Xi"
    "D^}sa>sy9;n=DzxNY^RMDNt<+y4gAtzkmZrKf3zNogqepVCpsD(vz`;N+f^yxPSZ4J3ii7O@RK_R`1SDF=S`IIH<cys(&P#f;ky6"
    "`sGngi-8c3YSO|m!P!_hQ~b+RR||XeOJ++QY4?+%|B5M=exa-~0;UUzd|EH2)sSW*O^-Bo?yYv_fL6z9&1j+g+Ng@yEt(_n{5d%C"
    "Vbx6tU9N&SBHPsw+i0#v!eA2CQNRG8Pt_bPQyiU@7_Y{}t(hmm&5_ogt|Qywl=4)ikfX3}xfKCb=xMX3X-ROtK1p4cb$~iIn4UP3"
    "p{;dp@d~QHmIR!$hR-E@zjP;#L9Jh`$6d_gDDRHxzMEoqcS4=Wk@XHu1H+HLa6b)q9HIA1#*-aW%if7z40dLFQiL#gxKEV&GpC#4"
    "A<fj_On8IE6!*NT3=+DswOk>Tc>ozw5Od^R8c}%ORS1+gB8vIBM3;bLJM~5)*o}AM>2uovdfr~Be#P}vS||or?*-h1z~J}S-3*;a"
    "adRkMb9KMr1s*p4rWA$cgT!F1`G<q_=>}-`Oi}|aRn>jc3E26QGu+OpW6-(ae4|yCjodDXt98y0rSQ>z75`=H_Jh~dK$lu^`Zv3F"
    "!Zyc?mRg<;=4oe7w(EpAa4RTJK6b}scT9FW*d6RnJ1b}&!HKRZ4;~8<{cepS8g}GPi(Q)TG)$@%JM~=B5+x#(7zJOM4hP&nu!35C"
    "cLd71ccldg0KhD^ZA-(TAnP~N6d_i%MiyNX87S(vt<pFImk%z<6r+8j9ts#Z#Ne6xx0>CXa3(X-q+T5??I8vjcMTQ!ULfuLU7eg;"
    "7Nzw4ivEzV)j49jr6-btpFz8>cjwdHS#ZDG4w~o&uLwf%ET1eModLQ2IxZeea?T|5_{~LcfSky~PBVDz;iKkr3*uJC*;(q!UR~KM"
    "2j_y4h^N~vYk;eNb&Z$uSKv4O`*lbbk~G@D)~J#6PPI{pZGF0Yo)G?i+F<d=l3(`6S8HJK<=Gso=ckmO>4!bphiNkq3CF?xb@d#&"
    "`&NLk(mlKLsKeQt?(oZtm>$-i>iA=xPHk))sRYQKjvsrwI!^+(|1lj#{<R+lsQ{eZA=Er+9mIi?+UhUx?~=|J0%QlOd+$lG*v<Og"
    "><KSm2%jaPCsKLYD-wO=7jep%x^H8R*qe)(<$TaAP<C8;dqV7p?fcG#NKo_;n`uT@32l%tWP0bLd+S3`4YqBsXxS|tenMt2Zj@{@"
    "xtOj7qV6;fr(;l8S>E(E?8ena&;L|28ZDVcA*vVD1CFqK5Stl|nL}Nh&ks20dDz`i60q($P&+&aYKQAvGyQW8{uNKYCTm~-$KKfJ"
    "^9pen%!O890&Gop?tcqxrKWpJl=VpuH`9u;aiX9+&?}}sf9$KfG_Tb<FPRFe4XF>)W~#Q6Dm1GpIj`H|d4t^-*tx%MdNE+_znQ7Y"
    "!krZBbW5G%ad{9V_qfN7xId3&D#Seo0?nRsiK<K2d1??;xhzm@0=r?)&ta>dFFP4_a`@}u3k%5T2nMi=)^uDQkj!}1Yp^Ju)*wH~"
    "<caL@^d8tmajIa77XDFYPp*jQmMm0u${nL}_m{F@mVbCAMVx~yo0d}d6j;|^haaE?h+N?CH(&DW&QxY<l$cE1CPxJ^_fhEx{H1@`"
    "ap$&aP@Btm{T3+>YIW#-Jw32>Q*{B;Q!2qoD2a-X*Zq@@$H(7O3d+sU0S5dUG^Ywc@^5;`nSR)5=yIt7bAfMvS|IBV>F{0A!QIfH"
    "()uRV1lmXlsD>3v`8-`d?D|d=J4%NE76^}B--#k2K=EY0rfd9GQXr~pal*|&{mZ4p^x9!sqJ8@K&}t1*t3fI?2yk`o+)4q`)c$3i"
    "?OAF2_s11`4O0(5K$Wh3g%I!+bLuAZ6yM>R+HK97oO<2*;v`t?BqefZ|6Pkc|HZj7hML}Ox)BjuHK9?kw>jC{ls@mF4Hc@&PC+pu"
    "OmCh|Z<|f;mrcujPYZ6(ovz&d!=$U9DR4P0U^zMWnO>03fm^mJrnf4mcPa%H_#<_i-eEjU`A@zdv2qXK>V_!8hL~7=y`+FIXvFBn"
    "OygBOth|v9ej}3mcWoM&|8$5Spd9#nvXdU5@$D~1#=jgG|5T5H-23H640c$%i+(_D{?tVGyjbcfdPtqc&WrkviF#>h17xIuSTuO<"
    "+ldxF)-NkY&=b}X5HDF{Cdnl0Mqr$=W&}~(UD>%0toU}VdqNoAkd>U;PYR+HI8Y4yqlLIYEmJu7R1@)|=#$+iQT{kEIn2vNTTCM="
    "dV=vQ#;%yoiiU|A=Dc&cXlkv3#QIc+I`8+2Q)%Ly>Rabsm2}2(SMd{sXAhqe1X9Zb*-Q##FKJe)DX;<Z2#pxCzO~gkIbod$oJ{rF"
    "L6pb;oX7v1$N#t*0_=t<7<|Ag-M`w2Qi^`(BC+HtZIu%((Q~;H+QOYk$zkb(%hz*3;eUW~Z6Vhd^_oFrFj3F0%v&VFB|1e5JeG8F"
    "8??gX5!P4vjOO3~#d?u;;TRQE_oG*@#K3B&z+zD7gQ&9P2PQxW5<HvBTyQmc@ElZ40Bw%T=?HR{6qo>Ul+@W=X$#0!2i5McaTv5Z"
    "j}c5MUcW2v9tMLdzd&DvnCq=D#)v`bUNF7*FCCI9>|pTf$Ip8Qql=dTEyMg_2Xn4>+q?S;PA~;2EtrpiV|6c#&SD<<&m;fo7u$W<"
    "vj_W2fyCsYTtsQZL<(slgfx*snmk(~sv7~|X45L*<ZSyeiq)@_;RdjG6FB=pPz$g83P~03QwrvfL2j4KPj$3&?Ux6+E=5lmcZt^p"
    "%>3S^AT@xO&_O-J9ZV*F=h{J_Vrt!gLcN_MoL#QDp|Y9TDMc^Og_?fO^@aUcdiruQU-jl<dih{<u4l|>V_vyYYd0=aO%B=T_8lwo"
    "WR~*%VeV!)jurDtlZrBRm_@KmZ34_#Rm;b#<gb7x(1Ek^qu-kB+??c%O}S~|b3lK(zHG%-O5O0bXoW41D30(gkJ+fud`eya7IU=@"
    "5F?4A2x$EQ#ehZap9*-!C>SzDYPy4#n3E5fo1T{zqrp$O==o(aydy3~TMEK{u}xJ8!3OMCVA$|Q#n|qWl>#vKM<vboO6J|GBcOG;"
    "fFPWVyOVLJ(-L5Vv)pOX_<(8CxjEXZwA(|sO9C26V(ud#YMO<LKKxOk%@mKT$p)3*NI}dLf)F+hAx8d?QUJlkcy(x`N;^8xVjwg;"
    "VT==C!9|4dn4uXRV_hQ<?1lr_osRvAmEF1F0e3^)_>^WA5e_^iY9S`a){{ePQIe+|ue>NXdD%>pagl{8^1D!9e%Zo~3A$%Z!AvrI"
    "mC98kO?6w5loEse?eh4>AJX2*sh-tcn%oSsA1lwG`(^tXAhKdpzFzu|8COw1mn!7{3Smc3jE4Em@81OWO6*YU7=WG|UJDT!P$eJB"
    "gWP9q*qlb~IPj>5h}3@x`I}0Iq>7+pLuc9oyzO?%|2h_!+v}oUcte%9fFUMuIII^t5Jr;siUKD`UpXz=(DW^!<2o;VopN+$6+2N+"
    "H6?Xa1yRb9QQ;|+sqKmRL_^fn_Rf6Xk*c(&8PN?oMJv3L*`?!qQc;80WYfl)RzfkYp2$kFy4e!SmsdH^%U7;-Sn7On-m6uO%CfWM"
    "o)T1H38PbBkpfFo75IyRsB0KsKtgq6)Qwva9fyG<flu{1S_v8O<?h!D#o%0xpg&O0sm0Rui_@FQWTyXabh6#g`%ZL@i!v$hp4@c5"
    "uPf|^JwH|1I*$)d-`oZ4WPSsO4G#>tFE+aeb!OL{JS10{qIEyLWvnoorF9m<f)z?8JY6_i0c*uZqO<}Q-JtwI7CoIsPqO4$?Y`PQ"
    "8KkPzT|~a&8d!;3>Pik~E-wE;Duy#>I8%l*V>mO0Gh;Y2hI3&!7q}lNRX|?K^x@p##sPrccaQ^#|Jh$Oht8YXGpF@hkMah55G`7E"
    "76Ut_DG?75wGkvwM2Bes&WnMse*5w>^3VxXEc7M8|1J1LX<3A2T7qR-fMp`TG7(>yNUuzUS0*=6rWVb5p8jI$$Q@WxzU<$+$Pkkv"
    "FUa<5bwKDx0`jYVrLrUeE>-4qBYNvt=~S-mu55a@HbHS9c^)<W^r96jO+;iSYa`Z@QY#$PE3MrtElKNX8j2<=(I+2aTX!=>qjO$B"
    "dCVm-K)EfDA@kdyb^HZ3YNwzW)GZ!XGjpJ3MpRAzu(}z8KQ%-P5so;}Lvx@G^*|d<Lgd9kg@$SmE}6~Dux}A@=wka#WSZ_l(MNFT"
    "5M6qmz9qY9y-%W>O_kgO1u(##pW|Y%>BrDc=2xnVN^Mbxrt1eHJy1I;ib2e?91f)?#1(TA;YKh_KEPt!P3=*2T<Yh`Rvee=SX9SC"
    ">kVnH+KQnX@J)kZz|>#S=^PibQqLV0<4o`;RKjY2yse!SX-5Ij$3OY`uc;J%UC_T0QVy6?wP4{YsZdua4k?cbQuwR5f-I#QhN(ZM"
    "sY-RR%e%spNVDjb{8}m{zSNtkW5C--hHkW_d%C?>|4n`@zkjY=i{rVFxJ9QHhn2|)9K)T0Uv@{Id|D=DvrI~3A(LQCn>{_I@gzbz"
    "SvpY29`p&p;Ayuj3eS$qMreA}uO!OBM&KJYZ6lX9*XJ$k>Xx;1%L=+>4VCs5=`V9SHwu5Fo@pLB-(t3GXd6{F305G(0ge1;IJ-Ag"
    "ff$RCJYn_*Y=#avV50ae5DHmxmqdd5pobKh;QN1Mvt~m1)eTB{cYouy)9H1(<JKKxL|i%yQR~^dyJOg$WBu|mv{QS1*v8?%$U@yO"
    "0r=4N<H0VIs2gr~ysDIfB|~=i>NsX6ptJjHnr|P2@xjj@r_qtCX`jsG7#whLwt<k@ad8*fYkJ%=0`!MetlqGX0d0Wc_mI*MD4p(Z"
    "f*o1k8-#B%&wbNQo}uXDK+%T>|HH9nvLI_i*Qr5_r#zT9NK+Cdt#e2|hvdxxX;h5Kjg>=(e+L5Vhg3U=?4nhK?dYTEAV^dxFYXM="
    "4R<;SI(Q{mRCPh1gcYk-73xx^(cgA>*wTTYx+^MJ4R}X?EOBBH2d&9HPz<(UFQ}~nC1J&MI_&A7Ctm7)Oi-fE&{7yug3=I$4Nyey"
    "M23OG$_bD1C`e@{bBd{&sUMOx3UZ})FV#i_Lxs|mG|0j>otVX0>8_*XU|UlE*dbY@ARE1a5o?NxhKKU20|Kc^RBM$A2&iTO#WQv="
    "VI=t9o>2WSt+z0N2mJ5H&~_&Duo+pt5FZ8|)J;J7Upu=;S+c|#bWk|~y%>rCk4V!(u4!xjK>fr~%))7xH2{wejcC%IU?B50dU0z~"
    "I5YrGfCAZ={RrfhrYcgX@NIWDp5qWh#o0d9)v6W1!+&&J!(&(yj;aFzeiyrCuoYB;ZQ$~LF(u*JQZhI!SGLWy&AT~5`%QJw1|MzJ"
    "yDtY4Txi5JrQM<*6IecIt9{MC_e3Yn^C5IApiI+-l=1eDg5Un}LFw|S&mrNk!_9!5g~O^4fc$bib(7AJf4c^tYRqVl(pL$qClVN!"
    "n-fbi>2c5Rv^NuMYEP&C<S+j*`NRFe=Kf%tE}&^gf1(H{3us&JThLDnF!Y)kFk4z<_uLGBd_zb<|8@d|)kr$DNdV0+MAgI))(v@R"
    "nC&;2=`d~*gajQ-R@i>4S6i$uo?y~tFX>l|QTE+*(p-hbI8N*pr^>Ivi+S|&|4dKDHml9+UOtS?siPlP+wFgh|K9E&le-Pr&NgEM"
    "Vpv|)|FZ`S?hfFmJeFjf<3DY&)%(R68!Hcc=@Sc>$A=*ix{oNRi^IHE>UqB-*A&d-ljV<(7mxBbQ)vdh_DmyN?ScO;nKG#%8fKo)"
    "Waba3vkKvIag2XkrbPz{fJ=$Z6C)0nPb}EZ2k(jXVay~i^<%?*Nc02w-7<Qbf+zEFGo7>Rr{*!B1kIveb)0ylo(`kUX~(*YBsy0Y"
    "$2zmEh{0ql>0tYOXKiz)yC>^(kKLKOO>LAOdVY=i=$@iKlV(lOgLP({)MwOUp{KUi^8sMVHQkd1sqU!$_Ge8O)%h>+D#6SQ=`IHT"
    "+wJS_5w-6gAbaNJPFL8O*cE5r_*9IMr9LkH#Qi}0%uE^-ryUIfLS)^{_>b<|V##Y5ogj&srrEQMiM#1coX%lpQeD#vnAass`E|(_"
    "tb0vnKDF+ZlcxUqw4>LjZoE7@>90=(e3kU&(=J{ueK|k*aArQ7*&NQA+3c4GVK)16erl~wy8t?_o$2ZBp`W!R;>HJRPL7O<i(>cS"
    "v%A^u#Fojogpi@dv;))!J((tOQSZB_M|&2vPR@_wyG=(<d3U`t4p8uZJ|}P<rp&sAhn7L)z2qy>rw1smEc1$+kJR%R`KLlKAPK|M"
    "v*DT6@KkFs=noTYb*CO-Sdjnti->x<HU<;d;o*D?XEHJ@f$j-u0n>3p?Ye-;7UL@waeDWrOzIeQ@J(XhPHd{W6C?L;lIw2uP0(-r"
    "eUq3s>3l1~x^5(@3v5R&1S^?Yb>YXL5l<s&7ubeIT?D^H2i8{+?Q|brCsxE61odLzYe1*Sf%$>0Z@Lr#Zoy(kxn6l69XM={*nFb_"
    "L0IjHtX@48r_on!c`BHzBY0J1s#nUaa`Jlc>Xux4so@)~f|Uqd5nd2BW`gxbNz|O{8oL?AoD8@XrvHHr+D-kjLy7lI5)lFH<kTC5"
    "A3$Pmwyru*_10%lhz@#sGHt-9Qn5m+=%o{Ql~S#O&Pa%=7*($mTfe&1s~?`-R9o$&i`jSeDy~|O5ZLq2Bh3$+LnkCErw(0I!@Zs5"
    "&8(mqse4`W`(xgK6`EG$*PVDWaS&xsPYi7<nCAL=XX{HqkkTg$kl^17ROjYLL_iGyD4@D7$7aceXkE~iCL~)IXM`jmkJNH~c##>="
    "CVsSnMUOWGa)fqBO^aUQMf(hl{*zF>C^cY1L%EO+t?HnkWU;EL%;D^pj+hBA&yvLurrkBEDH4Mbk#*B?39yTWhL)gzi>dx@EOG_-"
    ")4XEUR?Ha22{@~omzUmU6;(d+1~;$+{6#z(;nDTir!(@&mWEZa9NtT=tVjGZsbGb&+O`%JU;ycuL80aznYFI~HvJgd<urW*hyNna"
    "*$)$Si8E`f?oo1+thy;``syg&r{h=`)BLE09oS3>fgGU)=dqg@s!Mkcb@Wn!jc*<Tg3;&hPMG1idN{5O$2z(vFLp%kgw5q0%$^4H"
    "=7H1huJ}lz8Ne&=wF>x~r0%X-JE_>6ik&e9s387S_X&G-sO<3v(3|tDJAf58OeO`DNkL^&5R|`ZF?uLjblN)#bk889*WK9j&m+w#"
    "M?bzT%#>5>b_ueBN-+Kn3URoe4Ub;K!<RJuZZ@W-5R2gr6zQ?SdA(k%(JhfAkF3gE7&Y35Zd3Aec*nT<RuJgWxcnl-D`N5{pC+Zs"
    ")S!A+P(2-BceGC37Cs`k-S-`=tpydhlOcx}(V+kS7>@*->I#b(zCO+2DEW8x;RkvuK^yn{qHH{Quk0gL-clDFwn8cSVGto{IuMLW"
    ">@dW^9e?x_F6)C4;BcpMaI+`S-Ns=XZmFmElf7#J_D}Cf3lC!&vmpZdJ3RGru3ep>jWvU4epJA-E2#i_3;2%-V7vXA;)z;Pqrlsp"
    "2HZIJXu9+TRYo*#SP7I{&8K=TPxYEl^_ovgnosqt`RB0aAHjqk{_Ef`^(H}S;9UL^C0KH{Au1)nEkm#LU<Tn|A7wO--Wtlr1?ml&"
    "#GQibkLm%i<xq}xp~G)OA0H({Vrm+&3&QLsh<zAorcC<v8APCH`pvi`$|&0w@@~nz^JvvF_}qkT-h^$r`I<vn^X99dE+0$-`$2{<"
    "-EZEFZQhM-i<BGaU<_{xWy{`db4nN508os}2h-dxx}#HuX-2v@T2vNK%K{vHaqtMq2_Kl&{H#uU#q(bg(zTR70K3?DVjXKcri42("
    "e}^;J5?(MLoQ5O+cVvc>>_xLN4YmYZBe=PmVs(y$YQUbxiKe|%)EkLnzM(7nU?JY5`rxo88=wNqle$fx*tj8mNTrQ7p{?3RP^!VP"
    "w!o0E5tsfw`(3ELK#)?^E}k|3n=UU`Ea-O4VTClnPQ0iIo#}4tdN;&KIdtTHkCwY-!VRx-v#fnK%Yu>8eld?r{$&+PW`@z}dZZ^0"
    "r{_^^z1jK1u47EK=>IZOzj{VnjKy_fC_p5Tj596Rm*o>pZF%9x!sdrWrGoI6WXJ-Ziv)I$=8YhMBguvkdTDTCi9MKGG1|IY0F6X@"
    "H$b702EKuw#y#WU%a@0g!rUEAM0bwV79%WoL#HHP8P}KYv;-pCBh-FJ(?gPmVyFfcEZYdylmZL@i#|4P!#&Gz=j@$^=H}x+s8wt?"
    "c;w<1Vo-0xG&ddg8-h*)4Ff%PKs68th$DbqvNwBdch%E_Vw>4BPD=;0d2qWWs7wFP>v(XQ;gnZ668J2xkAG=P+ji18;t{w@EtaUK"
    "4E?h(%4^AouAnOT$(S>vJ5_?`a(9;#OcVXRV7iE4QHQ=f^_S0Z0V6+0ek)6Oo$GZ`pf9zymzr~sUxYl(Y{m}Q_$HgT8srCa-ECBT"
    "lF+H^RZ!i&4$z|Jb;%E@9m5JrLBREk3i#6XM1(Z8%_r}EMWQEo>1Cl!!7iF`3;h?1QK4QIdg)OiBF~MBmoF8(EadUZCx(R6j@Db+"
    "-gNHp^7%=?8Dy2grjR!>X8RS<-x82|U7k7ye)*vm!3K8yrOj(O>`GS8KQ?0GmqG%cUnpb>GO>l9J14L&-F=W{$0l0pt9*ZpNYKjL"
    "oiF4hgT^@a3%0w!?;D9RULSi*3SK&qdHJ|RAeZG=Cyv@PRd4UTQ&Ek+AfI%{fpovZ4E^rzH<;g;l%Hajj~6^a9jMMhTd^Wk3T>nY"
    "(SGl%RHaB)4TGvG1?4$mG29e-N!*lJRQ#xlNL_jC<)w2SZR+yJj{Y(+(;o0~5}QS}GAI&j!6+XVl8B72VAD(0!8|dAl?NNK+HTki"
    "um^sjInc%mA_mC&<!&awJ7AmrX49V!@aK<$=!#8;d$r}~%iGgIW8hNu>_kb6I`*q2s4POt9*V%D?!Pf%0Rt?8E!Y!>s9H+BQS3FT"
    "jspcmQM+UU*9=|X5q*&P+S$Tz$1t*bg8UT||DbG_1v=vcB_sXvHqlE{h9JL$N5)&YS}y=n9fbtMTM2-|Qx%flUF8l{yh`X?_BhTB"
    "I1}(}J6(C|^9Nsa9r{)KHy_=h_g}8IiqTep(8=%eh=3?#t?T)q(rT4W{Ez?#WPM~?t$yb{@TCxAB!4xonMXZpnn1mHw(P~)Cg{|A"
    "^e=5<L^jE%rdf!ytUWf`Vqn2+L$q29@6U;O=#d;4iD8Igw16RX!Dz4+GIbEMJ6;cWK7p=v!JyF9b+6H*Hm<V08b#GyQ~^4Bdue(Z"
    "bfeQmx#Wupr0D!HDA}D9MJ_+uQ_M=1IaYLcL0yWP5d=M&sZ7qu0Mu)}tno~+L&N#Z%A&V$U))CsK;(;=$xAm2gY34fdFD&^nO@Tu"
    "7C<@IAAiy6-xnT_c_YI5w&<#0*la>$E)k#&r?;LZd|!UF92Kn4J^)$%DHuiRiDFXWEAF&g^}bZxRUAmZJ}AyA4r&wW7;B3BzTkFo"
    ")D}l=!SRB#h0qopBgG=X(hA>*GpSq&dBySSbV)W*lmJ&eT=8lp;wwIF#BzI^5~(L%J@M*^vnTO*;`oW<CysgN?5)Sk-iY-XWUD(L"
    "oyy)811Ugb#rx77Kz9h;L3D?~$+kcl)*UNC8fKg59K>^uVvyZQIu2*afn~Pq1LQ_xe(&-V3n<aThe*Y|Mp%G8bQ}1s^MRlnBr5W|"
    "bbAr&5`e$EebV9Z+eg7~9&0e*N|CSMy6Oz<f(bx~QT@?m37A0fmwXV|uwq{s!(O|n0<7qKdZV63R5c1EHE)#Ah;C3!Dm-4f%%vUt"
    "UAtq0dYyntbjfAy`ibJzz^j2*1Fr^NsRSywPJs#VkM5biwVx&r*=u~)H?^VBI-8p%s-xdj>UL9kHE!Ap<Y|+f)*FS!=~xm_Z(3gC"
    "c7|Yu$`v&WjVo^y(7qe*Rlm_Y`=%CJ8SJ|`<&E;xx@-k-gF4VRi;$pdOO3b=RW+$Od{38XKxF!qf~5D<hUk0#=;rTR7pyM^e~DI|"
    "JpvI3iX+~Bp#1Fz%HI>M%Ws|`7gdQ))GNPvl>E)3<Zm7&fAbo7&<bC%qiE=m<jqB?_f+-dX3|?Pa<72wkZ5UrTmii3xb8%o*QMWc"
    "SC=z~BSoc{!;zwH1U>i%Z>S=ZDl(}es26zCNG0<0{##mfnO}bhd_XnE|7mdeyTtS&XpB;SdTml5t&#yT_5RaI^q=+)|D^0YNENY#"
    "7?^^ff%5OU>)`3@PwHNRK6St0)bMsHkn<u{9|epGA9!c@4eYUy=Jr>RRb&gIBc>A-he7?;@OjaFX#J_NGpLj%oCtuQy!9#H(Mof&"
    "&N#KsI8ma1qB$_=S#@dajLvpQ_92)b5j`&m5Z;rmUT|EDhs`zOonEJ$JS2I#|3%S(C^72tSceOzWOp&*_TS0tkN?le!Bm2$IJO@G"
    "&(ki1@m(~UoJDzhqFP2&)5sGQ#V7O3vp7!+|11A2#dT^?@WJhWj9ln_v(vZG0L;?zB5#z(5;cX69hjm8BW$YEIg$E25%4@&51bO}"
    "JT?74HT^%mfq$Z@PA@~l!%8`vU?yNV96?J3g36^L<vb^P=b#Q$nwdlu-gDqivUZ}e)K@^>1rs8Jbbds`&O(k^uIkhoxQHUauFz)2"
    "psC&|DHct3PIWbBVXAuagvx1ginGi+BpU9?N<lQHN&+_m)&pmC1XvaTdwcksfV2b%vf9pSJ1a9%iOU4}`2p@|hzx9mc-I9<!2qIV"
    "1yCNb(%WTYwP$N2LJxGD=ubQK_6FvDkM`6O;nc-b$>fM|N^x?WDwiw^&dOBrtWu^e_`N{+D;5KC$Q<LWp531kK-KlGQ^S#n{IY@+"
    "qrw=@lHvP|XGPza&~Ao#vOchOf8$b$=>m@^)fz2bz0cCd-`C0038z(_0TDvGRb6-jbxY!G*!dAh^^a-1{#MmNum7o?qhg4(X*d*7"
    "aZ24iM)3HqaWd#BFMP~u#D}&*WJA3Vy2egajh(0%JGG~IHXf+}szLv#qA8i}WdH7*S|yxQOP$kw%>0(-v6Eg{^g&N5-CM>7f07r|"
    "c@aRpn-Vs~T$|59tx)2eY%-ry+sb_VU237SM>?FKMRds!g4q?bAC67Hdoeb_d?;jgqy>cU4H4lz@sYSRVn8nybeA}p7%h2(FRJUj"
    "e`0p8_~&O(gIU-e5i@P@yj<`~N|J73*!UK5DK?l-9^G|V5a5%nV6>eZaK0SrhjmAYnLmbI4pMK$Ie%^bn_cq!Z74Vl29d{evgj0S"
    "PWEDb9WWyqyjU_{mQvH)U7B7qB_A!{88{)ze@S>^rbnSfCygiOFEnPod~7$dKxb&2s}mgHTCv5bECY|Mb1M%=f6KumQ^AOfCIXyq"
    "Q?Iw4v-KMTPt1lgLt}7F=EtDwkIuCdS(S5odtT_Al?s<r*Mk>-k{RANKj-e;)74l0MP<i1Q&k6yYvP`@X?M5FTdg*D(&J9+?+|u1"
    "(ZH$pIfp}_!<rli1k_l_@ZB%Yh194kMh60?vM=aizqKAer*?xCl^4Un)IJ<eUY4mAlX3E<n6NvSyxVk6Z3Jf3)9z^n;}5nagI19)"
    ")5^oF#w}46RaY=y*ycIe8rl-OagjH*W18JJTBOd@A_dal{{1eVoCTwSAVBr*FZ?FLe_Q=cw6!M_Ac52XiK*(ZgticM{{H~>%3>e"
)


def carregar_palavras():
    """Carrega automaticamente as 38.504 palavras embutidas no próprio código
    (verificando seu hash SHA-256 contra adulteração) e, opcionalmente, soma
    arquivos .txt extras caso exista uma pasta 'listas/'."""
    palavras = set()
    try:
        bruto_embutido = zlib.decompress(base64.b85decode(PALAVRAS_EMBUTIDAS_B85.encode("ascii")))
        digest_embutido = hashlib.sha256(bruto_embutido).hexdigest()
        if secrets.compare_digest(digest_embutido, HASH_PALAVRAS_EMBUTIDAS):
            for p in bruto_embutido.decode("utf-8").splitlines():
                if p:
                    palavras.add(p)
    except Exception:
        pass

    pasta_listas = os.path.join(PASTA, "listas")
    if os.path.isdir(pasta_listas):
        for nome_arquivo in sorted(os.listdir(pasta_listas)):
            if not nome_arquivo.lower().endswith(".txt"):
                continue
            caminho = os.path.join(pasta_listas, nome_arquivo)
            if os.path.islink(caminho):
                continue
            try:
                with open(caminho, "r", encoding="utf-8-sig") as f:
                    linhas = f.readlines()
            except UnicodeDecodeError:
                with open(caminho, "r", encoding="latin-1") as f:
                    linhas = f.readlines()
            for linha in linhas:
                partes = linha.split()
                if not partes:
                    continue
                palavra = partes[-1].strip().lower()
                if palavra.isalpha() and 3 <= len(palavra) <= 20:
                    palavras.add(palavra)

    if len(palavras) < 1000:
        return [], None
    ordenadas = sorted(palavras)
    digest = hashlib.sha256("\n".join(ordenadas).encode("utf-8")).hexdigest()
    return ordenadas, digest


PALAVRAS, HASH_PALAVRAS = carregar_palavras()


def validar_integridade_palavras(meta, confirmar_fn=None):
    if not PALAVRAS or not HASH_PALAVRAS:
        return True
    hash_salvo = meta.get("hash_palavras")
    if not hash_salvo:
        meta["hash_palavras"] = HASH_PALAVRAS
        return True
    if not secrets.compare_digest(str(hash_salvo), HASH_PALAVRAS):
        registrar("alerta_lista_palavras")
        if confirmar_fn is not None:
            aceitou = confirmar_fn(
                "ATENÇÃO: Os arquivos da pasta 'listas/' foram alterados desde a "
                "última validação! Deseja aceitar a nova lista mesmo assim?"
            )
        else:
            print("ATENÇÃO: Os arquivos da pasta 'listas/' foram alterados desde a "
                  "última validação!")
            resp = entrada("Aceitar a nova lista de palavras mesmo assim? Digite sim: ")
            aceitou = (resp.strip().lower() == "sim")
        if aceitou:
            meta["hash_palavras"] = HASH_PALAVRAS
            return True
        return False
    return True


# ----------------------------------------------------------------- auditoria

AUD = {"chave": None, "seq": -1, "h": GENESE, "carregado": False}
TRAVA_LOG = threading.Lock()


def definir_chave_log(meta):
    limpar_chave_log()
    chave_bytes = bytes.fromhex(meta["chave_log"])
    buf = bytearray(chave_bytes)
    apagar_bytes_efemeros(chave_bytes)
    trancar_buffer(buf)
    AUD["chave"] = buf


def limpar_chave_log():
    if AUD["chave"] is not None:
        apagar_buffer(AUD["chave"])
        AUD["chave"] = None


def impressao(nome):
    if AUD["chave"] is None:
        return None
    return hmac.new(AUD["chave"], b"item:" + nome.encode(), hashlib.sha256).hexdigest()[:10]


def _corpo(seq, t, ev, item):
    return json.dumps({"seq": seq, "t": t, "ev": ev, "item": item},
                      separators=(",", ":"), sort_keys=True)


def _hash_entrada(anterior, corpo):
    return hashlib.sha256((anterior + corpo).encode()).hexdigest()


def _carregar_log():
    if AUD["carregado"]:
        return
    AUD["carregado"] = True
    AUD["seq"], AUD["h"] = -1, GENESE
    if not os.path.exists(LOG):
        return
    ultima, total = None, 0
    with open(LOG, "rb") as f:
        for linha in f:
            if linha.strip():
                ultima, total = linha.strip(), total + 1
    if ultima is None:
        return
    try:
        e = json.loads(ultima)
        AUD["seq"], AUD["h"] = int(e["seq"]), str(e["h"])
    except Exception:
        AUD["seq"] = total - 1
        AUD["h"] = hashlib.sha256(ultima).hexdigest()


def registrar(evento, nome_item=None):
    try:
        with TRAVA_LOG:
            _carregar_log()
            seq = AUD["seq"] + 1
            t = time.strftime(FORMATO_TEMPO, time.gmtime())
            item = impressao(nome_item) if nome_item is not None else None
            h = _hash_entrada(AUD["h"], _corpo(seq, t, evento, item))
            entrada_log = {"seq": seq, "t": t, "ev": evento, "item": item,
                           "prev": AUD["h"], "h": h}
            if AUD["chave"] is not None:
                entrada_log["mac"] = hmac.new(AUD["chave"], h.encode(),
                                              hashlib.sha256).hexdigest()
            linha = json.dumps(entrada_log, separators=(",", ":"), sort_keys=True) + "\n"
            anexar_seguro(LOG, linha.encode())
            AUD["seq"], AUD["h"] = seq, h
    except Exception:
        print("Aviso: não foi possível gravar no registro de auditoria.")


def ancora_atual():
    with TRAVA_LOG:
        _carregar_log()
        if AUD["seq"] < 0:
            return None
        return {"seq": AUD["seq"], "h": AUD["h"]}


def verificar_auditoria(meta):
    ok_rb, msg_rb = verificar_rollback_so(meta)
    if not ok_rb:
        return False, msg_rb
    ancora = meta.get("ancora")
    achou_ancora = ancora is None
    if not os.path.exists(LOG):
        if ancora is None:
            return True, "ainda não há entradas."
        return False, "o arquivo do registro sumiu."
    anterior, esperado, sem_selo, pos_ancora_sem_selo = GENESE, 0, 0, 0
    with open(LOG, "r", encoding="utf-8") as f:
        for numero, linha in enumerate(f, 1):
            linha = linha.strip()
            if not linha:
                continue
            try:
                e = json.loads(linha)
                seq, t, ev, item = e["seq"], e["t"], e["ev"], e["item"]
                prev, h = e["prev"], e["h"]
            except Exception:
                return False, f"a linha {numero} está ilegível."
            if seq != esperado:
                return False, f"a sequência quebra na entrada {esperado}."
            if prev != anterior:
                return False, f"o encadeamento quebra na entrada {seq}."
            if _hash_entrada(anterior, _corpo(seq, t, ev, item)) != h:
                return False, f"a entrada {seq} foi alterada."
            if "mac" in e:
                if AUD["chave"] is None:
                    return False, "sem a chave do cofre não dá para conferir os selos."
                esperado_mac = hmac.new(AUD["chave"], h.encode(),
                                        hashlib.sha256).hexdigest()
                if not hmac.compare_digest(esperado_mac, str(e["mac"])):
                    return False, f"o selo da entrada {seq} não confere."
                if ancora is not None and seq > ancora["seq"]:
                    return False, (f"a entrada autenticada {seq} é mais recente que "
                                   "a âncora do cofre (possível rollback do cofre.dat).")
            elif ev in SEM_SELO_PERMITIDO:
                sem_selo += 1
                if ancora is not None and seq > ancora["seq"]:
                    pos_ancora_sem_selo += 1
            else:
                return False, f"a entrada {seq} perdeu o selo."
            if ancora is not None and seq == ancora["seq"]:
                if h != ancora["h"]:
                    return False, f"a entrada {seq} não é a que o cofre registrou."
                achou_ancora = True
            anterior, esperado = h, esperado + 1
    if not achou_ancora:
        return False, "entradas foram removidas do final do registro."
    detalhe = f"{esperado} entradas conferem; {sem_selo} sem selo"
    if pos_ancora_sem_selo:
        detalhe += f" ({pos_ancora_sem_selo} após a última âncora)."
    else:
        detalhe += " (todas já amarradas pela âncora)."
    return True, detalhe


def ultimas_entradas(quantas):
    lidas = []
    if not os.path.exists(LOG):
        return lidas
    with open(LOG, "r", encoding="utf-8", errors="replace") as f:
        for linha in f:
            try:
                lidas.append(json.loads(linha))
            except Exception:
                continue
    return lidas[-quantas:]


def formatar_entradas_auditoria(nomes_itens, quantas=ENTRADAS_NA_TELA):
    nomes = {impressao(n): n for n in nomes_itens}
    linhas = []
    for e in ultimas_entradas(quantas):
        try:
            hora = time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(
                calendar.timegm(time.strptime(e["t"], FORMATO_TEMPO))))
            evento = e["ev"] if e["ev"] in EVENTOS else "evento_desconhecido"
            item = ""
            if e.get("item"):
                item = "  [" + nomes.get(e["item"], "#" + str(e["item"])[:10]) + "]"
            linhas.append(f"#{int(e.get('seq', 0)):04d}  {hora}  {evento}{item}")
        except Exception:
            linhas.append("(entrada ilegível)")
    return linhas


def mostrar_auditoria(nomes_itens, meta):
    ok, msg = verificar_auditoria(meta)
    print(("Registro íntegro: " if ok else "ATENÇÃO, registro adulterado: ") + msg)
    print(f"Últimas {ENTRADAS_NA_TELA} entradas:")
    for linha in formatar_entradas_auditoria(nomes_itens, ENTRADAS_NA_TELA):
        print("  " + linha)


# ------------------------------------------------------ bloqueio por tentativas

def salvar_estado(estado):
    escrever_seguro(ESTADO, json.dumps(estado).encode())
    salvar_guarda_so({"erros": int(estado["erros"]),
                      "liberado_em": float(estado["liberado_em"])})


def ler_estado():
    guarda = ler_guarda_so()
    erros_so = 0
    lib_so = 0.0
    if guarda:
        if guarda.get("adulterado"):
            erros_so = MAX_TENTATIVAS
            lib_so = time.time() + 300
        else:
            erros_so = int(guarda.get("erros", 0))
            lib_so = float(guarda.get("liberado_em", 0.0))

    if not os.path.exists(ESTADO):
        if erros_so > 0 or lib_so > time.time():
            estado = {"erros": max(erros_so, MAX_TENTATIVAS),
                      "liberado_em": max(lib_so, time.time() + 300)}
            try:
                salvar_estado(estado)
            except OSError:
                pass
            return estado
        return {"erros": 0, "liberado_em": 0}
    try:
        with open(ESTADO, "r") as f:
            bruto = json.load(f)
        erros = int(bruto["erros"])
        liberado_em = float(bruto["liberado_em"])
        if erros < 0 or liberado_em < 0:
            raise ValueError
        if erros < erros_so or liberado_em < lib_so:
            erros = max(erros, erros_so)
            liberado_em = max(liberado_em, lib_so)
        return {"erros": erros, "liberado_em": liberado_em}
    except Exception:
        estado = {"erros": max(MAX_TENTATIVAS, erros_so),
                  "liberado_em": max(time.time() + 300, lib_so)}
        try:
            salvar_estado(estado)
        except OSError:
            pass
        return estado


def segundos_bloqueio_restantes():
    estado = ler_estado()
    agora = time.time()
    liberado_em = min(estado["liberado_em"], agora + 3600)
    if liberado_em > agora:
        return int(liberado_em - agora) + 1
    return 0


def verificar_bloqueio():
    restante = segundos_bloqueio_restantes()
    if restante > 0:
        registrar("tentativa_bloqueada")
        print(f"Bloqueado. Tente de novo em {restante} segundos.")
        raise SystemExit(1)


def registrar_erro():
    estado = ler_estado()
    estado["erros"] += 1
    espera = min(5 * 2 ** (estado["erros"] - 1), 3600)
    if estado["erros"] >= MAX_TENTATIVAS:
        espera = max(espera, 300)
    estado["liberado_em"] = time.time() + espera
    salvar_estado(estado)
    registrar("senha_errada")
    print(f"Credencial incorreta. Espera de {espera} segundos para a próxima tentativa.")
    return espera


def zerar_erros():
    salvar_estado({"erros": 0, "liberado_em": 0})


# ------------------------------ cofre em memória e proteção do segredo mestre

class CofreMemoria:
    """Mantém o segredo base (da Senha Infra), a chave de dados e os itens
    cifrados individualmente na RAM física."""

    def __init__(self):
        self._chave_sessao = bytearray(32)
        self._segredo_mascarado = bytearray(32)
        self._mascara = bytearray(32)
        self._chave_disco_mascarada = bytearray(32)
        self._mascara_disco = bytearray(32)
        self._cabecalho_cache = None
        self._tem_chave_disco = False
        self._usou_keyfile = False
        self._abriu_por_recuperacao = False
        self._caminho_keyfile = None
        self._itens_cifrados = {}
        self.meta = {}
        self.aberto = False
        self._trava = threading.RLock()

    def inicializar(self, segredo_mestre_buf, itens_claros, meta,
                    usou_keyfile=False, caminho_keyfile=None,
                    chave_disco_buf=None, cabecalho_cache=None,
                    abriu_por_recuperacao=False):
        with self._trava:
            self.limpar()
            self._chave_sessao[:] = os.urandom(32)
            self._mascara[:] = os.urandom(32)
            for i in range(32):
                self._segredo_mascarado[i] = segredo_mestre_buf[i] ^ self._mascara[i]
            trancar_buffer(self._chave_sessao)
            trancar_buffer(self._segredo_mascarado)
            trancar_buffer(self._mascara)
            self._usou_keyfile = bool(usou_keyfile)
            self._abriu_por_recuperacao = bool(abriu_por_recuperacao)
            self._caminho_keyfile = caminho_keyfile
            self.meta = dict(meta)
            self.aberto = True
            if chave_disco_buf is not None and cabecalho_cache is not None:
                self.definir_chave_disco(chave_disco_buf, cabecalho_cache)
            for nome, valor in itens_claros.items():
                self.definir_item(nome, valor)

    def definir_chave_disco(self, chave_disco_buf, cabecalho_cache):
        with self._trava:
            self._mascara_disco[:] = os.urandom(32)
            for i in range(32):
                self._chave_disco_mascarada[i] = chave_disco_buf[i] ^ self._mascara_disco[i]
            trancar_buffer(self._chave_disco_mascarada)
            trancar_buffer(self._mascara_disco)
            self._cabecalho_cache = bytes(cabecalho_cache)
            self._tem_chave_disco = True

    def obter_chave_disco(self):
        with self._trava:
            if not self.aberto:
                raise Bloqueio()
            if not self._tem_chave_disco or self._cabecalho_cache is None:
                return None, None
            out = bytearray(32)
            trancar_buffer(out)
            for i in range(32):
                out[i] = self._chave_disco_mascarada[i] ^ self._mascara_disco[i]
            return out, self._cabecalho_cache

    def obter_segredo_mestre(self):
        with self._trava:
            if not self.aberto:
                raise Bloqueio()
            out = bytearray(32)
            trancar_buffer(out)
            for i in range(32):
                out[i] = self._segredo_mascarado[i] ^ self._mascara[i]
            return out

    def usou_keyfile(self):
        return bool(self.meta.get("kf_hash")) or self._usou_keyfile

    def tem_segunda_senha(self):
        return bool(self.meta.get("s2_kdf") and self.meta.get("s2_salt"))

    def abriu_por_recuperacao(self):
        return self._abriu_por_recuperacao

    def caminho_keyfile(self):
        return self._caminho_keyfile

    def nomes(self):
        with self._trava:
            if not self.aberto:
                raise Bloqueio()
            return list(self._itens_cifrados.keys())

    def contem(self, nome):
        with self._trava:
            if not self.aberto:
                raise Bloqueio()
            return nome in self._itens_cifrados

    def definir_item(self, nome, segredo_str):
        with self._trava:
            if not self.aberto:
                raise Bloqueio()
            nonce = os.urandom(TAM_NONCE)
            dados = bytearray(segredo_str.encode("utf-8"))
            trancar_buffer(dados)
            try:
                cifrado = AESGCM(self._chave_sessao).encrypt(
                    nonce, bytes(dados), nome.encode("utf-8")
                )
            finally:
                apagar_buffer(dados)
            self._itens_cifrados[nome] = nonce + cifrado

    def obter_item(self, nome):
        with self._trava:
            if not self.aberto:
                raise Bloqueio()
            pacote = self._itens_cifrados.get(nome)
            if pacote is None:
                return None
            nonce, cifrado = pacote[:TAM_NONCE], pacote[TAM_NONCE:]
            dados = AESGCM(self._chave_sessao).decrypt(
                nonce, cifrado, nome.encode("utf-8")
            )
            try:
                return dados.decode("utf-8")
            finally:
                apagar_bytes_efemeros(dados)

    def apagar_item(self, nome):
        with self._trava:
            if not self.aberto:
                raise Bloqueio()
            self._itens_cifrados.pop(nome, None)

    def exportar_itens_claros(self):
        with self._trava:
            if not self.aberto:
                raise Bloqueio()
            saida = {}
            for nome in self._itens_cifrados:
                saida[nome] = self.obter_item(nome)
            return saida

    def limpar(self):
        with self._trava:
            self.aberto = False
            self._tem_chave_disco = False
            self._cabecalho_cache = None
            self._abriu_por_recuperacao = False
            apagar_buffer(self._chave_sessao)
            apagar_buffer(self._segredo_mascarado)
            apagar_buffer(self._mascara)
            apagar_buffer(self._chave_disco_mascarada)
            apagar_buffer(self._mascara_disco)
            self._itens_cifrados.clear()
            self.meta.clear()


COFRE_RAM = CofreMemoria()


# ------------------------------------------------------------------- cripto

def ler_keyfile(caminho):
    """Lê um keyfile regular (bloqueando symlinks, dispositivos especiais e
    arquivos gigantes > 1 MB) e devolve seu hash SHA-256 em bytearray travado."""
    caminho_norm = normalizar_caminho_keyfile(caminho, para_criacao=False)
    try:
        st = os.lstat(caminho_norm)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Keyfile não encontrado em:\n{caminho_norm}\n\n"
            "Conecte o pendrive ou use a sua Segunda Senha para entrar sem o pendrive."
        )
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ValueError(
            f"O caminho '{caminho_norm}' não é um arquivo comum (links simbólicos e dispositivos são bloqueados)."
        )
    if st.st_size <= 0:
        raise ValueError(f"O arquivo Keyfile '{caminho_norm}' está vazio (0 bytes).")
    if st.st_size > TAM_MAX_KEYFILE:
        raise ValueError(
            f"O arquivo selecionado excede o tamanho máximo permitido para Keyfile (1 MB)."
        )

    h = hashlib.sha256()
    flags_leitura = os.O_RDONLY | SEM_SYMLINK | getattr(os, "O_BINARY", 0)
    fd = os.open(caminho_norm, flags_leitura)
    total = 0
    with os.fdopen(fd, "rb") as f:
        while total < TAM_MAX_KEYFILE:
            bloco = f.read(65536)
            if not bloco:
                break
            total += len(bloco)
            h.update(bloco)
            apagar_bytes_efemeros(bloco)
    if total == 0:
        raise ValueError(f"O arquivo Keyfile '{caminho_norm}' está vazio.")
    digest = h.digest()
    buf = bytearray(digest)
    apagar_bytes_efemeros(digest)
    trancar_buffer(buf)
    return buf


def criar_keyfile(caminho):
    """Cria um novo keyfile de 64 bytes aleatórios de forma compatível com
    pendrives FAT32/exFAT/NTFS/ext4 e devolve o caminho absoluto gravado."""
    caminho_norm = normalizar_caminho_keyfile(caminho, para_criacao=True)
    pasta_destino = os.path.dirname(caminho_norm)
    if not os.path.isdir(pasta_destino):
        raise FileNotFoundError(
            f"Unidade ou pasta de destino não encontrada:\n{pasta_destino}\n\n"
            "Conecte o pendrive antes de criar a Keyfile."
        )
    dados = os.urandom(TAM_KEYFILE)
    temporario = os.path.join(pasta_destino, f"nvlt_kf_{secrets.token_hex(4)}.tmp")
    try:
        with open(temporario, "wb") as f:
            f.write(dados)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(temporario, caminho_norm)
        try:
            restringir_permissoes(caminho_norm)
        except Exception:
            pass
    except BaseException:
        try:
            if os.path.exists(temporario):
                os.remove(temporario)
        except OSError:
            pass
        raise
    finally:
        apagar_bytes_efemeros(dados)

    if not os.path.isfile(caminho_norm) or os.path.getsize(caminho_norm) != TAM_KEYFILE:
        raise IOError(f"Não foi possível confirmar a gravação da Keyfile em {caminho_norm}.")
    return caminho_norm


def _derivar_segredo_infra_v4(senha_infra):
    """Pré-deriva um bytearray de 32 bytes da Senha Infra para o Scrypt v4."""
    senha_bytes = senha_infra.encode("utf-8")
    try:
        digest = hmac.new(b"nvlt-v4-infra", senha_bytes, hashlib.sha256).digest()
        buf = bytearray(digest)
        apagar_bytes_efemeros(digest)
        trancar_buffer(buf)
        return buf
    finally:
        apagar_bytes_efemeros(senha_bytes)


def gerar_chave_scrypt(segredo_buf, salt, n_log2):
    """Deriva 32 bytes com Scrypt a partir de um bytearray."""
    kdf = Scrypt(salt=salt, length=32, n=2 ** n_log2, r=8, p=1)
    derivada_bytes = kdf.derive(segredo_buf)
    try:
        chave = bytearray(derivada_bytes)
        trancar_buffer(chave)
        return chave
    finally:
        apagar_bytes_efemeros(derivada_bytes)


def _derivar_segunda_senha_scrypt(segredo_infra_buf, segunda_senha, salt_s2, n_log2):
    """Combina o segredo da Senha Infra com a Segunda Senha e aplica o próprio
    Scrypt de 512 MB (2^n_log2), impedindo ataques de GPU contra o slot de recuperação."""
    s2_bytes = segunda_senha.strip().encode("utf-8")
    combinado_buf = None
    try:
        digest = hmac.new(segredo_infra_buf, b"nvlt-v4-s2:" + s2_bytes, hashlib.sha256).digest()
        combinado_buf = bytearray(digest)
        apagar_bytes_efemeros(digest)
        trancar_buffer(combinado_buf)
        n_ef = n_log2
        while n_ef >= N_LOG2_MIN:
            try:
                return gerar_chave_scrypt(combinado_buf, salt_s2, n_ef)
            except MemoryError:
                n_ef -= 1
        raise MemoryError("Memória insuficiente para derivar Scrypt da Segunda Senha.")
    finally:
        apagar_bytes_efemeros(s2_bytes)
        apagar_buffer(combinado_buf)


def _kek_de_slot(kdf_base_buf, etiqueta_bytes, fator1_buf=None, fator2_buf=None):
    """Combina a saída Scrypt de 512 MB (kdf_base_buf) com os fatores do slot
    (Keyfile e/ou saída Scrypt da Segunda Senha) gerando uma KEK AES-256."""
    h = hmac.new(kdf_base_buf, etiqueta_bytes, hashlib.sha256)
    if fator1_buf is not None:
        h.update(b":f1:")
        h.update(fator1_buf)
    if fator2_buf is not None:
        h.update(b":f2:")
        h.update(fator2_buf)
    digest = h.digest()
    buf = bytearray(digest)
    apagar_bytes_efemeros(digest)
    trancar_buffer(buf)
    return buf


def _combinar_credencial_v3(senha_mestra, bytes_keyfile=None):
    """Compatibilidade com Versão 3."""
    senha_bytes = senha_mestra.encode("utf-8")
    try:
        if bytes_keyfile is not None:
            digest = hmac.new(bytes_keyfile, b"nvlt-v3:" + senha_bytes,
                              hashlib.sha256).digest()
        else:
            digest = hmac.new(b"nvlt-v3-sem-keyfile", senha_bytes,
                              hashlib.sha256).digest()
        buf = bytearray(digest)
        apagar_bytes_efemeros(digest)
        trancar_buffer(buf)
        return buf
    finally:
        apagar_bytes_efemeros(senha_bytes)


def gerar_chave_legado(senha_mestra, salt, n_log2):
    """Compatibilidade com cofres de versões 0, 1 e 2."""
    senha_buf = bytearray(senha_mestra.encode("utf-8"))
    trancar_buffer(senha_buf)
    try:
        kdf = Scrypt(salt=salt, length=32, n=2 ** n_log2, r=8, p=1)
        derivada_bytes = kdf.derive(senha_buf)
        try:
            chave = bytearray(derivada_bytes)
            trancar_buffer(chave)
            return chave
        finally:
            apagar_bytes_efemeros(derivada_bytes)
    finally:
        apagar_buffer(senha_buf)


def serializar_conteudo_buf(itens, meta):
    """Serializa o JSON do cofre com preenchimento em blocos de 1024 bytes e
    devolve um bytearray travado na RAM (limpando a cópia temporária bytes)."""
    envelope = {"itens": itens, "meta": meta, "pad": ""}
    temp1 = json.dumps(envelope, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    base = len(temp1)
    apagar_bytes_efemeros(temp1)
    falta = (-base) % BLOCO_PREENCHIMENTO
    envelope["pad"] = "0" * falta
    bruto = json.dumps(envelope, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    try:
        buf = bytearray(bruto)
        trancar_buffer(buf)
        return buf
    finally:
        apagar_bytes_efemeros(bruto)


def _embrulhar_slot(kek_buf, chave_dados_buf, aad_cabecalho):
    nonce_slot = os.urandom(TAM_NONCE)
    cifrado_slot = AESGCM(kek_buf).encrypt(nonce_slot, bytes(chave_dados_buf), aad_cabecalho)
    return nonce_slot + cifrado_slot  # 60 bytes


def _desembrulhar_slot(kek_buf, slot_bytes, aad_cabecalho):
    nonce_slot = slot_bytes[:TAM_NONCE]
    cifrado_slot = slot_bytes[TAM_NONCE:]
    dados = AESGCM(kek_buf).decrypt(nonce_slot, cifrado_slot, aad_cabecalho)
    try:
        out = bytearray(dados)
        trancar_buffer(out)
        return out
    finally:
        apagar_bytes_efemeros(dados)


def salvar_cofre(segredo_infra_buf, itens, meta, manter_backup=True,
                 chave_dados_cache=None, cabecalho_cache=None):
    """Grava o cofre na Versão 4 (Multi-Slot Envelope Encryption)."""
    nonce_dados = os.urandom(TAM_NONCE)
    chave_dados = None
    kdf_base = None
    kf_buf = None
    s2_buf = None
    texto_buf = None
    usou_cache = False

    try:
        if chave_dados_cache is not None and cabecalho_cache is not None:
            chave_dados = chave_dados_cache
            cabecalho_completo = cabecalho_cache
            usou_cache = True
        else:
            salt_scrypt = os.urandom(TAM_SALT)
            n_log2_efetivo = N_LOG2_ATUAL
            while n_log2_efetivo >= N_LOG2_MIN:
                try:
                    kdf_base = gerar_chave_scrypt(segredo_infra_buf, salt_scrypt, n_log2_efetivo)
                    break
                except MemoryError:
                    n_log2_efetivo -= 1
            if kdf_base is None:
                raise MemoryError("Memória insuficiente para derivar a chave Scrypt.")

            chave_dados = bytearray(os.urandom(32))
            trancar_buffer(chave_dados)

            tem_kf = bool(meta.get("kf_hash"))
            tem_s2 = bool(meta.get("s2_kdf") and meta.get("s2_salt"))

            flags = 0
            if tem_kf:
                flags |= FLAG_TEM_KEYFILE
                kf_bytes = bytes.fromhex(meta["kf_hash"])
                kf_buf = bytearray(kf_bytes)
                apagar_bytes_efemeros(kf_bytes)
                trancar_buffer(kf_buf)
            if tem_s2:
                flags |= FLAG_TEM_SEGUNDA_SENHA
                salt_s2 = bytes.fromhex(meta["s2_salt"])
                s2_bytes = bytes.fromhex(meta["s2_kdf"])
                s2_buf = bytearray(s2_bytes)
                apagar_bytes_efemeros(s2_bytes)
                trancar_buffer(s2_buf)
            else:
                salt_s2 = b"\x00" * TAM_SALT

            lista_keks = []
            if tem_kf and tem_s2:
                lista_keks.append(_kek_de_slot(kdf_base, b"slot-combo", kf_buf, s2_buf))
                lista_keks.append(_kek_de_slot(kdf_base, b"slot-kf", kf_buf))
                lista_keks.append(_kek_de_slot(kdf_base, b"slot-s2", s2_buf))
            elif tem_kf:
                lista_keks.append(_kek_de_slot(kdf_base, b"slot-kf", kf_buf))
            elif tem_s2:
                lista_keks.append(_kek_de_slot(kdf_base, b"slot-s2", s2_buf))
            else:
                lista_keks.append(_kek_de_slot(kdf_base, b"slot-base"))

            num_slots = len(lista_keks)
            cabecalho_base = (
                MAGIC
                + bytes([VERSAO, n_log2_efetivo, flags])
                + salt_scrypt
                + salt_s2
                + bytes([num_slots])
            )
            slots_bytes = b""
            for kek in lista_keks:
                try:
                    slots_bytes += _embrulhar_slot(kek, chave_dados, cabecalho_base)
                finally:
                    apagar_buffer(kek)

            cabecalho_completo = cabecalho_base + slots_bytes
            if COFRE_RAM.aberto:
                COFRE_RAM.definir_chave_disco(chave_dados, cabecalho_completo)

        texto_buf = serializar_conteudo_buf(itens, meta)
        cifrado = AESGCM(chave_dados).encrypt(nonce_dados, bytes(texto_buf), cabecalho_completo)
    finally:
        apagar_buffer(kdf_base)
        apagar_buffer(kf_buf)
        apagar_buffer(s2_buf)
        apagar_buffer(texto_buf)
        if not usou_cache:
            apagar_buffer(chave_dados)

    if os.path.exists(ARQUIVO):
        if manter_backup:
            with open(ARQUIVO, "rb") as f:
                escrever_seguro(BACKUP, f.read())
        else:
            apagar_seguro(BACKUP)
    escrever_seguro(ARQUIVO, cabecalho_completo + nonce_dados + cifrado)


def gravar_cofre_memoria(manter_backup=True, renovar_salt=True):
    """Grava o cofre a partir do estado em COFRE_RAM."""
    ancora = ancora_atual()
    if ancora is not None:
        COFRE_RAM.meta["ancora"] = ancora
    segredo_buf = COFRE_RAM.obter_segredo_mestre()
    chave_cache, cabecalho_cache = (None, None)
    if not renovar_salt:
        chave_cache, cabecalho_cache = COFRE_RAM.obter_chave_disco()
    itens_claros = None
    try:
        itens_claros = COFRE_RAM.exportar_itens_claros()
        salvar_cofre(segredo_buf, itens_claros, COFRE_RAM.meta, manter_backup,
                     chave_dados_cache=chave_cache, cabecalho_cache=cabecalho_cache)
        if ancora is not None:
            registrar_ancora_guarda(ancora)
    finally:
        apagar_buffer(segredo_buf)
        apagar_buffer(chave_cache)
        if itens_claros is not None:
            itens_claros.clear()


def abrir_cofre(senha_infra, caminho_keyfile=None, segunda_senha=None, sair_em_erro=True):
    """Devolve (segredo_infra_buf, itens, meta, precisa_atualizar, usou_keyfile,
    chave_dados_buf, cabecalho_v4, abriu_por_recuperacao)."""
    with open(ARQUIVO, "rb") as f:
        dados = f.read()

    if dados[:len(MAGIC)] == MAGIC:
        if len(dados) < TAM_CAB_V3 + TAM_NONCE + TAM_TAG:
            registrar("cofre_invalido")
            msg = "Cofre corrompido."
            if sair_em_erro:
                print(msg)
                raise SystemExit(1)
            raise ValueError(msg)
        versao = dados[4]
        n_log2 = dados[5]
        if versao not in VERSOES_LEITURA or not N_LOG2_MIN <= n_log2 <= N_LOG2_MAX:
            registrar("cofre_invalido")
            msg = "Cofre corrompido ou de versão desconhecida."
            if sair_em_erro:
                print(msg)
                raise SystemExit(1)
            raise ValueError(msg)
    else:
        if len(dados) < TAM_SALT + TAM_NONCE + TAM_TAG:
            registrar("cofre_invalido")
            msg = "Cofre corrompido."
            if sair_em_erro:
                print(msg)
                raise SystemExit(1)
            raise ValueError(msg)
        versao = 0
        n_log2 = N_LOG2_LEGADO

    # ---- Leitura da Versão 4 (Multi-Slot com Scrypt em todos os fatores de senha) ----
    if versao == 4:
        if len(dados) < TAM_CAB_V4_FIXO + TAM_SLOT_V4 + TAM_NONCE + TAM_TAG:
            registrar("cofre_invalido")
            raise ValueError("Cabeçalho v4 corrompido.")
        flags = dados[6]
        salt_scrypt = dados[7:23]
        salt_s2 = dados[23:39]
        num_slots = dados[39]
        tam_slots = num_slots * TAM_SLOT_V4
        fim_cab = TAM_CAB_V4_FIXO + tam_slots
        if num_slots < 1 or num_slots > 4 or len(dados) < fim_cab + TAM_NONCE + TAM_TAG:
            registrar("cofre_invalido")
            raise ValueError("Estrutura de slots do cofre corrompida.")

        cabecalho_base = dados[:TAM_CAB_V4_FIXO]
        cabecalho_completo = dados[:fim_cab]
        slots = [
            dados[TAM_CAB_V4_FIXO + i * TAM_SLOT_V4: TAM_CAB_V4_FIXO + (i + 1) * TAM_SLOT_V4]
            for i in range(num_slots)
        ]
        nonce_dados = dados[fim_cab:fim_cab + TAM_NONCE]
        cifrado = dados[fim_cab + TAM_NONCE:]

        tem_kf_cofre = bool(flags & FLAG_TEM_KEYFILE)
        tem_s2_cofre = bool(flags & FLAG_TEM_SEGUNDA_SENHA)
        s2_limpa = (segunda_senha or "").strip()

        bytes_kf = None
        caminho_kf_norm = None
        if caminho_keyfile and caminho_keyfile.strip():
            try:
                caminho_kf_norm = normalizar_caminho_keyfile(caminho_keyfile, para_criacao=False)
                bytes_kf = ler_keyfile(caminho_kf_norm)
            except FileNotFoundError:
                if s2_limpa and tem_s2_cofre:
                    bytes_kf = None
                    caminho_kf_norm = None
                else:
                    raise

        if (tem_kf_cofre or tem_s2_cofre) and bytes_kf is None and not s2_limpa:
            if tem_kf_cofre and tem_s2_cofre:
                raise ValueError(
                    "Este cofre exige o Pendrive (Keyfile) OU a sua Segunda Senha (caso esteja sem o pendrive)."
                )
            elif tem_kf_cofre:
                raise ValueError("Este cofre exige a Keyfile no pendrive para abrir.")
            else:
                raise ValueError("Este cofre exige a Segunda Senha além da Senha Infra.")

        segredo_infra_buf = _derivar_segredo_infra_v4(senha_infra)
        kdf_base = None
        s2_buf = None
        chave_dados = None
        abriu_recuperacao = False

        try:
            kdf_base = gerar_chave_scrypt(segredo_infra_buf, salt_scrypt, n_log2)
            if s2_limpa and tem_s2_cofre:
                s2_buf = _derivar_segunda_senha_scrypt(segredo_infra_buf, s2_limpa, salt_s2, n_log2)

            candidatos_kek = []
            if bytes_kf is not None and s2_limpa:
                if s2_buf is not None:
                    candidatos_kek.append((_kek_de_slot(kdf_base, b"slot-combo", bytes_kf, s2_buf), False))
                else:
                    candidatos_kek.append((_kek_de_slot(kdf_base, b"slot-invalido", bytes_kf), False))
            elif bytes_kf is not None:
                candidatos_kek.append((_kek_de_slot(kdf_base, b"slot-kf", bytes_kf), False))
            elif s2_buf is not None:
                candidatos_kek.append((_kek_de_slot(kdf_base, b"slot-s2", s2_buf), tem_kf_cofre))
            else:
                candidatos_kek.append((_kek_de_slot(kdf_base, b"slot-base"), False))

            for kek_cand, eh_rec in candidatos_kek:
                try:
                    for slot_bytes in slots:
                        try:
                            chave_dados = _desembrulhar_slot(kek_cand, slot_bytes, cabecalho_base)
                            abriu_recuperacao = eh_rec
                            break
                        except InvalidTag:
                            continue
                    if chave_dados is not None:
                        break
                finally:
                    apagar_buffer(kek_cand)

            if chave_dados is None:
                raise InvalidTag()

            texto = AESGCM(chave_dados).decrypt(nonce_dados, cifrado, cabecalho_completo)
        except InvalidTag:
            apagar_buffer(chave_dados)
            apagar_buffer(segredo_infra_buf)
            espera = registrar_erro()
            if sair_em_erro:
                raise SystemExit(1)
            raise InvalidTag(
                f"Senha Infra, Segunda Senha ou Keyfile incorretos. Aguarde {espera} s."
            )
        finally:
            apagar_buffer(kdf_base)
            apagar_buffer(bytes_kf)
            apagar_buffer(s2_buf)

        zerar_erros()
        try:
            conteudo = json.loads(texto.decode("utf-8"))
        finally:
            apagar_bytes_efemeros(texto)

        itens, meta = conteudo["itens"], conteudo["meta"]
        # Migração automática se o formato antigo de s2_hash (PBKDF2) estiver presente
        precisa_atualizar = (n_log2 < N_LOG2_ATUAL) or ("s2_hash" in meta and "s2_kdf" not in meta)
        if precisa_atualizar:
            apagar_buffer(chave_dados)
            chave_dados = None
        return (segredo_infra_buf, itens, meta, precisa_atualizar,
                bool(meta.get("kf_hash")), chave_dados, cabecalho_completo,
                abriu_recuperacao)

    # ---- Leitura e Migração Automática das Versões 0, 1, 2 e 3 ----
    if versao >= 1:
        associado = dados[:TAM_CAB_V3]
        salt = dados[6:TAM_CAB_V3]
        nonce = dados[TAM_CAB_V3:TAM_CAB_V3 + TAM_NONCE]
        cifrado = dados[TAM_CAB_V3 + TAM_NONCE:]
    else:
        associado = None
        salt = dados[:TAM_SALT]
        nonce = dados[TAM_SALT:TAM_SALT + TAM_NONCE]
        cifrado = dados[TAM_SALT + TAM_NONCE:]

    bytes_kf = None
    caminho_kf_norm = None
    if caminho_keyfile and caminho_keyfile.strip():
        caminho_kf_norm = normalizar_caminho_keyfile(caminho_keyfile, para_criacao=False)
        bytes_kf = ler_keyfile(caminho_kf_norm)

    segredo_v3_buf = _combinar_credencial_v3(senha_infra, bytes_kf)
    chave_legado = None
    texto = None
    try:
        if versao >= 3:
            chave_legado = gerar_chave_scrypt(segredo_v3_buf, salt, n_log2)
        else:
            chave_legado = gerar_chave_legado(senha_infra, salt, n_log2)
        texto = AESGCM(chave_legado).decrypt(nonce, cifrado, associado)
    except InvalidTag:
        apagar_buffer(bytes_kf)
        apagar_buffer(segredo_v3_buf)
        apagar_buffer(chave_legado)
        espera = registrar_erro()
        if sair_em_erro:
            raise SystemExit(1)
        raise InvalidTag(f"Senha Infra ou Keyfile incorretos. Aguarde {espera} s.")
    finally:
        apagar_buffer(segredo_v3_buf)
        apagar_buffer(chave_legado)

    zerar_erros()
    try:
        conteudo = json.loads(texto.decode("utf-8"))
    finally:
        if texto is not None:
            apagar_bytes_efemeros(texto)

    if versao >= 2:
        itens, meta = conteudo["itens"], conteudo["meta"]
    else:
        itens, meta = conteudo, {}

    if bytes_kf is not None:
        meta["kf_hash"] = bytes(bytes_kf).hex()
        meta["usa_keyfile"] = True
    apagar_buffer(bytes_kf)

    segredo_infra_buf = _derivar_segredo_infra_v4(senha_infra)
    return (segredo_infra_buf, itens, meta, True,
            bool(caminho_kf_norm), None, None, False)


# ----------------------------------------------- geração e filtro de senhas

PADROES_FRACOS = ("password", "senha", "admin", "qwerty", "letmein", "iloveyou",
                  "welcome", "abc123", "mudar", "brasil", "123456")
LINHAS_TECLADO = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "0987654321")


def _sem_padroes(senha):
    t = senha.lower()
    for padrao in PADROES_FRACOS:
        t = t.replace(padrao, "")
    marcado = [False] * len(t)
    i = 0
    while i < len(t) - 3:
        passo = ord(t[i + 1]) - ord(t[i])
        if passo in (1, -1):
            j = i + 1
            while j < len(t) and ord(t[j]) - ord(t[j - 1]) == passo:
                j += 1
            if j - i >= 4:
                for k in range(i, j):
                    marcado[k] = True
                i = j
                continue
        i += 1
    for linha in LINHAS_TECLADO:
        for tam in range(len(linha), 3, -1):
            for ini in range(len(linha) - tam + 1):
                trecho = linha[ini:ini + tam]
                pos = t.find(trecho)
                while pos != -1:
                    for k in range(pos, pos + tam):
                        marcado[k] = True
                    pos = t.find(trecho, pos + 1)
    return "".join(c for c, m in zip(t, marcado) if not m)


def senha_mestra_aceitavel(senha):
    if len(senha) < TAM_MIN_MESTRA:
        return False, f"use pelo menos {TAM_MIN_MESTRA} caracteres."
    if len(set(senha)) < 6:
        return False, "caracteres repetidos demais."
    resto = _sem_padroes(senha)
    if len(resto) < 8:
        return False, "baseada em padrões comuns (sequências, teclado ou palavras óbvias)."
    pool = 0
    if any(c.islower() for c in senha):
        pool += 26
    if any(c.isupper() for c in senha):
        pool += 26
    if any(c.isdigit() for c in senha):
        pool += 10
    if any(not c.isalnum() for c in senha):
        pool += 33
    distintos = len(set(resto))
    efetivo = distintos + 0.3 * (len(resto) - distintos)
    if efetivo * math.log2(max(pool, 2)) < MIN_BITS_SENHA:
        return False, ("previsível demais. Use uma frase longa com várias palavras "
                       "ou gere uma frase aleatória.")
    return True, ""


def segunda_senha_aceitavel(segunda_senha, senha_infra=""):
    """Exige o mesmo padrão rigoroso de entropia da Senha Infra principal para que
    o slot de recuperação nunca seja um elo fraco contra força bruta."""
    aceita, motivo = senha_mestra_aceitavel(segunda_senha)
    if not aceita:
        return False, f"Segunda Senha fraca: {motivo}"
    if senha_infra and secrets.compare_digest(segunda_senha.strip().encode("utf-8"),
                                              senha_infra.strip().encode("utf-8")):
        return False, "a Segunda Senha deve ser diferente da Senha Infra principal."
    return True, ""


def configurar_fatores_meta(meta, segredo_infra_buf, bytes_kf=None, segunda_senha=None):
    """Atualiza os hashes de Keyfile e a chave derivada Scrypt da Segunda Senha
    dentro do dicionário cifrado meta."""
    if bytes_kf is not None:
        meta["kf_hash"] = bytes(bytes_kf).hex()
        meta["usa_keyfile"] = True
    else:
        meta.pop("kf_hash", None)
        meta["usa_keyfile"] = False

    meta.pop("s2_hash", None)
    s2_limpa = (segunda_senha or "").strip()
    if s2_limpa:
        salt_s2 = os.urandom(TAM_SALT)
        s2_buf = _derivar_segunda_senha_scrypt(segredo_infra_buf, s2_limpa, salt_s2, N_LOG2_ATUAL)
        try:
            meta["s2_salt"] = salt_s2.hex()
            meta["s2_kdf"] = bytes(s2_buf).hex()
        finally:
            apagar_buffer(s2_buf)
    else:
        meta.pop("s2_salt", None)
        meta.pop("s2_kdf", None)


def verificar_segundo_fator_atual(segredo_infra_buf, meta, caminho_kf_tentativa=None, s2_tentativa=None):
    """Para autorizar alteração/remoção de credenciais quando o cofre já possui
    Keyfile ou Segunda Senha, exige que a Keyfile atual esteja conectada OU que
    a Segunda Senha atual seja confirmada."""
    tem_kf = bool(meta.get("kf_hash"))
    tem_s2 = bool(meta.get("s2_kdf") and meta.get("s2_salt"))
    if not tem_kf and not tem_s2:
        return True, ""

    # 1. Tenta validar pela Keyfile conectada
    if tem_kf:
        caminhos_teste = []
        if caminho_kf_tentativa:
            caminhos_teste.append(caminho_kf_tentativa)
        if COFRE_RAM.caminho_keyfile():
            caminhos_teste.append(COFRE_RAM.caminho_keyfile())
        kf_auto = encontrar_keyfile_em_pendrive()
        if kf_auto:
            caminhos_teste.append(kf_auto)

        for cam in caminhos_teste:
            try:
                kf_buf = ler_keyfile(cam)
                try:
                    if secrets.compare_digest(bytes(kf_buf).hex(), str(meta["kf_hash"])):
                        return True, ""
                finally:
                    apagar_buffer(kf_buf)
            except Exception:
                continue

    # 2. Tenta validar pela Segunda Senha atual (caso o pendrive não esteja conectado)
    s2_limpa = (s2_tentativa or "").strip()
    if tem_s2 and s2_limpa:
        try:
            salt_s2 = bytes.fromhex(meta["s2_salt"])
            s2_buf = _derivar_segunda_senha_scrypt(segredo_infra_buf, s2_limpa, salt_s2, N_LOG2_ATUAL)
            try:
                if secrets.compare_digest(bytes(s2_buf).hex(), str(meta["s2_kdf"])):
                    return True, ""
            finally:
                apagar_buffer(s2_buf)
        except Exception:
            pass

    if tem_kf and tem_s2:
        return False, (
            "Para alterar ou remover a Keyfile/Senha, mantenha o pendrive com a Keyfile atual "
            "conectado OU informe a Segunda Senha atual."
        )
    if tem_kf:
        return False, "Conecte o pendrive com a Keyfile atual para autorizar esta alteração."
    return False, "Informe a Segunda Senha atual para autorizar esta alteração."


def gerar_senha_aleatoria(tamanho=20):
    if tamanho < 16:
        raise ValueError("O tamanho mínimo é 16 caracteres.")
    alfabeto = string.ascii_letters + string.digits + SIMBOLOS
    while True:
        senha = "".join(secrets.choice(alfabeto) for _ in range(tamanho))
        if (any(c.islower() for c in senha)
                and any(c.isupper() for c in senha)
                and any(c.isdigit() for c in senha)
                and any(c in SIMBOLOS for c in senha)):
            return senha, tamanho * math.log2(len(alfabeto))


def gerar_frase_palavras(incluir_numero=True):
    if not PALAVRAS:
        raise RuntimeError("A lista interna de palavras falhou na verificação de integridade.")
    palavras = [secrets.choice(PALAVRAS) for _ in range(PALAVRAS_FRASE)]
    bits = PALAVRAS_FRASE * math.log2(len(PALAVRAS))
    if incluir_numero:
        numero = str(secrets.randbelow(100))
        palavras.insert(secrets.randbelow(len(palavras)), numero)
        bits += math.log2(100) + math.log2(PALAVRAS_FRASE + 1)
    return "-".join(palavras), bits


# ------------------------------------------------------- sessão e modo CLI

SESSAO = {"ultima": time.time(), "bloqueado": False, "ativa": False}


def tocar():
    SESSAO["ultima"] = time.time()


def limpar_tela():
    if not sys.stdout.isatty():
        return
    if os.name == "nt":
        os.system("cls")
    print("\033[3J\033[2J\033[H", end="", flush=True)


def bloquear_sessao_imediato(silencioso=False):
    if SESSAO["bloqueado"]:
        return
    SESSAO["bloqueado"] = True
    try:
        if COFRE_RAM.aberto:
            registrar("sessao_bloqueada")
            gravar_cofre_memoria(manter_backup=True, renovar_salt=False)
    except Exception:
        pass
    finally:
        COFRE_RAM.limpar()
        limpar_chave_log()
        if not silencioso:
            limpar_tela()
            print("Cofre bloqueado por inatividade (dados removidos da RAM). "
                  "Pressione Enter para desbloquear.")


def vigia():
    while SESSAO["ativa"]:
        time.sleep(1)
        if (not SESSAO["bloqueado"]
                and time.time() - SESSAO["ultima"] > TEMPO_INATIVO):
            bloquear_sessao_imediato()


def entrada(texto):
    valor = input(texto)
    if SESSAO["bloqueado"]:
        raise Bloqueio()
    tocar()
    return valor


def entrada_oculta(texto):
    valor = getpass.getpass(texto)
    if SESSAO["bloqueado"]:
        raise Bloqueio()
    tocar()
    return valor


def iguais(a, b):
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def reautenticar(caminho_keyfile_padrao=None):
    for _ in range(3):
        verificar_bloqueio()
        tentativa = getpass.getpass("Senha infra para desbloquear: ")
        caminho_kf = caminho_keyfile_padrao
        if caminho_kf is None:
            kf_in = input("Caminho do Keyfile (Enter se não usar): ").strip()
            caminho_kf = kf_in if kf_in else None
        s2_in = getpass.getpass("Segunda Senha (Enter se não usar): ").strip() or None
        try:
            (segredo_buf, itens, meta, _,
             usou_kf, chave_dados, cab_v4, abriu_rec) = abrir_cofre(
                tentativa, caminho_kf, segunda_senha=s2_in, sair_em_erro=False
            )
            del tentativa, s2_in
            definir_chave_log(meta)
            COFRE_RAM.inicializar(
                segredo_buf, itens, meta,
                usou_keyfile=usou_kf,
                caminho_keyfile=caminho_kf,
                chave_disco_buf=chave_dados,
                cabecalho_cache=cab_v4,
                abriu_por_recuperacao=abriu_rec,
            )
            apagar_buffer(chave_dados)
            apagar_buffer(segredo_buf)
            itens.clear()
            SESSAO["bloqueado"] = False
            tocar()
            registrar("sessao_desbloqueada")
            gravar_cofre_memoria(manter_backup=True, renovar_salt=False)
            return
        except InvalidTag:
            verificar_bloqueio()
        except Exception as e:
            print(f"Falha ao desbloquear: {e}")
    limpar_tela()
    registrar("desbloqueio_falhou")
    raise SystemExit(1)


def esperar_enter(segundos):
    if os.name == "nt":
        import msvcrt
        fim = time.time() + segundos
        while time.time() < fim:
            if msvcrt.kbhit():
                msvcrt.getwch()
                return
            time.sleep(0.1)
    else:
        import select
        pronto, _, _ = select.select([sys.stdin], [], [], segundos)
        if pronto:
            sys.stdin.readline()


def mostrar_temporario(texto, segundos=TEMPO_TELA):
    tocar()
    print(texto)
    print(f"(some da tela em {segundos} s; Enter para limpar agora)")
    esperar_enter(segundos)
    limpar_tela()
    tocar()


def oferecer_frase(ler, perguntar):
    if not PALAVRAS:
        return None
    resposta = perguntar(f"Gerar uma frase aleatória de {PALAVRAS_FRASE} palavras "
                         "como senha? (s/n): ")
    if resposta.strip().lower() != "s":
        return None
    for _ in range(3):
        frase, bits = gerar_frase_palavras(incluir_numero=False)
        mostrar_temporario(f"Sua frase: {frase}\nForça estimada: ~{int(bits)} bits\n"
                           "Anote-a em lugar seguro; a tela será limpa e você vai "
                           "digitá-la para confirmar.", 60)
        if iguais(ler("Digite a frase para confirmar: "), frase):
            return frase
        print("Não confere. Vou gerar outra.")
    print("Vamos pela senha digitada.")
    return None


def pedir_nova_senha(texto1, texto2, ler, perguntar=input):
    frase = oferecer_frase(ler, perguntar)
    if frase is not None:
        return frase
    while True:
        senha = ler(texto1)
        if len(senha) < TAM_MIN_MESTRA:
            print(f"Use pelo menos {TAM_MIN_MESTRA} caracteres "
                  "(uma frase longa funciona bem).")
            continue
        aceita, motivo = senha_mestra_aceitavel(senha)
        if not aceita:
            print(f"Senha fraca: {motivo}")
            continue
        if not iguais(senha, ler(texto2)):
            print("As senhas não são iguais. Tente de novo.")
            continue
        return senha


def perguntar_keyfile_novo(perguntar=input):
    resp = perguntar("Deseja associar um Keyfile no pendrive? (s/n): ")
    if resp.strip().lower() != "s":
        return None, None
    pendrives = detectar_pendrives()
    sugestao = os.path.join(pendrives[0], NOME_PADRAO_KEYFILE) if pendrives else ""
    prompt_kf = f"Caminho do Keyfile [{sugestao}]: " if sugestao else "Caminho do Keyfile: "
    caminho = perguntar(prompt_kf).strip() or sugestao
    if not caminho:
        return None, None
    caminho_exp = normalizar_caminho_keyfile(caminho, para_criacao=True)
    if os.path.isfile(caminho_exp):
        usar = perguntar(f"O arquivo '{caminho_exp}' já existe. Usar este arquivo existente? (s/n): ")
        if usar.strip().lower() != "s":
            return None, None
    else:
        caminho_exp = criar_keyfile(caminho_exp)
        print(f"Novo Keyfile de {TAM_KEYFILE} bytes gerado em: {caminho_exp}")
    return ler_keyfile(caminho_exp), caminho_exp


def perguntar_segunda_senha_cli(senha_infra, ler=getpass.getpass, perguntar=input):
    resp = perguntar(
        "Deseja definir uma Segunda Senha (para usar com a Keyfile e recuperar sem o pendrive)? (s/n): "
    )
    if resp.strip().lower() != "s":
        return None
    while True:
        s2 = ler("Digite a Segunda Senha (mín. 12 caracteres): ").strip()
        ok, motivo = segunda_senha_aceitavel(s2, senha_infra)
        if not ok:
            print(motivo)
            continue
        if not iguais(s2, ler("Confirme a Segunda Senha: ").strip()):
            print("A confirmação da Segunda Senha não confere.")
            continue
        return s2


def criar_cofre_novo():
    print("Nenhum cofre encontrado. Vamos criar um novo.")
    senha = pedir_nova_senha("Crie sua senha infra: ",
                             "Repita a senha infra: ", getpass.getpass)
    bytes_kf, caminho_kf = perguntar_keyfile_novo(input)
    s2 = perguntar_segunda_senha_cli(senha, getpass.getpass, input)

    segredo_buf = _derivar_segredo_infra_v4(senha)
    del senha

    meta = {"chave_log": secrets.token_hex(32)}
    if HASH_PALAVRAS:
        meta["hash_palavras"] = HASH_PALAVRAS
    configurar_fatores_meta(meta, segredo_buf, bytes_kf=bytes_kf, segunda_senha=s2)
    apagar_buffer(bytes_kf)
    del s2

    definir_chave_log(meta)
    COFRE_RAM.inicializar(segredo_buf, {}, meta,
                          usou_keyfile=bool(caminho_kf),
                          caminho_keyfile=caminho_kf)
    apagar_buffer(segredo_buf)
    registrar("cofre_criado")
    gravar_cofre_memoria(manter_backup=False, renovar_salt=True)
    print("Cofre criado!")


def gerar_senha():
    print("\n1 - Senha aleatória  2 - Frase com palavras")
    tipo = entrada("Escolha: ")
    if tipo == "1":
        try:
            tamanho = int(entrada("Tamanho (mínimo 16): "))
        except ValueError:
            print("Número inválido.")
            return None
        if tamanho < 16:
            print("Use pelo menos 16.")
            return None
        return gerar_senha_aleatoria(tamanho)
    elif tipo == "2":
        if not PALAVRAS:
            print("Coloque os arquivos de palavras na pasta listas.")
            return None
        if not validar_integridade_palavras(COFRE_RAM.meta):
            print("Operação cancelada por divergência na lista de palavras.")
            return None
        if len(PALAVRAS) < MIN_PALAVRAS_IDEAL:
            print(f"Aviso: a lista tem só {len(PALAVRAS)} palavras; "
                  f"o ideal é {MIN_PALAVRAS_IDEAL} ou mais.")
        return gerar_frase_palavras(incluir_numero=True)
    print("Opção inválida.")
    return None


def trocar_senha_mestra():
    confirmar = entrada_oculta("Digite a senha infra atual: ")
    candidato_buf = _derivar_segredo_infra_v4(confirmar)

    atual_buf = COFRE_RAM.obter_segredo_mestre()
    try:
        confere = secrets.compare_digest(candidato_buf, atual_buf)
        if confere and (COFRE_RAM.usou_keyfile() or COFRE_RAM.tem_segunda_senha()):
            s2_atual = None
            ok_2fa, _ = verificar_segundo_fator_atual(atual_buf, COFRE_RAM.meta)
            if not ok_2fa:
                s2_atual = entrada_oculta("Confirme a Segunda Senha atual (pois o pendrive atual não está presente): ")
                ok_2fa, msg_2fa = verificar_segundo_fator_atual(
                    atual_buf, COFRE_RAM.meta, s2_tentativa=s2_atual
                )
                del s2_atual
                if not ok_2fa:
                    print(msg_2fa)
                    del confirmar
                    return
    finally:
        apagar_buffer(candidato_buf)
        apagar_buffer(atual_buf)

    if not confere:
        del confirmar
        print("Senha infra atual incorreta.")
        return

    if not validar_integridade_palavras(COFRE_RAM.meta):
        del confirmar
        return

    manter = entrada("Manter a mesma senha infra e alterar apenas Keyfile / Segunda Senha? (s/n): ").strip().lower()
    if manter == "s":
        nova = confirmar
    else:
        nova = pedir_nova_senha("Nova senha infra: ",
                                "Repita a nova senha: ", entrada_oculta, entrada)
    del confirmar

    bytes_kf_novo, caminho_kf_novo = perguntar_keyfile_novo(entrada)
    s2_nova = perguntar_segunda_senha_cli(nova, entrada_oculta, entrada)
    novo_segredo_buf = _derivar_segredo_infra_v4(nova)
    del nova

    itens_claros = COFRE_RAM.exportar_itens_claros()
    try:
        configurar_fatores_meta(COFRE_RAM.meta, novo_segredo_buf, bytes_kf=bytes_kf_novo, segunda_senha=s2_nova)
        COFRE_RAM.inicializar(novo_segredo_buf, itens_claros, COFRE_RAM.meta,
                              usou_keyfile=bool(caminho_kf_novo),
                              caminho_keyfile=caminho_kf_novo)
    finally:
        apagar_buffer(bytes_kf_novo)
        apagar_buffer(novo_segredo_buf)
        del s2_nova
        itens_claros.clear()

    registrar("senha_trocada")
    gravar_cofre_memoria(manter_backup=False, renovar_salt=True)
    print("Credencial, Keyfile e Segunda Senha atualizadas com sucesso.")


def main_cli():
    proteger_processo()
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Execute em um terminal de verdade. Em consoles de algumas IDEs a "
              "senha aparece enquanto você digita.")
        raise SystemExit(1)
    if os.name == "nt":
        os.system("")

    if os.path.exists(ARQUIVO):
        verificar_bloqueio()
        senha = getpass.getpass("Senha infra: ")
        kf_auto = encontrar_keyfile_em_pendrive()
        prompt_kf = (f"Caminho do Keyfile (Enter p/ '{kf_auto}' ou 'nenhum' se sem pendrive): "
                     if kf_auto else "Caminho do Keyfile (Enter se não usar ou sem pendrive): ")
        kf_in = input(prompt_kf).strip()
        if kf_in.lower() == "nenhum":
            caminho_kf = None
        else:
            caminho_kf = kf_in if kf_in else kf_auto
        s2_in = getpass.getpass("Segunda Senha (Enter se não usar): ").strip() or None

        (segredo_buf, itens, meta, atualizar,
         usou_kf, chave_dados, cab_v4, abriu_rec) = abrir_cofre(
            senha, caminho_kf, segunda_senha=s2_in
        )
        del senha, s2_in

        if "chave_log" not in meta:
            meta["chave_log"] = secrets.token_hex(32)
            atualizar = True
        if HASH_PALAVRAS and "hash_palavras" not in meta:
            meta["hash_palavras"] = HASH_PALAVRAS
            atualizar = True

        definir_chave_log(meta)
        ok_rb, msg_rb = verificar_rollback_so(meta)
        if not ok_rb:
            registrar("alerta_rollback")
            print(f"ALERTA CRÍTICO DE SEGURANÇA: {msg_rb}")

        COFRE_RAM.inicializar(
            segredo_buf, itens, meta,
            usou_keyfile=usou_kf,
            caminho_keyfile=caminho_kf,
            chave_disco_buf=chave_dados,
            cabecalho_cache=cab_v4,
            abriu_por_recuperacao=abriu_rec,
        )
        apagar_buffer(chave_dados)
        apagar_buffer(segredo_buf)
        itens.clear()

        registrar("abertura_recuperacao" if abriu_rec else "abertura_ok")
        if abriu_rec:
            print("AVISO: Cofre aberto usando a Segunda Senha (sem o pendrive da Keyfile).")
        if atualizar:
            registrar("cofre_migrado")
            gravar_cofre_memoria(manter_backup=True, renovar_salt=True)
            print("Cofre atualizado para o formato mais recente.")
        else:
            gravar_cofre_memoria(manter_backup=True, renovar_salt=False)
        validar_integridade_palavras(COFRE_RAM.meta)
    else:
        criar_cofre_novo()

    SESSAO["ativa"] = True
    SESSAO["bloqueado"] = False
    tocar()
    threading.Thread(target=vigia, daemon=True).start()

    try:
        while True:
            try:
                print("\n1 - Adicionar  2 - Ver  3 - Listar  4 - Senha Infra/Keyfile/2ª Senha  "
                      "5 - Gerar senha  6 - Apagar  7 - Sair  8 - Auditoria")
                opcao = entrada("Escolha: ")
                if opcao == "1":
                    nome = entrada("Nome do item: ").strip()
                    if not nome:
                        print("O nome não pode ser vazio.")
                        continue
                    existia = COFRE_RAM.contem(nome)
                    if existia:
                        substituir = entrada(f"'{nome}' já existe. Substituir? Digite sim: ")
                        if substituir.lower() != "sim":
                            print("Cancelado.")
                            continue
                    segredo = entrada_oculta("Segredo: ")
                    COFRE_RAM.definir_item(nome, segredo)
                    del segredo
                    registrar("item_sobrescrito" if existia else "item_adicionado", nome)
                    gravar_cofre_memoria(manter_backup=not existia, renovar_salt=True)
                    print("Salvo.")
                elif opcao == "2":
                    nome = entrada("Nome do item: ").strip()
                    if COFRE_RAM.contem(nome):
                        registrar("item_visto", nome)
                        gravar_cofre_memoria(manter_backup=True, renovar_salt=False)
                        segredo_temp = COFRE_RAM.obter_item(nome)
                        try:
                            mostrar_temporario(segredo_temp)
                        finally:
                            del segredo_temp
                    else:
                        print("Não encontrado.")
                elif opcao == "3":
                    print(COFRE_RAM.nomes())
                elif opcao == "4":
                    trocar_senha_mestra()
                elif opcao == "5":
                    resultado = gerar_senha()
                    if resultado:
                        nova, bits = resultado
                        registrar("senha_gerada")
                        gravar_cofre_memoria(manter_backup=True, renovar_salt=False)
                        mostrar_temporario(
                            f"Senha gerada: {nova}\nForça estimada: ~{int(bits)} bits")
                        del nova
                elif opcao == "6":
                    nome = entrada("Nome do item a apagar: ").strip()
                    if COFRE_RAM.contem(nome):
                        confirmar = entrada(f"Apagar '{nome}' de verdade? Digite sim: ")
                        if confirmar.lower() == "sim":
                            COFRE_RAM.apagar_item(nome)
                            registrar("item_apagado", nome)
                            gravar_cofre_memoria(manter_backup=False, renovar_salt=True)
                            print("Item apagado. O backup anterior foi destruído.")
                        else:
                            print("Cancelado.")
                    else:
                        print("Item não encontrado.")
                elif opcao == "7":
                    break
                elif opcao == "8":
                    registrar("auditoria_consultada")
                    gravar_cofre_memoria(manter_backup=True, renovar_salt=False)
                    mostrar_auditoria(COFRE_RAM.nomes(), COFRE_RAM.meta)
            except Bloqueio:
                reautenticar(COFRE_RAM.caminho_keyfile())
    finally:
        SESSAO["ativa"] = False
        if COFRE_RAM.aberto and not SESSAO["bloqueado"]:
            registrar("saida")
            try:
                gravar_cofre_memoria(manter_backup=True, renovar_salt=False)
            except Exception:
                pass
        COFRE_RAM.limpar()
        limpar_chave_log()
        limpar_tela()


# ---------------------- proteções nativas para interface gráfica (GUI)

def _obter_hwnd_janela(janela_tk):
    """Obtém o identificador nativo (HWND) da janela principal de topo no Windows."""
    janela_tk.update_idletasks()
    wid = janela_tk.winfo_id()
    user32 = ctypes.windll.user32
    hwnd = user32.GetParent(wid)
    if not hwnd:
        hwnd = user32.GetAncestor(wid, 2)  # GA_ROOT = 2
    if not hwnd:
        hwnd = wid
    return hwnd


def aplicar_barra_titulo_preta(janela_tk):
    """Deixa a barra de título superior da janela preta (#000000) com letras
    brancas (#FFFFFF) no Windows 10/11 (via DWM API / UxTheme) e no Linux (X11)."""
    if os.name == "nt":
        try:
            hwnd = _obter_hwnd_janela(janela_tk)
            dwmapi = ctypes.windll.dwmapi
            user32 = ctypes.windll.user32

            # Ativa modo escuro nativo do processo/janela no uxtheme.dll (Windows 10/11)
            try:
                uxtheme = ctypes.windll.uxtheme
                uxtheme[135](2)          # SetPreferredAppMode(ForceDark = 2)
                uxtheme[133](hwnd, 1)    # AllowDarkModeForWindow(hwnd, True)
            except Exception:
                pass

            # DWMWA_USE_IMMERSIVE_DARK_MODE (20 no Win10 2004+/Win11, 19 em builds anteriores)
            modo_escuro = ctypes.c_int(1)
            for atributo in (20, 19):
                dwmapi.DwmSetWindowAttribute(
                    hwnd,
                    atributo,
                    ctypes.byref(modo_escuro),
                    ctypes.sizeof(modo_escuro),
                )

            # Windows 11+: força cor exata da barra preta (0x00000000) e texto branco (0x00FFFFFF)
            cor_barra_preta = ctypes.c_int(0x00000000)   # COLORREF BGR: #000000 (preto)
            cor_texto_branco = ctypes.c_int(0x00FFFFFF)  # COLORREF BGR: #FFFFFF (branco)
            cor_borda_escura = ctypes.c_int(0x00211712)  # COLORREF BGR: borda grafite escura
            dwmapi.DwmSetWindowAttribute(
                hwnd, 35, ctypes.byref(cor_barra_preta), ctypes.sizeof(cor_barra_preta)
            )  # DWMWA_CAPTION_COLOR = 35
            dwmapi.DwmSetWindowAttribute(
                hwnd, 36, ctypes.byref(cor_texto_branco), ctypes.sizeof(cor_texto_branco)
            )  # DWMWA_TEXT_COLOR = 36
            dwmapi.DwmSetWindowAttribute(
                hwnd, 34, ctypes.byref(cor_borda_escura), ctypes.sizeof(cor_borda_escura)
            )  # DWMWA_BORDER_COLOR = 34

            # Força o Windows 10/11 a redesenhar imediatamente a barra de título em preto
            user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x0037)
            user32.SendMessageW(hwnd, 0x0086, 0, 0)  # WM_NCACTIVATE (inativo)
            user32.SendMessageW(hwnd, 0x0086, 1, 0)  # WM_NCACTIVATE (ativo)
            return True
        except Exception:
            return False
    else:
        # No Linux (X11 / Cinnamon / GNOME / XFCE), solicita decoração de barra de título escura
        try:
            janela_tk.update_idletasks()
            wid = hex(janela_tk.winfo_id())
            subprocess.run(
                ["xprop", "-id", wid, "-f", "_GTK_THEME_VARIANT", "8u", "-set", "_GTK_THEME_VARIANT", "dark"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return True
        except Exception:
            return False


def proteger_janela_captura(janela_tk):
    if os.name != "nt":
        return False
    try:
        hwnd = _obter_hwnd_janela(janela_tk)
        ok = ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x00000011)
        if not ok:
            ok = ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x00000001)
        return bool(ok)
    except Exception:
        return False


def copiar_clipboard_protegido(janela_tk, texto_secreto):
    if os.name == "nt":
        try:
            from ctypes import wintypes
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32

            user32.OpenClipboard.argtypes = [wintypes.HWND]
            user32.OpenClipboard.restype = wintypes.BOOL
            user32.EmptyClipboard.restype = wintypes.BOOL
            user32.CloseClipboard.restype = wintypes.BOOL
            user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
            user32.SetClipboardData.restype = wintypes.HANDLE
            user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
            user32.RegisterClipboardFormatW.restype = wintypes.UINT

            kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
            kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
            kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
            kernel32.GlobalLock.restype = ctypes.c_void_p
            kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
            kernel32.GlobalUnlock.restype = wintypes.BOOL

            GMEM_MOVEABLE = 0x0002
            CF_UNICODETEXT = 13

            if user32.OpenClipboard(janela_tk.winfo_id()):
                try:
                    user32.EmptyClipboard()
                    raw = texto_secreto.encode("utf-16-le") + b"\x00\x00"
                    h_mem = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(raw))
                    if h_mem:
                        ptr = kernel32.GlobalLock(h_mem)
                        if ptr:
                            ctypes.memmove(ptr, raw, len(raw))
                            kernel32.GlobalUnlock(h_mem)
                            user32.SetClipboardData(CF_UNICODETEXT, h_mem)
                    apagar_bytes_efemeros(raw)

                    for fmt_nome in (
                        "ExcludeClipboardContentFromMonitorProcessing",
                        "CanIncludeInHistory",
                        "CanUploadToCloudClipboard",
                    ):
                        fmt_id = user32.RegisterClipboardFormatW(fmt_nome)
                        if fmt_id:
                            h_flag = kernel32.GlobalAlloc(GMEM_MOVEABLE, 4)
                            if h_flag:
                                p_flag = kernel32.GlobalLock(h_flag)
                                if p_flag:
                                    ctypes.memset(p_flag, 0, 4)
                                    kernel32.GlobalUnlock(h_flag)
                                    user32.SetClipboardData(fmt_id, h_flag)
                    return
                finally:
                    user32.CloseClipboard()
        except Exception:
            pass
    janela_tk.clipboard_clear()
    janela_tk.clipboard_append(texto_secreto)
    janela_tk.update_idletasks()


def limpar_clipboard_seguro(janela_tk):
    try:
        janela_tk.clipboard_clear()
        janela_tk.clipboard_append("")
        janela_tk.clipboard_clear()
        janela_tk.update_idletasks()
    except Exception:
        pass


def limpar_entry_seguro(entry_widget):
    try:
        entry_widget.delete(0, "end")
        entry_widget.insert(0, "0" * 64)
        entry_widget.delete(0, "end")
    except Exception:
        pass


# -------------------------------------------- interface gráfica (Tkinter)

COR_FUNDO = "#0B0E14"         # Grafite abissal principal
COR_PAINEL = "#121721"        # Superfície de cartões/painéis
COR_CAMPO = "#0D1117"         # Fundo de campos de entrada e listas
COR_BORDA = "#262F3F"         # Linhas divisórias e bordas técnicas
COR_TEXTO = "#E6EDF3"         # Texto primário de alto contraste
COR_SUBTEXTO = "#8B949E"      # Rótulos técnicos e metadados
COR_DESTAQUE = "#1F6FEB"      # Azul aço para foco e ação principal
COR_VERDE = "#238636"         # Verde segurança (íntegro / confirmado)
COR_VERDE_TEXTO = "#3FB950"   # Texto de status seguro
COR_ALERTA = "#D29922"        # Âmbar para avisos e temporizadores
COR_PERIGO = "#DA3633"        # Vermelho contido para exclusão / adulteração
COR_BOTAO_SEC = "#1C2331"     # Botões secundários


class NullvoutsGUI:
    """Interface gráfica escura de segurança para o Nullvouts."""

    def __init__(self, raiz):
        import tkinter as tk
        from tkinter import filedialog, messagebox

        self.tk = tk
        self.filedialog = filedialog
        self.messagebox = messagebox
        self.raiz = raiz
        self.raiz.title("Nullvouts")
        self.raiz.geometry("960x680")
        self.raiz.minsize(880, 620)
        self.raiz.configure(bg=COR_FUNDO)
        aplicar_barra_titulo_preta(self.raiz)
        self._carregar_icone()

        self.fonte_ui = ("Segoe UI" if os.name == "nt" else "DejaVu Sans", 10)
        self.fonte_bold = ("Segoe UI" if os.name == "nt" else "DejaVu Sans", 10, "bold")
        self.fonte_titulo = ("Segoe UI" if os.name == "nt" else "DejaVu Sans", 14, "bold")
        self.fonte_sub = ("Segoe UI" if os.name == "nt" else "DejaVu Sans", 9)
        self.fonte_mono = ("Consolas" if os.name == "nt" else "DejaVu Sans Mono", 10)
        self.fonte_mono_grande = ("Consolas" if os.name == "nt" else "DejaVu Sans Mono", 11, "bold")

        self._timer_revelacao = None
        self._timer_clipboard = None
        self._segundos_revelacao = 0
        self._segundos_clipboard = 0
        self._entries_ativos = []
        self._ultimo_keyfile = encontrar_keyfile_em_pendrive()
        self._anti_captura_ativo = False
        self._remover_s2_marcado = False

        for ev in ("<KeyPress>", "<ButtonPress>", "<Motion>"):
            self.raiz.bind_all(ev, self._ao_interagir, add="+")

        self.raiz.protocol("WM_DELETE_WINDOW", self.encerrar_seguro)
        self.container = tk.Frame(self.raiz, bg=COR_FUNDO)
        self.container.pack(fill="both", expand=True)

        self.raiz.after(150, self._aplicar_protecao_janela)
        self._iniciar_relogio_inatividade()

        if os.path.exists(ARQUIVO):
            self.mostrar_tela_login()
        else:
            self.mostrar_tela_criacao()

    def _carregar_icone(self):
        for nome_ico in ("nullvouts.ico", "icone.ico", "icon.ico", "app.ico"):
            caminho_ico = os.path.join(PASTA, nome_ico)
            if os.path.isfile(caminho_ico):
                try:
                    self.raiz.iconbitmap(caminho_ico)
                    break
                except Exception:
                    pass

    def _aplicar_protecao_janela(self):
        aplicar_barra_titulo_preta(self.raiz)
        self._anti_captura_ativo = proteger_janela_captura(self.raiz)

    def _ao_interagir(self, _evento=None):
        if COFRE_RAM.aberto and not SESSAO["bloqueado"]:
            tocar()

    def _iniciar_relogio_inatividade(self):
        if COFRE_RAM.aberto and not SESSAO["bloqueado"]:
            inativo = time.time() - SESSAO["ultima"]
            if inativo > TEMPO_INATIVO:
                self.bloquear_sessao_gui(motivo="Sessão bloqueada por inatividade.")
            elif hasattr(self, "lbl_relogio") and self.lbl_relogio.winfo_exists():
                restante = max(0, int(TEMPO_INATIVO - inativo))
                m, s = divmod(restante, 60)
                self.lbl_relogio.configure(text=f"AUTO-LOCK: {m:02d}:{s:02d}")
        self.raiz.after(1000, self._iniciar_relogio_inatividade)

    def _limpar_container(self):
        self._cancelar_revelacao()
        for w in self._entries_ativos:
            limpar_entry_seguro(w)
        self._entries_ativos.clear()
        for filho in self.container.winfo_children():
            filho.destroy()

    def _criar_entry(self, pai, mostrar=None, fonte=None, largura=36):
        tk = self.tk
        e = tk.Entry(
            pai,
            show=mostrar,
            font=fonte or self.fonte_mono,
            width=largura,
            bg=COR_CAMPO,
            fg=COR_TEXTO,
            insertbackground=COR_TEXTO,
            relief="flat",
            highlightthickness=1,
            highlightbackground=COR_BORDA,
            highlightcolor=COR_DESTAQUE,
        )
        self._entries_ativos.append(e)
        return e

    def _criar_botao(self, pai, texto, comando, cor_fundo=COR_BOTAO_SEC,
                     cor_texto=COR_TEXTO, largura=None):
        tk = self.tk
        btn = tk.Button(
            pai,
            text=texto,
            command=comando,
            font=self.fonte_bold,
            bg=cor_fundo,
            fg=cor_texto,
            activebackground=COR_DESTAQUE,
            activeforeground=COR_TEXTO,
            relief="flat",
            bd=0,
            padx=12,
            pady=6,
            cursor="hand2",
            width=largura,
        )
        return btn

    def _dialogo_criar_keyfile_pendrive(self, entry_destino, label_feedback=None):
        pendrives = detectar_pendrives()
        pasta_inicial = pendrives[0] if pendrives else PASTA
        caminho = self.filedialog.asksaveasfilename(
            title="Criar Keyfile no Pendrive",
            initialdir=pasta_inicial,
            initialfile=NOME_PADRAO_KEYFILE,
            defaultextension=".key",
            filetypes=[("Keyfile Nullvouts (*.key)", "*.key"), ("Todos os arquivos", "*.*")],
        )
        if not caminho:
            return None
        try:
            caminho_gravado = criar_keyfile(caminho)
            entry_destino.delete(0, "end")
            entry_destino.insert(0, caminho_gravado)
            msg = f"Keyfile criado e confirmado em: {caminho_gravado}"
            if label_feedback is not None and label_feedback.winfo_exists():
                label_feedback.configure(text=msg, fg=COR_VERDE_TEXTO)
            else:
                self.messagebox.showinfo(
                    "Keyfile Criada com Sucesso",
                    f"Arquivo Keyfile de {TAM_KEYFILE} bytes gravado em:\n\n{caminho_gravado}\n\n"
                    "Conclua clicando no botão verde abaixo para vincular ao cofre."
                )
            return caminho_gravado
        except Exception as e:
            if label_feedback is not None and label_feedback.winfo_exists():
                label_feedback.configure(text=f"Erro ao criar Keyfile: {e}", fg=COR_PERIGO)
            else:
                self.messagebox.showerror("Erro ao Criar Keyfile", str(e))
            return None

    # ------------------------------------------ tela de login / desbloqueio

    def mostrar_tela_login(self, mensagem_status=""):
        tk = self.tk
        self._limpar_container()

        quadro_central = tk.Frame(
            self.container, bg=COR_PAINEL, padx=36, pady=28,
            highlightthickness=1, highlightbackground=COR_BORDA
        )
        quadro_central.place(relx=0.5, rely=0.5, anchor="center", width=540)

        tk.Label(
            quadro_central, text="Nullvouts",
            font=self.fonte_titulo, bg=COR_PAINEL, fg=COR_TEXTO
        ).pack(anchor="w", pady=(0, 10))

        self.lbl_msg_login = tk.Label(
            quadro_central, text=mensagem_status,
            font=self.fonte_sub, bg=COR_PAINEL, fg=COR_ALERTA, wraplength=460, justify="left"
        )
        self.lbl_msg_login.pack(anchor="w", pady=(0, 8))

        tk.Label(
            quadro_central, text="SENHA INFRA",
            font=self.fonte_bold, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")
        self.ent_senha_login = self._criar_entry(quadro_central, mostrar="•", largura=44)
        self.ent_senha_login.pack(fill="x", pady=(4, 12), ipady=6)
        self.ent_senha_login.focus_set()

        tk.Label(
            quadro_central,
            text="SEGUNDA SENHA (JUNTO COM A KEYFILE OU P/ ENTRAR SEM PENDRIVE)",
            font=self.fonte_bold, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")
        self.ent_s2_login = self._criar_entry(quadro_central, mostrar="•", largura=44)
        self.ent_s2_login.pack(fill="x", pady=(4, 12), ipady=6)

        tk.Label(
            quadro_central,
            text="KEYFILE NO PENDRIVE (SE PERDEU O PENDRIVE, DEIXE VAZIO E USE A 2ª SENHA)",
            font=self.fonte_bold, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")

        linha_kf = tk.Frame(quadro_central, bg=COR_PAINEL)
        linha_kf.pack(fill="x", pady=(4, 18))
        self.ent_kf_login = self._criar_entry(linha_kf, largura=30)
        kf_detectado = self._ultimo_keyfile or encontrar_keyfile_em_pendrive()
        if kf_detectado and os.path.isfile(kf_detectado):
            self.ent_kf_login.insert(0, kf_detectado)
        self.ent_kf_login.pack(side="left", fill="x", expand=True, ipady=6)

        self._criar_botao(
            linha_kf, "Procurar...", self._escolher_kf_login
        ).pack(side="left", padx=(6, 0))

        self._criar_botao(
            linha_kf, "Limpar", lambda: self.ent_kf_login.delete(0, "end")
        ).pack(side="left", padx=(6, 0))

        self.btn_abrir = self._criar_botao(
            quadro_central, "DESTRANCAR COFRE", self._acao_abrir_cofre,
            cor_fundo=COR_DESTAQUE
        )
        self.btn_abrir.pack(fill="x", ipady=3)
        self.ent_senha_login.bind("<Return>", lambda _e: self._acao_abrir_cofre())
        self.ent_s2_login.bind("<Return>", lambda _e: self._acao_abrir_cofre())

        self._atualizar_bloqueio_login()

    def _escolher_kf_login(self):
        pendrives = detectar_pendrives()
        pasta_inicial = pendrives[0] if pendrives else PASTA
        caminho = self.filedialog.askopenfilename(
            title="Selecionar Keyfile Existente",
            initialdir=pasta_inicial,
            filetypes=[("Keyfile Nullvouts (*.key)", "*.key"), ("Todos os arquivos", "*.*")],
        )
        if caminho:
            self.ent_kf_login.delete(0, "end")
            self.ent_kf_login.insert(0, caminho)

    def _atualizar_bloqueio_login(self):
        if not hasattr(self, "lbl_msg_login") or not self.lbl_msg_login.winfo_exists():
            return
        restante = segundos_bloqueio_restantes()
        if restante > 0:
            self.btn_abrir.configure(state="disabled")
            self.lbl_msg_login.configure(
                text=f"BLOQUEIO TEMPORÁRIO ATIVO: Aguarde {restante} s para nova tentativa.",
                fg=COR_PERIGO
            )
            self.raiz.after(1000, self._atualizar_bloqueio_login)
        else:
            self.btn_abrir.configure(state="normal")

    def _acao_abrir_cofre(self):
        if segundos_bloqueio_restantes() > 0:
            registrar("tentativa_bloqueada")
            self._atualizar_bloqueio_login()
            return

        senha = self.ent_senha_login.get()
        segunda_senha = self.ent_s2_login.get().strip() or None
        caminho_kf = self.ent_kf_login.get().strip() or None
        limpar_entry_seguro(self.ent_senha_login)
        limpar_entry_seguro(self.ent_s2_login)

        if not senha:
            self.lbl_msg_login.configure(text="Digite a senha infra.", fg=COR_ALERTA)
            return

        self.lbl_msg_login.configure(
            text="Verificando credenciais e abrindo cofre...",
            fg=COR_SUBTEXTO
        )
        self.raiz.update_idletasks()

        try:
            (segredo_buf, itens, meta, atualizar,
             usou_kf, chave_dados, cab_v4, abriu_rec) = abrir_cofre(
                senha, caminho_kf, segunda_senha=segunda_senha, sair_em_erro=False
            )
        except Exception as e:
            del senha, segunda_senha
            self.lbl_msg_login.configure(text=str(e), fg=COR_PERIGO)
            self._atualizar_bloqueio_login()
            return
        del senha, segunda_senha

        if "chave_log" not in meta:
            meta["chave_log"] = secrets.token_hex(32)
            atualizar = True
        if HASH_PALAVRAS and "hash_palavras" not in meta:
            meta["hash_palavras"] = HASH_PALAVRAS
            atualizar = True

        definir_chave_log(meta)
        ok_rb, msg_rb = verificar_rollback_so(meta)
        if not ok_rb:
            registrar("alerta_rollback")
            self.messagebox.showwarning(
                "Alerta Crítico Anti-Rollback",
                f"ATENÇÃO: {msg_rb}"
            )

        if caminho_kf and os.path.isfile(caminho_kf):
            self._ultimo_keyfile = caminho_kf
        COFRE_RAM.inicializar(
            segredo_buf, itens, meta,
            usou_keyfile=usou_kf,
            caminho_keyfile=caminho_kf if (caminho_kf and os.path.isfile(caminho_kf)) else None,
            chave_disco_buf=chave_dados,
            cabecalho_cache=cab_v4,
            abriu_por_recuperacao=abriu_rec,
        )
        apagar_buffer(chave_dados)
        apagar_buffer(segredo_buf)
        itens.clear()

        SESSAO["ativa"] = True
        SESSAO["bloqueado"] = False
        tocar()

        registrar("abertura_recuperacao" if abriu_rec else "abertura_ok")
        if atualizar:
            registrar("cofre_migrado")
            gravar_cofre_memoria(manter_backup=True, renovar_salt=True)
        else:
            gravar_cofre_memoria(manter_backup=True, renovar_salt=False)

        validar_integridade_palavras(
            COFRE_RAM.meta,
            confirmar_fn=lambda msg: self.messagebox.askyesno("Lista de Palavras Alterada", msg)
        )
        self.mostrar_painel_principal()
        if abriu_rec:
            self.lbl_rodape.configure(
                text="Cofre aberto via Segunda Senha (sem o pendrive). Para cadastrar novo pendrive, use 'Senha Infra / Keyfile'.",
                fg=COR_ALERTA
            )

    # ------------------------------------------ tela de criação de cofre

    def mostrar_tela_criacao(self):
        tk = self.tk
        self._limpar_container()

        quadro = tk.Frame(
            self.container, bg=COR_PAINEL, padx=36, pady=22,
            highlightthickness=1, highlightbackground=COR_BORDA
        )
        quadro.place(relx=0.5, rely=0.5, anchor="center", width=580)

        tk.Label(
            quadro, text="Nullvouts",
            font=self.fonte_titulo, bg=COR_PAINEL, fg=COR_TEXTO
        ).pack(anchor="w")

        tk.Label(
            quadro,
            text="Defina sua Senha Infra, sua Keyfile no pendrive e sua Segunda Senha de segurança/recuperação.",
            font=self.fonte_sub, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w", pady=(2, 8))

        self.lbl_msg_criacao = tk.Label(
            quadro, text="", font=self.fonte_sub, bg=COR_PAINEL,
            fg=COR_ALERTA, wraplength=500, justify="left"
        )
        self.lbl_msg_criacao.pack(anchor="w", pady=(0, 6))

        tk.Label(
            quadro, text="1. NOVA SENHA INFRA (MÍNIMO 12 CARACTERES)",
            font=self.fonte_bold, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")
        self.ent_nova1 = self._criar_entry(quadro, mostrar="•", largura=46)
        self.ent_nova1.pack(fill="x", pady=(3, 6), ipady=5)

        tk.Label(
            quadro, text="CONFIRMAR SENHA INFRA",
            font=self.fonte_bold, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")
        self.ent_nova2 = self._criar_entry(quadro, mostrar="•", largura=46)
        self.ent_nova2.pack(fill="x", pady=(3, 8), ipady=5)

        tk.Label(
            quadro,
            text="2. SEGUNDA SENHA — USAR COM A KEYFILE E RECUPERAR SEM PENDRIVE (MÍN. 12 CAR.)",
            font=self.fonte_bold, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")
        self.ent_s2_criacao = self._criar_entry(quadro, mostrar="•", largura=46)
        self.ent_s2_criacao.pack(fill="x", pady=(3, 6), ipady=5)

        linha_gerar_frases = tk.Frame(quadro, bg=COR_PAINEL)
        linha_gerar_frases.pack(fill="x", pady=(0, 10))
        if PALAVRAS:
            self._criar_botao(
                linha_gerar_frases, "Gerar Frase p/ Senha Infra",
                self._gerar_frase_para_criacao
            ).pack(side="left", padx=(0, 8))
        self._criar_botao(
            linha_gerar_frases, "Gerar 2ª Senha Forte Automática",
            self._gerar_s2_para_criacao
        ).pack(side="left")

        tk.Label(
            quadro, text="3. KEYFILE EM PENDRIVE (OPCIONAL)",
            font=self.fonte_bold, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")

        linha_kf = tk.Frame(quadro, bg=COR_PAINEL)
        linha_kf.pack(fill="x", pady=(3, 6))
        self.ent_kf_novo = self._criar_entry(linha_kf, largura=30)
        self.ent_kf_novo.pack(side="left", fill="x", expand=True, ipady=5)

        linha_botoes_kf = tk.Frame(quadro, bg=COR_PAINEL)
        linha_botoes_kf.pack(fill="x", pady=(0, 14))

        self._criar_botao(
            linha_botoes_kf, "Criar Keyfile no Pendrive...",
            lambda: self._dialogo_criar_keyfile_pendrive(self.ent_kf_novo, self.lbl_msg_criacao),
            cor_fundo=COR_DESTAQUE
        ).pack(side="left", padx=(0, 8))

        self._criar_botao(
            linha_botoes_kf, "Usar Existente...", self._escolher_kf_criacao
        ).pack(side="left", padx=(0, 8))

        self._criar_botao(
            linha_botoes_kf, "Limpar", lambda: self.ent_kf_novo.delete(0, "end")
        ).pack(side="left")

        self._criar_botao(
            quadro, "CRIAR E TRANCAR COFRE",
            self._acao_criar_cofre, cor_fundo=COR_VERDE
        ).pack(fill="x", ipady=3)

    def _gerar_frase_para_criacao(self):
        try:
            frase, bits = gerar_frase_palavras(incluir_numero=False)
            limpar_entry_seguro(self.ent_nova1)
            limpar_entry_seguro(self.ent_nova2)
            self.ent_nova1.insert(0, frase)
            self.ent_nova2.insert(0, frase)
            self.messagebox.showinfo(
                "Frase Gerada",
                f"Anote sua Senha Infra em local físico seguro:\n\n{frase}\n\n"
                f"Força estimada: ~{int(bits)} bits."
            )
            del frase
        except Exception as e:
            self.lbl_msg_criacao.configure(text=str(e), fg=COR_PERIGO)

    def _gerar_s2_para_criacao(self):
        try:
            if PALAVRAS:
                s2, bits = gerar_frase_palavras(incluir_numero=True)
            else:
                s2, bits = gerar_senha_aleatoria(20)
            limpar_entry_seguro(self.ent_s2_criacao)
            self.ent_s2_criacao.insert(0, s2)
            self.messagebox.showinfo(
                "Segunda Senha de Recuperação Gerada",
                f"Anote sua Segunda Senha em papel (para abrir o cofre caso perca o pendrive):\n\n{s2}\n\n"
                f"Força estimada: ~{int(bits)} bits."
            )
            del s2
        except Exception as e:
            self.lbl_msg_criacao.configure(text=str(e), fg=COR_PERIGO)

    def _escolher_kf_criacao(self):
        pendrives = detectar_pendrives()
        pasta_inicial = pendrives[0] if pendrives else PASTA
        caminho = self.filedialog.askopenfilename(
            title="Selecionar Keyfile Existente",
            initialdir=pasta_inicial,
            filetypes=[("Keyfile Nullvouts (*.key)", "*.key"), ("Todos os arquivos", "*.*")],
        )
        if caminho:
            self.ent_kf_novo.delete(0, "end")
            self.ent_kf_novo.insert(0, caminho)

    def _acao_criar_cofre(self):
        s1 = self.ent_nova1.get()
        s2 = self.ent_nova2.get()
        segunda_senha = self.ent_s2_criacao.get().strip() or None
        caminho_kf_bruto = self.ent_kf_novo.get().strip() or None

        aceita, motivo = senha_mestra_aceitavel(s1)
        if not aceita:
            self.lbl_msg_criacao.configure(text=f"Senha infra fraca: {motivo}", fg=COR_PERIGO)
            return
        if not iguais(s1, s2):
            self.lbl_msg_criacao.configure(text="As senhas infra digitadas não conferem.", fg=COR_PERIGO)
            return

        if segunda_senha:
            ok_s2, motivo_s2 = segunda_senha_aceitavel(segunda_senha, s1)
            if not ok_s2:
                self.lbl_msg_criacao.configure(text=motivo_s2, fg=COR_PERIGO)
                return

        bytes_kf = None
        caminho_kf = None
        if caminho_kf_bruto:
            try:
                caminho_kf = normalizar_caminho_keyfile(caminho_kf_bruto, para_criacao=True)
                if not os.path.isfile(caminho_kf):
                    caminho_kf = criar_keyfile(caminho_kf)
                bytes_kf = ler_keyfile(caminho_kf)
            except Exception as e:
                self.lbl_msg_criacao.configure(text=f"Erro no Keyfile: {e}", fg=COR_PERIGO)
                return

        limpar_entry_seguro(self.ent_nova1)
        limpar_entry_seguro(self.ent_nova2)
        limpar_entry_seguro(self.ent_s2_criacao)
        self.lbl_msg_criacao.configure(
            text="Derivando chaves Scrypt (512 MB) e gravando cofre...", fg=COR_SUBTEXTO
        )
        self.raiz.update_idletasks()

        segredo_buf = _derivar_segredo_infra_v4(s1)
        del s1, s2

        meta = {"chave_log": secrets.token_hex(32)}
        if HASH_PALAVRAS:
            meta["hash_palavras"] = HASH_PALAVRAS
        configurar_fatores_meta(meta, segredo_buf, bytes_kf=bytes_kf, segunda_senha=segunda_senha)
        apagar_buffer(bytes_kf)
        del segunda_senha

        definir_chave_log(meta)
        self._ultimo_keyfile = caminho_kf
        COFRE_RAM.inicializar(segredo_buf, {}, meta,
                              usou_keyfile=bool(caminho_kf),
                              caminho_keyfile=caminho_kf)
        apagar_buffer(segredo_buf)

        SESSAO["ativa"] = True
        SESSAO["bloqueado"] = False
        tocar()

        registrar("cofre_criado")
        gravar_cofre_memoria(manter_backup=False, renovar_salt=True)
        self.mostrar_painel_principal()

    # ------------------------------------------ painel principal do cofre

    def mostrar_painel_principal(self):
        tk = self.tk
        self._limpar_container()

        topo = tk.Frame(
            self.container, bg=COR_PAINEL, padx=20, pady=12,
            highlightthickness=1, highlightbackground=COR_BORDA
        )
        topo.pack(fill="x")

        bloco_esq = tk.Frame(topo, bg=COR_PAINEL)
        bloco_esq.pack(side="left")

        tk.Label(
            bloco_esq, text="Nullvouts",
            font=self.fonte_titulo, bg=COR_PAINEL, fg=COR_TEXTO
        ).pack(anchor="w")

        bloco_dir = tk.Frame(topo, bg=COR_PAINEL)
        bloco_dir.pack(side="right")

        self.lbl_relogio = tk.Label(
            bloco_dir, text="AUTO-LOCK: 05:00",
            font=self.fonte_mono, bg=COR_PAINEL, fg=COR_SUBTEXTO
        )
        self.lbl_relogio.pack(side="left", padx=(0, 14))

        self._criar_botao(
            bloco_dir, "Bloquear Agora",
            lambda: self.bloquear_sessao_gui("Sessão bloqueada manualmente.")
        ).pack(side="left", padx=(0, 8))

        self._criar_botao(
            bloco_dir, "Sair", self.encerrar_seguro, cor_fundo=COR_PERIGO
        ).pack(side="left")

        corpo = tk.Frame(self.container, bg=COR_FUNDO, padx=16, pady=14)
        corpo.pack(fill="both", expand=True)

        col_esq = tk.Frame(
            corpo, bg=COR_PAINEL, padx=14, pady=14, width=290,
            highlightthickness=1, highlightbackground=COR_BORDA
        )
        col_esq.pack(side="left", fill="y")
        col_esq.pack_propagate(False)

        tk.Label(
            col_esq, text="ITENS NO COFRE",
            font=self.fonte_bold, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")

        self.ent_filtro = self._criar_entry(col_esq, fonte=self.fonte_ui, largura=24)
        self.ent_filtro.pack(fill="x", pady=(6, 10), ipady=4)
        self.ent_filtro.bind("<KeyRelease>", lambda _e: self._atualizar_lista_itens())

        quadro_lista = tk.Frame(col_esq, bg=COR_CAMPO, highlightthickness=1,
                                highlightbackground=COR_BORDA)
        quadro_lista.pack(fill="both", expand=True)

        rolagem = tk.Scrollbar(quadro_lista, orient="vertical")
        self.lista_itens = tk.Listbox(
            quadro_lista,
            font=self.fonte_mono,
            bg=COR_CAMPO,
            fg=COR_TEXTO,
            selectbackground=COR_DESTAQUE,
            selectforeground=COR_TEXTO,
            relief="flat",
            bd=0,
            highlightthickness=0,
            activestyle="none",
            yscrollcommand=rolagem.set,
        )
        rolagem.config(command=self.lista_itens.yview)
        self.lista_itens.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        rolagem.pack(side="right", fill="y")
        self.lista_itens.bind("<<ListboxSelect>>", self._ao_selecionar_item)

        self._criar_botao(
            col_esq, "+ Novo Item", self._mostrar_aba_adicionar, cor_fundo=COR_DESTAQUE
        ).pack(fill="x", pady=(10, 0))

        col_dir = tk.Frame(corpo, bg=COR_FUNDO)
        col_dir.pack(side="left", fill="both", expand=True, padx=(14, 0))

        barra_abas = tk.Frame(col_dir, bg=COR_FUNDO)
        barra_abas.pack(fill="x", pady=(0, 10))

        self._criar_botao(
            barra_abas, "Inspecionar Item", self._mostrar_aba_inspecionar
        ).pack(side="left", padx=(0, 6))
        self._criar_botao(
            barra_abas, "Adicionar / Editar", self._mostrar_aba_adicionar
        ).pack(side="left", padx=(0, 6))
        self._criar_botao(
            barra_abas, "Gerador de Senhas", self._mostrar_aba_gerador
        ).pack(side="left", padx=(0, 6))
        self._criar_botao(
            barra_abas, "Senha Infra / Keyfile", self._mostrar_aba_senha_mestra
        ).pack(side="left", padx=(0, 6))
        self._criar_botao(
            barra_abas, "Auditoria", self._mostrar_aba_auditoria
        ).pack(side="left")

        self.area_trabalho = tk.Frame(
            col_dir, bg=COR_PAINEL, padx=24, pady=18,
            highlightthickness=1, highlightbackground=COR_BORDA
        )
        self.area_trabalho.pack(fill="both", expand=True)

        self.lbl_rodape = tk.Label(
            col_dir, text="Pronto.",
            font=self.fonte_sub, bg=COR_FUNDO, fg=COR_SUBTEXTO, anchor="w"
        )
        self.lbl_rodape.pack(fill="x", pady=(8, 0))

        self._atualizar_lista_itens()
        self._mostrar_aba_inspecionar()

    def _limpar_area_trabalho(self):
        self._cancelar_revelacao()
        for filho in self.area_trabalho.winfo_children():
            filho.destroy()

    def _atualizar_lista_itens(self, selecionar_nome=None):
        if not hasattr(self, "lista_itens") or not self.lista_itens.winfo_exists():
            return
        filtro = self.ent_filtro.get().strip().lower() if hasattr(self, "ent_filtro") else ""
        nomes = sorted(COFRE_RAM.nomes(), key=lambda s: s.lower())
        self.lista_itens.delete(0, "end")
        idx_sel = None
        for nome in nomes:
            if not filtro or filtro in nome.lower():
                self.lista_itens.insert("end", nome)
                if selecionar_nome and nome == selecionar_nome:
                    idx_sel = self.lista_itens.size() - 1
        if idx_sel is not None:
            self.lista_itens.selection_set(idx_sel)
            self.lista_itens.see(idx_sel)

    def _item_selecionado(self):
        if not hasattr(self, "lista_itens") or not self.lista_itens.winfo_exists():
            return None
        sel = self.lista_itens.curselection()
        if not sel:
            return None
        return self.lista_itens.get(sel[0])

    def _ao_selecionar_item(self, _evento=None):
        nome = self._item_selecionado()
        if nome:
            self._mostrar_aba_inspecionar(nome)

    # ------------------------------------------ aba: inspecionar / copiar item

    def _mostrar_aba_inspecionar(self, nome_forcado=None):
        tk = self.tk
        self._limpar_area_trabalho()
        nome = nome_forcado or self._item_selecionado()

        tk.Label(
            self.area_trabalho, text="INSPEÇÃO DE SEGREDO",
            font=self.fonte_titulo, bg=COR_PAINEL, fg=COR_TEXTO
        ).pack(anchor="w")

        if not nome or not COFRE_RAM.contem(nome):
            tk.Label(
                self.area_trabalho,
                text="Selecione um item na coluna à esquerda ou clique em '+ Novo Item' para cadastrar.",
                font=self.fonte_ui, bg=COR_PAINEL, fg=COR_SUBTEXTO
            ).pack(anchor="w", pady=(12, 0))
            return

        tk.Label(
            self.area_trabalho, text=f"IDENTIFICADOR:  {nome}",
            font=self.fonte_mono_grande, bg=COR_PAINEL, fg=COR_DESTAQUE
        ).pack(anchor="w", pady=(14, 4))

        tk.Label(
            self.area_trabalho,
            text=f"Impressão na auditoria: #{impressao(nome)}",
            font=self.fonte_sub, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w", pady=(0, 18))

        quadro_segredo = tk.Frame(
            self.area_trabalho, bg=COR_CAMPO, padx=16, pady=16,
            highlightthickness=1, highlightbackground=COR_BORDA
        )
        quadro_segredo.pack(fill="x", pady=(0, 16))

        self.lbl_valor_segredo = tk.Label(
            quadro_segredo, text="••••••••••••••••••••••••",
            font=self.fonte_mono_grande, bg=COR_CAMPO, fg=COR_TEXTO,
            wraplength=520, justify="left"
        )
        self.lbl_valor_segredo.pack(anchor="w")

        self.lbl_timer_segredo = tk.Label(
            quadro_segredo, text="Segredo protegido na memória.",
            font=self.fonte_sub, bg=COR_CAMPO, fg=COR_SUBTEXTO
        )
        self.lbl_timer_segredo.pack(anchor="w", pady=(6, 0))

        linha_acoes = tk.Frame(self.area_trabalho, bg=COR_PAINEL)
        linha_acoes.pack(fill="x", pady=(4, 16))

        self._criar_botao(
            linha_acoes, f"Revelar na Tela ({TEMPO_TELA}s)",
            lambda n=nome: self._revelar_item(n), cor_fundo=COR_DESTAQUE
        ).pack(side="left", padx=(0, 8))

        self._criar_botao(
            linha_acoes, f"Copiar p/ Clipboard ({TEMPO_TELA}s)",
            lambda n=nome: self._copiar_item(n), cor_fundo=COR_VERDE
        ).pack(side="left", padx=(0, 8))

        self._criar_botao(
            linha_acoes, "Ocultar / Limpar Agora",
            self._ocultar_e_limpar_agora
        ).pack(side="left")

        linha_sec = tk.Frame(self.area_trabalho, bg=COR_PAINEL)
        linha_sec.pack(fill="x", pady=(10, 0))

        self._criar_botao(
            linha_sec, "Substituir Segredo",
            lambda n=nome: self._mostrar_aba_adicionar(nome_inicial=n)
        ).pack(side="left", padx=(0, 8))

        self._criar_botao(
            linha_sec, "Apagar Item",
            lambda n=nome: self._apagar_item_gui(n), cor_fundo=COR_PERIGO
        ).pack(side="left")

    def _revelar_item(self, nome):
        self._cancelar_revelacao()
        registrar("item_visto", nome)
        gravar_cofre_memoria(manter_backup=True, renovar_salt=False)
        segredo = COFRE_RAM.obter_item(nome)
        if segredo is None:
            return
        self.lbl_valor_segredo.configure(text=segredo, fg=COR_VERDE_TEXTO)
        del segredo
        self._segundos_revelacao = TEMPO_TELA
        self._tick_revelacao()

    def _tick_revelacao(self):
        if not hasattr(self, "lbl_valor_segredo") or not self.lbl_valor_segredo.winfo_exists():
            return
        if self._segundos_revelacao <= 0:
            self._cancelar_revelacao()
            return
        self.lbl_timer_segredo.configure(
            text=f"Visível temporariamente — ocultando em {self._segundos_revelacao} s...",
            fg=COR_ALERTA
        )
        self._segundos_revelacao -= 1
        self._timer_revelacao = self.raiz.after(1000, self._tick_revelacao)

    def _cancelar_revelacao(self):
        if self._timer_revelacao is not None:
            try:
                self.raiz.after_cancel(self._timer_revelacao)
            except Exception:
                pass
            self._timer_revelacao = None
        if hasattr(self, "lbl_valor_segredo") and self.lbl_valor_segredo.winfo_exists():
            self.lbl_valor_segredo.configure(text="••••••••••••••••••••••••", fg=COR_TEXTO)
        if hasattr(self, "lbl_timer_segredo") and self.lbl_timer_segredo.winfo_exists():
            self.lbl_timer_segredo.configure(
                text="Segredo protegido na memória.", fg=COR_SUBTEXTO
            )

    def _copiar_item(self, nome):
        registrar("item_visto", nome)
        gravar_cofre_memoria(manter_backup=True, renovar_salt=False)
        segredo = COFRE_RAM.obter_item(nome)
        if segredo is None:
            return
        copiar_clipboard_protegido(self.raiz, segredo)
        del segredo
        self._iniciar_contagem_clipboard(f"Segredo de '{nome}' copiado")

    def _iniciar_contagem_clipboard(self, prefixo="Segredo copiado"):
        if self._timer_clipboard is not None:
            try:
                self.raiz.after_cancel(self._timer_clipboard)
            except Exception:
                pass
        self._segundos_clipboard = TEMPO_TELA
        self._tick_clipboard(prefixo)

    def _tick_clipboard(self, prefixo):
        if self._segundos_clipboard <= 0:
            limpar_clipboard_seguro(self.raiz)
            if hasattr(self, "lbl_rodape") and self.lbl_rodape.winfo_exists():
                self.lbl_rodape.configure(
                    text="Área de transferência limpa automaticamente com segurança.",
                    fg=COR_VERDE_TEXTO
                )
            self._timer_clipboard = None
            return
        if hasattr(self, "lbl_rodape") and self.lbl_rodape.winfo_exists():
            self.lbl_rodape.configure(
                text=f"{prefixo} — limpando em {self._segundos_clipboard} s...",
                fg=COR_ALERTA
            )
        self._segundos_clipboard -= 1
        self._timer_clipboard = self.raiz.after(1000, lambda: self._tick_clipboard(prefixo))

    def _ocultar_e_limpar_agora(self):
        self._cancelar_revelacao()
        if self._timer_clipboard is not None:
            try:
                self.raiz.after_cancel(self._timer_clipboard)
            except Exception:
                pass
            self._timer_clipboard = None
        limpar_clipboard_seguro(self.raiz)
        if hasattr(self, "lbl_rodape") and self.lbl_rodape.winfo_exists():
            self.lbl_rodape.configure(
                text="Tela ocultada e área de transferência esvaziada.", fg=COR_SUBTEXTO
            )

    def _apagar_item_gui(self, nome):
        if not self.messagebox.askyesno(
            "Confirmar Exclusão Definitiva",
            f"Apagar '{nome}' permanentemente?\n\n"
            "O backup anterior (cofre.bak) também será destruído para não reter o segredo antigo."
        ):
            return
        self._ocultar_e_limpar_agora()
        COFRE_RAM.apagar_item(nome)
        registrar("item_apagado", nome)
        gravar_cofre_memoria(manter_backup=False, renovar_salt=True)
        self._atualizar_lista_itens()
        self._mostrar_aba_inspecionar()
        self.lbl_rodape.configure(
            text=f"Item '{nome}' apagado e backup anterior destruído.", fg=COR_VERDE_TEXTO
        )

    # ------------------------------------------ aba: adicionar / sobrescrever

    def _mostrar_aba_adicionar(self, nome_inicial="", segredo_inicial=""):
        tk = self.tk
        self._limpar_area_trabalho()

        tk.Label(
            self.area_trabalho, text="ADICIONAR OU ATUALIZAR ITEM",
            font=self.fonte_titulo, bg=COR_PAINEL, fg=COR_TEXTO
        ).pack(anchor="w", pady=(0, 14))

        tk.Label(
            self.area_trabalho, text="NOME DO ITEM (EX.: BANCO, E-MAIL, SERVIDOR SSH)",
            font=self.fonte_bold, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")
        self.ent_nome_item = self._criar_entry(self.area_trabalho, fonte=self.fonte_ui, largura=44)
        if nome_inicial:
            self.ent_nome_item.insert(0, nome_inicial)
        self.ent_nome_item.pack(fill="x", pady=(4, 14), ipady=6)

        tk.Label(
            self.area_trabalho, text="SEGREDO / SENHA",
            font=self.fonte_bold, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")
        self.ent_segredo_item = self._criar_entry(self.area_trabalho, mostrar="•", largura=44)
        if segredo_inicial:
            self.ent_segredo_item.insert(0, segredo_inicial)
        self.ent_segredo_item.pack(fill="x", pady=(4, 10), ipady=6)

        linha_aux = tk.Frame(self.area_trabalho, bg=COR_PAINEL)
        linha_aux.pack(fill="x", pady=(0, 18))

        self._mostrar_segredo_add = False

        def alternar_visao():
            self._mostrar_segredo_add = not self._mostrar_segredo_add
            self.ent_segredo_item.configure(show="" if self._mostrar_segredo_add else "•")

        self._criar_botao(
            linha_aux, "Mostrar / Ocultar Digitado", alternar_visao
        ).pack(side="left", padx=(0, 8))

        self._criar_botao(
            linha_aux, "Preencher com Senha Aleatória (20 car.)",
            self._preencher_senha_rapida
        ).pack(side="left")

        self._criar_botao(
            self.area_trabalho, "SALVAR E CIFRAR NO COFRE",
            self._acao_salvar_item, cor_fundo=COR_VERDE
        ).pack(fill="x", ipady=3)

    def _preencher_senha_rapida(self):
        senha, bits = gerar_senha_aleatoria(20)
        limpar_entry_seguro(self.ent_segredo_item)
        self.ent_segredo_item.insert(0, senha)
        del senha
        registrar("senha_gerada")
        gravar_cofre_memoria(manter_backup=True, renovar_salt=False)
        self.lbl_rodape.configure(
            text=f"Senha aleatória de 20 caracteres (~{int(bits)} bits) gerada no campo.",
            fg=COR_VERDE_TEXTO
        )

    def _acao_salvar_item(self):
        nome = self.ent_nome_item.get().strip()
        segredo = self.ent_segredo_item.get()
        if not nome:
            self.messagebox.showwarning("Campo Obrigatório", "O nome do item não pode ser vazio.")
            return
        if not segredo:
            self.messagebox.showwarning("Campo Obrigatório", "O segredo não pode ser vazio.")
            return

        existia = COFRE_RAM.contem(nome)
        if existia:
            if not self.messagebox.askyesno(
                "Substituir Item Existente",
                f"O item '{nome}' já existe no cofre. Deseja substituir o valor?\n\n"
                "O backup anterior (cofre.bak) será destruído para não guardar o segredo antigo."
            ):
                return

        limpar_entry_seguro(self.ent_segredo_item)
        self.lbl_rodape.configure(
            text="Salvando alterações no cofre...", fg=COR_SUBTEXTO
        )
        self.raiz.update_idletasks()

        COFRE_RAM.definir_item(nome, segredo)
        del segredo

        registrar("item_sobrescrito" if existia else "item_adicionado", nome)
        gravar_cofre_memoria(manter_backup=not existia, renovar_salt=True)

        self._atualizar_lista_itens(selecionar_nome=nome)
        self._mostrar_aba_inspecionar(nome_forcado=nome)
        self.lbl_rodape.configure(
            text=f"Item '{nome}' salvo com segurança no cofre.", fg=COR_VERDE_TEXTO
        )

    # ------------------------------------------ aba: gerador de senhas

    def _mostrar_aba_gerador(self):
        tk = self.tk
        self._limpar_area_trabalho()

        tk.Label(
            self.area_trabalho, text="GERADOR DE SENHAS E FRASES",
            font=self.fonte_titulo, bg=COR_PAINEL, fg=COR_TEXTO
        ).pack(anchor="w", pady=(0, 14))

        linha_op = tk.Frame(self.area_trabalho, bg=COR_PAINEL)
        linha_op.pack(fill="x", pady=(0, 14))

        tk.Label(
            linha_op, text="COMPRIMENTO (MÍN. 16):",
            font=self.fonte_bold, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(side="left")

        self.ent_tam_gerador = self._criar_entry(linha_op, largura=6)
        self.ent_tam_gerador.insert(0, "24")
        self.ent_tam_gerador.pack(side="left", padx=(8, 14), ipady=4)

        self._criar_botao(
            linha_op, "Gerar Senha Aleatória", self._acao_gerar_aleatoria,
            cor_fundo=COR_DESTAQUE
        ).pack(side="left", padx=(0, 8))

        self._criar_botao(
            linha_op, "Gerar Frase de Palavras", self._acao_gerar_frase
        ).pack(side="left")

        quadro_res = tk.Frame(
            self.area_trabalho, bg=COR_CAMPO, padx=16, pady=16,
            highlightthickness=1, highlightbackground=COR_BORDA
        )
        quadro_res.pack(fill="x", pady=(4, 14))

        self.lbl_senha_gerada = tk.Label(
            quadro_res, text="(Clique em uma das opções acima para gerar)",
            font=self.fonte_mono_grande, bg=COR_CAMPO, fg=COR_SUBTEXTO,
            wraplength=520, justify="left"
        )
        self.lbl_senha_gerada.pack(anchor="w")

        self.lbl_bits_gerada = tk.Label(
            quadro_res, text="", font=self.fonte_sub, bg=COR_CAMPO, fg=COR_VERDE_TEXTO
        )
        self.lbl_bits_gerada.pack(anchor="w", pady=(6, 0))

        self._ultima_gerada = None

        linha_dest = tk.Frame(self.area_trabalho, bg=COR_PAINEL)
        linha_dest.pack(fill="x")

        self._criar_botao(
            linha_dest, f"Copiar Gerada ({TEMPO_TELA}s)",
            self._copiar_gerada, cor_fundo=COR_VERDE
        ).pack(side="left", padx=(0, 8))

        self._criar_botao(
            linha_dest, "Usar em Novo Item...",
            self._usar_gerada_em_item
        ).pack(side="left")

    def _acao_gerar_aleatoria(self):
        try:
            tam = int(self.ent_tam_gerador.get().strip())
            senha, bits = gerar_senha_aleatoria(tam)
        except Exception as e:
            self.messagebox.showwarning("Parâmetro Inválido", str(e))
            return
        self._exibir_gerada(senha, bits)

    def _acao_gerar_frase(self):
        if not validar_integridade_palavras(
            COFRE_RAM.meta,
            confirmar_fn=lambda msg: self.messagebox.askyesno("Lista de Palavras Alterada", msg)
        ):
            return
        try:
            frase, bits = gerar_frase_palavras(incluir_numero=True)
        except Exception as e:
            self.messagebox.showwarning("Lista de Palavras Ausente", str(e))
            return
        self._exibir_gerada(frase, bits)

    def _exibir_gerada(self, valor, bits):
        registrar("senha_gerada")
        gravar_cofre_memoria(manter_backup=True, renovar_salt=False)
        self._ultima_gerada = valor
        self.lbl_senha_gerada.configure(text=valor, fg=COR_VERDE_TEXTO)
        self.lbl_bits_gerada.configure(text=f"Entropia estimada: ~{int(bits)} bits")

    def _copiar_gerada(self):
        if not getattr(self, "_ultima_gerada", None):
            return
        copiar_clipboard_protegido(self.raiz, self._ultima_gerada)
        self._iniciar_contagem_clipboard("Senha gerada copiada")

    def _usar_gerada_em_item(self):
        valor = getattr(self, "_ultima_gerada", None) or ""
        self._ultima_gerada = None
        self._mostrar_aba_adicionar(segredo_inicial=valor)

    # ------------------------------------------ aba: senha infra, keyfile e 2ª senha

    def _mostrar_aba_senha_mestra(self):
        tk = self.tk
        self._limpar_area_trabalho()
        self._remover_s2_marcado = False

        tk.Label(
            self.area_trabalho, text="SENHA INFRA, KEYFILE E SEGUNDA SENHA",
            font=self.fonte_titulo, bg=COR_PAINEL, fg=COR_TEXTO
        ).pack(anchor="w", pady=(0, 4))

        partes_status = []
        if COFRE_RAM.usou_keyfile():
            partes_status.append("Keyfile: ATIVA")
        else:
            partes_status.append("Keyfile: NÃO VINCULADA")
        if COFRE_RAM.tem_segunda_senha():
            partes_status.append("Segunda Senha (Scrypt 512 MB): ATIVA")
        else:
            partes_status.append("Segunda Senha: NÃO CONFIGURADA")

        self.lbl_status_kf_aba = tk.Label(
            self.area_trabalho, text="  •  ".join(partes_status),
            font=self.fonte_sub, bg=COR_PAINEL,
            fg=COR_VERDE_TEXTO if (COFRE_RAM.usou_keyfile() or COFRE_RAM.tem_segunda_senha()) else COR_SUBTEXTO,
            wraplength=560, justify="left"
        )
        self.lbl_status_kf_aba.pack(anchor="w", pady=(0, 8))

        linha_atuais = tk.Frame(self.area_trabalho, bg=COR_PAINEL)
        linha_atuais.pack(fill="x", pady=(0, 6))

        col_at1 = tk.Frame(linha_atuais, bg=COR_PAINEL)
        col_at1.pack(side="left", fill="x", expand=True, padx=(0, 6))
        tk.Label(
            col_at1, text="1. SENHA INFRA ATUAL (OBRIGATÓRIA)",
            font=self.fonte_bold, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")
        self.ent_atual_troca = self._criar_entry(col_at1, mostrar="•", largura=20)
        self.ent_atual_troca.pack(fill="x", pady=(2, 0), ipady=4)

        col_at2 = tk.Frame(linha_atuais, bg=COR_PAINEL)
        col_at2.pack(side="left", fill="x", expand=True, padx=(6, 0))
        tk.Label(
            col_at2, text="2ª SENHA ATUAL (SE ESTIVER SEM O PENDRIVE ATUAL)",
            font=self.fonte_sub, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")
        self.ent_s2_atual_troca = self._criar_entry(col_at2, mostrar="•", largura=20)
        self.ent_s2_atual_troca.pack(fill="x", pady=(2, 0), ipady=4)

        linha_novas = tk.Frame(self.area_trabalho, bg=COR_PAINEL)
        linha_novas.pack(fill="x", pady=(0, 6))

        col_n1 = tk.Frame(linha_novas, bg=COR_PAINEL)
        col_n1.pack(side="left", fill="x", expand=True, padx=(0, 6))
        tk.Label(
            col_n1, text="NOVA SENHA INFRA (VAZIO = MANTER ATUAL)",
            font=self.fonte_sub, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")
        self.ent_nova_troca1 = self._criar_entry(col_n1, mostrar="•", largura=20)
        self.ent_nova_troca1.pack(fill="x", pady=(2, 0), ipady=4)

        col_n2 = tk.Frame(linha_novas, bg=COR_PAINEL)
        col_n2.pack(side="left", fill="x", expand=True, padx=(6, 0))
        tk.Label(
            col_n2, text="CONFIRMAR NOVA SENHA INFRA",
            font=self.fonte_sub, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")
        self.ent_nova_troca2 = self._criar_entry(col_n2, mostrar="•", largura=20)
        self.ent_nova_troca2.pack(fill="x", pady=(2, 0), ipady=4)

        tk.Label(
            self.area_trabalho,
            text="2. NOVA SEGUNDA SENHA — MÍN. 12 CARACTERES (DEIXE VAZIO PARA MANTER A ATUAL)",
            font=self.fonte_bold, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")

        linha_s2 = tk.Frame(self.area_trabalho, bg=COR_PAINEL)
        linha_s2.pack(fill="x", pady=(2, 4))
        self.ent_s2_troca1 = self._criar_entry(linha_s2, mostrar="•", largura=20)
        self.ent_s2_troca1.pack(side="left", fill="x", expand=True, padx=(0, 6), ipady=4)
        self.ent_s2_troca2 = self._criar_entry(linha_s2, mostrar="•", largura=20)
        self.ent_s2_troca2.pack(side="left", fill="x", expand=True, padx=(6, 0), ipady=4)

        linha_botoes_s2 = tk.Frame(self.area_trabalho, bg=COR_PAINEL)
        linha_botoes_s2.pack(fill="x", pady=(0, 8))
        self._criar_botao(
            linha_botoes_s2, "Gerar 2ª Senha Forte...",
            self._gerar_s2_aba_troca
        ).pack(side="left", padx=(0, 8))
        self._criar_botao(
            linha_botoes_s2, "Remover 2ª Senha",
            self._marcar_remocao_s2
        ).pack(side="left")

        tk.Label(
            self.area_trabalho, text="3. CAMINHO DA KEYFILE NO PENDRIVE (DEIXE VAZIO PARA DESATIVAR KEYFILE)",
            font=self.fonte_bold, bg=COR_PAINEL, fg=COR_SUBTEXTO
        ).pack(anchor="w")

        linha_kf = tk.Frame(self.area_trabalho, bg=COR_PAINEL)
        linha_kf.pack(fill="x", pady=(2, 4))
        self.ent_kf_troca = self._criar_entry(linha_kf, largura=30)
        if COFRE_RAM.caminho_keyfile():
            self.ent_kf_troca.insert(0, COFRE_RAM.caminho_keyfile())
        self.ent_kf_troca.pack(side="left", fill="x", expand=True, ipady=4)

        linha_botoes_kf = tk.Frame(self.area_trabalho, bg=COR_PAINEL)
        linha_botoes_kf.pack(fill="x", pady=(0, 10))

        self._criar_botao(
            linha_botoes_kf, "Criar Keyfile no Pendrive...",
            lambda: self._dialogo_criar_keyfile_pendrive(self.ent_kf_troca, self.lbl_status_kf_aba),
            cor_fundo=COR_DESTAQUE
        ).pack(side="left", padx=(0, 8))

        self._criar_botao(
            linha_botoes_kf, "Selecionar Existente...", self._escolher_kf_troca
        ).pack(side="left", padx=(0, 8))

        self._criar_botao(
            linha_botoes_kf, "Remover Keyfile", lambda: self.ent_kf_troca.delete(0, "end")
        ).pack(side="left")

        self._criar_botao(
            self.area_trabalho, "SALVAR SENHA INFRA / KEYFILE / SEGUNDA SENHA",
            self._acao_trocar_senha_gui, cor_fundo=COR_VERDE
        ).pack(fill="x", ipady=3)

    def _gerar_s2_aba_troca(self):
        self._remover_s2_marcado = False
        if PALAVRAS:
            s2, bits = gerar_frase_palavras(incluir_numero=True)
        else:
            s2, bits = gerar_senha_aleatoria(20)
        limpar_entry_seguro(self.ent_s2_troca1)
        limpar_entry_seguro(self.ent_s2_troca2)
        self.ent_s2_troca1.insert(0, s2)
        self.ent_s2_troca2.insert(0, s2)
        self.messagebox.showinfo(
            "Nova Segunda Senha Gerada",
            f"Anote sua nova Segunda Senha em papel seguro:\n\n{s2}\n\n"
            f"Força estimada: ~{int(bits)} bits.\n"
            "Clique no botão verde de salvar abaixo para gravar."
        )
        del s2

    def _marcar_remocao_s2(self):
        limpar_entry_seguro(self.ent_s2_troca1)
        limpar_entry_seguro(self.ent_s2_troca2)
        self._remover_s2_marcado = True
        self.lbl_status_kf_aba.configure(
            text="Segunda Senha marcada para REMOÇÃO ao clicar em Salvar.",
            fg=COR_ALERTA
        )

    def _escolher_kf_troca(self):
        pendrives = detectar_pendrives()
        pasta_inicial = pendrives[0] if pendrives else PASTA
        caminho = self.filedialog.askopenfilename(
            title="Selecionar Keyfile no Pendrive",
            initialdir=pasta_inicial,
            filetypes=[("Keyfile Nullvouts (*.key)", "*.key"), ("Todos os arquivos", "*.*")],
        )
        if caminho:
            self.ent_kf_troca.delete(0, "end")
            self.ent_kf_troca.insert(0, caminho)

    def _acao_trocar_senha_gui(self):
        atual = self.ent_atual_troca.get()
        s2_atual = self.ent_s2_atual_troca.get().strip() or None
        nova1 = self.ent_nova_troca1.get()
        nova2 = self.ent_nova_troca2.get()
        s2_1 = self.ent_s2_troca1.get().strip()
        s2_2 = self.ent_s2_troca2.get().strip()
        caminho_kf_bruto = self.ent_kf_troca.get().strip() or None

        if not atual:
            self.messagebox.showwarning(
                "Senha Infra Atual Necessária",
                "Digite sua Senha Infra atual no primeiro campo para confirmar."
            )
            return

        candidato_buf = _derivar_segredo_infra_v4(atual)
        atual_buf = COFRE_RAM.obter_segredo_mestre()
        try:
            confere = secrets.compare_digest(candidato_buf, atual_buf)
            if confere:
                ok_2fa, msg_2fa = verificar_segundo_fator_atual(
                    atual_buf, COFRE_RAM.meta,
                    caminho_kf_tentativa=caminho_kf_bruto,
                    s2_tentativa=s2_atual
                )
            else:
                ok_2fa, msg_2fa = False, ""
        finally:
            apagar_buffer(candidato_buf)
            apagar_buffer(atual_buf)

        if not confere:
            del atual, s2_atual
            limpar_entry_seguro(self.ent_atual_troca)
            self.messagebox.showerror("Acesso Negado", "A senha infra atual está incorreta.")
            return

        if not ok_2fa:
            del atual, s2_atual
            self.messagebox.showerror("Segundo Fator Necessário", msg_2fa)
            return

        if not nova1 and not nova2:
            senha_final = atual
        else:
            aceita, motivo = senha_mestra_aceitavel(nova1)
            if not aceita:
                del atual, s2_atual
                self.messagebox.showwarning("Senha Infra Fraca", f"Senha fraca: {motivo}")
                return
            if not iguais(nova1, nova2):
                del atual, s2_atual
                self.messagebox.showwarning("Divergência", "A confirmação da nova senha infra não confere.")
                return
            senha_final = nova1

        atualizar_s2 = False
        nova_s2 = None
        if s2_1 or s2_2:
            ok_s2, motivo_s2 = segunda_senha_aceitavel(s2_1, senha_final)
            if not ok_s2:
                del atual, s2_atual, senha_final
                self.messagebox.showwarning("Segunda Senha Inválida", motivo_s2)
                return
            if not iguais(s2_1, s2_2):
                del atual, s2_atual, senha_final
                self.messagebox.showwarning(
                    "Divergência na Segunda Senha",
                    "Digite a mesma Segunda Senha nos dois campos lado a lado para confirmar."
                )
                return
            atualizar_s2 = True
            nova_s2 = s2_1
            self._remover_s2_marcado = False

        trocou_senha_infra = not iguais(atual, senha_final)
        del atual, nova1, nova2, s2_1, s2_2

        bytes_kf_novo = None
        caminho_kf_novo = None
        if caminho_kf_bruto:
            try:
                caminho_kf_novo = normalizar_caminho_keyfile(caminho_kf_bruto, para_criacao=True)
                if not os.path.isfile(caminho_kf_novo):
                    caminho_kf_novo = criar_keyfile(caminho_kf_novo)
                bytes_kf_novo = ler_keyfile(caminho_kf_novo)
            except Exception as e:
                del senha_final, nova_s2, s2_atual
                self.messagebox.showerror("Erro no Keyfile", str(e))
                return

        limpar_entry_seguro(self.ent_atual_troca)
        limpar_entry_seguro(self.ent_s2_atual_troca)
        limpar_entry_seguro(self.ent_nova_troca1)
        limpar_entry_seguro(self.ent_nova_troca2)
        limpar_entry_seguro(self.ent_s2_troca1)
        limpar_entry_seguro(self.ent_s2_troca2)

        self.lbl_rodape.configure(
            text="Derivando slots Scrypt (512 MB) e re-cifrando cofre...",
            fg=COR_SUBTEXTO
        )
        self.raiz.update_idletasks()

        novo_segredo_buf = _derivar_segredo_infra_v4(senha_final)
        del senha_final

        itens_claros = COFRE_RAM.exportar_itens_claros()
        try:
            if bytes_kf_novo is not None:
                COFRE_RAM.meta["kf_hash"] = bytes(bytes_kf_novo).hex()
                COFRE_RAM.meta["usa_keyfile"] = True
            else:
                COFRE_RAM.meta.pop("kf_hash", None)
                COFRE_RAM.meta["usa_keyfile"] = False

            if self._remover_s2_marcado:
                COFRE_RAM.meta.pop("s2_salt", None)
                COFRE_RAM.meta.pop("s2_kdf", None)
                COFRE_RAM.meta.pop("s2_hash", None)
            elif atualizar_s2 and nova_s2:
                salt_s2 = os.urandom(TAM_SALT)
                s2_buf = _derivar_segunda_senha_scrypt(novo_segredo_buf, nova_s2, salt_s2, N_LOG2_ATUAL)
                try:
                    COFRE_RAM.meta["s2_salt"] = salt_s2.hex()
                    COFRE_RAM.meta["s2_kdf"] = bytes(s2_buf).hex()
                finally:
                    apagar_buffer(s2_buf)
            elif trocou_senha_infra and COFRE_RAM.tem_segunda_senha() and s2_atual:
                # Se trocou a Senha Infra e informou a 2ª senha atual, re-deriva com o novo segredo_infra_buf
                salt_s2 = os.urandom(TAM_SALT)
                s2_buf = _derivar_segunda_senha_scrypt(novo_segredo_buf, s2_atual, salt_s2, N_LOG2_ATUAL)
                try:
                    COFRE_RAM.meta["s2_salt"] = salt_s2.hex()
                    COFRE_RAM.meta["s2_kdf"] = bytes(s2_buf).hex()
                finally:
                    apagar_buffer(s2_buf)

            self._ultimo_keyfile = caminho_kf_novo
            COFRE_RAM.inicializar(
                novo_segredo_buf, itens_claros, COFRE_RAM.meta,
                usou_keyfile=bool(caminho_kf_novo),
                caminho_keyfile=caminho_kf_novo,
            )
        finally:
            apagar_buffer(bytes_kf_novo)
            apagar_buffer(novo_segredo_buf)
            del nova_s2, s2_atual
            itens_claros.clear()

        registrar("senha_trocada")
        gravar_cofre_memoria(manter_backup=False, renovar_salt=True)
        self.mostrar_painel_principal()
        resumo = []
        if caminho_kf_novo:
            resumo.append(f"Keyfile ativa ({os.path.basename(caminho_kf_novo)})")
        if COFRE_RAM.tem_segunda_senha():
            resumo.append("Segunda Senha ativa (Scrypt 512 MB)")
        texto_resumo = " + ".join(resumo) if resumo else "Apenas Senha Infra ativa"
        self.lbl_rodape.configure(
            text=f"Configuração salva com sucesso: {texto_resumo}.",
            fg=COR_VERDE_TEXTO
        )

    # ------------------------------------------ aba: auditoria de integridade

    def _mostrar_aba_auditoria(self):
        tk = self.tk
        self._limpar_area_trabalho()

        registrar("auditoria_consultada")
        gravar_cofre_memoria(manter_backup=True, renovar_salt=False)

        ok, msg = verificar_auditoria(COFRE_RAM.meta)

        tk.Label(
            self.area_trabalho, text="AUDITORIA DE INTEGRIDADE",
            font=self.fonte_titulo, bg=COR_PAINEL, fg=COR_TEXTO
        ).pack(anchor="w", pady=(0, 10))

        cor_banner = COR_VERDE if ok else COR_PERIGO
        titulo_banner = "REGISTRO ÍNTEGRO: " if ok else "ALERTA DE ADULTERAÇÃO: "
        banner = tk.Frame(self.area_trabalho, bg=cor_banner, padx=12, pady=8)
        banner.pack(fill="x", pady=(0, 12))
        tk.Label(
            banner, text=titulo_banner + msg,
            font=self.fonte_bold, bg=cor_banner, fg=COR_TEXTO,
            wraplength=520, justify="left"
        ).pack(anchor="w")

        quadro_log = tk.Frame(
            self.area_trabalho, bg=COR_CAMPO,
            highlightthickness=1, highlightbackground=COR_BORDA
        )
        quadro_log.pack(fill="both", expand=True)

        rolagem = tk.Scrollbar(quadro_log, orient="vertical")
        txt_log = tk.Text(
            quadro_log,
            font=self.fonte_mono,
            bg=COR_CAMPO,
            fg=COR_TEXTO,
            relief="flat",
            bd=0,
            padx=10,
            pady=10,
            yscrollcommand=rolagem.set,
        )
        rolagem.config(command=txt_log.yview)
        txt_log.pack(side="left", fill="both", expand=True)
        rolagem.pack(side="right", fill="y")

        for linha in formatar_entradas_auditoria(COFRE_RAM.nomes(), quantas=40):
            txt_log.insert("end", linha + "\n")
        txt_log.see("end")
        txt_log.configure(state="disabled")

    # ------------------------------------------ bloqueio e encerramento GUI

    def bloquear_sessao_gui(self, motivo="Sessão bloqueada."):
        self._ocultar_e_limpar_agora()
        bloquear_sessao_imediato(silencioso=True)
        self.mostrar_tela_login(mensagem_status=motivo)

    def encerrar_seguro(self):
        self._ocultar_e_limpar_agora()
        SESSAO["ativa"] = False
        if COFRE_RAM.aberto and not SESSAO["bloqueado"]:
            registrar("saida")
            try:
                gravar_cofre_memoria(manter_backup=True, renovar_salt=False)
            except Exception:
                pass
        COFRE_RAM.limpar()
        limpar_chave_log()
        try:
            self.raiz.destroy()
        except Exception:
            pass


# Alias para retrocompatibilidade
NuvoltsGUI = NullvoutsGUI


def iniciar_gui():
    proteger_processo()
    import tkinter as tk
    raiz = tk.Tk()
    NullvoutsGUI(raiz)
    raiz.mainloop()


if __name__ == "__main__":
    if "--cli" in sys.argv:
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            main_cli()
        except getpass.GetPassWarning:
            print("Este terminal não consegue esconder a digitação da senha. "
                  "Use um terminal comum.")
            raise SystemExit(1)
    else:
        try:
            iniciar_gui()
        except Exception as erro_gui:
            if sys.stdin.isatty() and sys.stdout.isatty():
                print(f"Ambiente gráfico indisponível ({erro_gui}). Iniciando modo terminal...")
                main_cli()
            else:
                raise