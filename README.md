# 🔐 Nullvault

**Gerenciador de senhas offline em Python, com cofre criptografado e foco em privacidade.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Plataformas](https://img.shields.io/badge/Plataformas-Windows%20%7C%20Linux-informational) ![Status](https://img.shields.io/badge/Seguran%C3%A7a-sem%20auditoria%20externa-orange)

O **Nullvault** é um projeto de gerenciador de senhas para desktop, com interface gráfica em **Tkinter** e opção de execução pelo terminal. Seu objetivo é armazenar segredos localmente, sem depender de contas, servidores ou sincronização em nuvem.

> **Aviso:** esta documentação descreve as funcionalidades informadas pelo projeto. A implementação e a eficácia de cada proteção precisam ser verificadas no código e em testes. O Nullvault ainda não passou por auditoria de segurança independente.

## 📚 Sumário

- [Recursos](#-recursos)
- [Arquitetura de segurança](#-arquitetura-de-segurança)
- [Instalação](#-instalação)
- [Como usar](#-como-usar)
- [Auditoria e integridade](#-auditoria-e-integridade)
- [Arquivos locais](#-arquivos-locais)
- [Desenvolvimento e verificações](#-desenvolvimento-e-verificações)
- [Limitações e cuidados](#-limitações-e-cuidados)
- [Contribuições e licença](#-contribuições-e-licença)

## ✨ Recursos

| Área | Funcionalidade descrita |
| --- | --- |
| Armazenamento | Cofre local protegido com **AES-256-GCM** |
| Derivação de chave | **Scrypt** com parâmetro anunciado `N = 2^19` e uso elevado de memória |
| Acesso | **Senha Infra**, **Keyfile** em pendrive e **Segunda Senha** |
| Formato | Envelope criptográfico com múltiplos slots (versão 4) |
| Interface | Aplicação desktop Tkinter e modo terminal (`--cli`) |
| Sessão | Bloqueio por inatividade após **5 minutos** |
| Exibição | Revelação temporária de segredos por **15 segundos** |
| Área de transferência | Limpeza temporizada, com proteções adicionais previstas para Windows |
| Auditoria | Eventos encadeados por hash e autenticados com HMAC |
| Integridade | Mecanismo anti-rollback para alertar sobre restauração de estados anteriores |
| Senhas | Gerador de senhas aleatórias e frases de palavras |
| Compatibilidade | Leitura e migração previstas para formatos antigos de cofre |

Algumas proteções são específicas do sistema operacional, e mecanismos como bloqueio de captura de tela e limpeza de memória **não eliminam o risco de malware com privilégios elevados**.

## 🛡️ Arquitetura de segurança

### Criptografia do cofre

O projeto descreve o uso de **AES-256-GCM**, uma modalidade de criptografia autenticada que protege a confidencialidade dos dados e permite detectar modificações indevidas. O formato v4 usa uma chave de dados aleatória, protegida por slots associados aos fatores de acesso.

### Derivação de chaves

A Senha Infra passa por **Scrypt**, função projetada para tornar tentativas de adivinhação mais custosas em tempo e memória. O parâmetro anunciado é `N = 2^19`, com custo de memória aproximado de 512 MiB na configuração descrita. Esse custo **dificulta**, mas não impossibilita, ataques offline ou por GPU. A configuração efetiva pode variar conforme a implementação e a memória disponível.

### Fatores de acesso

| Configuração | Fatores utilizados |
| --- | --- |
| Básica | Senha Infra |
| Com Keyfile | Senha Infra + arquivo de chave |
| Com Segunda Senha | Senha Infra + Segunda Senha |
| Com ambos configurados | Senha Infra + Keyfile **ou** Senha Infra + Segunda Senha, conforme os slots de recuperação descritos |

A **Keyfile** é descrita como um arquivo de 64 bytes aleatórios, preferencialmente mantido em um pendrive separado. A Segunda Senha oferece uma alternativa de acesso caso o pendrive seja perdido, desde que a Senha Infra ainda seja conhecida.

**Importante:** a Segunda Senha e a Keyfile não devem ser tratadas como meios garantidos de recuperar uma **Senha Infra esquecida**. A recuperação depende dos fatores e slots realmente implementados.

### Proteção de sessão

O projeto descreve criptografia individual de itens em memória, limpeza de buffers sensíveis, bloqueio automático e limitação progressiva de tentativas incorretas. Essas medidas reduzem a exposição, mas não garantem proteção contra captura de teclado, leitura de memória privilegiada ou comprometimento do sistema operacional.

## 💻 Instalação

### Requisitos

- **Python 3.10 ou superior**;
- Biblioteca Python `cryptography`;
- **Tkinter** para a interface gráfica;
- Windows ou Linux.

### Clonar e preparar o ambiente

```bash
git clone https://github.com/JotaCyberKiK/Projeto-Nullvault.git
cd Projeto-Nullvault
python -m venv .venv
```

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\python.exe -m pip install cryptography
.\.venv\Scripts\python.exe Nullvouts.py
```

**Linux (Debian/Ubuntu):**

```bash
sudo apt update
sudo apt install python3-tk
source .venv/bin/activate
python -m pip install cryptography
python Nullvouts.py
```

> O arquivo principal é apresentado na documentação como `Nullvouts.py`. Confira se esse nome corresponde ao arquivo existente no repositório.

### Modo terminal

```bash
python Nullvouts.py --cli
```

Execute em um terminal que permita ocultar a entrada de senhas.

## 🚀 Como usar

1. Inicie o aplicativo e escolha a opção de criar um cofre.
2. Defina uma **Senha Infra forte** (o projeto informa mínimo de 12 caracteres).
3. Opcionalmente, configure uma **Keyfile** em pendrive e uma **Segunda Senha**.
4. Adicione itens com um nome identificador e o segredo correspondente.
5. Consulte os itens pela interface, revelando ou copiando o segredo temporariamente.
6. Ao terminar, utilize **Bloquear Agora** ou **Sair**.

**Guarde os fatores de acesso e os backups em locais seguros e separados.** A perda das credenciais necessárias pode tornar o cofre permanentemente inacessível.

## 🧾 Auditoria e integridade

A documentação do Nullvault descreve um registro `auditoria.log` com eventos como criação e abertura de cofre, falhas de autenticação, alterações de itens, bloqueios e avisos de integridade.

O mecanismo proposto combina:

- **Hash encadeado:** cada registro depende do anterior, permitindo identificar determinadas alterações na sequência;
- **HMAC:** autenticação de eventos quando há uma chave apropriada disponível;
- **Âncora anti-rollback:** referência adicional para detectar determinadas restaurações de estados antigos.

Esses mecanismos são **controles de detecção**, não uma garantia de que toda adulteração será detectada em qualquer cenário.

## 📁 Arquivos locais

| Arquivo ou pasta | Finalidade |
| --- | --- |
| `Nullvouts.py` | Código principal descrito |
| `cofre.dat` | Cofre criptografado |
| `cofre.bak` | Cópia de segurança de uma gravação anterior |
| `tentativas.json` | Estado de tentativas de autenticação |
| `auditoria.log` | Histórico de auditoria |
| `nullvouts.key` | Arquivo de chave, preferencialmente fora do computador |
| `listas/` | Listas opcionais de palavras para o gerador |

### Nunca envie dados sensíveis ao Git

Inclua no `.gitignore`, no mínimo:

```gitignore
# Ambientes e arquivos temporários
.venv/
__pycache__/
*.py[cod]
.pytest_cache/

# Cofres, backups, chaves e dados locais
cofre.dat
cofre.bak
cofre.dat.*
cofre.bak.*
*.key
tentativas.json
auditoria.log

# Arquivos locais de configuração sensível
.env
.env.*
```

> Um `.gitignore` não remove arquivos já enviados ao histórico do Git. Se algum segredo tiver sido publicado, considere-o comprometido e faça a rotação apropriada.

## 🧪 Desenvolvimento e verificações

Para instalar uma ferramenta de análise estática e executá-la localmente:

```bash
python -m pip install bandit
bandit -r .
```

Para priorizar achados de severidade média e alta:

```bash
bandit -r . -ll
```

A documentação do projeto menciona verificações com **Bandit, Semgrep, CodeQL, Gitleaks, OpenSSF Scorecard e Dependabot**. Confirme quais workflows estão realmente presentes e funcionando em `.github/workflows/` antes de declarar que todas essas verificações passam automaticamente.

Resultados de análise estática e testes automatizados ajudam a encontrar problemas, mas **não substituem uma auditoria criptográfica independente**.

### Diretrizes para contribuições

- Não inclua senhas reais, cofres, chaves ou dados pessoais em commits, testes e relatórios.
- Use **cofres fictícios** para testes automatizados.
- Preserve a compatibilidade do formato e teste cuidadosamente rotinas de migração e backup.
- Evite novas dependências de rede sem uma discussão explícita sobre o objetivo offline.
- Trate avisos de segurança como itens a investigar, não como falsos positivos por padrão.

## ⚠️ Limitações e cuidados

O Nullvault é um **projeto independente sem auditoria externa conhecida**. Antes de armazenar credenciais importantes, valide o código, os testes, o comportamento de backup e o processo de recuperação.

- Um computador comprometido pode expor senhas enquanto o cofre está aberto.
- A proteção contra captura de tela no Windows não impede fotos do monitor nem todas as formas de captura.
- A limpeza da área de transferência não garante remoção de cópias já feitas por outros processos.
- A exclusão por sobrescrita não garante apagamento físico em SSDs e sistemas de arquivos com journaling.
- A proteção de memória depende das permissões e dos recursos disponíveis no sistema operacional.
- O projeto não oferece sincronização em nuvem como recurso central.

**Não confunda recursos descritos com propriedades de segurança formalmente comprovadas.**

## 🤝 Contribuições e licença

Sugestões, correções e testes são bem-vindos por meio de issues e pull requests, observando as configurações de acesso do repositório.

Para reportar uma possível vulnerabilidade, **evite publicar detalhes exploráveis em uma issue pública**. Prefira um canal privado disponibilizado pelo mantenedor.

**Licença:** ainda precisa ser definida pelo mantenedor. Adicione um arquivo `LICENSE` antes de declarar o projeto sob uma licença específica.

---

**Desenvolvido por [JotaCyberKiK](https://github.com/JotaCyberKiK).**

*Nullvault — controle local dos seus segredos, com transparência sobre os limites de segurança.*
