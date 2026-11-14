# 🔐 Nullvault

**Gerenciador de senhas local em Python, com cofre criptografado, interface gráfica e modo terminal.**

O **Nullvault** é um projeto de gerenciador de senhas para desktop voltado ao armazenamento local de credenciais. Foi concebido para funcionar **sem conta, servidor, telemetria ou sincronização em nuvem**, com interface em **Tkinter** e opção de uso pelo terminal.

> **Estado da documentação:** os recursos técnicos abaixo foram organizados a partir da descrição fornecida pelo projeto. Eles **não representam uma auditoria do código-fonte** nem uma certificação de segurança. É necessário conferir a implementação e executar testes antes de afirmar que todas as proteções funcionam como descrito.

## Sumário

- [Visão geral](#visão-geral)
- [Recursos principais](#recursos-principais)
- [Segurança e fatores de acesso](#segurança-e-fatores-de-acesso)
- [Funcionamento do cofre](#funcionamento-do-cofre)
- [Requisitos e instalação](#requisitos-e-instalação)
- [Como usar](#como-usar)
- [Auditoria e proteção anti-rollback](#auditoria-e-proteção-anti-rollback)
- [Formato do cofre e arquivos locais](#formato-do-cofre-e-arquivos-locais)
- [Desenvolvimento e verificações](#desenvolvimento-e-verificações)
- [Limitações de segurança](#limitações-de-segurança)
- [Perguntas frequentes](#perguntas-frequentes)
- [Contribuições e licença](#contribuições-e-licença)

## Visão geral

O objetivo do Nullvault é manter senhas e outros segredos em um **arquivo criptografado no computador do usuário**, sem exigir serviços externos para abrir ou gerenciar o cofre.

O projeto descreve as seguintes características:

- Aplicativo em **Python 3.10+**, com interface gráfica em **Tkinter**.
- **Modo terminal** para uso sem interface gráfica (`--cli`).
- Criptografia autenticada com **AES-256-GCM**.
- Derivação de chaves de senha com **Scrypt**.
- Autenticação por **Senha Infra**, com **Keyfile** e **Segunda Senha** opcionais.
- Gerador de senhas e de frases aleatórias.
- Recursos de proteção da sessão, registro de eventos e detecção de alterações.
- Proposta de funcionamento local, sem sincronização automática em nuvem.

**Importante:** o projeto busca reduzir riscos, mas não garante proteção absoluta contra invasões, malware ou comprometimento do sistema operacional.

## Recursos principais

| Categoria | Funcionalidade descrita |
| --- | --- |
| Criptografia | Cofre protegido com AES-256-GCM e autenticação dos dados associados |
| Derivação de chaves | Scrypt, com parâmetro documentado `N = 2^19` |
| Formato | Envelope criptográfico de múltiplos slots (versão 4) |
| Acesso | Senha Infra e, opcionalmente, Keyfile e Segunda Senha |
| Keyfile | Arquivo de chave de 64 bytes, preferencialmente armazenado em pendrive |
| Interface | Tkinter e modo terminal |
| Bloqueio | Bloqueio automático após 5 minutos de inatividade, conforme documentação |
| Exibição de senhas | Revelação temporária por 15 segundos, conforme documentação |
| Área de transferência | Limpeza temporizada, com medidas adicionais previstas para Windows |
| Gerador | Senhas aleatórias e frases com palavras selecionadas aleatoriamente |
| Auditoria | Registro de eventos com hash encadeado e HMAC |
| Integridade | Detecção de determinadas restaurações de versões antigas do cofre (*anti-rollback*) |
| Compatibilidade | Suporte descrito para leitura e migração de cofres antigos para o formato v4 |

### Gerador de senhas e frases

A documentação descreve o uso do módulo `secrets` do Python para sorteios criptograficamente apropriados. Entre as opções anunciadas estão senhas com letras, números e símbolos e frases de **seis palavras**. A lista de palavras é descrita como um conjunto de **38.504 palavras de seis idiomas**.

Esses números e os critérios de qualidade precisam ser conferidos no código. Uma estimativa de entropia não substitui uma avaliação real da aleatoriedade e da forma como palavras e caracteres são selecionados.

## Segurança e fatores de acesso

### AES-256-GCM

O **AES-256-GCM** é um modo de criptografia autenticada. Ele protege a confidencialidade do conteúdo e permite detectar alterações nos dados autenticados, desde que o mecanismo seja usado corretamente, incluindo geração e gestão seguras de chaves e *nonces*.

Segundo a documentação, o formato v4 usa uma **chave de dados aleatória**, que protege o conteúdo do cofre. Os fatores de acesso são utilizados para proteger essa chave por meio de slots criptográficos. Isso separa a chave que cifra os dados das credenciais usadas para desbloqueá-los.

### Scrypt e custo de memória

O **Scrypt** aumenta o custo de tentativas de adivinhação de senha, exigindo processamento e memória. O parâmetro documentado para o Nullvault é `N = 2^19`.

Na configuração comum `r = 8`, esse valor corresponde a um consumo básico aproximado de **512 MiB** de memória por operação (`128 × N × r` bytes), além de possíveis custos adicionais. **O valor real depende também dos parâmetros `r` e `p` e da implementação.**

O Scrypt **dificulta, mas não inviabiliza**, ataques de força bruta com GPU ou equipamentos especializados. Uma senha fraca continua sendo arriscada. A documentação também menciona redução adaptativa do custo em máquinas com pouca memória; se implementada, essa redução precisa ser registrada e considerada no nível de segurança efetivo do cofre.

### Senha Infra, Keyfile e Segunda Senha

A **Senha Infra** é a credencial principal. A documentação indica mínimo de **12 caracteres** e verificações adicionais de qualidade.

A **Keyfile** é descrita como um arquivo de **64 bytes aleatórios**, que pode ser guardado em um pendrive. A **Segunda Senha** é uma credencial opcional que pode oferecer uma alternativa de acesso caso o pendrive seja perdido.

| Configuração | Credenciais exigidas para abrir, segundo a documentação |
| --- | --- |
| Somente Senha Infra | Senha Infra |
| Senha Infra + Keyfile | Senha Infra **e** Keyfile |
| Senha Infra + Segunda Senha | Senha Infra **e** Segunda Senha |
| Keyfile e Segunda Senha configuradas | Senha Infra **e** Keyfile **ou** Senha Infra **e** Segunda Senha, conforme o slot utilizado |

**Atenção sobre recuperação:** todos os caminhos de abertura descritos exigem a **Senha Infra**. Assim, **perder ou esquecer a Senha Infra não é resolvido apenas por possuir a Keyfile ou a Segunda Senha**. A Segunda Senha é uma alternativa para a *perda da Keyfile*, não uma substituta garantida para a senha principal.

Quando tanto a Keyfile quanto a Segunda Senha estiverem configuradas, recomenda-se manter a Segunda Senha em local separado do pendrive, sem armazenar tudo junto ao cofre.

### Proteção da sessão e da memória

A documentação descreve medidas como:

- Manter itens individualmente cifrados enquanto estão na memória, com uma chave de sessão.
- Utilizar buffers mutáveis para reduzir o tempo de permanência de segredos em texto puro.
- Tentar travar determinados buffers contra paginação (*swap*) e zerá-los após o uso.
- Restringir *core dumps* e algumas formas de depuração no Linux, quando permitido pelo sistema.
- Ocultar segredos exibidos após um período e bloquear a sessão por inatividade.
- Aplicar espera progressiva diante de tentativas incorretas de autenticação.

Essas medidas **dependem do sistema operacional e da implementação**. Python, bibliotecas e componentes gráficos podem criar cópias temporárias de valores em memória. Portanto, não é correto afirmar que nenhum segredo jamais poderá ser obtido de um processo comprometido.

### Captura de tela e área de transferência

No Windows, o projeto descreve o uso de mecanismos do sistema para **reduzir a exposição da janela em programas comuns de captura**. Isso não impede necessariamente todas as técnicas de gravação, ferramentas privilegiadas, acesso remoto ou uma câmera apontada para o monitor.

O projeto também descreve a **limpeza da área de transferência após 15 segundos**. A limpeza não recupera segredos que outro processo tenha lido ou copiado antes dela. Os comportamentos e recursos disponíveis podem ser diferentes no Linux.

## Funcionamento do cofre

De acordo com a arquitetura documentada, o fluxo de abertura é aproximadamente este:

1. O usuário informa a **Senha Infra** e, conforme a configuração, uma **Keyfile** ou uma **Segunda Senha**.
2. A aplicação utiliza **Scrypt** e os fatores aplicáveis para obter material criptográfico de desbloqueio.
3. Um **slot** válido permite recuperar a chave de dados aleatória protegida no cabeçalho.
4. A aplicação autentica e decifra o conteúdo com **AES-256-GCM**.
5. Os itens ficam disponíveis durante a sessão, com as medidas de proteção em memória descritas pelo projeto.
6. Ao bloquear ou encerrar, o programa deve salvar e encerrar a sessão de maneira segura, tratando erros de gravação e preservando a recuperabilidade do cofre.

A descrição original menciona também **HMAC-SHA256**, *salts* aleatórios e campos autenticados no cabeçalho. Os detalhes exatos da combinação de fatores, da derivação de chaves e da serialização **devem ser confirmados no código da versão publicada**.

## Requisitos e instalação

### Requisitos

- **Python 3.10 ou superior**.
- Biblioteca Python [`cryptography`](https://pypi.org/project/cryptography/).
- **Tkinter** para usar a interface gráfica.
- **Windows ou Linux**, com diferenças nas proteções disponíveis.
- Memória compatível com o custo de Scrypt configurado.

### Obter o código

```bash
git clone https://github.com/JotaCyberKiK/Projeto-Nullvault.git
cd Projeto-Nullvault
```

> Se o repositório estiver **privado**, o comando `git clone` exigirá autenticação de uma conta com permissão de acesso.

### Windows 10/11 — PowerShell

Execute os comandos na pasta do projeto:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install cryptography
.\.venv\Scripts\python.exe .\Nullvouts.py
```

Os comandos utilizam diretamente o Python do ambiente virtual, **sem exigir a ativação de scripts do PowerShell**.

### Linux — Ubuntu/Debian

```bash
sudo apt update
sudo apt install python3 python3-venv python3-tk
python3 -m venv .venv
./.venv/bin/python -m pip install cryptography
./.venv/bin/python Nullvouts.py
```

Outras distribuições podem utilizar gerenciadores de pacotes e nomes de pacotes diferentes.

### Modo terminal

**Windows:**

```powershell
.\.venv\Scripts\python.exe .\Nullvouts.py --cli
```

**Linux:**

```bash
./.venv/bin/python Nullvouts.py --cli
```

Use um terminal que permita ocultar a digitação das senhas. A interface gráfica requer um ambiente com suporte a janelas.

> **Nome do arquivo:** a documentação recebida identifica o programa principal como `Nullvouts.py`. O nome foi **mantido intencionalmente**, pois não é possível concluir que seja um erro de digitação sem verificar o arquivo real no repositório.

## Como usar

### Criar o primeiro cofre

1. Inicie o aplicativo.
2. Se ainda não houver cofre, escolha a opção de criação.
3. Defina uma **Senha Infra forte** e confirme-a.
4. Se desejar, configure uma **Segunda Senha** e/ou crie uma **Keyfile** no pendrive.
5. Conclua a criação e mantenha uma **cópia de segurança protegida**.

A documentação menciona a criação de `cofre.dat` e indica que o caminho de armazenamento pode variar conforme a execução ou o empacotamento do aplicativo. Confira o local utilizado na sua instalação.

### Desbloquear o cofre

1. Abra o Nullvault e informe a **Senha Infra**.
2. Se a configuração exigir Keyfile, conecte o pendrive que contém `nullvouts.key`.
3. Se você **perdeu o pendrive**, mas configurou anteriormente uma **Segunda Senha**, utilize o caminho de acesso com **Senha Infra + Segunda Senha**.
4. Confirme a abertura.

Não dependa de uma opção de recuperação que não tenha sido configurada e testada antes da perda de um fator.

### Gerenciar senhas

A interface descrita possui uma lista pesquisável de itens e áreas destinadas a:

- **Inspecionar item:** visualizar, copiar temporariamente ou excluir um segredo.
- **Adicionar / Editar:** cadastrar ou atualizar itens.
- **Gerador de senhas:** criar senhas e frases aleatórias.
- **Senha Infra / Keyfile:** administrar os fatores de acesso.
- **Auditoria:** consultar registros e avisos de integridade.

Os nomes e a disposição dos botões podem variar entre versões.

### Bloqueio, saída e backups

A documentação informa bloqueio automático após **300 segundos (5 minutos)** de inatividade, além de opções de bloqueio manual e encerramento. O programa deve tratar a gravação do cofre antes de descartar o estado necessário à recuperação.

O arquivo `cofre.bak`, quando presente, pode representar uma cópia anterior. **Não o apague nem o restaure manualmente sem confirmar o estado do cofre e o procedimento de recuperação.** Uma cópia antiga pode não conter alterações recentes e pode gerar avisos de *rollback*.

## Auditoria e proteção anti-rollback

### Registro de eventos

A documentação descreve o arquivo `auditoria.log`, usado para registrar eventos como:

- Criação, abertura e migração do cofre.
- Tentativas de autenticação incorretas e bloqueios.
- Inclusão, alteração, consulta e exclusão de itens.
- Alterações nos fatores de acesso.
- Bloqueio da sessão, encerramento e alertas de integridade.

O mecanismo descrito usa **hash encadeado** para relacionar entradas e **HMAC** para autenticar determinados eventos. Os nomes de itens seriam representados no log por identificadores HMAC abreviados, em vez de texto puro.

Hash encadeado e HMAC podem detectar **determinadas** alterações ou falsificações; sua eficácia depende da gestão da chave, da continuidade dos registros e de âncoras confiáveis. Não são prova de que todo ataque será sempre detectado.

### Anti-rollback

O objetivo do *anti-rollback* é alertar quando um cofre antigo é colocado no lugar de uma versão mais recente. A documentação descreve uma referência de integridade guardada no cofre e outra fora da pasta de dados, com proteção adicional via **DPAPI no Windows** e uma área de dados do usuário no **Linux**.

Esse recurso depende do estado da máquina, das permissões e de como backups e migrações são realizados. **Restaurar um backup legítimo também pode disparar alertas**; a presença de um alerta, isoladamente, não comprova ataque.

## Formato do cofre e arquivos locais

### Estrutura documentada do formato v4

A descrição original informa:

| Campo ou área | Descrição informada |
| --- | --- |
| Identificador | `NVLT` (4 bytes) |
| Versão | `4` |
| Parâmetro Scrypt | Valor de `log2(N)` registrado no cabeçalho |
| Indicadores | Flags associadas à Keyfile e à Segunda Senha |
| *Salts* | Valores usados na derivação de chaves |
| Slots | Estruturas que protegem a chave de dados |
| Corpo | *Nonce* e dados criptografados/autenticados com AES-GCM |
| Preenchimento | Preenchimento em blocos, descrito como múltiplos de 1.024 bytes |

**Correção de inconsistência:** uma parte da documentação anterior dizia que o envelope tinha **até três slots**, mas a descrição binária do formato informa **de um a quatro slots**. Aqui, o limite físico informado para o **formato v4** é de **até quatro slots**; isso não significa que existam quatro métodos de abertura. A validação definitiva depende do código que grava e lê o formato.

O preenchimento pode reduzir a precisão de inferências feitas a partir do tamanho do arquivo, mas **não garante ocultar a quantidade de itens**.

### Arquivos associados

| Arquivo ou pasta | Finalidade descrita |
| --- | --- |
| `Nullvouts.py` | Programa principal |
| `cofre.dat` | Cofre criptografado |
| `cofre.bak` | Backup de uma gravação anterior, quando existir |
| `tentativas.json` | Estado local das tentativas de acesso |
| `auditoria.log` | Registro de eventos |
| `nullvouts.key` | Keyfile mantida preferencialmente em dispositivo separado |
| `listas/` | Listas opcionais para o gerador de frases |

A localização e as permissões reais desses arquivos podem variar conforme a plataforma, a versão e a forma de instalação.

### Proteja o repositório com `.gitignore`

Nunca publique cofres reais, cópias de segurança, chaves ou arquivos com segredos. Um exemplo inicial de `.gitignore` é:

```gitignore
# Python
.venv/
__pycache__/
*.py[cod]
.pytest_cache/

# Segredos e dados locais do Nullvault
cofre.dat
cofre.bak
cofre.dat.*
cofre.bak.*
*.key
tentativas.json
auditoria.log

# Configurações locais sensíveis
.env
.env.*
```

> **Atenção:** o `.gitignore` impede o rastreamento de arquivos novos que correspondam às regras, mas **não retira arquivos já versionados nem apaga o histórico do Git**. Se um segredo foi publicado, considere sua substituição e a remoção segura do histórico com orientação adequada.

## Desenvolvimento e verificações

### Organização do código

A documentação descreve o programa em módulos lógicos dentro do arquivo principal, incluindo:

- Proteção de memória e integração com o sistema operacional.
- Leitura da Keyfile, gerenciamento de arquivos e backups.
- Derivação de chaves, criptografia e migração do formato do cofre.
- Regras e geração de senhas.
- Bloqueio por tentativas e registro de auditoria.
- Interface de terminal e interface Tkinter.

### Executar verificações locais

Para instalar e executar o **Bandit** com um ambiente virtual já criado:

**Windows:**

```powershell
.\.venv\Scripts\python.exe -m pip install bandit
.\.venv\Scripts\python.exe -m bandit -r .
```

**Linux:**

```bash
./.venv/bin/python -m pip install bandit
./.venv/bin/python -m bandit -r .
```

Para visualizar somente os achados de severidade média e alta, acrescente `-ll` ao comando do Bandit. Os avisos precisam ser **avaliados individualmente**; não devem ser descartados automaticamente como falsos positivos.

### Testes e integração contínua

A documentação menciona **Bandit, Semgrep, CodeQL, Gitleaks, OpenSSF Scorecard e Dependabot**. Contudo, citar ferramentas não comprova que todos os respectivos workflows estão instalados, habilitados ou passando.

Antes de divulgar resultados, confira os arquivos em `.github/workflows/`, as configurações de segurança e o histórico de execução do **GitHub Actions**. Execuções com falha devem ser investigadas. Essas ferramentas complementam, mas **não substituem**, testes funcionais e uma auditoria de segurança independente.

Ao contribuir, utilize **cofres fictícios** e ambiente isolado para validar alterações, especialmente nas rotinas de gravação, restauração e migração. Nunca teste alterações destrutivas diretamente em cofres reais.

## Limitações de segurança

O Nullvault é apresentado como um projeto independente **sem auditoria externa de segurança informada**. Algumas limitações importantes:

- **Malware ou sistema comprometido:** um atacante com privilégios suficientes pode registrar teclas, observar a tela ou tentar acessar dados durante o uso.
- **Senha Infra perdida:** os caminhos de recuperação descritos exigem conhecer a Senha Infra; a Keyfile e a Segunda Senha não a substituem.
- **Capturas de tela:** as medidas do Windows podem reduzir capturas comuns, mas não bloqueiam todas as técnicas de gravação.
- **Área de transferência:** limpar o conteúdo não apaga cópias obtidas anteriormente por outros processos.
- **Memória:** travamento e limpeza de buffers são medidas de redução de exposição, não garantias de ausência de cópias.
- **SSD e backups:** a sobrescrita não garante apagamento físico definitivo em SSDs, sistemas com *journaling*, snapshots ou mecanismos semelhantes.
- **Anti-rollback e auditoria:** mecanismos de detecção têm limites e podem apresentar alertas em restaurações legítimas.
- **Armazenamento local:** não há sincronização automática prevista; cabe ao usuário manter backups seguros e verificar sua recuperabilidade.

**Não armazene credenciais críticas confiando apenas nas alegações desta documentação.** Revise a implementação, execute testes e mantenha cópias de segurança apropriadas.

## Perguntas frequentes

### Esqueci a Senha Infra. A Keyfile ou a Segunda Senha resolvem?

**Não, segundo os caminhos de acesso documentados.** Eles exigem a Senha Infra. A Segunda Senha foi descrita como alternativa para a perda da Keyfile, não como recuperação da senha principal esquecida.

### Perdi o pendrive com a Keyfile. E agora?

Se você **já havia configurado a Segunda Senha**, a documentação prevê abrir com **Senha Infra + Segunda Senha**. Se não existir outro slot de acesso válido, a perda da Keyfile poderá impedir a abertura.

### Posso usar o mesmo cofre em dois computadores?

A proposta é local e sem sincronização automática. Copiar arquivos pode exigir cuidados com **âncoras anti-rollback, fatores de acesso, backups e versões do formato**. Teste o procedimento com um cofre fictício antes de migrar dados importantes.

### O Nullvault precisa da internet?

O funcionamento **offline é um objetivo declarado** do projeto. Esta revisão documental não verificou a ausência de chamadas de rede no código ou em dependências externas.

### Por que a abertura pode demorar?

O Scrypt foi projetado para consumir recursos de processamento e memória. A duração depende do hardware e dos parâmetros efetivamente utilizados.

### Posso confiar que a auditoria do GitHub não encontrou falhas?

Não somente por existir um workflow. Confira se as verificações realmente **executaram e passaram**, analise os achados e considere uma auditoria independente para avaliar propriedades criptográficas.

## Contribuições e licença

Correções de código, testes e sugestões de melhoria podem ser enviadas por **issues** e **pull requests**, quando habilitados pelo mantenedor.

Se identificar uma vulnerabilidade, **evite publicar os detalhes de exploração em uma issue pública**. Utilize um canal privado disponibilizado pelo responsável pelo repositório.

**Licença:** não foi possível confirmar uma licença específica a partir dos materiais recebidos. O mantenedor deve definir os termos e incluir um arquivo `LICENSE` antes de apresentar o projeto como MIT, Apache-2.0 ou outra licença.

---

**Projeto de [JotaCyberKiK](https://github.com/JotaCyberKiK)**  
*Nullvault — armazenamento local de segredos, com transparência sobre suas proteções e limitações.*
