Nullvault
Gerenciador de senhas desktop, 100% offline, com cofre criptografado em AES-256-GCM, derivação de chave Scrypt de 512 MB e proteção contra captura de tela. Zero rede, zero telemetria, zero nuvem.
O Nullvault é um aplicativo em Python com interface gráfica em Tkinter e modo terminal. Ele foi desenhado para que o cofre fique protegido mesmo se alguém roubar o arquivo, copiar a memória ou espiar a tela.
Principais recursos
• 100% offline: o código não abre nenhuma conexão de rede. Tudo roda e fica na sua máquina.
• Criptografia AES-256-GCM: cifra autenticada, que além de esconder os dados detecta qualquer alteração no arquivo.
• Scrypt com 512 MB de RAM por tentativa: cada palpite de senha custa caro, o que inviabiliza ataques por GPU.
• Envelope multi-slot (formato v4): uma chave de dados aleatória é embrulhada em vários slots. Senha Infra, Keyfile e Segunda Senha abrem o cofre por caminhos diferentes.
• Keyfile em pendrive: arquivo de 64 bytes aleatórios que funciona como segundo fator físico. O app detecta o pendrive sozinho.
• Segunda Senha de recuperação: se você perder o pendrive, entra com a Senha Infra mais a Segunda Senha. Ela também passa por Scrypt de 512 MB.
• Proteção contra captura de tela: a janela fica invisível para programas de screenshot e gravação no Windows.
• Área de transferência protegida: o segredo copiado é excluído do histórico do Windows e da nuvem, e some sozinho depois de 15 segundos.
• Segredos protegidos na RAM: cada item fica cifrado individualmente na memória, com buffers travados contra swap e zerados após o uso.
• Bloqueio por inatividade: após 5 minutos parado, o cofre é regravado, apagado da RAM e a sessão trava.
• Anti-força-bruta: espera crescente a cada senha errada, com bloqueio mínimo de 5 minutos a partir da quinta falha.
• Anti-rollback: detecta se alguém restaurou uma cópia antiga do cofre.
• Auditoria encadeada: registro com hash em cadeia e selo HMAC, que acusa qualquer entrada apagada ou alterada.
• Gerador de senhas e frases: senhas aleatórias de 16 ou mais caracteres e frases de 6 palavras sorteadas entre 38.504 palavras de seis idiomas.
• Compatibilidade: abre cofres das versões 0 a 3 e os migra para a versão 4 automaticamente.
Instalação
Requisitos
• Python 3.10 ou superior.
• Biblioteca cryptography.
• Tkinter (já vem com o Python no Windows; no Linux, instale o pacote python3-tk).
• Windows ou Linux. As proteções de tela, de clipboard e de barra de título são mais completas no Windows.
A partir do código-fonte
git clone https://github.com/JotaCyberKiK/Projeto-Nullvault.git
cd Projeto-Nullvault
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux: source .venv/bin/activate
pip install cryptography
python Nullvouts.py
Para abrir no terminal em vez da janela gráfica, use python Nullvouts.py --cli.
Confirme o nome do arquivo principal no seu repositório. No código que você enviou ele aparece como Nullvouts.py.
Início rápido
1.  Abra o app. Na primeira execução ele pede para criar o cofre.
2.  Defina a Senha Infra, com no mínimo 12 caracteres. Se preferir, gere uma frase aleatória.
3.  Opcional: crie a Keyfile no pendrive e defina a Segunda Senha de recuperação.
4.  Adicione seus itens. Cada um tem nome e segredo.
5.  Para consultar, selecione o item. Você pode revelar na tela ou copiar por 15 segundos.
6.  Ao terminar, clique em Bloquear Agora ou em Sair.
Não existe recuperação da Senha Infra. Se você perder a senha e não tiver a Segunda Senha ou a Keyfile, ninguém consegue abrir o cofre, nem você.
Como a segurança funciona
Camada
O que faz
Para que serve
AES-256-GCM
Cifra o cofre e autentica o cabeçalho
Esconde os dados e detecta adulteração
Scrypt, N = 2^19 (512 MB)
Deriva a chave a partir da Senha Infra
Torna cada tentativa lenta e cara
Envelope multi-slot
Embrulha a chave de dados em até 3 slots
Permite abrir por Keyfile, Segunda Senha ou ambas
Keyfile de 64 bytes
Segundo fator guardado no pendrive
Sem o arquivo, a senha sozinha não basta
Proteção de memória
Trava buffers na RAM e zera após o uso
Evita vazar segredo por swap ou dump de memória
Anti-rollback
Guarda âncora do cofre fora da pasta (DPAPI no Windows)
Acusa a troca por uma cópia antiga
Auditoria em cadeia
Hash encadeado e selo HMAC por entrada
Acusa qualquer registro removido ou editado
Captura de tela
Exclui a janela da captura
Impede screenshot e gravação do cofre aberto
O que o Nullvault garante
• O cofre em disco fica sempre cifrado, e o cabeçalho inteiro é autenticado.
• Nenhum dado sai da máquina, porque não há código de rede.
• Os nomes dos itens no registro de auditoria aparecem só como impressão digital HMAC, nunca em texto puro.
• Em caso de erro, o app exige a espera crescente antes de nova tentativa, e esse contador sobrevive a reinícios.
O que o Nullvault não faz
• Não protege contra malware com acesso total ao seu computador enquanto o cofre está aberto.
• Não recupera uma Senha Infra esquecida.
• Não sincroniza entre dispositivos, de propósito.
• A exclusão segura por sobrescrita não é garantida em SSD ou em sistemas de arquivos com journaling.
Verificações automáticas do repositório
O repositório usa GitHub Actions para manter o código seguro: Bandit e Semgrep para análise estática, CodeQL para análise de código, Gitleaks para detecção de segredos, OpenSSF Scorecard para boas práticas e Dependabot para dependências vulneráveis.
Desenvolvimento
git clone https://github.com/JotaCyberKiK/Projeto-Nullvault.git
cd Projeto-Nullvault
pip install cryptography bandit
bandit -r .
Licença
Escolha uma licença, por exemplo MIT ou Apache 2.0, e adicione o arquivo LICENSE. do README.md diretamente no diretório do projeto via terminal?"/>
