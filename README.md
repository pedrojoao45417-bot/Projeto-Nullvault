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
Escolha uma licença, por exemplo MIT ou Apache 2.0, e adicione o arquivo LICENSE.
Desenvolvido por Jota.
Versão detalhada para o README.md
Nullvault
Gerenciador de senhas desktop, 100% offline, com cofre criptografado em AES-256-GCM, derivação de chave Scrypt de 512 MB e proteção contra captura de tela.
Zero conexões externas. Zero telemetria. Zero dependência da nuvem. Privacidade absoluta.
Sumário
1.  Visão geral
2.  Principais recursos
3.  Como o cofre funciona por dentro
4.  Segurança em detalhe
5.  Instalação
6.  Como usar
7.  Auditoria de integridade
8.  Formato do arquivo
9.  Estrutura do projeto
10.  Verificações automáticas
11.  Desenvolvimento
12.  Perguntas frequentes
13.  Licença
Visão geral
O Nullvault é um aplicativo desktop seguro, escrito em Python, para guardar senhas localmente. Ele tem interface gráfica em Tkinter, com tema escuro, e também um modo terminal.
O projeto foi construído para rodar de forma isolada. O código não abre nenhuma conexão de rede, não coleta métricas e não depende de conta ou servidor. Tudo o que você guarda fica num arquivo criptografado na própria pasta do aplicativo.
A ideia central é simples: mesmo que alguém roube o arquivo do cofre, copie a memória do processo ou espie a sua tela, os dados continuam protegidos.
Principais recursos
Criptografia e derivação de chave
• AES-256-GCM: cifra autenticada. Além de esconder os dados, detecta qualquer alteração no arquivo. O cabeçalho inteiro entra como dado associado, então ninguém consegue trocar o formato sem quebrar a autenticação.
• Scrypt com N = 2^19: cada tentativa de senha exige cerca de 512 MB de RAM. Isso torna ataques por GPU e por hardware dedicado caros demais para valer a pena.
• Adaptação à memória disponível: se a máquina não tiver RAM suficiente, o aplicativo reduz o custo do Scrypt passo a passo, em vez de travar.
• Envelope multi-slot (formato v4): o conteúdo é cifrado com uma chave de dados aleatória. Essa chave é embrulhada em um a três slots, e cada slot é aberto por uma combinação diferente de fatores.
Fatores de autenticação
• Senha Infra: a senha principal, com no mínimo 12 caracteres e filtro de qualidade.
• Keyfile em pendrive: um arquivo de 64 bytes aleatórios que funciona como segundo fator físico. O aplicativo detecta o pendrive sozinho.
• Segunda Senha: serve para usar junto com a Keyfile e também como recuperação. Se você perder o pendrive, entra com a Senha Infra mais a Segunda Senha. Ela passa pelo mesmo Scrypt de 512 MB.
Proteção do processo e da memória
• Segredos cifrados na RAM: cada item fica cifrado individualmente em memória, com uma chave de sessão que existe só enquanto o cofre está aberto.
• Mascaramento por XOR: a chave de sessão e o segredo mestre ficam mascarados na memória, nunca inteiros em um único lugar.
• Buffers travados e zerados: os buffers sensíveis são travados na memória física, para não irem ao swap, e zerados assim que deixam de ser usados.
• Sem core dump e sem ptrace: no Linux, o processo desativa core dumps, bloqueia depuradores e tenta travar as páginas na RAM.
Proteção da interface
• Anti-captura de tela: no Windows, a janela fica invisível para programas de screenshot e de gravação.
• Área de transferência protegida: o segredo copiado é marcado para ficar fora do histórico do Windows e da sincronização em nuvem, e é apagado sozinho depois de 15 segundos.
• Revelação temporária: o segredo na tela some depois de 15 segundos, com contagem regressiva visível.
• Bloqueio por inatividade: depois de 5 minutos sem uso, o cofre é regravado, removido da RAM e a sessão trava.
• Barra de título escura: a janela usa barra de título preta com letras brancas, no Windows 10 e 11 e no Linux.
Defesas contra ataques
• Anti-força-bruta: espera crescente a cada senha errada. A partir da quinta falha, o bloqueio é de no mínimo 5 minutos.
• Contador que sobrevive a reinícios: o estado das tentativas é guardado em dois lugares, e o app sempre usa o pior dos dois. Apagar o arquivo de tentativas não zera o bloqueio.
• Anti-rollback: detecta se alguém restaurou uma cópia antiga do cofre para voltar a um estado anterior.
• Auditoria encadeada: registro de eventos com hash em cadeia e selo HMAC, que acusa qualquer entrada apagada, editada ou reordenada.
• Tamanho do cofre escondido: o arquivo é preenchido em blocos de 1024 bytes, então o tamanho exato não revela quantos itens existem.
Ferramentas de senha
• Gerador de senhas aleatórias: de 16 caracteres ou mais, com letras maiúsculas, minúsculas, números e símbolos, sorteados com secrets.
• Gerador de frases: 6 palavras sorteadas entre 38.504 palavras embutidas, de seis idiomas, com número opcional.
• Filtro de senha fraca: recusa sequências, padrões de teclado, palavras óbvias e senhas com entropia baixa demais.
Compatibilidade
• Migração automática: abre cofres das versões 0, 1, 2 e 3 e os converte para a versão 4 sem perder dados.
• Backup automático: mantém uma cópia anterior, cofre.bak, e a destrói quando você apaga um item, para não reter o segredo antigo.
Como o cofre funciona por dentro
Quando você abre o cofre, o aplicativo executa estes passos:
1.  Pega a Senha Infra e a transforma em um segredo de 32 bytes com HMAC-SHA256.
2.  Aplica o Scrypt de 512 MB sobre esse segredo, usando um salt aleatório gravado no cabeçalho.
3.  Combina o resultado com a Keyfile e, se houver, com a Segunda Senha. Isso gera a chave que abre um dos slots.
4.  Abre o slot e obtém a chave de dados, uma chave aleatória de 32 bytes.
5.  Decifra o conteúdo com AES-256-GCM, verificando o cabeçalho como dado associado.
6.  Recifra cada item individualmente com uma chave de sessão nova e guarda só isso na RAM.
A chave de dados nunca é derivada da senha. Ela é sorteada, e a senha apenas abre o slot que a guarda. Por isso dá para trocar senha, Keyfile ou Segunda Senha sem recifrar tudo do zero.
Segurança em detalhe
Camadas de proteção
Camada
O que faz
Para que serve
AES-256-GCM
Cifra o cofre e autentica o cabeçalho inteiro
Esconde os dados e detecta adulteração
Scrypt, N = 2^19 (512 MB)
Deriva a chave a partir da Senha Infra
Torna cada tentativa lenta e cara
Envelope multi-slot
Embrulha a chave de dados em até 3 slots
Abre por Keyfile, Segunda Senha ou ambas
Keyfile de 64 bytes
Segundo fator guardado no pendrive
Sem o arquivo, a senha sozinha não basta
Proteção de memória
Cifra itens na RAM, trava buffers e zera após o uso
Evita vazar segredo por swap ou dump de memória
Anti-rollback
Guarda uma âncora do cofre fora da pasta
Acusa a troca por uma cópia antiga
Auditoria em cadeia
Hash encadeado e selo HMAC por entrada
Acusa qualquer registro removido ou editado
Anti-captura de tela
Exclui a janela da captura
Impede screenshot e gravação do cofre aberto
Anti-força-bruta
Espera crescente e bloqueio persistente
Limita o número de palpites por hora
Defesas contra cada tipo de ataque
Ataque
Como o Nullvault se defende
Roubo do arquivo cofre.dat
O arquivo é AES-256-GCM. Sem a senha, o Scrypt de 512 MB torna cada palpite muito caro, e a Keyfile adiciona um segundo fator.
Força bruta com GPU
O Scrypt exige 512 MB de RAM por tentativa, o que inviabiliza paralelismo massivo em GPU.
Força bruta no próprio aplicativo
Espera crescente a cada erro, com bloqueio de pelo menos 5 minutos a partir da quinta falha.
Apagar o arquivo de tentativas para zerar o bloqueio
O estado é duplicado numa guarda do sistema. O app usa o pior dos dois, então apagar um não ajuda.
Restaurar uma cópia antiga do cofre
A âncora guardada fora da pasta acusa que o cofre regrediu.
Editar ou apagar linhas do registro
O hash em cadeia e o selo HMAC acusam a entrada alterada ou removida.
Trocar o cabeçalho do cofre
O cabeçalho é dado associado do AES-GCM, e qualquer mudança quebra a autenticação.
Link simbólico no lugar da Keyfile
O app recusa links e dispositivos, e só lê arquivo comum de até 1 MB.
Captura de tela e gravação
No Windows, a janela é excluída da captura.
Espionar o histórico da área de transferência
O segredo é marcado para ficar fora do histórico e da nuvem, e é apagado em 15 segundos.
Despejo de memória (core dump)
No Linux, os core dumps são desativados e o ptrace é bloqueado.
Segredos que sobram na RAM
Os buffers são zerados após o uso, e os itens ficam cifrados individualmente.
Descobrir o número de itens pelo tamanho
O arquivo é preenchido em blocos de 1024 bytes.
Trocar a lista de palavras do gerador
A lista embutida tem hash SHA-256 fixo, conferido a cada uso.
Regras de senha
A Senha Infra e a Segunda Senha seguem o mesmo padrão rigoroso, para que o slot de recuperação nunca seja o elo fraco:
• No mínimo 12 caracteres.
• No mínimo 6 caracteres diferentes.
• Sem sequências como abcd ou 1234, sem linhas do teclado como qwerty e sem palavras óbvias como senha ou admin.
• Entropia estimada de pelo menos 60 bits depois de descontar os padrões.
• A Segunda Senha precisa ser diferente da Senha Infra.
Se preferir não inventar uma senha, use o gerador de frases. Ele sorteia 6 palavras entre 38.504 opções, o que dá uma força muito acima do mínimo exigido.
O que o Nullvault garante
• O cofre em disco fica sempre cifrado, e o cabeçalho inteiro é autenticado.
• Nenhum dado sai da máquina, porque não existe código de rede.
• Os nomes dos itens aparecem no registro de auditoria só como impressão digital HMAC, nunca em texto puro.
• O contador de tentativas erradas sobrevive a reinícios e a tentativas de apagá-lo.
• Trocar a senha, a Keyfile ou a Segunda Senha exige provar que você já tem o segundo fator atual.
Limites e o que o Nullvault não faz
Segurança honesta inclui dizer o que não está coberto:
• Malware com acesso total: se o computador já estiver comprometido enquanto o cofre está aberto, um programa malicioso com privilégios pode ler a memória ou registrar o teclado. Nenhum gerenciador de senhas resolve isso sozinho.
• Sem recuperação: se você perder a Senha Infra e não tiver a Segunda Senha nem a Keyfile, ninguém abre o cofre. Isso é proposital.
• Sem sincronização: o cofre não vai para outro dispositivo, de propósito. Se quiser levar para outro computador, copie o arquivo manualmente.
• Exclusão segura limitada: a sobrescrita de arquivos não é garantida em SSD nem em sistemas de arquivos com journaling.
• Proteções por sistema: a anti-captura de tela, a proteção do clipboard e a guarda do sistema com DPAPI funcionam plenamente no Windows. No Linux, parte delas tem comportamento mais simples.
• Perda do pendrive e da Segunda Senha: se perder os dois ao mesmo tempo, o cofre não abre.
Instalação
Requisitos
• Python 3.10 ou superior.
• Biblioteca cryptography, usada para AES-GCM e Scrypt.
• Tkinter, para a interface gráfica. No Windows ele já vem com o Python. No Linux, instale o pacote python3-tk.
• Memória livre: cerca de 512 MB de RAM por abertura do cofre, por causa do Scrypt. Em máquinas com menos memória, o app reduz o custo automaticamente.
• Sistema operacional: Windows ou Linux. As proteções de tela, de área de transferência e de barra de título são mais completas no Windows.
Instalando a partir do código-fonte
git clone https://github.com/JotaCyberKiK/Projeto-Nullvault.git
cd Projeto-Nullvault
python -m venv .venv
Ative o ambiente virtual. No Windows, use .venv\Scripts\activate. No Linux, use source .venv/bin/activate.
pip install cryptography
python Nullvouts.py
No código que você enviou, o arquivo principal se chama Nullvouts.py. Confirme o nome certo no seu repositório antes de publicar.
Instalando no Linux
sudo apt-get install python3-tk
pip install cryptography
python3 Nullvouts.py
Modo terminal
Para usar sem a janela gráfica, por exemplo num servidor ou por SSH:
python Nullvouts.py --cli
O modo terminal exige um terminal de verdade, que esconda a digitação da senha. Consoles de algumas IDEs mostram a senha enquanto você digita, e o app recusa rodar nesses casos.
Gerando um executável
O aplicativo detecta quando roda empacotado, por exemplo com PyInstaller, e passa a guardar o cofre ao lado do executável. Se quiser um ícone próprio, coloque um arquivo nullvouts.ico na mesma pasta.
Como usar
Primeira execução: criando o cofre
1.  Abra o aplicativo. Se não existir cofre, aparece a tela de criação.
2.  Digite a Senha Infra e confirme. Mínimo de 12 caracteres, com filtro de qualidade.
3.  Se preferir, clique em Gerar Frase p/ Senha Infra. O app sorteia 6 palavras. Anote a frase em papel, em lugar seguro.
4.  Opcional: defina a Segunda Senha, ou clique em Gerar 2ª Senha Forte Automática.
5.  Opcional: crie a Keyfile no pendrive, com o botão Criar Keyfile no Pendrive.
6.  Clique em Criar e Trancar Cofre.
O cofre é gravado em cofre.dat, na mesma pasta do aplicativo.
Anote a Segunda Senha em papel. Ela é o que abre o cofre se você perder o pendrive. Sem a Keyfile e sem a Segunda Senha, não há como recuperar.
Abrindo o cofre
1.  Digite a Senha Infra.
2.  Se o cofre usa Keyfile, conecte o pendrive. O app preenche o caminho sozinho quando encontra nullvouts.key.
3.  Se estiver sem o pendrive, deixe o campo da Keyfile vazio e digite a Segunda Senha.
4.  Clique em Destrancar Cofre.
Se a senha estiver errada, o app impõe uma espera antes da próxima tentativa. A espera cresce a cada erro, e o bloqueio sobrevive a fechar e reabrir o programa.
Tela principal
A tela tem uma lista de itens à esquerda e cinco abas à direita:
• Inspecionar Item: revela o segredo na tela por 15 segundos, copia para a área de transferência ou apaga o item.
• Adicionar / Editar: cria um item novo ou substitui um existente. Dá para preencher com uma senha aleatória de 20 caracteres.
• Gerador de Senhas: gera senhas aleatórias e frases de palavras, e permite usar o resultado num item novo.
• Senha Infra / Keyfile: troca a senha, a Keyfile e a Segunda Senha.
• Auditoria: mostra o registro de eventos e confere a integridade dele.
O campo de busca acima da lista filtra os itens pelo nome.
Adicionando e consultando senhas
1.  Clique em + Novo Item.
2.  Digite o nome, por exemplo banco ou servidor-ssh.
3.  Digite o segredo, ou use Preencher com Senha Aleatória.
4.  Clique em Salvar e Cifrar no Cofre.
5.  Para consultar, selecione o item na lista e clique em Revelar na Tela ou em Copiar p/ Clipboard.
Depois de 15 segundos, o segredo some da tela e a área de transferência é limpa sozinha. O botão Ocultar / Limpar Agora faz isso na hora.
Ao substituir ou apagar um item, o backup anterior cofre.bak é destruído, para não guardar o segredo antigo.
Keyfile e Segunda Senha
A Senha Infra pode ser combinada com dois fatores extras. Eles não são obrigatórios, mas aumentam muito a proteção.
Configuração
Para abrir, você precisa de
Só Senha Infra
A Senha Infra
Senha Infra + Keyfile
A Senha Infra e o pendrive com a Keyfile
Senha Infra + Segunda Senha
A Senha Infra e a Segunda Senha
Senha Infra + Keyfile + Segunda Senha
A Senha Infra e o pendrive, ou a Senha Infra e a Segunda Senha, se estiver sem o pendrive
O último caso é o mais seguro e o mais prático: o pendrive é o dia a dia, e a Segunda Senha em papel é o plano B se o pendrive se perder.
Para trocar qualquer um dos três fatores, abra a aba Senha Infra / Keyfile. O app pede a Senha Infra atual e, se o cofre já tem segundo fator, exige o pendrive atual conectado ou a Segunda Senha atual. Assim, quem só roubou a sessão aberta não consegue trocar suas credenciais.
Bloqueio e saída
• Bloquear Agora: trava a sessão na hora e apaga os dados da RAM.
• Bloqueio automático: depois de 5 minutos sem mexer, o cofre trava sozinho. O relógio aparece no topo da tela.
• Sair: regrava o cofre, limpa a memória e fecha.
Auditoria de integridade
O Nullvault mantém um registro de eventos em auditoria.log. Ele existe para você descobrir se alguém mexeu no cofre ou no próprio registro.
O que é registrado
Cada evento ganha um número de sequência, a hora em UTC e o tipo. Entre os eventos estão:
• criação, abertura e migração do cofre;
• abertura por recuperação, quando você entrou com a Segunda Senha e sem o pendrive;
• senha errada e tentativa bloqueada;
• item adicionado, sobrescrito, visto e apagado;
• troca de senha e geração de senha;
• bloqueio e desbloqueio da sessão;
• consulta à própria auditoria e saída;
• alerta de rollback e alerta de lista de palavras alterada.
Os nomes dos itens nunca aparecem em texto puro. O registro guarda só uma impressão digital HMAC de 10 caracteres. Quem tem acesso ao arquivo de log não descobre o que você guarda.
Como a integridade é garantida
Cada entrada carrega o hash da anterior, formando uma corrente. Eventos que acontecem com o cofre aberto ainda recebem um selo HMAC, feito com uma chave que só existe dentro do cofre cifrado.
Tentativa de adulteração
Como é detectada
Editar uma linha
O hash da entrada deixa de bater
Apagar uma linha no meio
A sequência e o encadeamento quebram
Apagar linhas do final
O cofre guarda uma âncora, e a entrada âncora some
Forjar uma entrada nova
Sem a chave do cofre, o selo HMAC não confere
Trocar o cofre por uma cópia antiga
A âncora do sistema acusa a regressão
Na aba Auditoria, o app mostra um banner verde com Registro íntegro ou um banner vermelho com Alerta de adulteração, seguido das últimas 40 entradas. No modo terminal, a opção 8 faz o mesmo.
Proteção anti-rollback
A cada gravação, o app guarda uma âncora, com o número e o hash da última entrada, em dois lugares: dentro do cofre cifrado e numa guarda do sistema fora da pasta do aplicativo. No Windows, essa guarda é protegida pela DPAPI, ligada ao seu usuário. No Linux, ela fica em ~/.local/share/nvlt_guard.
Se alguém restaurar uma cópia antiga do cofre.dat, a âncora do cofre fica atrás da âncora do sistema. O app avisa na hora, com um alerta crítico.
Formato do arquivo
O cofre.dat usa o formato versão 4, de envelope multi-slot.
Cabeçalho (autenticado como dado associado):
  MAGIC            4 bytes   "NVLT"
  versão           1 byte    4
  log2(N) do Scrypt 1 byte   19
  flags            1 byte    bit 0 = Keyfile, bit 1 = Segunda Senha
  salt do Scrypt  16 bytes
  salt da 2ª Senha 16 bytes
  número de slots  1 byte    de 1 a 4
  slots            60 bytes cada (nonce de 12 + chave de 32 + tag de 16)
Corpo:
  nonce dos dados 12 bytes
  conteúdo cifrado AES-256-GCM, preenchido em múltiplos de 1024 bytes
O conteúdo decifrado é um JSON com dois campos: os itens e os metadados, que guardam a chave do log, a âncora e os fatores de autenticação.
Arquivos que o aplicativo cria
Arquivo
Para que serve
cofre.dat
O cofre cifrado, com todos os seus itens
cofre.bak
Cópia da gravação anterior, destruída ao apagar ou substituir um item
tentativas.json
Contador de senhas erradas e hora de liberação
auditoria.log
Registro de eventos com hash em cadeia
nullvouts.key
A Keyfile, normalmente guardada no pendrive
listas/
Pasta opcional com listas extras de palavras para o gerador de frases
Todos são gravados de forma atômica, com permissão restrita ao seu usuário: modo 0600 no Linux e ACL exclusiva no Windows.
Importante: não coloque cofre.dat, cofre.bak, tentativas.json, auditoria.log nem a Keyfile no Git. Adicione-os ao .gitignore.
Estrutura do projeto
O aplicativo é um único arquivo Python, organizado em blocos:
Bloco
Responsabilidade
Proteção de memória e SO
Core dumps, ptrace, travar e zerar buffers
Pendrive e arquivos
Detectar pendrives, gravar e apagar com segurança
Guarda do sistema
DPAPI no Windows e pasta protegida no Linux
Lista de palavras
38.504 palavras embutidas, com hash de integridade
Auditoria
Registro com hash em cadeia e selo HMAC
Bloqueio por tentativas
Espera crescente e estado persistente
Cofre em memória
Itens cifrados na RAM e segredos mascarados
Criptografia
Scrypt, slots, abrir e salvar o cofre, migração
Senhas
Regras de qualidade, gerador de senhas e de frases
Interface de terminal
Menu em linha de comando, sessão e inatividade
Proteções da janela
Anti-captura, clipboard protegido, barra de título
Interface gráfica
Telas de login, criação e painel principal em Tkinter
Constantes ajustáveis
Constante
Valor padrão
O que controla
TAM_MIN_MESTRA
12
Tamanho mínimo da senha
TEMPO_TELA
15
Segundos que um segredo fica visível ou no clipboard
TEMPO_INATIVO
300
Segundos sem uso até bloquear a sessão
MAX_TENTATIVAS
5
Erros antes do bloqueio mínimo de 5 minutos
N_LOG2_ATUAL
19
Custo do Scrypt, 2^19 equivale a 512 MB
PALAVRAS_FRASE
6
Palavras de uma frase gerada
MIN_BITS_SENHA
60
Entropia mínima exigida na senha
Verificações automáticas
O repositório usa GitHub Actions para manter o próprio código seguro. Cada push e cada pull request passam por estas verificações:
Ferramenta
O que verifica
Bandit
Análise estática de segurança para código Python
Semgrep
Análise estática com regras de segurança, com resultados enviados à aba de segurança do GitHub
CodeQL
Análise de código nativa do GitHub, que procura falhas de lógica e de injeção
Gitleaks
Varredura do histórico atrás de senhas, tokens e chaves vazadas
OpenSSF Scorecard
Nota para as boas práticas de segurança do repositório
Dependabot
Alertas e atualizações automáticas para dependências vulneráveis
Os workflows ficam na pasta .github/workflows.
Sobre os achados do Bandit
O Bandit aponta alguns avisos de severidade baixa no código, com confiança alta. Eles são esperados num aplicativo que mexe diretamente com memória e com chamadas do sistema, e nenhum é de severidade média ou alta. Entre os motivos estão o uso de ctypes para travar e zerar memória, o uso de subprocess para ajustar permissões no Windows, e blocos try com except genérico em limpezas de recursos.
Qualquer achado de severidade média ou alta deve ser investigado antes de publicar uma nova versão.
Desenvolvimento
Preparando o ambiente
git clone https://github.com/JotaCyberKiK/Projeto-Nullvault.git
cd Projeto-Nullvault
python -m venv .venv
Ative o ambiente virtual e instale as dependências:
pip install cryptography bandit
Rodando as verificações localmente
bandit -r .
Para ver só os achados de severidade média ou alta:
bandit -r . -ll
Cuidados ao contribuir
• Nunca registre senhas, segredos ou nomes de itens em print, em logs ou em mensagens de erro.
• Todo buffer que guarda dado sensível deve ser um bytearray, travado com trancar_buffer e zerado com apagar_buffer.
• Toda gravação de arquivo deve passar por escrever_seguro ou anexar_seguro, que garantem escrita atômica e permissão restrita.
• Qualquer novo evento de auditoria precisa entrar no conjunto EVENTOS.
• Mudanças no formato do cofre exigem subir VERSAO e manter a leitura das versões anteriores em VERSOES_LEITURA.
• Não adicione bibliotecas que abram conexão de rede. A promessa de 100% offline faz parte do projeto.
Perguntas frequentes
O que acontece se eu esquecer a Senha Infra? Se você tiver a Keyfile no pendrive junto com a Segunda Senha, ainda dá para abrir e trocar a Senha Infra, desde que lembre da atual para confirmar a troca. Se não lembrar de nada, não há recuperação. É assim de propósito: uma porta dos fundos enfraqueceria o cofre para todo mundo.
Perdi o pendrive. E agora? Abra o cofre deixando o campo da Keyfile vazio e digitando a Senha Infra mais a Segunda Senha. Depois, na aba Senha Infra / Keyfile, crie uma Keyfile nova em outro pendrive.
Posso usar o cofre em dois computadores? O Nullvault não sincroniza, de propósito. Você pode copiar o cofre.dat para outro computador, mas cada cópia passa a ter o próprio histórico de auditoria e a própria âncora. O aplicativo pode acusar rollback ao abrir uma cópia mais antiga num computador onde já viu uma mais nova.
Por que o aplicativo demora alguns segundos para abrir o cofre? Por causa do Scrypt de 512 MB. Essa lentidão é a defesa: ela faz cada palpite de senha custar o mesmo tempo para um atacante.
O aplicativo usa a internet? Não. O código não tem nenhuma chamada de rede, e você pode conferir lendo o arquivo.
Por que o app avisou de rollback se eu não fiz nada? Isso acontece quando o cofre aberto está numa sequência anterior à que o sistema já viu, por exemplo se você restaurou um backup antigo ou trocou de pasta. Se não foi você, trate como possível adulteração.
Posso confiar na proteção contra captura de tela? No Windows, a janela é excluída da captura por programas comuns de screenshot e gravação. Ela não protege contra uma câmera apontada para o monitor, nem contra malware com acesso total ao sistema.
Posso trocar a lista de palavras do gerador? Pode, colocando arquivos .txt na pasta listas/. O app detecta a mudança, avisa e pede confirmação antes de aceitar a nova lista.
Aviso de segurança
O Nullvault foi feito com cuidado, mas é um projeto independente e não passou por auditoria externa de segurança. Use por sua conta e risco, e mantenha cópias do seu cofre em local seguro.
Se você encontrar uma vulnerabilidade, não abra uma issue pública com os detalhes. Avise o autor em particular, para que a falha seja corrigida antes de ser divulgada.
Licença
Escolha uma licença antes de publicar, por exemplo MIT ou Apache 2.0, e adicione o arquivo LICENSE na raiz do repositório. Depois, troque este parágrafo pelo nome da licença escolhida.
Créditos
Desenvolvido por Jota (JotaCyberKiK).
O Nullvault usa a biblioteca cryptography para AES-GCM e Scryp
