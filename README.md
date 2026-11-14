# 🛡️ Nullvouts

O **Nullvouts** é um aplicativo desktop seguro desenvolvido em Python para o gerenciamento e armazenamento local de senhas. Focado em privacidade e criptografia de ponta, o projeto foi construído para rodar de forma isolada, garantindo que dados confidenciais fiquem protegidos contra interceptações, telemetria e acessos indesejados.

---

## 🔒 Funcionamento 100% Offline (Air-Gapped)

Uma das premissas arquiteturais mais fundamentais do Nullvouts é o seu **isolamento total de rede**:
* **Zero Conexões Externas:** O aplicativo não realiza requisições HTTP, chamadas de API ou comunicação com servidores de terceiros.
* **Sem Telemetria ou Nuvem:** Nenhum dado, log ou metadado é enviado para a internet. Seus segredos pertencem exclusivamente ao seu dispositivo.
* **Armazenamento 100% Local:** Todo o cofre criptografado reside estritamente no seu sistema de arquivos local, garantindo total soberania e segurança dos seus dados mesmo em ambientes sem acesso à internet.

---

## 🚀 Principais Funcionalidades e Arquitetura de Segurança

* **Criptografia Robusta:** Utiliza **AES-256-GCM** para a criptografia dos dados do cofre.
* **Derivação de Chaves Avançada:** Implementação de **Scrypt** (`N_LOG2 = 19`) para proteger a chave mestra contra ataques de força bruta.
* **Proteção contra Captura de Tela:** Utiliza a API `WDA_EXCLUDEFROMCAPTURE` para impedir que softwares maliciosos tirem prints da janela do aplicativo.
* **Autenticação por Keyfile:** Suporte opcional a arquivos de chave personalizados para reforçar o acesso ao cofre.
* **Limpeza Automática de Clipboard:** O conteúdo copiado da área de transferência é limpo automaticamente após um período de inatividade.
* **Interface Moderna:** Tema escuro (dark theme) elegante e focado em usabilidade.

---

## 🛠️ Tecnologias e Dependências Utilizadas

* **Linguagem:** Python 3.14+
* **Criptografia:** Biblioteca `cryptography` e `cffi`
* **Interface Gráfica:** Tkinter / CustomTkinter (ou framework GUI equivalente)
* **Empacotamento Standalone:** PyInstaller (modo `--onefile`)
* **Ambiente de Desenvolvimento:** Linux Mint (WSL2 / Ubuntu-based)

---

## 📝 Histórico de Correções e Configurações Realizadas

1. **Dependência do Sistema (`objdump`):** Instalação do pacote `binutils` via gerenciador de pacotes (`sudo apt install binutils`).
2. **Resolução de Caminhos no WSL:** Correção de erros de espaços em caminhos do Windows (`/mnt/c/Users/pedro/Projeto ZeroKnow`) usando aspas duplas.
3. **Biblioteca Compartilhada do Python (`libpython3.14.so.1.0`):** Instalação de `python3.14-dev` e recriação do `venv` com `--system-site-packages`.
4. **Módulo Oculto (`cryptography`):** Configuração explícita de `hiddenimports` no arquivo `cofre.spec` para garantir que a criptografia funcione no executável compilado.
5. **Empacotamento Standalone (`cofre.spec`):** Ajuste completo do script de especificação para gerar um binário portátil e único (`--onefile`).

---

## ⚙️ Como Compilar o Projeto (PyInstaller)

1. Navegue até a pasta do projeto no WSL:
   ```bash
   cd "/mnt/c/Users/pedro/Projeto ZeroKnow"
Ative o ambiente virtual e instale as dependências:

Bash
source ~/Nullvouts/venv/bin/activate
pip install cryptography
Gere o executável com o PyInstaller:

Bash
pyinstaller cofre.spec
O binário final estará disponível na pasta dist/.

Desenvolvido por João 


---

<ElicitationsGroup message="Para refinar ainda mais o seu projeto:">
  <Elicitation label="Adicionar licença de uso ao README" query="Como adiciono uma licença MIT ou GPL ao README.md do Nullvouts?"/>
  <Elicitation label="Criar script automatizado de build" query="Como crio um script Bash simples para automatizar a limpeza e a compilação do Nullvouts com PyInstaller?"/>
</ElicitationsGroup>

<FollowUp label="Quer que eu salve esse README atualizado diretamente para você?" query="Como posso salvar o novo conteúdo do README.md diretamente no diretório do projeto via terminal?"/>
