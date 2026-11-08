# Projeto-Nullvault
Gerenciador de segredos em linha de comando, em Python. Criptografa tudo localmente com AES-256-GCM e Scrypt, tem bloqueio progressivo contra tentativas erradas, gerador de senhas e frases Diceware multilíngue, cópia de segurança e executável para Windows. Projeto de estudo em proteção de dados, sem auditoria independente. 

# Nullvaut

O **Nullvaut** é um gerenciador de senhas para Windows que funciona no terminal. Ele reúne as credenciais em um cofre criptografado, aberto com uma senha mestra. Em um menu numerado, você pode cadastrar novas senhas, listar os itens do cofre, consultar uma credencial pelo nome e excluir registros que já não usa.

## Como o cofre protege as senhas

As credenciais ficam armazenadas em um arquivo local protegido por **AES-256-GCM**. A chave de 256 bits é derivada da senha mestra. Além de criptografar o conteúdo, esse mecanismo permite detectar alterações nos dados ao abrir o cofre. A escolha da senha mestra importa porque ela é a base da chave que protege todos os registros.

Os caracteres ficam ocultos enquanto você digita uma senha no terminal. Quando precisar consultar uma credencial salva, selecione **2 — Ver** e informe o nome do item. A senha é então exibida no terminal.

## Geração de senhas e frases-senha

O Nullvaut também gera senhas aleatórias de pelo menos 16 caracteres, combinando letras, números e símbolos. Quando há listas de palavras na pasta `listas`, ao lado do executável, o aplicativo também pode criar frases-senha a partir dessas listas. Assim, você pode escolher entre uma sequência de caracteres e uma combinação de palavras.

## Primeira execução

Abra o executável no Windows e defina a senha mestra do seu cofre. Depois de criar o cofre, você pode usar o menu para cadastrar suas primeiras credenciais ou gerar uma senha para uma nova conta.
