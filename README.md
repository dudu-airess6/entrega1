# Projeto Integrador - Segurança da Informação (Entrega 1)

## 📌 Visão Geral
Este repositório contém a implementação da **Entrega 1** do Projeto Integrador de Segurança da Informação (Universidade Tiradentes). O objetivo principal é garantir o **sigilo**, a **integridade** e a **autenticidade** no tráfego de mensagens sensíveis através de um mecanismo de **Cifragem Híbrida**.

---

## 🛠️ Arquitetura Criptográfica

A solução utiliza uma abordagem híbrida combinando criptografia simétrica de alta performance e criptografia assimétrica segura:

- **Cifragem Simétrica com Autenticação (AEAD):** **AES-256-GCM**
  - **Sigilo:** Cifra o conteúdo da mensagem com chave simétrica de 256 bits.
  - **Integridade & Autenticidade:** O modo **GCM (Galois/Counter Mode)** gera uma tag de verificação que impede qualquer adulteração do texto cifrado (*tampering*).
- **Gerenciamento e Encapsulamento de Chave:** **RSA-OAEP (2048 bits)**
  - A chave simétrica temporal (Session Key) é encapsulada usando a chave pública RSA do destinatário com padding **OAEP (MGF1 com SHA-256)**, mitigando ataques de preenchimento (*padding oracle*).

---

## 🔒 Fundamentação Teórica & Padrões da Indústria

### Confidencialidade vs. Autenticidade/Integridade
- **Confidencialidade (Sigilo):** Garante que apenas o detentor da chave privada RSA correspondente consiga recuperar a chave AES e decifrar a mensagem original.
- **Integridade e Autenticidade:** O **AES-GCM** garante que a mensagem não foi modificada por terceiros durante o tráfego. Caso ocorra alteração de um único bit, a validação da tag GCM falhará e a decifragem será abortada.

### Papel da PKI e Certificados Digitais
Para evolução da infraestrutura de chaves públicas em ambientes de produção, os pares de chaves assimétricas devem ser ancorados em **Certificados Digitais (X.509)** emitidos por uma **Autoridade Certificadora (AC)** confiável, evitando ataques do tipo *Man-in-the-Middle* (MitM).

### Conformidade e Padrões de Segurança
- **OWASP Top 10 (A04:2021):** Prevenção contra *Cryptographic Failures* (uso de algoritmos consolidados e ausência de algoritmos próprios).
- **OWASP ASVS V11:** Validação da proteção criptográfica de dados em trânsito e em repouso.
- **ISO/IEC 27002 Control 8.24:** Uso de controles criptográficos alinhados às melhores práticas internacionais.

---

## 📁 Estrutura do Repositório

```text
projeto-integrador-e1/
├── .gitignore              # Ignora ambientes virtuais (.venv) e arquivos temporários
├── crypto_service.py       # Módulo central com a lógica de cifragem/decifragem híbrida
├── main.py                 # Script de demonstração da execução funcional
├── test_crypto.py          # Suíte de testes automatizados (unittest/pytest)
├── requirements.txt        # Dependências do projeto (cryptography)
└── README.md               # Documentação técnica do projeto
```

---

## 🚀 Instalação e Execução

### 1. Pré-requisitos
- Python 3.10 ou superior.

### 2. Configurar o Ambiente Virtual (.venv)

No terminal (VS Code / Bash / PowerShell):

```bash
# Criar o ambiente virtual
python -m venv .venv

# Ativar o ambiente virtual:
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# Instalar as dependências
pip install -r requirements.txt
```

### 3. Executar a Demonstração Principal

```bash
python main.py
```

---

## 🧪 Execução dos Testes Automatizados

A suíte de testes em `test_crypto.py` cobre casos de sucesso e cenários reais de ataques por adulteração (*tampering*):

```bash
# Executar via unittest nativo do Python:
python -m unittest test_crypto.py -v

# Ou caso possua o PyTest instalado na .venv:
pytest test_crypto.py -v
```

### Casos de Teste Cobertos:
1. `test_cifragem_decifragem_sucesso`: Valida o fluxo completo de cifragem e decifragem com chaves válidas.
2. `test_falha_adulteracao_payload`: Simula a modificação de bytes no texto cifrado e confirma que o AES-GCM dispara a exceção `InvalidTag`.
3. `test_falha_chave_privada_incorreta`: Confirma que uma chave privada não autorizada falha ao tentar descompactar o envelope RSA.
4. `test_falha_adulteracao_chave_encapsulada`: Simula adulteração no envelope RSA e confirma a rejeição.

---

## ⚠️ Análise de Riscos, Limitações e Próximos Passos
- **Gestão de Chaves:** Atualmente, as chaves são geradas em memória para fins demonstrativos. Em ambiente de produção, as chaves privadas devem ser armazenadas em cofres de senhas/chaves seguros (ex: AWS KMS, HashiCorp Vault ou HSM).
- **Próximas Entregas:** Integração de hashes criptográficos (SHA-256/SHA-512) e autenticação de usuários via assinatura digital.
