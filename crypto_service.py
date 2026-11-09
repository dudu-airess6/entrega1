import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoService:
    @staticmethod
    def gerar_par_chaves_rsa(tamanho: int = 2048):
        """Gera um par de chaves assimétricas RSA."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=tamanho
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def cifrar_mensagem_hibrida(mensagem: str, public_key_destino):
        """
        1. Gera uma chave simétrica AES-256 (32 bytes).
        2. Cifra o conteúdo via AES-GCM (garante sigilo e integridade).
        3. Encapsula a chave AES utilizando a chave pública RSA (RSA-OAEP).
        """
        dados = mensagem.encode('utf-8')

        chave_aes = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(chave_aes)
        nonce = os.urandom(12) # Nonce de 96 bits recomendado para GCM

        mensagem_cifrada = aesgcm.encrypt(nonce, dados, associated_data=None)

        chave_aes_encapsulada = public_key_destino.encrypt(
            chave_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return {
            "chave_aes_encapsulada": chave_aes_encapsulada,
            "nonce": nonce,
            "mensagem_cifrada": mensagem_cifrada
        }

    @staticmethod
    def decifrar_mensagem_hibrida(pacote_cripto: dict, private_key_destino) -> str:
        """
        1. Decifra a chave AES usando a Chave Privada RSA.
        2. Decifra o conteúdo usando a chave AES recuperada e valida a integridade.
        """
        chave_aes_encapsulada = pacote_cripto["chave_aes_encapsulada"]
        nonce = pacote_cripto["nonce"]
        mensagem_cifrada = pacote_cripto["mensagem_cifrada"]

        chave_aes = private_key_destino.decrypt(
            chave_aes_encapsulada,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        aesgcm = AESGCM(chave_aes)
        dados_decifrados = aesgcm.decrypt(nonce, mensagem_cifrada, associated_data=None)
        
        return dados_decifrados.decode('utf-8')
