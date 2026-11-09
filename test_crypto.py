import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.exceptions import InvalidTag
from crypto_service import CryptoService

class TestCryptoService(unittest.TestCase):
    def test_cifragem_decifragem_sucesso(self):
        """Caso de Sucesso: Cifra e decifra uma mensagem validando integridade e sigilo."""
        priv_key, pub_key = CryptoService.gerar_par_chaves_rsa()
        mensagem_original = "Mensagem de Teste: Integridade e Autenticidade"
        
        pacote = CryptoService.cifrar_mensagem_hibrida(mensagem_original, pub_key)
        mensagem_recuperada = CryptoService.decifrar_mensagem_hibrida(pacote, priv_key)
        
        self.assertEqual(mensagem_recuperada, mensagem_original)

    def test_falha_adulteracao_payload(self):
        """Caso de Falha: Adulteração do payload cifrado dispara exceção InvalidTag (AES-GCM)."""
        priv_key, pub_key = CryptoService.gerar_par_chaves_rsa()
        mensagem_original = "Dados financeiros confidenciais: R$ 100.000,00"
        
        pacote = CryptoService.cifrar_mensagem_hibrida(mensagem_original, pub_key)
        
        # Simula adulteração (modifica o último byte do texto cifrado)
        mensagem_adulterada = bytearray(pacote["mensagem_cifrada"])
        mensagem_adulterada[-1] ^= 0xFF
        pacote["mensagem_cifrada"] = bytes(mensagem_adulterada)
        
        # O AES-GCM deve rejeitar a mensagem devido à falha na tag de autenticação
        with self.assertRaises(InvalidTag):
            CryptoService.decifrar_mensagem_hibrida(pacote, priv_key)

    def test_falha_chave_privada_incorreta(self):
        """Caso de Falha: Decifrar com chave privada RSA não autorizada deve falhar."""
        priv_key_autorizada, pub_key_autorizada = CryptoService.gerar_par_chaves_rsa()
        priv_key_atacante, _ = CryptoService.gerar_par_chaves_rsa()
        
        mensagem = "Informação ultra secreta"
        pacote = CryptoService.cifrar_mensagem_hibrida(mensagem, pub_key_autorizada)
        
        with self.assertRaises(ValueError):
            CryptoService.decifrar_mensagem_hibrida(pacote, priv_key_atacante)

    def test_falha_adulteracao_chave_encapsulada(self):
        """Caso de Falha: Adulteração na chave AES encapsulada deve falhar na decifragem RSA-OAEP."""
        priv_key, pub_key = CryptoService.gerar_par_chaves_rsa()
        mensagem = "Mensagem de Teste"
        
        pacote = CryptoService.cifrar_mensagem_hibrida(mensagem, pub_key)
        
        chave_adulterada = bytearray(pacote["chave_aes_encapsulada"])
        chave_adulterada[0] ^= 0xFF
        pacote["chave_aes_encapsulada"] = bytes(chave_adulterada)
        
        with self.assertRaises(ValueError):
            CryptoService.decifrar_mensagem_hibrida(pacote, priv_key)

if __name__ == "__main__":
    unittest.main()
