from crypto_service import CryptoService

def executar_demonstracao():
    print("=== ENTREGA 1: DEMONSTRAÇÃO DE CIFRAGEM HÍBRIDA ===")
    
    # 1. Geração de chaves do Destinatário
    print("\n[1] Gerando par de chaves RSA (2048 bits)...")
    private_key, public_key = CryptoService.gerar_par_chaves_rsa()
    print("✓ Par de chaves gerado com sucesso!")

    # 2. Mensagem original
    mensagem_original = "Mensagem Confidencial: Dados de homologação do Projeto Integrador."
    print(f"\n[2] Mensagem Original: '{mensagem_original}'")

    # 3. Cifragem
    print("\n[3] Cifrando mensagem com esquema Híbrido (AES-256-GCM + RSA-OAEP)...")
    pacote_seguro = CryptoService.cifrar_mensagem_hibrida(mensagem_original, public_key)
    print("✓ Mensagem cifrada com sucesso!")
    print(f" - Payload cifrado (hex): {pacote_seguro['mensagem_cifrada'][:20].hex()}...")

    # 4. Decifragem com sucesso
    print("\n[4] Receptor decifrando o pacote com sua Chave Privada...")
    mensagem_recuperada = CryptoService.decifrar_mensagem_hibrida(pacote_seguro, private_key)
    print(f"✓ Mensagem Decifrada: '{mensagem_recuperada}'")

if __name__ == "__main__":
    executar_demonstracao()
