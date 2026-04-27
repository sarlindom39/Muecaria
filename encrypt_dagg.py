#!/usr/bin/env python3
"""
Simpsons VPN - Gerador de ficheiros .dagg encriptados
Encripta um JSON de configuração no formato .dagg (AES-256-GCM).

Uso:
    python encrypt_dagg.py <input.json> [output.dagg]

Formato do JSON de entrada (igual ao config.enc):
{
    "versao": 1,
    "lista_servidores": [
        {
            "id": "001",
            "nome": "Servidor 1",
            "protocolo": "vmess",
            "config": "vmess://..."
        }
    ]
}

Regras de IDs:
    - ID normal (ex: "001") → Adiciona ou atualiza servidor
    - ID + "rem" (ex: "001rem") → Remove servidor pelo ID base
"""

import os
import sys
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Chave hexadecimal de 64 caracteres (32 bytes) — IDÊNTICA À DO NDK/Kotlin
HEX_KEY_STRING = "785439764c326b4d347051386a52317746356e59376243337a58366448306753"


def encrypt_dagg(input_file_path, output_file_path="config.dagg"):
    """Encripta um ficheiro JSON no formato .dagg usando AES-256-GCM."""

    # Validar que o input é JSON válido
    with open(input_file_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"❌ Erro: ficheiro não é JSON válido: {e}")
            sys.exit(1)

    # Validar estrutura mínima
    if "lista_servidores" not in data:
        print("❌ Erro: JSON deve conter 'lista_servidores'")
        sys.exit(1)

    servidores = data["lista_servidores"]
    print(f"📋 Encontrados {len(servidores)} servidores no JSON")

    # Converter a chave hexadecimal para bytes
    key_bytes = bytes.fromhex(HEX_KEY_STRING)

    # Derivar a chave AES-256 (32 bytes) via SHA-256 (idêntico ao Kotlin)
    secret_key = hashlib.sha256(key_bytes).digest()

    # Gerar IV aleatório de 12 bytes para GCM
    iv = os.urandom(12)

    # Ler conteúdo como bytes
    plaintext = json.dumps(data, ensure_ascii=False, separators=(",", ": ")).encode("utf-8")

    # Encriptar com AES-256-GCM
    cipher = Cipher(algorithms.AES(secret_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    # Estrutura final: [12 bytes IV] + [Ciphertext] + [16 bytes GCM Tag]
    encrypted_data = iv + ciphertext + tag

    # Guardar
    with open(output_file_path, "wb") as f:
        f.write(encrypted_data)

    print(f"✅ '{input_file_path}' encriptado com sucesso para '{output_file_path}'")
    print(f"   Tamanho: {len(encrypted_data)} bytes")
    print(f"   IV: {iv.hex()[:16]}...")
    print(f"\n📱 Partilhe este ficheiro .dagg com os utilizadores do Simpsons VPN.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python encrypt_dagg.py <input.json> [output.dagg]")
        print("\nExemplo:")
        print('  python encrypt_dagg.py servers.json meus_servidores.dagg')
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "config.dagg"

    if not os.path.exists(input_path):
        print(f"❌ Ficheiro não encontrado: {input_path}")
        sys.exit(1)

    encrypt_dagg(input_path, output_path)
