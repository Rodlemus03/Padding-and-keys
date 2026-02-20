import secrets
import random

def padding_manual(data, block_size):
    if isinstance(data, str):
        data = data.encode()
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpadding_manual(data):
    padding_len = data[-1]
    return data[:-padding_len]

def generar_clave_des():
    return secrets.token_bytes(8)

def generar_clave_3des():
    return secrets.token_bytes(24)

def generar_clave_aes(tamano=16):
    if tamano not in [16, 24, 32]:
        tamano = 16
    return secrets.token_bytes(tamano)

if __name__ == "__main__":
    mensaje = "Buenas buenas"
    padded = padding_manual(mensaje, 8)
    print(padded)
    print(generar_clave_des())
    print(generar_clave_3des())
    print(generar_clave_aes(16))