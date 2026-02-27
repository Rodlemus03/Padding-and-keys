import secrets
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


SIZE = 8

def verificar_llave(n):
    if n not in (16, 24):
        raise ValueError("La llave 3DES debe ser de 16 o 24 bytes.")
def generar_llave_3des(length: int = 24) -> bytes:
    verificar_llave(length)

    while True:
        key = secrets.token_bytes(length)
        try:
            key = DES3.adjust_key_parity(key)
            DES3.new(key, DES3.MODE_ECB)
            return key
        except ValueError:
            continue


def generar_iv() -> bytes:
    return secrets.token_bytes(SIZE)


def cifrar_3des_cbc(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    if len(key) not in (16, 24):
        raise ValueError("La llave 3DES debe ser de 16 o 24 bytes.")

    key = DES3.adjust_key_parity(key)
    iv = generar_iv()
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext, SIZE))
    return iv, ciphertext


def descifrar_3des_cbc(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    if len(key) not in (16, 24):
        raise ValueError("La llave 3DES debe ser de 16 o 24 bytes.")
    if len(iv) != SIZE:
        raise ValueError("El IV debe ser de 8 bytes para 3DES-CBC.")

    key = DES3.adjust_key_parity(key)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), SIZE)
    return plaintext


def _to_hex(b: bytes) -> str:
    return b.hex()

if __name__ == "__main__":
    key = generar_llave_3des(24)
    msg = b"Buenas buenas, cifrado 3DES"

    iv, ct = cifrar_3des_cbc(msg, key)
    pt = descifrar_3des_cbc(iv, ct, key)

    print("KEY_HEX:", _to_hex(key))
    print("IV_HEX:", _to_hex(iv))
    print("CT_HEX:", _to_hex(ct))
    print("PT:", pt.decode("utf-8", errors="replace"))