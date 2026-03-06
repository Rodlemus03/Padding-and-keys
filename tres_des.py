import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from avance import a_bytes


TAM_BLOQUE_DES = 8


def verificar_key(longitud):
    if longitud not in (16, 24):
        raise ValueError("La key 3DES debe ser de 16 o 24 bytes")


def generar_key_3des(longitud=24):
    verificar_key(longitud)
    return os.urandom(longitud)


def generar_llave_3des(longitud=24):
    return generar_key_3des(longitud)


def cifrar_3des_cbc(plaintext, key):
    verificar_key(len(key))
    iv = os.urandom(TAM_BLOQUE_DES)
    padder = padding.PKCS7(64).padder()
    plano = padder.update(a_bytes(plaintext)) + padder.finalize()
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plano) + encryptor.finalize()
    return iv, ciphertext


def descifrar_3des_cbc(iv, ciphertext, key):
    verificar_key(len(key))
    if len(iv) != TAM_BLOQUE_DES:
        raise ValueError("El iv de 3DES debe ser de 8 bytes")
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plano_rellenado = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    return unpadder.update(plano_rellenado) + unpadder.finalize()


def cifrar_tres_des_cbc(plaintext, key):
    return cifrar_3des_cbc(plaintext, key)


def descifrar_tres_des_cbc(iv, ciphertext, key):
    return descifrar_3des_cbc(iv, ciphertext, key)
