from tres_des import (
    cifrar_tres_des_cbc,
    descifrar_tres_des_cbc,
    generar_llave_3des,
)


if __name__ == "__main__":
    key = generar_llave_3des(24)
    mensaje = b"Buenas buenas, cifrado 3DES"
    iv, ciphertext = cifrar_tres_des_cbc(mensaje, key)
    plaintext = descifrar_tres_des_cbc(iv, ciphertext, key)
    print("KEY_HEX:", key.hex())
    print("IV_HEX:", iv.hex())
    print("CT_HEX:", ciphertext.hex())
    print("PT:", plaintext.decode("utf-8", errors="replace"))
