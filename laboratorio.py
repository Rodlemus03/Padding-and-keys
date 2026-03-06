import os
import struct
import time
import zlib
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from avance import (
    a_bytes,
    generar_key_aes,
    generar_key_des,
    pkcs7_quitar_manual,
    pkcs7_rellenar_manual,
)
from tres_des import cifrar_3des_cbc, descifrar_3des_cbc, generar_key_3des


TAM_BLOQUE_AES = 16


def cifrar_des_ecb(plaintext, key):
    if len(key) != 8:
        raise ValueError("La key para DES debe ser de 8 bytes")
    plano = pkcs7_rellenar_manual(plaintext, 8)
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plano) + encryptor.finalize()


def descifrar_des_ecb(ciphertext, key):
    if len(key) != 8:
        raise ValueError("La key para DES debe ser de 8 bytes")
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
    decryptor = cipher.decryptor()
    plano_rellenado = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_quitar_manual(plano_rellenado, 8)


def cifrar_aes_ecb(plaintext, key):
    padder = padding.PKCS7(128).padder()
    plano = padder.update(a_bytes(plaintext)) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plano) + encryptor.finalize()


def descifrar_aes_ecb(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    plano_rellenado = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(plano_rellenado) + unpadder.finalize()


def cifrar_aes_cbc(plaintext, key, iv=None):
    if iv is None:
        iv = os.urandom(TAM_BLOQUE_AES)
    padder = padding.PKCS7(128).padder()
    plano = padder.update(a_bytes(plaintext)) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plano) + encryptor.finalize()
    return iv, ciphertext


def descifrar_aes_cbc(iv, ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plano_rellenado = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(plano_rellenado) + unpadder.finalize()


def cifrar_aes_ctr(plaintext, key, nonce=None):
    if nonce is None:
        nonce = os.urandom(TAM_BLOQUE_AES)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(a_bytes(plaintext)) + encryptor.finalize()
    return nonce, ciphertext


def descifrar_aes_ctr(nonce, ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def dividir_bloques(data, tam_bloque):
    return [data[i:i + tam_bloque] for i in range(0, len(data), tam_bloque)]


def oraculo_padding_cbc(iv, ciphertext, key):
    try:
        descifrar_aes_cbc(iv, ciphertext, key)
        return True
    except ValueError:
        return False


def atacar_bloque_padding_oracle(prev_bloque, bloque_objetivo, oraculo):
    intermedio = bytearray(16)
    plano = bytearray(16)
    manipulado = bytearray(prev_bloque)

    for pad in range(1, 17):
        idx = 16 - pad
        for j in range(idx + 1, 16):
            manipulado[j] = intermedio[j] ^ pad

        encontrado = None
        for guess in range(256):
            manipulado[idx] = guess
            if not oraculo(bytes(manipulado), bloque_objetivo):
                continue

            if pad == 1 and idx > 0:
                verificacion = bytearray(manipulado)
                verificacion[idx - 1] ^= 1
                if not oraculo(bytes(verificacion), bloque_objetivo):
                    continue

            encontrado = guess
            break

        if encontrado is None:
            raise RuntimeError("No se encontró byte válido en el ataque")

        intermedio[idx] = encontrado ^ pad
        plano[idx] = intermedio[idx] ^ prev_bloque[idx]

    return bytes(plano)


def ataque_padding_oracle_cbc(iv, ciphertext, oraculo):
    if len(iv) != 16 or len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise ValueError("Parámetros inválidos para ataque CBC")
    bloques = [iv] + dividir_bloques(ciphertext, 16)
    plano_rellenado = b""
    for i in range(1, len(bloques)):
        plano_rellenado += atacar_bloque_padding_oracle(
            bloques[i - 1], bloques[i], oraculo
        )
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(plano_rellenado) + unpadder.finalize()


def cargar_ppm(path):
    with open(path, "rb") as archivo:
        lineas = archivo.readlines()
    header = lineas[:3]
    body = b"".join(lineas[3:])
    return header, body


def guardar_ppm(path, header, body):
    with open(path, "wb") as archivo:
        archivo.writelines(header)
        archivo.write(body)


def guardar_png_desde_ppm(path, header, body):
    width, height = map(int, header[1].decode("ascii").strip().split())
    maxval = int(header[2].decode("ascii").strip())
    if maxval != 255:
        raise ValueError("Solo se soporta PPM con maxval 255")
    row_size = width * 3
    expected = row_size * height
    if len(body) < expected:
        raise ValueError("Body PPM incompleto")
    body = body[:expected]
    raw = b"".join(
        b"\x00" + body[i:i + row_size]
        for i in range(0, expected, row_size)
    )
    compressed = zlib.compress(raw, level=9)

    def chunk(tag, data):
        return (
            struct.pack("!I", len(data))
            + tag
            + data
            + struct.pack("!I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", compressed)
        + chunk(b"IEND", b"")
    )
    with open(path, "wb") as archivo:
        archivo.write(png)


def cifrar_cuerpo_ppm_aes_ecb(body, key):
    padder = padding.PKCS7(128).padder()
    relleno = padder.update(body) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    cifrado = encryptor.update(relleno) + encryptor.finalize()
    return cifrado[:len(body)]


def cifrar_cuerpo_ppm_aes_cbc(body, key):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    relleno = padder.update(body) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cifrado = encryptor.update(relleno) + encryptor.finalize()
    return iv, cifrado[:len(body)]


def escribir_texto(path, texto):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as archivo:
        archivo.write(texto)


def ejecutar_laboratorio():
    carpeta_resultados = Path("resultados")
    carpeta_resultados.mkdir(exist_ok=True)
    carpeta_imagenes = carpeta_resultados / "imagenes"
    carpeta_imagenes.mkdir(exist_ok=True)

    mensaje = b"Buenas buenas, laboratorio de cifrado por bloques"

    key_des = generar_key_des()
    ciphertext_des = cifrar_des_ecb(mensaje, key_des)
    recuperado_des = descifrar_des_ecb(ciphertext_des, key_des)
    escribir_texto(
        carpeta_resultados / "des_ecb_demo.txt",
        "\n".join([
            f"key_hex={key_des.hex()}",
            f"ciphertext_hex={ciphertext_des.hex()}",
            f"plaintext={recuperado_des.decode('utf-8')}"
        ])
    )

    key_3des_16 = generar_key_3des(16)
    iv_3des_16, ciphertext_3des_16 = cifrar_3des_cbc(mensaje, key_3des_16)
    recuperado_3des_16 = descifrar_3des_cbc(iv_3des_16, ciphertext_3des_16, key_3des_16)
    key_3des_24 = generar_key_3des(24)
    iv_3des_24, ciphertext_3des_24 = cifrar_3des_cbc(mensaje, key_3des_24)
    recuperado_3des_24 = descifrar_3des_cbc(iv_3des_24, ciphertext_3des_24, key_3des_24)
    escribir_texto(
        carpeta_resultados / "tres_des_cbc_demo.txt",
        "\n".join([
            "dos_keys_16_bytes",
            f"key_hex={key_3des_16.hex()}",
            f"iv_hex={iv_3des_16.hex()}",
            f"ciphertext_hex={ciphertext_3des_16.hex()}",
            f"plaintext={recuperado_3des_16.decode('utf-8')}",
            "",
            "tres_keys_24_bytes",
            f"key_hex={key_3des_24.hex()}",
            f"iv_hex={iv_3des_24.hex()}",
            f"ciphertext_hex={ciphertext_3des_24.hex()}",
            f"plaintext={recuperado_3des_24.decode('utf-8')}"
        ])
    )

    imagen_original = Path("header_imagenes/tux.ppm")
    if imagen_original.exists():
        header, body = cargar_ppm(imagen_original)
        key_aes = generar_key_aes(32)
        body_ecb = cifrar_cuerpo_ppm_aes_ecb(body, key_aes)
        iv_img, body_cbc = cifrar_cuerpo_ppm_aes_cbc(body, key_aes)
        guardar_ppm(carpeta_imagenes / "original.ppm", header, body)
        guardar_ppm(carpeta_imagenes / "aes_ecb.ppm", header, body_ecb)
        guardar_ppm(carpeta_imagenes / "aes_cbc.ppm", header, body_cbc)
        guardar_png_desde_ppm(carpeta_imagenes / "original.png", header, body)
        guardar_png_desde_ppm(carpeta_imagenes / "aes_ecb.png", header, body_ecb)
        guardar_png_desde_ppm(carpeta_imagenes / "aes_cbc.png", header, body_cbc)
        escribir_texto(
            carpeta_resultados / "aes_imagen_demo.txt",
            "\n".join([
                f"key_hex={key_aes.hex()}",
                f"iv_cbc_hex={iv_img.hex()}",
                f"bytes_body={len(body)}"
            ])
        )

    repetido = b"BLOQUE-REPETIDO!BLOQUE-REPETIDO!BLOQUE-REPETIDO!"
    key_aes_rep = generar_key_aes(32)
    ciphertext_ecb_rep = cifrar_aes_ecb(repetido, key_aes_rep)
    iv_rep, ciphertext_cbc_rep = cifrar_aes_cbc(repetido, key_aes_rep)
    bloques_ecb = dividir_bloques(ciphertext_ecb_rep, 16)
    bloques_cbc = dividir_bloques(ciphertext_cbc_rep, 16)
    escribir_texto(
        carpeta_resultados / "vulnerabilidad_ecb.txt",
        "\n".join([
            f"plaintext={repetido.decode('utf-8')}",
            "bloques_ecb_hex=",
            *[bloque.hex() for bloque in bloques_ecb],
            "",
            "bloques_cbc_hex=",
            *[bloque.hex() for bloque in bloques_cbc],
            "",
            f"iv_cbc_hex={iv_rep.hex()}"
        ])
    )

    mensaje_iv = b"mensaje igual para evaluar iv"
    key_iv = generar_key_aes(32)
    iv_fijo = os.urandom(16)
    iv_a, cifrado_a = cifrar_aes_cbc(mensaje_iv, key_iv, iv=iv_fijo)
    iv_b, cifrado_b = cifrar_aes_cbc(mensaje_iv, key_iv, iv=iv_fijo)
    iv_c, cifrado_c = cifrar_aes_cbc(mensaje_iv, key_iv)
    iv_d, cifrado_d = cifrar_aes_cbc(mensaje_iv, key_iv)
    escribir_texto(
        carpeta_resultados / "experimento_iv.txt",
        "\n".join([
            "mismo_iv",
            f"iv_hex={iv_a.hex()}",
            f"cifrado_1={cifrado_a.hex()}",
            f"cifrado_2={cifrado_b.hex()}",
            f"iguales={cifrado_a == cifrado_b}",
            "",
            "iv_distintos",
            f"iv_1={iv_c.hex()}",
            f"iv_2={iv_d.hex()}",
            f"cifrado_1={cifrado_c.hex()}",
            f"cifrado_2={cifrado_d.hex()}",
            f"iguales={cifrado_c == cifrado_d}"
        ])
    )

    casos_padding = [b"ABCDE", b"ABCDEFGH", b"ABCDEFGHIJ"]
    lineas_padding = []
    for caso in casos_padding:
        padded = pkcs7_rellenar_manual(caso, 8)
        recuperado = pkcs7_quitar_manual(padded, 8)
        lineas_padding.extend([
            f"mensaje={caso.decode('utf-8')}",
            f"len_original={len(caso)}",
            f"padded_hex={padded.hex()}",
            f"ultimo_byte={padded[-1]}",
            f"recuperado={recuperado.decode('utf-8')}",
            ""
        ])
    escribir_texto(carpeta_resultados / "pruebas_padding.txt", "\n".join(lineas_padding).strip())

    tamano = 10 * 1024 * 1024
    datos_10mb = os.urandom(tamano)
    key_perf = generar_key_aes(32)

    inicio_cbc = time.perf_counter()
    iv_perf, cifrado_perf_cbc = cifrar_aes_cbc(datos_10mb, key_perf)
    fin_cbc = time.perf_counter()
    tiempo_cbc = fin_cbc - inicio_cbc

    inicio_ctr = time.perf_counter()
    nonce_perf, cifrado_perf_ctr = cifrar_aes_ctr(datos_10mb, key_perf)
    fin_ctr = time.perf_counter()
    tiempo_ctr = fin_ctr - inicio_ctr

    escribir_texto(
        carpeta_resultados / "rendimiento_ctr_vs_cbc.txt",
        "\n".join([
            f"tamano_bytes={tamano}",
            f"cbc_segundos={tiempo_cbc:.6f}",
            f"ctr_segundos={tiempo_ctr:.6f}",
            f"cbc_cipher_len={len(cifrado_perf_cbc)}",
            f"ctr_cipher_len={len(cifrado_perf_ctr)}",
            f"cbc_recuperado_ok={descifrar_aes_cbc(iv_perf, cifrado_perf_cbc, key_perf) == datos_10mb}",
            f"ctr_recuperado_ok={descifrar_aes_ctr(nonce_perf, cifrado_perf_ctr, key_perf) == datos_10mb}"
        ])
    )

    mensaje_oraculo = b"CBC vulnerable al padding oracle"
    key_oraculo = generar_key_aes(32)
    iv_oraculo, ct_oraculo = cifrar_aes_cbc(mensaje_oraculo, key_oraculo)
    oracle = lambda iv, ct: oraculo_padding_cbc(iv, ct, key_oraculo)
    recuperado_oraculo = ataque_padding_oracle_cbc(iv_oraculo, ct_oraculo, oracle)
    escribir_texto(
        carpeta_resultados / "padding_oracle_demo.txt",
        "\n".join([
            f"iv_hex={iv_oraculo.hex()}",
            f"ciphertext_hex={ct_oraculo.hex()}",
            f"plaintext_recuperado={recuperado_oraculo.decode('utf-8')}",
            f"recuperado_ok={recuperado_oraculo == mensaje_oraculo}"
        ])
    )


if __name__ == "__main__":
    ejecutar_laboratorio()
