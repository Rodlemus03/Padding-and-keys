import os


def a_bytes(dato):
    if isinstance(dato, bytes):
        return dato
    return str(dato).encode("utf-8")


def pkcs7_rellenar_manual(data, tam_bloque):
    data = a_bytes(data)
    faltante = tam_bloque - (len(data) % tam_bloque)
    if faltante == 0:
        faltante = tam_bloque
    return data + bytes([faltante]) * faltante


def pkcs7_quitar_manual(data, tam_bloque):
    data = a_bytes(data)
    if not data or len(data) % tam_bloque != 0:
        raise ValueError("Longitud inválida para PKCS#7")
    faltante = data[-1]
    if faltante < 1 or faltante > tam_bloque:
        raise ValueError("Padding inválido")
    if data[-faltante:] != bytes([faltante]) * faltante:
        raise ValueError("Padding inválido")
    return data[:-faltante]


def generar_key_des():
    return os.urandom(8)


def generar_key_aes(longitud=32):
    if longitud not in (16, 24, 32):
        raise ValueError("La key de AES debe ser de 16, 24 o 32 bytes")
    return os.urandom(longitud)


if __name__ == "__main__":
    mensaje = "Buenas buenas"
    padded = pkcs7_rellenar_manual(mensaje, 8)
    print(padded)
    print(pkcs7_quitar_manual(padded, 8))
    print(generar_key_des())
    print(generar_key_aes(16))
