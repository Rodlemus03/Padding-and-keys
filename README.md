# Laboratorio de Cifrados de Bloque

## Instalación
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install cryptography
```

## Ejecución
```bash
python3 laboratorio.py
```

Esto genera evidencias en `resultados/`.

## Estructura del repositorio
- `laboratorio.py`: ejecución integral del laboratorio y generación de evidencias.
- `avance.py`: utilidades reutilizadas (`a_bytes`, padding PKCS#7 manual, generación de claves DES/AES).
- `tres_des.py`: módulo reutilizado para 3DES-CBC (generación de clave, cifrado y descifrado).
- `3des.py`: demo puntual que reutiliza `tres_des.py`.
- `header_imagenes/tux.ppm`: imagen base para análisis visual.
- `resultados/`: artefactos y reportes de ejecución.

Reuso aplicado:
- `laboratorio.py` importa funciones de `avance.py` para padding manual y generación de claves.
- `laboratorio.py` y `3des.py` importan funciones 3DES desde `tres_des.py`.

## 1. Implementación

### 1.1 DES con modo ECB
Funciones:
- `cifrar_des_ecb(plaintext, key)`
- `descifrar_des_ecb(ciphertext, key)`
- `pkcs7_rellenar_manual(data, tam_bloque)`
- `pkcs7_quitar_manual(data, tam_bloque)`

Evidencia:
- `resultados/des_ecb_demo.txt`

Ejemplo de ejecución:
```bash
python3 laboratorio.py
cat resultados/des_ecb_demo.txt
```

### 1.2 3DES con modo CBC
Funciones:
- `cifrar_3des_cbc(plaintext, key)`
- `descifrar_3des_cbc(iv, ciphertext, key)`

Se usan claves de 16 y 24 bytes, y un IV aleatorio por cifrado.

Evidencia:
- `resultados/tres_des_cbc_demo.txt`

Diferencia entre 16 y 24 bytes:
- 16 bytes: 3DES de 2 claves efectivas (`K1, K2, K1`), seguridad efectiva aproximada de 112 bits.
- 24 bytes: 3DES de 3 claves (`K1, K2, K3`), mayor resistencia teórica, con limitaciones prácticas por bloque de 64 bits.

Cómo manejar IV en producción:
- Enviar `iv || ciphertext`.
- Al descifrar, separar los primeros 8 bytes como IV y el resto como ciphertext.

### 1.3 AES con ECB y CBC sobre imagen (análisis visual)
Funciones:
- `cifrar_cuerpo_ppm_aes_ecb(body, key)`
- `cifrar_cuerpo_ppm_aes_cbc(body, key)`
- `cargar_ppm(...)`, `guardar_ppm(...)`

Se preserva el header PPM y solo se cifra el body de píxeles.

Archivos generados:
- `resultados/imagenes/original.ppm`
- `resultados/imagenes/aes_ecb.ppm`
- `resultados/imagenes/aes_cbc.ppm`
- `resultados/imagenes/original.png`
- `resultados/imagenes/aes_ecb.png`
- `resultados/imagenes/aes_cbc.png`

Evidencia técnica:
- `resultados/aes_imagen_demo.txt`

## 2. Análisis de seguridad

### 2.1 Análisis de tamaños de clave
Tamaños usados:
- DES: 8 bytes nominales (56 bits efectivos + bits de paridad).
- 3DES: 16 bytes (2-key 3DES) o 24 bytes (3-key 3DES).
- AES: 32 bytes (AES-256).

Snippet de generación de claves y longitudes:
```python
key_des = generar_key_des()      # len = 8 bytes
key_3des = generar_key_3des(24)  # len = 24 bytes
key_aes = generar_key_aes(32)    # len = 32 bytes
```

Por qué DES es inseguro hoy:
- Espacio de clave efectivo de `2^56`, alcanzable por fuerza bruta con hardware especializado.

Estimación de fuerza bruta DES:
- `2^56 ≈ 7.2e16` claves.
- A `10^12` claves/segundo: `~7.2e4` segundos (`~20` horas).

### 2.2 Comparación de modos ECB vs CBC
Modos implementados:
- DES: ECB.
- 3DES: CBC.
- AES: ECB, CBC y CTR.

Diferencias fundamentales:
- ECB cifra bloques iguales de plaintext en bloques iguales de ciphertext.
- CBC usa encadenamiento con IV; el mismo bloque de plaintext no produce el mismo bloque cifrado si cambia el contexto.

Código exacto usado para generar imágenes:
```python
header, body = cargar_ppm(Path("header_imagenes/tux.ppm"))
key_aes = generar_key_aes(32)
body_ecb = cifrar_cuerpo_ppm_aes_ecb(body, key_aes)
iv_img, body_cbc = cifrar_cuerpo_ppm_aes_cbc(body, key_aes)
guardar_ppm(Path("resultados/imagenes/original.ppm"), header, body)
guardar_ppm(Path("resultados/imagenes/aes_ecb.ppm"), header, body_ecb)
guardar_ppm(Path("resultados/imagenes/aes_cbc.ppm"), header, body_cbc)
```

Comparación visual lado a lado:

| Original | AES-ECB | AES-CBC |
|---|---|---|
| ![original](resultados/imagenes/original.png) | ![ecb](resultados/imagenes/aes_ecb.png) | ![cbc](resultados/imagenes/aes_cbc.png) |

Observación:
- En ECB se mantienen patrones y contornos del contenido original.
- En CBC la estructura visual desaparece y la imagen parece ruido.

### 2.3 Vulnerabilidad de ECB
Evidencia:
- `resultados/vulnerabilidad_ecb.txt`

Resultado observado:
- Bloques repetidos de plaintext generan bloques cifrados idénticos en ECB.
- En CBC esos bloques cambian por el encadenamiento e IV.

Esto filtra información real:
- Detección de campos repetidos.
- Detección de regiones iguales en imágenes.
- Correlación entre mensajes con estructura común.

### 2.4 Vector de Inicialización (IV)
Evidencia:
- `resultados/experimento_iv.txt`

Experimento realizado:
- Mismo mensaje + misma clave + mismo IV => ciphertext igual.
- Mismo mensaje + misma clave + IVs distintos => ciphertext distinto.

Conclusión:
- El IV en CBC evita determinismo entre cifrados del mismo contenido.
- Reutilizar IV permite correlacionar mensajes y filtrar información de prefijos comunes.

### 2.5 Padding
Padding PKCS#7 es necesario para alinear datos al tamaño de bloque.

Evidencia:
- `resultados/pruebas_padding.txt`

Detalle byte por byte:
- Mensaje de 5 bytes (`ABCDE`) en bloque DES de 8 bytes:
  - faltan 3 bytes, se agrega `03 03 03`.
  - resultado hexadecimal: `4142434445030303`.
- Mensaje de 8 bytes (`ABCDEFGH`) exacto al bloque:
  - se agrega bloque completo de padding, `08` repetido 8 veces.
  - resultado: `41424344454647480808080808080808`.
- Mensaje de 10 bytes (`ABCDEFGHIJ`) en bloques de 8:
  - próximo múltiplo es 16, faltan 6 bytes.
  - se agrega `06 06 06 06 06 06`.
  - resultado: `4142434445464748494a060606060606`.

`pkcs7_quitar_manual` recupera el mensaje original en todos los casos.

### 2.6 Recomendaciones de uso
| Modo | Recomendado para | Desventajas |
|---|---|---|
| ECB | No recomendado para datos sensibles | Filtra patrones de bloques |
| CBC | Compatibilidad legacy con IV único por mensaje | No autentica, requiere padding |
| CTR | Alto rendimiento y paralelización | No autentica, exige nonce/contador único |
| GCM (AEAD) | Uso moderno general | Error crítico si se reutiliza nonce |

Recomendación práctica:
- Preferir AEAD (`AES-GCM` o `ChaCha20-Poly1305`) para confidencialidad + integridad.

Ejemplo en Python (AES-GCM):
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, b"mensaje", b"aad")
pt = aesgcm.decrypt(nonce, ct, b"aad")
```

Ejemplo en Node.js (aes-256-gcm):
```javascript
const crypto = require('crypto');

const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const ciphertext = Buffer.concat([cipher.update('mensaje', 'utf8'), cipher.final()]);
const tag = cipher.getAuthTag();

const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
decipher.setAuthTag(tag);
const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
```

## 3. Validación y pruebas

### 3.1 Implementación de CTR (extra)
Funciones:
- `cifrar_aes_ctr(plaintext, key, nonce=None)`
- `descifrar_aes_ctr(nonce, ciphertext, key)`

Evidencia:
- `resultados/rendimiento_ctr_vs_cbc.txt`

Resultado medido en archivo de 10MB:
- CBC: `0.031387 s`
- CTR: `0.011948 s`

Conclusiones:
- CTR no requiere padding (`ctr_cipher_len == tamano_bytes`).
- CTR puede paralelizarse por bloques independientes de contador.
- CBC no puede cifrar en paralelo porque cada bloque depende del anterior.

### 3.2 Padding Oracle Attack (extra)
Implementación incluida:
- `oraculo_padding_cbc(iv, ciphertext, key)`
- `atacar_bloque_padding_oracle(prev_bloque, bloque_objetivo, oraculo)`
- `ataque_padding_oracle_cbc(iv, ciphertext, oraculo)`

Evidencia:
- `resultados/padding_oracle_demo.txt`

Qué demuestra:
- Un oráculo que responde solo “padding válido/inválido” permite recuperar plaintext en CBC sin conocer la clave.

Relación con casos reales:
- POODLE: explotación de errores de padding en SSLv3 con fallback inseguro.
- Lucky 13: ataques de temporización sobre validación MAC+padding en CBC/TLS.

Mitigaciones modernas:
- Usar AEAD (GCM/ChaCha20-Poly1305).
- Evitar mensajes de error distinguibles.
- Validaciones en tiempo constante.
- Eliminar protocolos legacy vulnerables.

## Proceso de testing
Comandos usados:
```bash
python3 laboratorio.py
python3 3des.py
python3 avance.py
```

Validaciones ejecutadas:
- Roundtrip correcto en DES/3DES/AES.
- Comportamiento de ECB vs CBC con bloques repetidos.
- Impacto de IV reutilizado vs IV aleatorio.
- Casos borde de PKCS#7 manual.
- Rendimiento y tamaño de salida CBC vs CTR en 10MB.
- Recuperación de plaintext mediante ataque de padding oracle.

## Nota de entorno
La implementación usa `cryptography`. Si el entorno permite `pycryptodome`, se puede adaptar la sección de padding de biblioteca a `Crypto.Util.Padding.pad/unpad` manteniendo las mismas pruebas y resultados.
