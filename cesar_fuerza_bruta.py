#!/usr/bin/env python3
"""Ataque de fuerza bruta contra el cifrado César.

Prueba las 25 claves posibles y se queda con la que produce un texto que el
detector de idioma reconoce como castellano.

Detección de idioma:
  - Si está instalada la librería `langdetect` (pip install langdetect), se usa
    la probabilidad de que el texto sea español.
  - Además se usa una heurística propia (palabras frecuentes del castellano),
    que funciona bien con textos cortos, donde langdetect es poco fiable.
"""

import re
import string

try:
    from langdetect import DetectorFactory, detect_langs
    DetectorFactory.seed = 0          # resultados reproducibles
    HAY_LANGDETECT = True
except ImportError:
    HAY_LANGDETECT = False

MENSAJE = "Uunejvxb dw vdwmx wdnex jzdr, nw wdnbcaxb lxajixwnb"

PALABRAS_ES = {
    "el", "la", "los", "las", "un", "una", "unos", "unas", "de", "del", "al",
    "y", "o", "en", "es", "que", "se", "no", "por", "con", "para", "su", "sus",
    "mi", "tu", "nos", "lo", "le", "les", "me", "te", "como", "mas", "pero",
    "si", "ya", "muy", "aqui", "alli", "esta", "este", "esto", "son", "ser",
    "hay", "todo", "todos", "nuestro", "nuestros", "nuestra", "mundo", "nuevo",
    "llevamos", "corazones", "corazon", "tiene", "tienen", "hace", "donde",
}


def descifrar_cesar(texto: str, clave: int) -> str:
    """Descifra desplazando cada letra `clave` posiciones hacia atrás."""
    resultado = []
    for c in texto:
        if c in string.ascii_lowercase:
            resultado.append(chr((ord(c) - ord("a") - clave) % 26 + ord("a")))
        elif c in string.ascii_uppercase:
            resultado.append(chr((ord(c) - ord("A") - clave) % 26 + ord("A")))
        else:
            resultado.append(c)
    return "".join(resultado)


def puntuacion_palabras(texto: str) -> float:
    """Fracción de palabras del texto que son palabras comunes del castellano."""
    palabras = re.findall(r"[a-záéíóúüñ]+", texto.lower())
    if not palabras:
        return 0.0
    return sum(p in PALABRAS_ES for p in palabras) / len(palabras)


def probabilidad_espanol(texto: str) -> float:
    """Probabilidad (0-1) de que el texto esté en español según langdetect."""
    if not HAY_LANGDETECT:
        return 0.0
    try:
        for idioma in detect_langs(texto):
            if idioma.lang == "es":
                return idioma.prob
    except Exception:
        pass
    return 0.0


def atacar(mensaje: str):
    candidatos = []
    for clave in range(1, 26):
        texto = descifrar_cesar(mensaje, clave)
        # Peso mayor a la heurística de palabras (más fiable en textos cortos)
        puntos = 2 * puntuacion_palabras(texto) + probabilidad_espanol(texto)
        candidatos.append((puntos, clave, texto))

    print(f"Mensaje cifrado: {mensaje}")
    print(f"Detector de idioma: {'langdetect + palabras frecuentes' if HAY_LANGDETECT else 'palabras frecuentes (langdetect no instalado)'}\n")
    print(f"{'clave':>5} | {'puntos':>6} | texto descifrado")
    print("-" * 70)
    for puntos, clave, texto in candidatos:
        print(f"{clave:>5} | {puntos:6.2f} | {texto}")

    puntos, clave, texto = max(candidatos)
    print("\n>>> Clave inferida:", clave)
    print(">>> Mensaje descifrado:", texto)
    return clave, texto


if __name__ == "__main__":
    atacar(MENSAJE)
