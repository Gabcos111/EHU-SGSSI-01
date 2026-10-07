#!/usr/bin/env python3
"""Ataque al cifrado por sustitución simple mediante análisis de frecuencias.

Uso:
    python3 sustitucion_frecuencias.py           # modo interactivo
    python3 sustitucion_frecuencias.py --auto    # intenta resolverlo solo y sale

Cómo funciona:
  1. Cuenta la frecuencia de cada símbolo del criptograma y la compara con la
     frecuencia de las letras en castellano.
  2. Propone una clave inicial emparejando por orden de frecuencia
     (el símbolo más frecuente -> E, el siguiente -> A, ...).
  3. Esa clave inicial nunca es perfecta, así que en el modo interactivo se
     refina a mano (con ayuda de patrones: "XT", "AX", "TE"...) y en el modo
     automático se refina por ascenso de colina, puntuando cada clave con la
     frecuencia de letras y con un pequeño diccionario de palabras frecuentes.

Nota: los símbolos del criptograma distinguen mayúsculas/minúsculas ("V" y "v"
son símbolos distintos). El texto original no tiene tildes ni signos
diacríticos, así que el texto descifrado tampoco los tendrá.
"""

import math
import random
import re
import sys
from collections import Counter

CRIPTOGRAMA = (
    "RIJ AZKKZHC PIKCE XT ACKCUXJHX SZX, E NZ PEJXKE, PXGIK XFDKXNEQE RIPI "
    "RIPQEHCK ET OENRCNPI AXNAX ZJ RKCHXKCI AX CJAXDXJAXJRCE AX RTENX, E "
    "ACOXKXJRCE AXT RITEQIKERCIJCNPI OKXJHXDIDZTCNHE AX TE ACKXRRCIJ "
    "EJEKSZCNHE.\n"
    "AZKKZHC OZX ZJ OERHIK AX DKCPXK IKAXJ XJ XT DEDXT AX TE RTENX IQKXKE XJ "
    "REHETZJVE XJ GZTCI AX 1936. DXKI AZKKZHC, RIPI IRZKKX RIJ TEN "
    "DXKNIJETCAEAXN XJ TE MCNHIKCE, JI REVI AXT RCXTI. DXKNIJCOCREQE TE "
    "HKEACRCIJ KXvITZRCIJEKCE AX TE RTENX IQKXKE. NZ XJIKPX DIDZTEKCAEA XJHKX "
    "TE RTENX HKEQEGEAIKE, KXOTXGEAE XJ XT XJHCXKKI PZTHCHZACJEKCI XJ "
    "QEKRXTIJE XT 22 AX JIvCXPQKX AX 1936, PZXNHKE XNE CAXJHCOCRERCIJ. NZ "
    "PZXKHX OZX NCJ AZAE ZJ UITDX IQGXHCvI ET DKIRXNI KXvITZRCIJEKCI XJ "
    "PEKRME. NCJ AZKKZHC SZXAI PEN TCQKX XT REPCJI DEKE SZX XT XNHETCJCNPI, "
    "RIJ TE RIPDTCRCAEA AXT UIQCXKJI AXT OKXJHX DIDZTEK V AX TE ACKXRRCIJ "
    "EJEKSZCNHE, HXKPCJEKE XJ PEVI AX 1937 TE HEKXE AX TCSZCAEK TE KXvITZRCIJ, "
    "AXNPIKETCLEJAI E TE RTENX IQKXKE V OERCTCHEJAI RIJ XTTI XT DINHXKCIK "
    "HKCZJOI OKEJSZCNHE."
)

# Frecuencia relativa (%) de las letras en castellano (sin ñ ni tildes).
# Si tu tabla del enunciado es distinta, cambia aquí los valores.
FRECUENCIAS_ES = {
    "e": 13.68, "a": 12.53, "o": 8.68, "s": 7.98, "r": 6.87, "n": 6.71,
    "i": 6.25, "d": 5.86, "l": 4.97, "c": 4.68, "t": 4.63, "u": 3.93,
    "m": 3.15, "p": 2.51, "b": 1.42, "h": 1.01, "q": 0.88, "y": 0.90,
    "v": 0.90, "g": 0.69, "f": 0.69, "j": 0.44, "z": 0.52, "x": 0.22,
    "k": 0.01, "w": 0.01,
}
ALFABETO = "abcdefghijklmnopqrstuvwxyz"

# Palabras muy frecuentes en castellano (para puntuar claves en modo auto).
PALABRAS_ES = set("""
a al algo ante antes aquel aqui as asi aun aunque bien cada como con contra
cual cuando de del desde donde dos durante e el ella ellos en entre era eran
es esa ese eso esta estaba estado estas este esto estos fue fueron ha han
hasta hay la las le les lo los mas me mi mientras muy ni no nos nuestra o
otra otro para pero por porque que quien se sea segun ser si sido sin sobre
solo su sus tambien tan tanto te tiene todo todos tras tu un una uno unos
y ya
hacer hace hacen hacia hecho hizo haber habia hombre hombres hoy hora horas
hijo hijos historia ahora alguna algunas alguno algunos ayer
julio junio juego jefe joven jovenes junto juntos justo justicia juicio
mejor mejores trabajo trabajos trabajador trabajadora trabajadores
trabajadoras mujer mujeres viaje viajes ejemplo ejemplos objeto objetivo
objetivos mucho mucha muchos muchas otros otras
expresar explicar existe existen exterior texto textos experiencia extremo
examen exacto exito exigir extra
vez veces luz paz voz zona zonas razon empezar comenzar fuerza fuerzas
esfuerzo realizar organizar lanzar centro cinco
primer primera primero tiempo tiempos mundo nuevo nueva nuevos nuevas
gobierno pueblo pueblos pais paises ciudad ciudades vida vidas casa casas
forma formas parte partes lugar lugares momento momentos grupo grupos
proceso procesos persona personas dia dias ano anos cosa cosas caso casos
""".split())

# Bigramas muy comunes en castellano (pequeña bonificación).
BIGRAMAS_ES = set("""
de en es el la los las un una al del que por con para
os ar ue ra re er as on st al or nt do ad se ta ci an co ei
ac nd ec ca ti to ie qu ia na te ro lo ri ni di ma me pa pe ol
ex xp pr res es sa ab ba br cr dr tr fr gr pl bl cl
de di dis des con com pro pre per per tra
""".split())

# Secuencias muy habituales en castellano. Se usan como evidencia adicional
# para distinguir soluciones que tienen la misma frecuencia de letras.
TRIGRAMAS_ES = set("""
que ent est sta era ado ada ido ida ian and end
con tra par ara res pre pro exp des men ter
aci cio ion nes por del los las una uno
nte ent ert dre str rie pri imp com
aba iaa ias asd ase ase asi
iza izo izo iza liz liza
exi exa exo ext exp
"""
.split())

# Prefijos y terminaciones frecuentes. Son especialmente útiles cuando una
# palabra concreta no está en PALABRAS_ES, pero su estructura sí es española.
PREFIJOS_ES = (
    "a", "e", "es", "en", "de", "re", "des", "con", "com",
    "pro", "pre", "per", "ex", "im", "in", "inter", "sobre"
)

SUFIJOS_ES = (
    "a", "o", "as", "os", "es", "aba", "abas", "aban",
    "ado", "ada", "ados", "adas", "ido", "ida", "idos", "idas",
    "ando", "iendo", "mente", "cion", "sion", "dad", "tad"
)

ANCHO = 64


# ----------------------------------------------------------------- utilidades
def simbolos_cifrado(texto):
    """Símbolos (letras, con distinción de mayúsculas) que aparecen en el texto."""
    return sorted({c for c in texto if c.isalpha()})


def frecuencias_cifrado(texto):
    letras = [c for c in texto if c.isalpha()]
    cont = Counter(letras)
    total = len(letras)
    return cont, total


def clave_inicial(texto):
    """Empareja símbolos y letras castellanas por orden de frecuencia."""
    cont, _ = frecuencias_cifrado(texto)
    simbolos = [s for s, _ in cont.most_common()]
    letras = sorted(FRECUENCIAS_ES, key=FRECUENCIAS_ES.get, reverse=True)
    return {s: letras[i] for i, s in enumerate(simbolos)}


def aplicar(texto, clave, desconocido="_"):
    """Texto descifrado; los símbolos sin asignar salen como '_'."""
    return "".join(
        clave.get(c, desconocido) if c.isalpha() else c for c in texto
    )


# ------------------------------------------------------------------ pantalla
def mostrar_frecuencias(texto, clave):
    cont, total = frecuencias_cifrado(texto)
    print(f"\n{'símbolo':>7} {'apar.':>5} {'%':>6}   asignado"
          f"   |   letra  % en castellano")
    print("-" * 66)
    es_ordenado = sorted(FRECUENCIAS_ES.items(), key=lambda kv: -kv[1])
    for i, (s, n) in enumerate(cont.most_common()):
        letra, frec = es_ordenado[i] if i < len(es_ordenado) else ("", 0)
        asignado = clave.get(s, "-")
        print(f"{s:>7} {n:>5} {100 * n / total:6.2f}   {asignado:>8}"
              f"   |   {letra:>5}  {frec:6.2f}")
    print(f"\n(total de letras: {total})")


def mostrar_texto(texto, clave):
    """Muestra el criptograma y el texto descifrado en líneas paralelas."""
    print()
    for parrafo in texto.split("\n"):
        palabras = parrafo.split(" ")
        lineas, actual = [], ""
        for p in palabras:
            if len(actual) + len(p) + (1 if actual else 0) > ANCHO:
                lineas.append(actual)
                actual = p
            else:
                actual = f"{actual} {p}" if actual else p
        lineas.append(actual)
        for linea in lineas:
            print("  cif:", linea)
            print("  cla:", aplicar(linea, clave))
            print()


def avisar_letras_poco_fiables(cifrado, clave, umbral=10):
    """Avisa de los símbolos con tan pocas apariciones que la frecuencia
    no basta para asegurar su letra (p. ej. j, h, x, z, k, w...)."""
    cont, _ = frecuencias_cifrado(cifrado)
    raros = [(s, n) for s, n in sorted(cont.items(), key=lambda kv: kv[1])
             if n < umbral and s in clave]
    if raros:
        detalle = ", ".join(f"{s}->{clave[s]} ({n} veces)" for s, n in raros)
        print("AVISO: estos símbolos aparecen muy pocas veces, así que la")
        print("frecuencia no es fiable para ellos; revísalos en el texto:")
        print("  " + detalle + "\n")


def mostrar_clave(clave):
    inv = {v: k for k, v in clave.items()}
    print("\nClave actual (letra original -> símbolo cifrado):")
    fila1 = " ".join(f"{l}" for l in ALFABETO)
    fila2 = " ".join(inv.get(l, "·") for l in ALFABETO)
    print("  original:", fila1)
    print("  cifrado :", fila2)


# ---------------------------------------------------------- modo automático
def patrones_palabra(palabra):
    """Devuelve el patrón de repetición de una palabra.

    Ejemplo:
        'casa' -> (0, 1, 2, 0)
        'ella' -> (0, 1, 1, 0)
    """
    mapa = {}
    siguiente = 0
    patron = []
    for c in palabra:
        if c not in mapa:
            mapa[c] = siguiente
            siguiente += 1
        patron.append(mapa[c])
    return tuple(patron)


def construir_indices_palabras():
    """Índice del diccionario por longitud y patrón de repetición."""
    indice = {}
    for palabra in PALABRAS_ES:
        if not palabra.isalpha():
            continue
        clave = (len(palabra), patrones_palabra(palabra))
        indice.setdefault(clave, set()).add(palabra)
    return indice


INDICE_PALABRAS = construir_indices_palabras()


def candidatos_palabra(palabra):
    """Devuelve palabras del diccionario compatibles con el patrón de 'palabra'."""
    return INDICE_PALABRAS.get(
        (len(palabra), patrones_palabra(palabra)), set()
    )


def puntuar(cifrado, clave, cont):
    """Mayor puntuación = más parecido al castellano.

    Además de frecuencias y palabras completas, utiliza secuencias de 2 y
    3 letras, prefijos y terminaciones. Esto permite detectar automáticamente
    errores como una X/Z intercambiada aunque la palabra exacta no esté en
    el diccionario.
    """
    # 1) Verosimilitud de las frecuencias de letras.
    ll = 0.0
    for s, n in cont.items():
        letra = clave.get(s)
        if letra in FRECUENCIAS_ES:
            ll += n * math.log(FRECUENCIAS_ES[letra] / 100.0)

    texto = aplicar(cifrado, clave).lower()
    palabras = re.findall(r"[a-z]+", texto)

    # 2) Palabras completas conocidas.
    pts_pal = sum(len(p) ** 2 for p in palabras if p in PALABRAS_ES)

    # 3) Bigramas.
    pts_big = sum(
        1 for p in palabras
        for i in range(len(p) - 1)
        if p[i:i + 2] in BIGRAMAS_ES
    )

    # 4) Trigramas: tienen mucho más poder para detectar combinaciones
    # poco naturales como "ezp" frente a "exp".
    pts_tri = sum(
        1 for p in palabras
        for i in range(len(p) - 2)
        if p[i:i + 3] in TRIGRAMAS_ES
    )

    # 5) Prefijos y sufijos.
    pts_morf = 0.0
    for p in palabras:
        if len(p) >= 3:
            if any(p.startswith(pref) for pref in PREFIJOS_ES if len(pref) >= 2):
                pts_morf += 0.8
            if any(p.endswith(suf) for suf in SUFIJOS_ES if len(suf) >= 3):
                pts_morf += 1.2

    # 6) Penalización suave de secuencias muy poco naturales.
    # No se prohíben: algunas pueden existir en nombres propios o extranjerismos.
    SECUENCIAS_RARAS = (
        "zx", "xz", "xq", "qx", "zq", "qz", "jq", "qj",
        "wv", "vw", "jj", "ww"
    )
    penalizacion = sum(
        1 for p in palabras
        for i in range(len(p) - 1)
        if p[i:i + 2] in SECUENCIAS_RARAS
    )

    # Los trigramas reciben bastante peso porque son precisamente los que
    # permiten diferenciar "expresaba" de "ezpresaba".
    return (
        ll
        + 6.0 * pts_pal
        + 1.5 * pts_big
        + 3.0 * pts_tri
        + 1.0 * pts_morf
        - 2.0 * penalizacion
    )


def refinamiento_local(cifrado, clave, cont):
    """Busca mejoras mediante intercambios de letras."""
    simbolos = list(cont)
    pts = puntuar(cifrado, clave, cont)

    while True:
        mejor_mov = None
        mejor_pts = pts

        # Intercambiar dos símbolos cifrados.
        for i, a in enumerate(simbolos):
            for b in simbolos[i + 1:]:
                clave[a], clave[b] = clave[b], clave[a]
                p = puntuar(cifrado, clave, cont)
                clave[a], clave[b] = clave[b], clave[a]

                if p > mejor_pts + 1e-9:
                    mejor_mov = ("swap", a, b)
                    mejor_pts = p

        if mejor_mov is None:
            break

        _, a, b = mejor_mov
        clave[a], clave[b] = clave[b], clave[a]
        pts = mejor_pts

    return clave, pts


def corregir_errores_raros(cifrado, clave, cont):
    """Comprueba automáticamente letras poco fiables.

    Las letras que aparecen pocas veces son las más susceptibles de quedar
    intercambiadas por análisis de frecuencia. Para corregirlas se prueba
    cada intercambio con otras letras y se conserva solo si mejora claramente
    la puntuación lingüística.

    Esto permite corregir casos como X/Z sin escribir:
        clave["X"] = "x"
        clave["Z"] = "z"
    """
    simbolos = list(cont)
    raros = [
        s for s in simbolos
        if cont[s] <= 10
    ]

    pts_actual = puntuar(cifrado, clave, cont)

    # Varias pasadas porque una corrección puede desbloquear otra.
    for _ in range(3):
        cambiado = False

        for a in raros:
            mejor_b = None
            mejor_pts = pts_actual

            for b in simbolos:
                if a == b:
                    continue

                clave[a], clave[b] = clave[b], clave[a]
                p = puntuar(cifrado, clave, cont)
                clave[a], clave[b] = clave[b], clave[a]

                if p > mejor_pts + 1e-9:
                    mejor_b = b
                    mejor_pts = p

            if mejor_b is not None:
                clave[a], clave[mejor_b] = clave[mejor_b], clave[a]
                pts_actual = mejor_pts
                cambiado = True

        if not cambiado:
            break

    return clave, pts_actual


def resolver_auto(cifrado, semilla=1, reinicios=12):
    """Resuelve automáticamente la sustitución.

    Se utilizan varios reinicios aleatorios para evitar quedarse atrapado
    en una solución local. Después se hace un segundo refinamiento centrado
    en símbolos poco frecuentes, que son los más propensos a intercambiarse.
    """
    rng = random.Random(semilla)
    cont, _ = frecuencias_cifrado(cifrado)
    simbolos = list(cont)
    inicial = clave_inicial(cifrado)

    mejor, mejor_pts = None, -math.inf

    for r in range(reinicios):
        clave = dict(inicial)

        # Reinicios: realizar más perturbaciones cuanto más avanzado esté
        # el número de reinicio.
        if r:
            for _ in range(rng.randint(3, min(20, max(3, len(simbolos))))):
                a, b = rng.sample(simbolos, 2)
                clave[a], clave[b] = clave[b], clave[a]

        clave, pts = refinamiento_local(cifrado, clave, cont)
        clave, pts = corregir_errores_raros(cifrado, clave, cont)
        clave, pts = refinamiento_local(cifrado, clave, cont)

        if pts > mejor_pts:
            mejor, mejor_pts = dict(clave), pts

    # Última comprobación: probar todos los intercambios entre símbolos
    # poco frecuentes sobre la mejor solución encontrada. Esto es barato y
    # es especialmente útil para pares como X/Z.
    raros = [s for s in simbolos if cont[s] <= 10]
    clave_final = dict(mejor)
    pts_final = puntuar(cifrado, clave_final, cont)

    mejoro = True
    while mejoro:
        mejoro = False
        for i, a in enumerate(raros):
            for b in raros[i + 1:]:
                clave_final[a], clave_final[b] = clave_final[b], clave_final[a]
                p = puntuar(cifrado, clave_final, cont)

                if p > pts_final + 1e-9:
                    pts_final = p
                    mejoro = True
                else:
                    clave_final[a], clave_final[b] = clave_final[b], clave_final[a]

    return clave_final


# -------------------------------------------------------- modo interactivo
AYUDA = """
Comandos (los símbolos cifrados distinguen mayúsculas: V y v son distintos):
  X=e        asigna al símbolo cifrado X la letra original e
  swap X Y   intercambia las letras asignadas a los símbolos X e Y
  del X      quita la asignación del símbolo X
  freq       tabla de frecuencias del criptograma vs castellano
  ver        muestra el criptograma y el texto descifrado
  clave      muestra la clave en forma de alfabeto
  auto       resuelve automáticamente (ascenso de colina)
  reset      vuelve a la clave inicial por frecuencias
  ayuda      muestra esta ayuda
  salir      termina
"""


def interactivo(cifrado):
    clave = clave_inicial(cifrado)
    simbolos = set(simbolos_cifrado(cifrado))
    print("ATAQUE POR ANÁLISIS DE FRECUENCIAS - sustitución simple")
    print("Clave inicial propuesta por orden de frecuencia (casi seguro habrá errores).")
    mostrar_frecuencias(cifrado, clave)
    mostrar_texto(cifrado, clave)
    print(AYUDA)

    while True:
        try:
            orden = input("> ").strip()
        except EOFError:
            print()
            break
        if not orden:
            continue
        partes = orden.split()
        cmd = partes[0].lower() if "=" not in orden else "="

        if cmd in ("salir", "exit", "q"):
            break
        elif cmd == "ayuda":
            print(AYUDA)
        elif cmd == "freq":
            mostrar_frecuencias(cifrado, clave)
        elif cmd == "ver":
            mostrar_texto(cifrado, clave)
        elif cmd == "clave":
            mostrar_clave(clave)
        elif cmd == "reset":
            clave = clave_inicial(cifrado)
            mostrar_texto(cifrado, clave)
        elif cmd == "auto":
            clave = resolver_auto(cifrado)
            mostrar_texto(cifrado, clave)
        elif cmd == "swap" and len(partes) == 3:
            a, b = partes[1], partes[2]
            if a in clave and b in clave:
                clave[a], clave[b] = clave[b], clave[a]
                mostrar_texto(cifrado, clave)
            else:
                print("Símbolo desconocido (¿mayúsculas/minúsculas?).")
        elif cmd == "del" and len(partes) == 2:
            clave.pop(partes[1], None)
            mostrar_texto(cifrado, clave)
        elif cmd == "=":
            izq, _, der = orden.partition("=")
            s, l = izq.strip(), der.strip().lower()
            if s not in simbolos or l not in ALFABETO or len(l) != 1:
                print("Formato: SIMBOLO=letra   (p. ej.  X=e)")
                continue
            # si la letra ya la usa otro símbolo, se intercambian
            otro = next((k for k, v in clave.items() if v == l and k != s), None)
            previa = clave.get(s)
            clave[s] = l
            if otro is not None:
                if previa is not None:
                    clave[otro] = previa
                else:
                    del clave[otro]
            mostrar_texto(cifrado, clave)
        else:
            print("Comando no reconocido. Escribe 'ayuda'.")

    print("\nClave final:")
    mostrar_clave(clave)
    print("\nTexto descifrado:\n")
    print(aplicar(cifrado, clave))


def main():
    if "--auto" in sys.argv:
        clave = resolver_auto(CRIPTOGRAMA)
        mostrar_clave(clave)
        mostrar_texto(CRIPTOGRAMA, clave)
        print("Texto descifrado:\n")
        print(aplicar(CRIPTOGRAMA, clave))
    else:
        interactivo(CRIPTOGRAMA)


if __name__ == "__main__":
    main()
