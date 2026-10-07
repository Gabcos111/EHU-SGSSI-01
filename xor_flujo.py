#!/usr/bin/env python3
"""Cifrado de flujo sencillo mediante XOR byte a byte.

Uso:
    python3 xor_flujo.py                      # datos de prueba (modo estricto)
    python3 xor_flujo.py --repetir-clave      # repite la clave si es más corta
    python3 xor_flujo.py "mensaje" "clave"    # otros datos

Por defecto el programa exige que mensaje y clave tengan la MISMA longitud en
bytes (como pide el enunciado). Con --repetir-clave la clave se repite
cíclicamente hasta cubrir el mensaje: funciona, pero deja de ser un cifrado de
un solo uso y es mucho más débil (patrones repetidos revelan la clave).
"""

import argparse
import sys

MENSAJE_PRUEBA = "ATAQUE AL AMANECER"
CLAVE_PRUEBA = "CLAVE12345678901"


def xor_bytes(datos: bytes, clave: bytes) -> bytes:
    """XOR byte a byte; datos y clave deben tener la misma longitud."""
    if len(datos) != len(clave):
        raise ValueError(
            f"longitudes distintas: datos={len(datos)} bytes, clave={len(clave)} bytes"
        )
    return bytes(d ^ k for d, k in zip(datos, clave))


def ajustar_clave(clave: bytes, longitud: int) -> bytes:
    """Repite la clave cíclicamente hasta alcanzar `longitud` bytes."""
    return (clave * (longitud // len(clave) + 1))[:longitud]


def hexa(datos: bytes) -> str:
    return datos.hex(" ").upper()


def main() -> int:
    ap = argparse.ArgumentParser(description="Cifrado de flujo XOR")
    ap.add_argument("mensaje", nargs="?", default=MENSAJE_PRUEBA)
    ap.add_argument("clave", nargs="?", default=CLAVE_PRUEBA)
    ap.add_argument("--repetir-clave", action="store_true",
                    help="repite la clave si es más corta que el mensaje")
    args = ap.parse_args()

    mensaje = args.mensaje.encode("utf-8")
    clave = args.clave.encode("utf-8")

    if len(mensaje) != len(clave):
        if not args.repetir_clave:
            print(f"ERROR: el mensaje tiene {len(mensaje)} bytes y la clave "
                  f"{len(clave)}; deben ser iguales.\n"
                  "       Usa una clave de la misma longitud o la opción "
                  "--repetir-clave.", file=sys.stderr)
            return 1
        if len(clave) > len(mensaje):
            clave = clave[:len(mensaje)]
        else:
            clave = ajustar_clave(clave, len(mensaje))
        print("AVISO: la clave se ha repetido/recortado para igualar la "
              "longitud del mensaje (cifrado más débil).\n")

    criptograma = xor_bytes(mensaje, clave)
    recuperado = xor_bytes(criptograma, clave)   # la misma operación descifra

    print(f"Mensaje    : {mensaje.decode()}")
    print(f"  hex      : {hexa(mensaje)}")
    print(f"Clave      : {clave.decode()}")
    print(f"  hex      : {hexa(clave)}")
    print(f"Criptograma: {hexa(criptograma)}")
    print(f"Descifrado : {recuperado.decode()}")
    print(f"  hex      : {hexa(recuperado)}")

    ok = recuperado == mensaje
    print(f"\nComprobación (descifrado == mensaje original): "
          f"{'CORRECTA' if ok else 'FALLIDA'}")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
