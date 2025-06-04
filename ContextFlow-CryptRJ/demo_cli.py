# demo_cli.py
from contextflow_crypt import ContextFlowCrypt, secrets

def main():
    print("== ContextFlow-Crypt demo ==")
    key = secrets.token_bytes(32)
    print(f"Clave hex: {key.hex()}")
    pt = input("Escribe texto plano -> ")
    ct, ctx = ContextFlowCrypt.encrypt(pt.encode(), key)
    print("Cipher (hex parcial):", ct.hex()[:60], "…")
    print("Contexto:", ctx)

    if input("¿Descifrar ahora? (s/n) ").lower() == "s":
        dec = ContextFlowCrypt.decrypt(ct, key, ctx)
        print("Resultado:", dec.decode())

if __name__ == "__main__":
    main()
