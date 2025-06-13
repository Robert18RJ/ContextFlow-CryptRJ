# ContextFlow-Crypt - Prototipo de referencia (Python 3.9+)

# • Cifrado de bloques adaptativo y sensible al contexto (bloques de 128 bits)
# • Cifrado autenticado: (texto cifrado ‖ MAC)
# • Rondas variables (8-16) impulsadas por SHA-256(contexto)
# • Operaciones: XOR, inversión de bits, rotación de bytes

from __future__ import annotations
import hashlib # Importa el módulo hashlib para funciones de hash como SHA-256 y BLAKE2s.
import hmac # Importa el módulo hmac para la creación y verificación de códigos de autenticación de mensajes (MAC).
import os # Importa el módulo os para interactuar con el sistema operativo, como obtener el nombre de usuario.
import secrets # Importa el módulo secrets para generar números aleatorios criptográficamente seguros.
import socket # Importa el módulo socket para obtener información de la red, como el nombre del host.
import time # Importa el módulo time para obtener la marca de tiempo actual.
import uuid # Importa el módulo uuid para generar identificadores únicos universales (UUID).
from typing import List, Dict, Tuple # Importa tipos para anotaciones de tipo, mejorando la legibilidad y validación.


class ContextFlowCrypt:
    BLOCK_SIZE = 16  # Define el tamaño del bloque en bytes (128 bits).
    MIN_ROUNDS = 8  # Define el número mínimo de rondas de cifrado.
    MAX_ROUNDS = 16 # Define el número máximo de rondas de cifrado.
    MAC_LEN    = 32  # Define la longitud del MAC en bytes (resultado de SHA-256).

    # ---------- API pública ---------- #
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, str]:
        """
        Cifra el texto plano y genera un MAC.
        Retorna una tupla que contiene el texto cifrado concatenado con el MAC, y el vector de contexto.
        """
        ContextFlowCrypt._validate_key(key) # Valida que la clave sea de tipo bytes y tenga la longitud adecuada.
        context_vec = ContextFlowCrypt._collect_context() # Recolecta el vector de contexto dinámicamente.
        cfc = ContextFlowCrypt(key, context_vec) # Inicializa una instancia de ContextFlowCrypt con la clave y el contexto.
        ctxt = cfc._encrypt_blocks(plaintext) # Cifra los bloques de texto plano.
        mac  = cfc._make_mac(ctxt) # Genera el MAC para el texto cifrado.
        return ctxt + mac, context_vec # Retorna el texto cifrado + MAC y el vector de contexto.

    @staticmethod
    def decrypt(pkg: bytes, key: bytes, context_vec: str) -> bytes:
        """
        Verifica el MAC con el contexto proporcionado y devuelve el texto plano.
        Lanza un ValueError si la verificación del MAC falla o el paquete es muy corto.
        """
        ContextFlowCrypt._validate_key(key) # Valida la clave antes de la desencriptación.
        if len(pkg) < ContextFlowCrypt.MAC_LEN:
            raise ValueError("Package too short") # Verifica que el paquete tenga al menos la longitud del MAC.
        ctxt, mac = pkg[:-ContextFlowCrypt.MAC_LEN], pkg[-ContextFlowCrypt.MAC_LEN:] # Separa el texto cifrado del MAC.
        cfc = ContextFlowCrypt(key, context_vec) # Inicializa una instancia con la clave y el contexto para la desencriptación.
        if not hmac.compare_digest(mac, cfc._make_mac(ctxt)): # Compara el MAC proporcionado con uno recién calculado para evitar ataques de temporización.
            raise ValueError("MAC verification failed") # Lanza un error si la verificación del MAC falla.
        return cfc._decrypt_blocks(ctxt) # Desencripta los bloques y retorna el texto plano.

    # ---------- Construcción ---------- #
    def __init__(self, key: bytes, context_vec: str):
        """
        Constructor de la clase ContextFlowCrypt.
        Inicializa la clave, el vector de contexto, calcula el hash del contexto
        y determina el número de rondas y las claves de ronda.
        """
        self.key           = key # Almacena la clave de cifrado.
        self.context_vec   = context_vec # Almacena el vector de contexto.
        self.context_hash  = hashlib.sha256(context_vec.encode()).digest() # Calcula el hash SHA-256 del vector de contexto.
        # Determina el número de rondas basándose en una parte del hash del contexto, asegurando que esté dentro del rango MIN_ROUNDS y MAX_ROUNDS.
        self.n_rounds      = (int.from_bytes(self.context_hash[24:28], "big") %
                              (self.MAX_ROUNDS - self.MIN_ROUNDS + 1)) + self.MIN_ROUNDS
        self.round_keys    = self._expand_key_schedule() # Expande la clave maestra en claves de ronda.

    # ---------- Utilidades de contexto y clave ---------- #
    @staticmethod
    def _collect_context() -> str:
        """
        Recolecta información de contexto del entorno actual.
        Incluye marca de tiempo, nombre de usuario, nombre de host y un UUID de sesión.
        """
        ts_ns = str(time.time_ns()) # Obtiene la marca de tiempo actual en nanosegundos.
        try:
            username = os.getlogin() # Intenta obtener el nombre de usuario del sistema.
        except OSError:
            import getpass
            username = getpass.getuser() # Si falla, usa getpass para obtener el nombre de usuario.
        hostname = socket.gethostname() # Obtiene el nombre del host de la máquina.
        session_uuid = str(uuid.uuid4()) # Genera un UUID único para la sesión.
        return f"{ts_ns}|{username}|{hostname}|{session_uuid}" # Concatena la información en una cadena de contexto.

    @staticmethod
    def _validate_key(key: bytes) -> None:
        """
        Valida que la clave proporcionada sea de tipo bytes y tenga una longitud mínima de 128 bits (16 bytes).
        Lanza TypeError o ValueError si la validación falla.
        """
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes") # Verifica que la clave sea de tipo bytes o bytearray.
        if len(key) < 16:
            raise ValueError("key length must be ≥128 bits") # Verifica que la longitud de la clave sea al menos 16 bytes.

    # ---------- Programación de claves ---------- #
    def _expand_key_schedule(self) -> List[bytes]:
        """
        Expande la clave maestra en un conjunto de claves de ronda utilizando BLAKE2s.
        Genera una clave de ronda para cada ronda de cifrado, más una para el blanqueamiento inicial/final.
        """
        rk = [] # Lista para almacenar las claves de ronda.
        for r in range(self.n_rounds + 1):  # +1 para la clave de blanqueamiento.
            data = self.key + r.to_bytes(4, "big") # Concatena la clave maestra con el número de ronda.
            # Genera una clave de ronda usando BLAKE2s con un tamaño de digestión igual al tamaño del bloque y una personalización específica.
            rk.append(hashlib.blake2s(data, digest_size=self.BLOCK_SIZE,
                                      person=b"CFCkey").digest())
        return rk # Retorna la lista de claves de ronda.

    # ---------- Derivación de operaciones ---------- #
    def _derive_operations(self, round_num: int) -> List[Dict]:
        """
        Deriva un conjunto de operaciones (XOR, INVERTIR, ROTAR) para una ronda específica
        basándose en el hash del contexto y el número de ronda.
        """
        seed = self.context_hash + round_num.to_bytes(4, "big") # Crea una semilla combinando el hash del contexto y el número de ronda.
        # Genera un flujo de bytes aleatorios a partir de la semilla usando BLAKE2s.
        stream = hashlib.blake2s(seed, digest_size=32, person=b"CFCRYPT").digest()
        ops: List[Dict] = [] # Lista para almacenar las operaciones.
        for i in range(0, 8, 2):  # Genera 4 operaciones.
            op_type = stream[i] % 3 # Determina el tipo de operación (0: XOR, 1: INVERTIR, 2: ROTAR).
            param   = stream[i + 1] # Obtiene el parámetro para la operación.
            if op_type == 2:
                param %= 8 # Asegura que el parámetro de rotación esté dentro del rango de bits de un byte.
            ops.append({"type": op_type, "param": param}) # Añade la operación y su parámetro a la lista.
        return ops # Retorna la lista de operaciones derivadas.

    # ---------- Funciones de ayuda para el relleno ---------- #
    def _pad(self, data: bytes) -> bytes:
        """
        Aplica el esquema de relleno PKCS#7 al final de los datos para asegurar que tengan
        una longitud múltiplo del tamaño del bloque.
        """
        pad_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE) # Calcula la longitud del relleno necesario.
        return data + bytes([pad_len]) * pad_len # Añade el relleno a los datos.

    def _unpad(self, data: bytes) -> bytes:
        """
        Elimina el relleno PKCS#7 de los datos.
        Lanza un ValueError si el relleno es inválido.
        """
        pad_len = data[-1] # Obtiene la longitud del relleno del último byte.
        if pad_len == 0 or pad_len > self.BLOCK_SIZE:
            raise ValueError("Invalid padding length") # Verifica que la longitud del relleno sea válida.
        if data[-pad_len:] != bytes([pad_len]) * pad_len:
            raise ValueError("Invalid padding") # Verifica que los bytes de relleno sean correctos.
        return data[:-pad_len] # Retorna los datos sin el relleno.

    @staticmethod
    def _rotate_bytes(block: bytearray, shift: int) -> bytearray:
        """
        Rota los bytes de un bloque circularmente a la izquierda o derecha.
        """
        if shift == 0:
            return block # Si el desplazamiento es 0, no hace nada.
        return block[shift:] + block[:shift] # Realiza la rotación de bytes.

    # ---------- Cifrado / Descenso ---------- #
    def _encrypt_blocks(self, plaintext: bytes) -> bytes:
        """
        Cifra los bloques de texto plano.
        Aplica blanqueamiento inicial, rondas de operaciones y XOR con claves de ronda.
        """
        pt = self._pad(plaintext) # Rellena el texto plano para que sea un múltiplo del tamaño del bloque.
        ct = bytearray() # Inicializa un array de bytes para el texto cifrado.

        for off in range(0, len(pt), self.BLOCK_SIZE): # Itera sobre el texto plano en bloques.
            block = bytearray(pt[off: off + self.BLOCK_SIZE]) # Obtiene el bloque actual.

            # Blanqueamiento inicial (XOR con la primera clave de ronda).
            for i in range(self.BLOCK_SIZE):
                block[i] ^= self.round_keys[0][i]

            # Rondas de cifrado.
            for r in range(1, self.n_rounds + 1):
                ops = self._derive_operations(r) # Deriva las operaciones para la ronda actual.
                block = self._apply_ops(block, ops) # Aplica las operaciones al bloque.
                rk = self.round_keys[r] # Obtiene la clave de ronda para la ronda actual.
                for i in range(self.BLOCK_SIZE):
                    block[i] ^= rk[i] # Aplica XOR al bloque con la clave de ronda.

            ct.extend(block) # Añade el bloque cifrado al texto cifrado total.
        return bytes(ct) # Retorna el texto cifrado como bytes.

    def _decrypt_blocks(self, ciphertext: bytes) -> bytes:
        """
        Descifra los bloques de texto cifrado.
        Aplica las operaciones inversas de las rondas y el des-blanqueamiento.
        """
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length multiple of block size required") # Verifica que la longitud del texto cifrado sea múltiplo del tamaño del bloque.
        pt = bytearray() # Inicializa un array de bytes para el texto plano.

        for off in range(0, len(ciphertext), self.BLOCK_SIZE): # Itera sobre el texto cifrado en bloques.
            block = bytearray(ciphertext[off: off + self.BLOCK_SIZE]) # Obtiene el bloque actual.

            # Rondas inversas (desde la última hasta la primera).
            for r in range(self.n_rounds, 0, -1):
                rk = self.round_keys[r] # Obtiene la clave de ronda para la ronda actual.
                for i in range(self.BLOCK_SIZE):
                    block[i] ^= rk[i] # Aplica XOR al bloque con la clave de ronda (es su propia inversa).
                ops = self._derive_operations(r) # Deriva las operaciones para la ronda actual.
                block = self._apply_ops_inv(block, ops) # Aplica las operaciones inversas al bloque.

            # Des-blanqueamiento (XOR con la primera clave de ronda).
            for i in range(self.BLOCK_SIZE):
                block[i] ^= self.round_keys[0][i]

            pt.extend(block) # Añade el bloque descifrado al texto plano total.
        return self._unpad(pt) # Retorna el texto plano sin el relleno.

    # ---------- Operaciones ---------- #
    def _apply_ops(self, state: bytearray, ops: List[Dict]) -> bytearray:
        """
        Aplica una lista de operaciones (XOR, INVERTIR, ROTAR) a un bloque de estado.
        """
        for op in ops:
            typ, param = op["type"], op["param"] # Obtiene el tipo de operación y su parámetro.
            if typ == 0:  # Operación XOR.
                state[:] = bytearray(b ^ param for b in state) # Aplica XOR a cada byte del estado con el parámetro.
            elif typ == 1:  # Operación INVERTIR.
                for idx in range(self.BLOCK_SIZE):
                    if param & (1 << (idx % 8)): # Si el bit correspondiente en el parámetro está configurado.
                        state[idx] ^= 0xFF # Invierte todos los bits del byte.
            else:  # Operación ROTAR.
                state[:] = self._rotate_bytes(state, param) # Rota los bytes del estado.
        return state # Retorna el estado modificado.

    def _apply_ops_inv(self, state: bytearray, ops: List[Dict]) -> bytearray:
        """
        Aplica las operaciones inversas a un bloque de estado.
        Las operaciones se aplican en orden inverso.
        """
        for op in reversed(ops): # Itera sobre las operaciones en orden inverso.
            typ, param = op["type"], op["param"] # Obtiene el tipo de operación y su parámetro.
            if typ == 0:  # Operación XOR (es su propia inversa).
                state[:] = bytearray(b ^ param for b in state) # Aplica XOR a cada byte del estado con el parámetro.
            elif typ == 1:  # Operación INVERTIR (es su propia inversa).
                for idx in range(self.BLOCK_SIZE):
                    if param & (1 << (idx % 8)):
                        state[idx] ^= 0xFF
            else:  # Operación ROTAR inversa.
                state[:] = self._rotate_bytes(state, -param % self.BLOCK_SIZE) # Rota los bytes en la dirección opuesta.
        return state # Retorna el estado modificado.

    # ---------- MAC ---------- #
    def _make_mac(self, ciphertext: bytes) -> bytes:
        """
        Calcula el Código de Autenticación de Mensajes (MAC) para el texto cifrado.
        Utiliza HMAC con SHA-256, la clave y el vector de contexto.
        """
        # Crea un nuevo objeto HMAC usando la clave, la concatenación del vector de contexto codificado y el texto cifrado, y SHA-256.
        return hmac.new(self.key, self.context_vec.encode() + ciphertext,
                                 hashlib.sha256).digest() # Retorna el digest del HMAC.


# --------------- Demostración ----------------- #
if __name__ == "__main__":
    key = secrets.token_bytes(32)  # Genera una clave aleatoria de 256 bits (32 bytes).
    msg = b"Attack at dawn! Meet at the oak tree." # Mensaje de texto plano a cifrar.
    package, ctx = ContextFlowCrypt.encrypt(msg, key) # Cifra el mensaje y obtiene el paquete cifrado y el contexto.
    print("Cipher (partial):", package.hex()[:60], "…") # Imprime una parte del texto cifrado en formato hexadecimal.
    recovered = ContextFlowCrypt.decrypt(package, key, ctx) # Descifra el paquete usando la clave y el contexto.
    assert recovered == msg # Afirma que el mensaje recuperado es idéntico al mensaje original.
    print("✅ Successful round-trip") # Imprime un mensaje de éxito si la ida y vuelta del cifrado/descifrado fue correcta.