
# 🔐 ContextFlow-Crypt

**ContextFlow-Crypt** es un prototipo de cifrado personalizado sensible al contexto, con autenticación integrada y una demo web interactiva hecha con Streamlit.

---

## 🚀 Características

- 🔒 Cifrado autenticado (AES-like) con bloques de 128 bits
- 🔁 Rondas variables (8–16) impulsadas por SHA-256 del contexto
- 📋 MAC verificado (HMAC-SHA256)
- 🧠 Sensibilidad al entorno: username, hostname, timestamp y UUID
- 🌐 Interfaz visual en Streamlit para cifrar, descifrar y copiar paquetes únicos

---

## 🧰 Requisitos

- Python 3.9 o superior
- Entorno virtual recomendado (`.venv`)
- Dependencias listadas en `requirements.txt`

---

## ⚙️ Instalación

### 1. Clona el repositorio o copia los archivos

```bash
git clone https://github.com/tu-usuario/ContextFlow-Crypt.git
cd ContextFlow-Crypt
```

### 2. Crea y activa un entorno virtual

```bash
python -m venv .venv
.\.venv\Scriptsctivate        # En Windows
# source .venv/bin/activate    # En Linux/macOS
```

### 3. Instala las dependencias

```bash
pip install -r requirements.txt
```

---

## ▶️ Ejecutar la demo

```bash
streamlit run demo_streamlit.py
```

Esto abrirá automáticamente la demo en tu navegador.

---

## 📦 ¿Qué es un "paquete único"?

Es una cadena codificada en Base64 que contiene:

- 🔑 La clave
- 🔐 El texto cifrado (ciphertext)
- 🌍 El vector de contexto

Este paquete puede copiarse/pegarse fácilmente entre computadoras para demostrar el cifrado y descifrado.

---

## 📋 Créditos

Desarrollado como parte de un proyecto académico de Seguridad Informática – UCSM.
