# demo_streamlit.py  –  ContextFlow-Crypt demo (sin botones de copiar/pegar)
import base64, json, secrets, streamlit as st
from contextflow_crypt import ContextFlowCrypt

# ---------- Configuración ----------
st.set_page_config(
    page_title="ContextFlow-Crypt Demo",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="collapsed",
)

ACCENT, BG_DARK = "#00FF87", "#0B0E11"

# ---------- CSS ----------
st.markdown(
    f"""
    <style>
        html, body, [data-testid="stApp"] {{
            background-color:{BG_DARK}; color:white;
        }}
        .stButton>button {{
            background-color:{ACCENT}; color:black; border:none;
            transition:.2s; font-weight:600;
        }}
        .stButton>button:hover {{ box-shadow:0 0 12px {ACCENT}; transform:scale(1.05); }}
        textarea, input {{
            background:rgba(255,255,255,.05); color:white;
            border:1px solid rgba(255,255,255,.15);
        }}
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🔐 ContextFlow-Crypt – Live Demo")

tab_enc, tab_dec = st.tabs(["Encrypt", "Decrypt"])

# ------------------- ENCRYPT -------------------
with tab_enc:
    st.subheader("Cifrar texto")
    plaintext = st.text_area("Texto plano")
    key_hex   = st.text_input("Clave (hex)", value=secrets.token_hex(32))

    if st.button("Encrypt"):
        try:
            key_bytes = bytes.fromhex(key_hex)
            cipher_bytes, context_vec = ContextFlowCrypt.encrypt(
                plaintext.encode(), key_bytes
            )
            cipher_b64 = base64.b64encode(cipher_bytes).decode()

            st.text_area("Ciphertext (Base64)", cipher_b64, height=120)
            st.text_input("Contexto generado", context_vec)

            # —— Paquete único
            package_str = base64.b64encode(
                json.dumps({"k": key_hex, "c": cipher_b64, "x": context_vec}).encode()
            ).decode()

            st.text_input(
                "Paquete único (copia con el icono 📋 o Ctrl+C)",
                package_str,
            )

            st.success("✅ Paquete generado. Copia con el icono 📋 o Ctrl+C")

        except Exception as e:
            st.error(f"Error: {e}")

# ------------------- DECRYPT -------------------
with tab_dec:
    st.subheader("Descifrar texto")

    st.markdown(
        "📋 **Paso 1.** Copia el paquete único desde la pestaña **Encrypt** "
        "usando el icono de copia o Ctrl+C.<br>"
        "💾 **Paso 2.** PégalO aquí (Ctrl+V) y pulsa **Importar paquete**.",
        unsafe_allow_html=True,
    )

    pkg_in = st.text_area("Paquete único")
    if st.button("Importar paquete"):
        try:
            data = json.loads(base64.b64decode(pkg_in).decode())
            st.session_state["cipher_b64_in"] = data["c"]
            st.session_state["context_in"]    = data["x"]
            st.session_state["key_hex_in"]    = data["k"]
            st.success("Campos cargados. Pulsa Decrypt ↓")
        except Exception as e:
            st.error(f"Paquete inválido: {e}")

    cipher_b64_in = st.text_area("Ciphertext (Base64)", key="cipher_b64_in", height=120)
    context_in    = st.text_input("Contexto", key="context_in")
    key_hex_in    = st.text_input("Clave (hex)", key="key_hex_in")

    if st.button("Decrypt"):
        try:
            pt = ContextFlowCrypt.decrypt(
                base64.b64decode(cipher_b64_in),
                bytes.fromhex(key_hex_in),
                context_in,
            )
            st.text_area("Texto plano recuperado", pt.decode(), height=120)
            st.success("✅ Descifrado correcto")
        except Exception as e:
            st.error(f"Error: {e}")
