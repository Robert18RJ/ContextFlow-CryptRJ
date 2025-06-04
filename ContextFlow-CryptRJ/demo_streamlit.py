# demo_streamlit.py
import base64
import secrets
import streamlit as st
from contextflow_crypt import ContextFlowCrypt

# ---------- Configuración de la página ----------
st.set_page_config(
    page_title="ContextFlow-Crypt Demo",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="collapsed",
)

ACCENT = "#00FF87"   # verde neón
BG_DARK = "#0B0E11"

# ---------- Estilos CSS para look “hacker elegante” ----------
st.markdown(
    f"""
    <style>
        html, body, [data-testid="stApp"] {{
            background-color: {BG_DARK};
            color: white;
        }}
        .stButton>button {{
            background-color:{ACCENT};
            color:black;
            border:none;
            transition: 0.2s;
            font-weight:600;
        }}
        .stButton>button:hover {{
            box-shadow:0 0 12px {ACCENT};
            transform: scale(1.05);
        }}
        textarea, input {{
            background:rgba(255,255,255,0.05);
            color:white;
            border:1px solid rgba(255,255,255,0.15);
        }}
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🔐 ContextFlow-Crypt – Live Demo")

tab_enc, tab_dec = st.tabs(["Encrypt", "Decrypt"])

# ---------- Pestaña ENCRYPT ----------
with tab_enc:
    st.subheader("Cifrar texto")
    plaintext = st.text_area("Texto plano", placeholder="Escribe aquí…")
    key_hex = st.text_input("Clave (hex)", value=secrets.token_hex(32))

    if st.button("Encrypt"):
        try:
            key_bytes = bytes.fromhex(key_hex)
            cipher_bytes, context_vec = ContextFlowCrypt.encrypt(
                plaintext.encode(), key_bytes
            )
            cipher_b64 = base64.b64encode(cipher_bytes).decode()

            st.text_area("Ciphertext (Base64)", cipher_b64, height=120)
            st.text_input("Contexto generado", context_vec)
            st.success("✅ Cifrado exitoso")
        except Exception as e:
            st.error(f"Error: {e}")

# ---------- Pestaña DECRYPT ----------
with tab_dec:
    st.subheader("Descifrar texto")
    cipher_b64_in = st.text_area("Ciphertext (Base64)")
    context_in = st.text_input("Contexto")
    key_hex_in = st.text_input("Clave (hex)")

    if st.button("Decrypt"):
        try:
            key_bytes = bytes.fromhex(key_hex_in)
            plaintext_out = ContextFlowCrypt.decrypt(
                base64.b64decode(cipher_b64_in),
                key_bytes,
                context_in,
            )
            st.text_area(
                "Texto plano recuperado", plaintext_out.decode(), height=120
            )
            st.success("✅ Descifrado correcto")
        except Exception as e:
            st.error(f"Error: {e}")
