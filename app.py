"""
APP INTERACTIVA — PromptShield
Materializa el pipeline defensivo del anteproyecto como una aplicación web:

    input del usuario → [normalización] → [clasificador ML] → ¿malicioso?
                                                               ├─ SÍ → ⛔ bloqueado (no llega al LLM)
                                                               └─ NO → Groq (LLaMA 3.3 70B) → respuesta

Características:
  - Chat multi-turno CON memoria, pero el clasificador filtra CADA turno
    (los prompts bloqueados nunca entran al historial enviado al LLM).
  - Panel de seguridad en vivo (etiqueta, confianza, categoría estimada).
  - Dashboard con métricas reales del modelo y tasa de evasión del ataque.

Ejecutar:
    streamlit run app.py

La clave de Groq se lee de st.secrets["GROQ_API_KEY"] (Streamlit Cloud)
o de la variable de entorno GROQ_API_KEY / archivo .env (local).
"""

import os
import joblib
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from groq import Groq

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

from security_utils import normalize_input, validate_input, preprocess_for_tfidf
from phase1_prompts import get_all_malicious

# ─────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────

MODEL_FILE = "classifier_model.pkl"
DATASET_FILE = "dataset.csv"
ATTACK_FILE = "attack_results.csv"
GROQ_MODEL = "llama-3.3-70b-versatile"

SYSTEM_PROMPT = (
    "Eres un asistente de soporte técnico especializado en ciberseguridad a nivel "
    "educativo. Respondes de forma clara y profesional. Rechaza cualquier solicitud "
    "fuera de ese ámbito."
)

st.set_page_config(
    page_title="PromptShield — Demo Defensiva",
    page_icon="🛡",
    layout="wide",
)


# ─────────────────────────────────────────────
# CARGA DE RECURSOS (cacheada)
# ─────────────────────────────────────────────

@st.cache_resource
def load_classifier():
    """Carga el clasificador binario entrenado (malicioso/benigno)."""
    if not os.path.exists(MODEL_FILE):
        return None
    return joblib.load(MODEL_FILE)


@st.cache_resource
def load_category_classifier():
    """
    Entrena (al vuelo, cacheado) un clasificador MULTICLASE para estimar
    la categoría del ataque. Solo se entrena con prompts maliciosos.
    """
    malicious = get_all_malicious()
    X = [m["prompt"] for m in malicious]
    y = [m["category"] for m in malicious]
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(preprocessor=preprocess_for_tfidf, ngram_range=(1, 2))),
        ("clf", MultinomialNB(alpha=0.1)),
    ])
    pipe.fit(X, y)
    return pipe


@st.cache_data
def load_attack_stats():
    """Tasa de evasión por categoría desde attack_results.csv."""
    if not os.path.exists(ATTACK_FILE):
        return None
    df = pd.read_csv(ATTACK_FILE)
    stats = df.groupby("category")["evaded"].agg(["sum", "count"]).reset_index()
    stats["tasa"] = (stats["sum"] / stats["count"] * 100).round(1)
    stats = stats.rename(columns={"sum": "evadidos", "count": "total"})
    return stats.sort_values("tasa", ascending=False)


def get_api_key():
    """Obtiene la clave de Groq de secrets (cloud) o entorno (local)."""
    try:
        if "GROQ_API_KEY" in st.secrets:
            return st.secrets["GROQ_API_KEY"]
    except Exception:
        pass
    load_dotenv()
    return os.getenv("GROQ_API_KEY")


@st.cache_resource
def get_groq_client(api_key: str):
    return Groq(api_key=api_key)


# ─────────────────────────────────────────────
# LÓGICA DEFENSIVA
# ─────────────────────────────────────────────

def classify(clf, cat_clf, text: str) -> dict:
    """Clasifica un prompt normalizado. Retorna etiqueta, confianza y categoría."""
    norm = normalize_input(text)
    label = int(clf.predict([norm])[0])
    try:
        proba = clf.predict_proba([norm])[0]
        confidence = float(proba[label])
    except Exception:
        confidence = None
    category = None
    if label == 1:
        try:
            category = cat_clf.predict([norm])[0]
        except Exception:
            category = "desconocida"
    return {"label": label, "confidence": confidence, "category": category}


def call_llm(client, history) -> str:
    """Llama a Groq con el historial (solo turnos benignos previos)."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}] + history
    try:
        resp = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=messages,
            max_tokens=512,
            temperature=0.5,
        )
        content = resp.choices[0].message.content
        return content.strip() if content else "[respuesta vacía del modelo]"
    except Exception as e:
        return f"[Error al consultar el modelo: {e}]"


# ─────────────────────────────────────────────
# ESTADO DE SESIÓN
# ─────────────────────────────────────────────

if "chat" not in st.session_state:
    st.session_state.chat = []          # lo que se muestra (incluye bloqueados)
if "llm_history" not in st.session_state:
    st.session_state.llm_history = []   # SOLO turnos benignos enviados al LLM
if "last_analysis" not in st.session_state:
    st.session_state.last_analysis = None
if "stats" not in st.session_state:
    st.session_state.stats = {"total": 0, "blocked": 0, "passed": 0}


# ─────────────────────────────────────────────
# CARGA
# ─────────────────────────────────────────────

clf = load_classifier()
cat_clf = load_category_classifier()
api_key = get_api_key()

# ─────────────────────────────────────────────
# UI
# ─────────────────────────────────────────────

st.title("🛡 PromptShield")
st.caption("Defensa contra Prompt Injection mediante clasificador ML · OWASP LLM01 · UTP")

if clf is None:
    st.error("No se encontró `classifier_model.pkl`. Ejecuta `python phase4_classifier.py` primero.")
    st.stop()

tab_chat, tab_dash = st.tabs(["💬 Chat defensivo", "📊 Dashboard"])

# ───────────── TAB CHAT ─────────────
with tab_chat:
    col_chat, col_sec = st.columns([2, 1])

    with col_sec:
        st.subheader("🔍 Panel de seguridad")
        a = st.session_state.last_analysis
        if a is None:
            st.info("Envía un prompt para ver el análisis.")
        elif a["label"] == 1:
            st.error("🔴 MALICIOSO — bloqueado")
            if a["confidence"] is not None:
                st.metric("Confianza", f"{a['confidence']:.2f}")
            st.write(f"**Categoría estimada:** `{a['category']}`")
            st.write("→ **NO** llegó al modelo.")
        else:
            st.success("🟢 BENIGNO — permitido")
            if a["confidence"] is not None:
                st.metric("Confianza", f"{a['confidence']:.2f}")
            st.write("→ Enviado al LLM.")

        s = st.session_state.stats
        st.divider()
        st.write(f"**Sesión:** {s['total']} prompts · "
                 f"🟢 {s['passed']} permitidos · 🔴 {s['blocked']} bloqueados")
        if not api_key:
            st.warning("⚠️ Sin `GROQ_API_KEY`. El clasificador funciona, pero los "
                       "prompts benignos no obtendrán respuesta del LLM.")
        if st.button("🗑 Reiniciar conversación"):
            st.session_state.chat = []
            st.session_state.llm_history = []
            st.session_state.last_analysis = None
            st.session_state.stats = {"total": 0, "blocked": 0, "passed": 0}
            st.rerun()

    with col_chat:
        # Render historial
        for msg in st.session_state.chat:
            if msg["role"] == "blocked":
                with st.chat_message("user"):
                    st.write(msg["content"])
                with st.chat_message("assistant", avatar="⛔"):
                    st.error(f"BLOQUEADO por la defensa ({msg['category']}). No llegó al modelo.")
            else:
                with st.chat_message(msg["role"]):
                    st.write(msg["content"])

        prompt = st.chat_input("Escribe un prompt (intenta atacar o pregunta algo normal)...")
        if prompt:
            valid, vmsg = validate_input(prompt)
            if not valid:
                st.warning(f"Input inválido: {vmsg}")
            else:
                result = classify(clf, cat_clf, prompt)
                st.session_state.last_analysis = result
                st.session_state.stats["total"] += 1

                if result["label"] == 1:
                    st.session_state.stats["blocked"] += 1
                    st.session_state.chat.append(
                        {"role": "blocked", "content": prompt, "category": result["category"]}
                    )
                else:
                    st.session_state.stats["passed"] += 1
                    st.session_state.chat.append({"role": "user", "content": prompt})
                    st.session_state.llm_history.append({"role": "user", "content": prompt})
                    if api_key:
                        client = get_groq_client(api_key)
                        answer = call_llm(client, st.session_state.llm_history)
                    else:
                        answer = "[Configura GROQ_API_KEY para obtener respuesta del modelo.]"
                    st.session_state.chat.append({"role": "assistant", "content": answer})
                    st.session_state.llm_history.append({"role": "assistant", "content": answer})
                st.rerun()

# ───────────── TAB DASHBOARD ─────────────
with tab_dash:
    st.subheader("Métricas del modelo")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("F1-score", "93.8%")
    c2.metric("AUC-ROC", "0.984")
    c3.metric("Falsos positivos", "7%", delta="-46 pts", delta_color="inverse")
    c4.metric("Dataset", "240")

    st.divider()
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("**Tasa de evasión por categoría (Fase 2)**")
        stats = load_attack_stats()
        if stats is not None:
            st.dataframe(
                stats[["category", "evadidos", "total", "tasa"]],
                hide_index=True, use_container_width=True,
            )
            st.bar_chart(stats.set_index("category")["tasa"])
        else:
            st.info("No se encontró attack_results.csv.")

    with col_b:
        st.markdown("**Comparación de modelos**")
        if os.path.exists("plots/model_comparison.png"):
            st.image("plots/model_comparison.png")
        st.markdown("**Curvas ROC / Precision-Recall**")
        if os.path.exists("plots/phase5_roc_pr.png"):
            st.image("plots/phase5_roc_pr.png")

    st.divider()
    st.caption("⚠️ Prototipo académico. Ver SECURITY.md para limitaciones reales del clasificador.")
