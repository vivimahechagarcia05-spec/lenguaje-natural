"""
FASE 5 - EVALUACIÓN Y PIPELINE COMPLETO
Integra el clasificador como capa defensiva previa al modelo LLaMA.
El flujo es:

    input del usuario
          │
          ▼
    [Clasificador ML]
      ┌───┴───┐
      │       │
    MALIC.  BENIGNO
      │       │
  BLOQUEAR  Groq API
              │
           Respuesta

Además genera:
  - Gráficos de métricas comparativas (antes/después de la defensa)
  - Reporte final completo

Uso:
    python phase5_evaluate.py

Requiere:
    - dataset.csv           (phase3)
    - classifier_model.pkl  (phase4)
    - .env con GROQ_API_KEY
"""

import os
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

from groq import Groq
from dotenv import load_dotenv
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_curve,
    auc,
    precision_recall_curve,
)
from sklearn.model_selection import train_test_split

DATASET_FILE  = "dataset.csv"
MODEL_FILE    = "classifier_model.pkl"
PLOTS_DIR     = "plots"

os.makedirs(PLOTS_DIR, exist_ok=True)
load_dotenv()


# ─────────────────────────────────────────────
# PIPELINE DEFENSIVO
# ─────────────────────────────────────────────

class DefensivePipeline:
    """
    Intercepta el input del usuario con el clasificador ML
    antes de enviarlo al modelo LLM.
    """

    SYSTEM_PROMPT = (
        "Eres un asistente de soporte técnico. Solo respondes sobre ciberseguridad "
        "a nivel educativo. Rechaza cualquier solicitud fuera de ese ámbito."
    )

    def __init__(self, model_path: str, groq_api_key: str):
        self.classifier = joblib.load(model_path)
        self.client = Groq(api_key=groq_api_key)
        self.model = "llama-3.3-70b-versatile"
        self.blocked_count = 0
        self.passed_count = 0

    def classify(self, prompt: str) -> dict:
        """Retorna etiqueta y probabilidad de ser malicioso."""
        label = self.classifier.predict([prompt])[0]
        # Probabilidades si el clasificador las soporta
        try:
            proba = self.classifier.predict_proba([prompt])[0]
            confidence = proba[label]
        except Exception:
            confidence = None

        return {"label": int(label), "confidence": confidence}

    def process(self, user_input: str) -> dict:
        """
        Procesa un input:
          - Si es malicioso → bloquea y retorna mensaje de rechazo
          - Si es benigno   → envía a Groq y retorna respuesta
        """
        classification = self.classify(user_input)

        if classification["label"] == 1:
            self.blocked_count += 1
            return {
                "blocked": True,
                "classification": classification,
                "response": "⛔ Solicitud bloqueada: el contenido fue detectado como un intento de ataque.",
            }
        else:
            self.passed_count += 1
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user",   "content": user_input},
                    ],
                    max_tokens=256,
                    temperature=0.5,
                )
                answer = resp.choices[0].message.content.strip()
            except Exception as e:
                answer = f"[Error al consultar el modelo: {e}]"

            return {
                "blocked": False,
                "classification": classification,
                "response": answer,
            }


# ─────────────────────────────────────────────
# DEMO INTERACTIVA
# ─────────────────────────────────────────────

def run_interactive_demo(pipeline: DefensivePipeline):
    print("\n" + "=" * 60)
    print("DEMO INTERACTIVA - Pipeline Defensivo")
    print("Escribe 'salir' para terminar.")
    print("=" * 60)

    while True:
        user_input = input("\n[Usuario] > ").strip()
        if user_input.lower() in ("salir", "exit", "quit"):
            break
        if not user_input:
            continue

        result = pipeline.process(user_input)
        status = "🔴 BLOQUEADO" if result["blocked"] else "🟢 PERMITIDO"
        conf   = result["classification"].get("confidence")
        conf_str = f" (confianza: {conf:.2f})" if conf is not None else ""

        print(f"[Clasificador] {status}{conf_str}")
        print(f"[Respuesta]    {result['response'][:300]}")


# ─────────────────────────────────────────────
# EVALUACIÓN CON MÉTRICAS
# ─────────────────────────────────────────────

def evaluate_classifier(pipeline: DefensivePipeline):
    if not os.path.exists(DATASET_FILE):
        print(f"⚠ No se encontró {DATASET_FILE}. Saltando evaluación de métricas.")
        return

    df = pd.read_csv(DATASET_FILE)
    X = df["prompt"].astype(str)
    y = df["label"].astype(int)

    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    y_pred = pipeline.classifier.predict(X_test)

    print("\n" + "=" * 60)
    print("REPORTE DE CLASIFICACIÓN - CONJUNTO DE PRUEBA")
    print("=" * 60)
    print(classification_report(y_test, y_pred, target_names=["Benigno", "Malicioso"]))

    # ── Matriz de confusión ──
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Reds",
                xticklabels=["Benigno", "Malicioso"],
                yticklabels=["Benigno", "Malicioso"], ax=ax)
    ax.set_xlabel("Predicción")
    ax.set_ylabel("Real")
    ax.set_title("Matriz de Confusión - Pipeline Defensivo (Fase 5)")
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/phase5_confusion.png", dpi=150)
    plt.close()

    # ── Curva ROC ──
    try:
        y_prob = pipeline.classifier.predict_proba(X_test)[:, 1]
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        roc_auc = auc(fpr, tpr)

        fig, axes = plt.subplots(1, 2, figsize=(13, 5))

        # ROC
        axes[0].plot(fpr, tpr, color="#C44E52", lw=2, label=f"ROC (AUC = {roc_auc:.3f})")
        axes[0].plot([0, 1], [0, 1], "k--", lw=1)
        axes[0].set_xlabel("Tasa de Falsos Positivos")
        axes[0].set_ylabel("Tasa de Verdaderos Positivos")
        axes[0].set_title("Curva ROC")
        axes[0].legend(loc="lower right")

        # Precision-Recall
        precision, recall, _ = precision_recall_curve(y_test, y_prob)
        axes[1].plot(recall, precision, color="#4C72B0", lw=2)
        axes[1].set_xlabel("Recall")
        axes[1].set_ylabel("Precision")
        axes[1].set_title("Curva Precision-Recall")

        plt.suptitle("Evaluación del Clasificador - Fase 5", fontsize=13)
        plt.tight_layout()
        plt.savefig(f"{PLOTS_DIR}/phase5_roc_pr.png", dpi=150)
        plt.close()
        print(f"  → AUC-ROC: {roc_auc:.4f}")
    except Exception:
        pass  # Naive Bayes puede no soportar predict_proba en todos los casos

    # ── Gráfico comparativo: sin defensa vs con defensa ──
    plot_before_after(cm)

    print(f"\n✔ Gráficos guardados en: {PLOTS_DIR}/")


def plot_before_after(cm):
    """
    Simula el escenario 'sin defensa' (todos los ataques llegan al modelo)
    vs 'con defensa' (el clasificador bloquea los maliciosos).
    """
    tn, fp, fn, tp = cm.ravel()
    total_malicious = tp + fn

    # Sin defensa: todos los maliciosos llegan al modelo
    without_defense = {"blocked": 0, "passed_malicious": total_malicious, "passed_benign": tn + fp}
    # Con defensa: el clasificador bloquea tp, deja pasar fn
    with_defense    = {"blocked": tp, "passed_malicious": fn, "passed_benign": tn}

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    for ax, data, title in zip(
        axes,
        [without_defense, with_defense],
        ["Sin defensa (baseline)", "Con clasificador ML"],
    ):
        labels = ["Bloqueados", "Maliciosos al modelo", "Benignos al modelo"]
        values = [data["blocked"], data["passed_malicious"], data["passed_benign"]]
        colors = ["#95a5a6", "#e74c3c", "#2ecc71"]
        bars = ax.bar(labels, values, color=colors, edgecolor="white", linewidth=1.2)
        ax.set_title(title, fontsize=12, fontweight="bold")
        ax.set_ylabel("N° de prompts")
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                    str(val), ha="center", va="bottom", fontweight="bold")
        ax.set_ylim(0, max(values) * 1.2 + 1)

    plt.suptitle("Impacto de la Capa Defensiva", fontsize=14, fontweight="bold")
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/before_after_defense.png", dpi=150)
    plt.close()
    print(f"  → Comparación antes/después guardada: {PLOTS_DIR}/before_after_defense.png")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print("=" * 60)
    print("FASE 5 - PIPELINE DEFENSIVO + EVALUACIÓN FINAL")
    print("=" * 60)

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError("No se encontró GROQ_API_KEY en el archivo .env")

    if not os.path.exists(MODEL_FILE):
        raise FileNotFoundError(
            f"No se encontró '{MODEL_FILE}'. Ejecuta phase4_classifier.py primero."
        )

    pipeline = DefensivePipeline(MODEL_FILE, api_key)
    print(f"✔ Modelo cargado: {MODEL_FILE}")

    # Evaluación automática con métricas
    evaluate_classifier(pipeline)

    # Demo interactiva
    print("\n¿Deseas probar el pipeline de forma interactiva? (s/n)")
    choice = input("> ").strip().lower()
    if choice in ("s", "si", "sí", "y", "yes"):
        run_interactive_demo(pipeline)

    print("\n" + "=" * 60)
    print("PROYECTO COMPLETADO")
    print("=" * 60)
    print("Entregables generados:")
    print("  📄 attack_results.csv     — resultados del ataque")
    print("  📄 dataset.csv            — dataset etiquetado")
    print("  🤖 classifier_model.pkl   — modelo entrenado")
    print("  📊 plots/                 — gráficos de evaluación")
    print("=" * 60)


if __name__ == "__main__":
    main()
