"""
FASE 4 - DEFENSA / ENTRENAMIENTO DEL CLASIFICADOR
Entrena y compara dos clasificadores de ML para detectar prompts maliciosos:
  - Naive Bayes Multinomial
  - Regresión Logística

Guarda el mejor modelo como 'classifier_model.pkl' para usarlo en la Fase 5.

Uso:
    python phase4_classifier.py

Requiere: dataset.csv (generado por phase3_dataset.py)
"""

import os
import joblib
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
)

DATASET_FILE = "dataset.csv"
MODEL_OUTPUT  = "classifier_model.pkl"
PLOTS_DIR     = "plots"

os.makedirs(PLOTS_DIR, exist_ok=True)


# ─────────────────────────────────────────────
# CARGA Y PREPARACIÓN DE DATOS
# ─────────────────────────────────────────────

def load_data():
    if not os.path.exists(DATASET_FILE):
        raise FileNotFoundError(
            f"No se encontró '{DATASET_FILE}'. Ejecuta phase3_dataset.py primero."
        )
    df = pd.read_csv(DATASET_FILE)
    X = df["prompt"].astype(str)
    y = df["label"].astype(int)
    return X, y, df


# ─────────────────────────────────────────────
# DEFINICIÓN DE MODELOS
# ─────────────────────────────────────────────

def build_pipelines():
    """Retorna diccionario de pipelines TF-IDF + clasificador."""
    return {
        "Naive Bayes": Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=5000,
                sublinear_tf=True,
            )),
            ("clf", MultinomialNB(alpha=0.1)),
        ]),
        "Regresión Logística": Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=5000,
                sublinear_tf=True,
            )),
            ("clf", LogisticRegression(
                C=1.0,
                max_iter=1000,
                random_state=42,
            )),
        ]),
    }


# ─────────────────────────────────────────────
# ENTRENAMIENTO Y EVALUACIÓN
# ─────────────────────────────────────────────

def train_and_evaluate(X_train, X_test, y_train, y_test, pipelines):
    results = {}

    for name, pipeline in pipelines.items():
        print(f"\n{'─'*50}")
        print(f"Entrenando: {name}")
        print(f"{'─'*50}")

        # Entrenamiento
        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)

        # Métricas
        acc = accuracy_score(y_test, y_pred)
        f1  = f1_score(y_test, y_pred, average="weighted")
        cv_scores = cross_val_score(pipeline, X_train, y_train, cv=5, scoring="f1_weighted")

        print(f"Accuracy      : {acc:.4f} ({acc*100:.1f}%)")
        print(f"F1-score      : {f1:.4f}")
        print(f"CV F1 (5-fold): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
        print()
        print(classification_report(
            y_test, y_pred,
            target_names=["Benigno (0)", "Malicioso (1)"],
        ))

        results[name] = {
            "pipeline": pipeline,
            "y_pred": y_pred,
            "accuracy": acc,
            "f1": f1,
            "cv_mean": cv_scores.mean(),
        }

        # Matriz de confusión
        plot_confusion_matrix(y_test, y_pred, name)

    return results


# ─────────────────────────────────────────────
# GRÁFICOS
# ─────────────────────────────────────────────

def plot_confusion_matrix(y_test, y_pred, model_name: str):
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["Benigno", "Malicioso"],
        yticklabels=["Benigno", "Malicioso"],
        ax=ax,
    )
    ax.set_xlabel("Predicción")
    ax.set_ylabel("Real")
    ax.set_title(f"Matriz de Confusión - {model_name}")
    filename = f"{PLOTS_DIR}/confusion_{model_name.replace(' ', '_').lower()}.png"
    plt.tight_layout()
    plt.savefig(filename, dpi=150)
    plt.close()
    print(f"  → Gráfico guardado: {filename}")


def plot_comparison(results: dict):
    names = list(results.keys())
    accuracies = [results[n]["accuracy"] for n in names]
    f1_scores  = [results[n]["f1"] for n in names]
    cv_means   = [results[n]["cv_mean"] for n in names]

    x = range(len(names))
    width = 0.25

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar([i - width for i in x], accuracies, width, label="Accuracy", color="#4C72B0")
    ax.bar(x,                       f1_scores,  width, label="F1-score",  color="#55A868")
    ax.bar([i + width for i in x], cv_means,   width, label="CV F1",     color="#C44E52")

    ax.set_xticks(list(x))
    ax.set_xticklabels(names, fontsize=11)
    ax.set_ylim(0, 1.1)
    ax.axhline(y=0.85, color="orange", linestyle="--", linewidth=1.5, label="Meta: 85%")
    ax.set_ylabel("Métrica")
    ax.set_title("Comparación de Modelos - Fase 4")
    ax.legend()
    plt.tight_layout()
    filename = f"{PLOTS_DIR}/model_comparison.png"
    plt.savefig(filename, dpi=150)
    plt.close()
    print(f"\n  → Comparación guardada: {filename}")


# ─────────────────────────────────────────────
# SELECCIÓN Y GUARDADO DEL MEJOR MODELO
# ─────────────────────────────────────────────

def select_and_save_best(results: dict):
    best_name = max(results, key=lambda n: results[n]["f1"])
    best = results[best_name]

    print(f"\n{'='*50}")
    print(f"MEJOR MODELO: {best_name}")
    print(f"  F1-score : {best['f1']:.4f} ({best['f1']*100:.1f}%)")
    print(f"  Accuracy : {best['accuracy']:.4f}")
    print(f"{'='*50}")

    if best["f1"] >= 0.85:
        print("✅ Se supera la meta del 85% de F1-score.")
    else:
        print("⚠  No se alcanzó la meta del 85%. Considera añadir más datos al dataset.")

    joblib.dump(best["pipeline"], MODEL_OUTPUT)
    print(f"\n✔ Modelo guardado en: {MODEL_OUTPUT}")
    print(f"\n→ Próximo paso: ejecuta phase5_evaluate.py para el pipeline completo.")

    return best["pipeline"]


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print("=" * 55)
    print("FASE 4 - ENTRENAMIENTO DEL CLASIFICADOR ML")
    print("=" * 55)

    X, y, df = load_data()
    print(f"Dataset cargado: {len(df)} entradas "
          f"({(y==1).sum()} maliciosas, {(y==0).sum()} benignas)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train)} | Test: {len(X_test)}")

    pipelines = build_pipelines()
    results   = train_and_evaluate(X_train, X_test, y_train, y_test, pipelines)
    plot_comparison(results)
    select_and_save_best(results)


if __name__ == "__main__":
    main()
