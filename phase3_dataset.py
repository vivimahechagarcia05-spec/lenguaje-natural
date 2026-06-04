"""
FASE 3 - RECOLECCIÓN DE DATOS
Construye el dataset etiquetado en formato CSV combinando:
  - Los prompts maliciosos del banco (phase1_prompts.py)
  - Los prompts benignos del banco (phase1_prompts.py)
  - Los resultados del ataque (attack_results.csv), si existe

Salida:
    - dataset.csv  (usado por phase4_classifier.py para entrenar el modelo)

Uso:
    python phase3_dataset.py
"""

import os
import csv
import pandas as pd
from phase1_prompts import get_all_malicious, get_all_benign

ATTACK_RESULTS_FILE = "attack_results.csv"
OUTPUT_FILE = "dataset.csv"


# ─────────────────────────────────────────────
# CONSTRUCCIÓN DEL DATASET
# ─────────────────────────────────────────────

def build_dataset():
    print("=" * 55)
    print("FASE 3 - CONSTRUCCIÓN DEL DATASET")
    print("=" * 55)

    all_entries = []

    # 1. Prompts maliciosos del banco (phase1)
    malicious = get_all_malicious()
    for item in malicious:
        all_entries.append({
            "prompt": item["prompt"],
            "category": item["category"],
            "label": 1,
            "source": "phase1_bank",
        })
    print(f"[+] Prompts maliciosos del banco  : {len(malicious)}")

    # 2. Prompts benignos del banco (phase1)
    benign = get_all_benign()
    for item in benign:
        all_entries.append({
            "prompt": item["prompt"],
            "category": "benigno",
            "label": 0,
            "source": "phase1_bank",
        })
    print(f"[+] Prompts benignos del banco    : {len(benign)}")

    # 3. Resultados del ataque real (si ya se ejecutó la Fase 2)
    if os.path.exists(ATTACK_RESULTS_FILE):
        attack_df = pd.read_csv(ATTACK_RESULTS_FILE)
        seen_prompts = {e["prompt"].strip().lower() for e in all_entries}
        attack_count = 0
        for _, row in attack_df.iterrows():
            normalized = str(row["prompt"]).strip().lower()
            if normalized not in seen_prompts:
                all_entries.append({
                    "prompt": row["prompt"],
                    "category": row.get("category", "ataque_real"),
                    "label": 1,
                    "source": "attack_results",
                })
                seen_prompts.add(normalized)
                attack_count += 1
        print(f"[+] Prompts nuevos del ataque real: {attack_count}")
    else:
        print(f"[!] No se encontró {ATTACK_RESULTS_FILE} — se usa solo el banco estático.")
        print(f"    Ejecuta phase2_attack.py primero para enriquecer el dataset.")

    # 4. Guardar
    df = pd.DataFrame(all_entries)
    df = df.drop_duplicates(subset=["prompt"]).reset_index(drop=True)
    df.to_csv(OUTPUT_FILE, index=False, encoding="utf-8")

    # 5. Reporte
    total = len(df)
    n_malicious = (df["label"] == 1).sum()
    n_benign = (df["label"] == 0).sum()

    print()
    print("─" * 55)
    print(f"{'Total de entradas':<35}: {total}")
    print(f"{'Prompts maliciosos (label=1)':<35}: {n_malicious}")
    print(f"{'Prompts benignos   (label=0)':<35}: {n_benign}")
    print(f"{'Balance (malic/benigno)':<35}: {n_malicious/n_benign:.2f}x")
    print("─" * 55)
    print(f"\n✔ Dataset guardado en: {OUTPUT_FILE}")

    if total < 200:
        print(f"\n⚠ El dataset tiene {total} entradas (mínimo recomendado: 200).")
        print("  Ejecuta phase2_attack.py para añadir más datos reales.")
    else:
        print(f"\n✅ Dataset listo ({total} entradas ≥ 200 mínimo requerido).")

    print(f"\n→ Próximo paso: ejecuta phase4_classifier.py para entrenar el modelo.")

    return df


def show_samples(df: pd.DataFrame, n: int = 5):
    """Muestra ejemplos de cada clase."""
    print("\n--- MUESTRA DE PROMPTS MALICIOSOS ---")
    print(df[df["label"] == 1][["prompt", "category"]].head(n).to_string(index=False))
    print("\n--- MUESTRA DE PROMPTS BENIGNOS ---")
    print(df[df["label"] == 0][["prompt", "category"]].head(n).to_string(index=False))


if __name__ == "__main__":
    df = build_dataset()
    show_samples(df)
