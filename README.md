# 🛡️ Ataque Automatizado de Prompt Injection y Defensa con Machine Learning

Sistema que demuestra, en un entorno controlado, cómo manipular un modelo de lenguaje
mediante **Prompt Injection** (OWASP LLM Top 10 — LLM01) y cómo construir una **capa
defensiva basada en Machine Learning** que detecta y bloquea esos ataques antes de que
lleguen al modelo.

🌐 **Página de previsualización:** https://vivimahechagarcia05-spec.github.io/lenguaje-natural/

> **Proyecto académico** — Universidad Tecnológica de Panamá · Licenciatura en Ciberseguridad
> Asignatura: Inteligencia Artificial aplicada a la Ciberseguridad · Prof. Eric Solís
> Equipo: Aracellys Camarena · Vivianne García · Giancarlos Ortiz

---

## ⚠️ Aviso

Este es un **prototipo educativo en entorno controlado**. El ataque se ejecuta
exclusivamente contra la propia API de Groq del equipo. **No es una defensa de
producción** — ver [SECURITY.md](SECURITY.md) para las limitaciones reales.

---

## 📊 Resultados (honestos)

Modelo entrenado sobre **240 prompts** (108 maliciosos / 132 benignos):

| Modelo | Accuracy | F1-score | CV F1 (5-fold) |
|--------|----------|----------|----------------|
| **Naive Bayes** (mejor) | 93.8% | 0.938 | 0.958 ± 0.022 |
| Regresión Logística | 93.8% | 0.937 | 0.931 ± 0.028 |

- **AUC-ROC:** 0.984
- **Falsos positivos** en prompts cotidianos: **7%** (tras endurecimiento; antes era 53%)

> Nota: una versión inicial reportaba "100% F1 / AUC 1.00". Ese resultado era
> **engañoso**: el modelo se evaluaba sobre el mismo banco de vocabulario con el que
> se entrenó y bloqueaba el 53% de los prompts benignos reales. Ver [SECURITY.md](SECURITY.md) V1.

---

## 🏗️ Arquitectura — 5 Fases

```
phase1_prompts.py → phase2_attack.py → phase3_dataset.py → phase4_classifier.py → phase5_evaluate.py
   (banco)            (ataque/fuzz)      (dataset CSV)        (entrena ML)          (defensa + eval)
```

| Fase | Archivo | Qué hace |
|------|---------|----------|
| 1 · Reconocimiento | `phase1_prompts.py` | Banco de 108 prompts maliciosos (7 categorías) + 132 benignos |
| 2 · Ataque | `phase2_attack.py` | Fuzzing automatizado contra LLaMA 3.3 70B (Groq) |
| 3 · Dataset | `phase3_dataset.py` | Construye `dataset.csv` etiquetado |
| 4 · Defensa | `phase4_classifier.py` | Entrena y compara Naive Bayes y Regresión Logística |
| 5 · Evaluación | `phase5_evaluate.py` | Pipeline defensivo + métricas (ROC, PR, matrices) |

El **pipeline defensivo**:

```
Input → [normalización anti-ofuscación] → [Clasificador ML] → ¿malicioso?
                                                                ├── SÍ → ⛔ bloqueado
                                                                └── NO → Groq API → respuesta
```

---

## 🚀 Uso

### Requisitos
- Python 3.10+
- Clave de API de Groq ([console.groq.com/keys](https://console.groq.com/keys))

### Instalación
```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # y edita .env con tu GROQ_API_KEY
```

### Ejecución (en orden)
```bash
python phase1_prompts.py     # ver resumen del banco
python phase2_attack.py      # ejecutar ataque (requiere GROQ_API_KEY)
python phase3_dataset.py     # construir dataset
python phase4_classifier.py  # entrenar clasificador
python phase5_evaluate.py    # evaluar pipeline defensivo
```

---

## 🔒 Seguridad

Este proyecto fue sometido a una **auditoría de seguridad y red-team**. Se identificaron
y mitigaron 10 grietas (CSV injection, deserialización pickle, evasión por ofuscación
Unicode, falsos positivos masivos, token filtrado, etc.).

👉 **Reporte completo:** [SECURITY.md](SECURITY.md)

Defensas implementadas en [`security_utils.py`](security_utils.py):
- `normalize_input()` — neutraliza ofuscación Unicode (fullwidth, zero-width, homoglyphs)
- `sanitize_for_csv()` — previene inyección de fórmulas CSV
- `validate_input()` — valida y limita el input del usuario

---

## 📁 Estructura

```
.
├── README.md / CLAUDE.md / SECURITY.md / ALGORITMO.md / AGENTE_CONTEXTO.md
├── security_utils.py          ← defensas compartidas
├── phase1..5_*.py             ← las 5 fases
├── docs/                      ← sitio de GitHub Pages (index.html + assets)
├── dataset.csv / attack_results.csv
├── plots/                     ← gráficos de evaluación
└── requirements.txt / .env.example / .gitignore
```

---

## 📚 Referencias
- [OWASP LLM Top 10 — LLM01: Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP CSV Injection](https://owasp.org/www-community/attacks/CSV_Injection)
- [Groq API](https://console.groq.com/docs)
