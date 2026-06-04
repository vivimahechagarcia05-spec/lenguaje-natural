# CLAUDE.md — Reglas de Oro para este Proyecto

## Contexto del Proyecto

**Título:** Ataque Automatizado de Prompt Injection y Defensa mediante Clasificador de Machine Learning en Sistemas de Procesamiento de Lenguaje Natural

**Universidad Tecnológica de Panamá** — Licenciatura en Ciberseguridad  
**Asignatura:** Inteligencia Artificial aplicada a la Ciberseguridad  
**Equipo:** Aracellys Camarena, Vivianne García, Giancarlos Ortiz  
**Profesor:** Eric Solís

Este proyecto es **educativo y controlado**. El ataque se ejecuta exclusivamente contra la propia API de Groq del equipo (LLaMA 3.3 70B). No se ataca ningún sistema externo ni de terceros.

---

## Reglas de Oro

### 1. Respetar el flujo de fases en orden
El proyecto tiene 5 fases con dependencias estrictas:
```
phase1_prompts.py → phase2_attack.py → phase3_dataset.py → phase4_classifier.py → phase5_evaluate.py
```
Nunca modificar una fase sin verificar que no rompa las fases siguientes.

### 2. Nunca atacar sistemas externos
Todo ataque se dirige exclusivamente a la API de Groq configurada en `.env` con la clave del equipo. Si se detecta cualquier intento de atacar sistemas de terceros, detener y reportar.

### 3. El dataset mínimo es 200 entradas (100 maliciosas + 100 benignas)
Si `dataset.csv` tiene menos de 200 entradas, agregar más prompts en `phase1_prompts.py` antes de entrenar el clasificador en Fase 4.

### 4. Meta de rendimiento: F1-score ≥ 85%
El clasificador debe alcanzar al menos 85% de F1-score. Si no lo logra:
- Revisar balance del dataset
- Agregar más prompts al banco (Fase 1)
- Ajustar hiperparámetros en Fase 4

### 5. Registrar todos los errores en AGENTE_CONTEXTO.md
Cada error encontrado durante el desarrollo — ya sea de código, lógica o datos — debe registrarse en [`AGENTE_CONTEXTO.md`](AGENTE_CONTEXTO.md) con su solución. Esto permite que el agente aprenda de sesión a sesión.

### 6. No modificar classifier_model.pkl manualmente
El modelo entrenado solo se regenera ejecutando `phase4_classifier.py`. Nunca editar ni reemplazar el archivo `.pkl` a mano.

### 7. Mantener el entorno virtual activado
Todas las ejecuciones deben usar el entorno virtual del proyecto:
```bash
source venv/bin/activate
```
No instalar dependencias globalmente. Actualizar `requirements.txt` si se añade algo nuevo.

### 8. Preservar attack_results.csv
Este archivo es el resultado del ataque real (Fase 2) y es insumo crítico para Fase 3. No sobreescribir sin respaldar primero.

### 9. Documentar cualquier cambio al banco de prompts
Si se añaden o modifican prompts en `phase1_prompts.py`, anotar el motivo en un comentario en el archivo y registrar el cambio en `AGENTE_CONTEXTO.md`.

### 10. Los gráficos van en /plots
Todo output visual se guarda en el directorio `plots/`. No guardar imágenes en la raíz del proyecto.

---

## Estructura de Archivos

```
.
├── CLAUDE.md                  ← Este archivo (reglas de oro)
├── AGENTE_CONTEXTO.md         ← Registro de errores y aprendizaje agentico
├── ALGORITMO.md               ← Documentación del algoritmo completo
├── phase1_prompts.py          ← Banco de prompts (maliciosos + benignos)
├── phase2_attack.py           ← Script ofensivo (fuzzing de prompts)
├── phase3_dataset.py          ← Construcción del dataset etiquetado
├── phase4_classifier.py       ← Entrenamiento del clasificador ML
├── phase5_evaluate.py         ← Pipeline defensivo + evaluación final
├── attack_results.csv         ← Resultados del ataque real (generado por Fase 2)
├── dataset.csv                ← Dataset etiquetado (generado por Fase 3)
├── classifier_model.pkl       ← Modelo entrenado (generado por Fase 4)
├── plots/                     ← Gráficos de métricas (generados por Fases 4 y 5)
├── requirements.txt           ← Dependencias del proyecto
├── .env                       ← Clave GROQ_API_KEY (NO commitear)
└── venv/                      ← Entorno virtual Python
```

---

## Comandos de Ejecución (en orden)

```bash
# Activar entorno
source venv/bin/activate

# Fase 1 — Ver resumen del banco de prompts
python phase1_prompts.py

# Fase 2 — Ejecutar ataque (requiere GROQ_API_KEY en .env)
python phase2_attack.py

# Fase 3 — Construir dataset
python phase3_dataset.py

# Fase 4 — Entrenar clasificador
python phase4_classifier.py

# Fase 5 — Pipeline defensivo + evaluación
python phase5_evaluate.py
```

---

## Variables de Entorno Requeridas

Crear un archivo `.env` en la raíz con:
```
GROQ_API_KEY=tu_clave_aqui
```

El archivo `.env` **nunca debe commitearse** al repositorio.

---

## Dependencias

```
groq>=0.9.0
scikit-learn>=1.4.0
pandas>=2.1.0
matplotlib>=3.8.0
seaborn>=0.13.0
python-dotenv>=1.0.0
joblib>=1.3.0
```

Instalar con:
```bash
pip install -r requirements.txt
```

---

## Referencias Técnicas

- [OWASP LLM Top 10 — LLM01: Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Groq API Documentation](https://console.groq.com/docs/openai)
- [scikit-learn TF-IDF + Naive Bayes](https://scikit-learn.org/stable/modules/naive_bayes.html)
- [scikit-learn Logistic Regression](https://scikit-learn.org/stable/modules/linear_model.html#logistic-regression)
