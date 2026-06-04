# SECURITY.md — Auditoría de Seguridad y Red-Team

> Auditoría realizada el **2026-06-04** sobre el proyecto de Prompt Injection + Clasificador ML.
> Metodología: revisión de código + red-team empírico contra el modelo entrenado.
> Cada hallazgo se clasifica por severidad e indica su estado de remediación.

---

## Resumen Ejecutivo

Se identificaron **10 grietas**. La más crítica no era un bug de código, sino la
**inutilidad del clasificador en el mundo real**: bloqueaba el **53% de los prompts
benignos cotidianos** ("Gracias por tu ayuda" → BLOQUEADO). El "100% F1-score" original
era un espejismo causado por evaluar sobre el mismo banco de vocabulario con el que se
entrenó.

Tras el endurecimiento:

| Métrica | Antes | Después |
|---------|-------|---------|
| Falsos positivos (prompts cotidianos) | **53%** | **7%** |
| Ofuscación Unicode (fullwidth/zero-width) | Sin defensa | Neutralizada |
| F1-score reportado | 100% (engañoso) | 93.8% (honesto) |
| AUC-ROC | 1.00 (engañoso) | 0.984 |
| Token filtrado en `.git/config` | Sí | Eliminado |
| CSV Injection | Vulnerable | Sanitizado |

---

## Hallazgos

### 🔴 V1 — CRÍTICA · Clasificador inservible (53% de falsos positivos)
- **Descripción:** El modelo bloqueaba más de la mitad de los prompts benignos
  cotidianos. Evidencia empírica:
  ```
  [BLOQUEADO p=0.68] Gracias por tu ayuda.
  [BLOQUEADO p=0.60] Recomiéndame una receta de pasta.
  [BLOQUEADO p=0.66] Traduce 'hola' al inglés.
  ```
- **Causa raíz:** El conjunto benigno contenía **exclusivamente** preguntas de
  ciberseguridad. El modelo nunca vio texto "normal", así que clasificaba como
  malicioso casi cualquier cosa fuera de ese dominio. El dataset de 200 muestras
  con vocabulario separable producía un "100% F1" que NO generaliza.
- **Remediación:** Se añadieron 40 prompts benignos cotidianos/fuera de dominio
  (`phase1_prompts.py`). FP bajó de **53% → 7%**. Métricas ahora honestas (93.8% F1).
- **Estado:** ✅ Mitigado (residual: dataset aún pequeño, ver Limitaciones).

### 🔴 V2 — CRÍTICA · Token de acceso personal filtrado
- **Descripción:** El PAT classic de GitHub se embebió en la URL del remote
  (`.git/config`) y se compartió en texto plano.
- **Impacto:** Acceso completo de lectura/escritura a los repos de la cuenta.
- **Remediación:** Remote limpiado (`git remote set-url` sin token).
- **Estado:** ✅ Eliminado del repo. ⚠️ **ACCIÓN PENDIENTE DEL USUARIO: revocar
  el token en GitHub → Settings → Developer settings → Tokens y generar uno nuevo.**

### 🟠 V3 — ALTA · CSV Injection (Formula Injection)
- **Descripción:** Los prompts (controlados por el atacante) se escribían en
  `attack_results.csv` y `dataset.csv` sin sanitizar. Un prompt que empiece con
  `=`, `+`, `-` o `@` ejecuta fórmulas al abrir el CSV en Excel/Google Sheets.
- **Remediación:** `sanitize_for_csv()` en `security_utils.py`, aplicado en
  Fases 2 y 3 (antepone `'` a valores peligrosos).
- **Estado:** ✅ Mitigado.

### 🟠 V4 — ALTA · Deserialización insegura de pickle
- **Descripción:** `joblib.load(classifier_model.pkl)` deserializa pickle, que
  permite ejecución de código arbitrario (RCE) si el `.pkl` fue manipulado.
- **Remediación:** El `.pkl` está en `.gitignore` (no se distribuye) y se regenera
  localmente. Se añadió advertencia explícita en `phase5_evaluate.py`.
- **Estado:** ✅ Mitigado (no cargar modelos de fuentes no confiables).

### 🟡 V5 — MEDIA · Falta de validación de input
- **Descripción:** `DefensivePipeline.process()` aceptaba cualquier input sin
  límite de longitud ni validación.
- **Remediación:** `validate_input()` + truncado a 4000 chars en `security_utils.py`,
  integrado en Fase 5.
- **Estado:** ✅ Mitigado.

### 🟡 V6 — MEDIA · Heurística de evasión frágil (Fase 2)
- **Descripción:** `detect_evasion()` usa coincidencia de palabras clave; frases
  como "por supuesto, no puedo ayudarte" generaban falsos positivos.
- **Remediación:** Umbral elevado a `evasión ≥ rechazo + 2`. Sigue siendo una
  heurística, no un clasificador — las etiquetas de la Fase 2 son aproximadas.
- **Estado:** ⚠️ Mitigado parcialmente (limitación inherente al enfoque por keywords).

### 🟡 V7 — MEDIA · Evasión por ofuscación Unicode
- **Descripción:** Caracteres fullwidth (`Ｉｇｎｏｒａ`), de ancho cero
  (`i​g​n​o​r​a`) y homoglyphs cambian los tokens TF-IDF y evaden la detección.
- **Remediación:** `normalize_input()` (NFKC + eliminación de zero-width) embebido
  en el pipeline vía `preprocess_for_tfidf`. Verificado: ataques fullwidth y
  zero-width ahora se bloquean.
- **Estado:** ✅ Mitigado para las técnicas probadas.

### 🟢 V8 — BAJA · Crash con respuesta vacía de Groq
- **Descripción:** `response.choices[0].message.content.strip()` lanza
  `AttributeError` si `content` es `None`.
- **Remediación:** Guarda `content.strip() if content else "[respuesta vacía]"`.
- **Estado:** ✅ Corregido en Fases 2 y 5.

### 🟢 V9 — BAJA · Dependencias sin versión fijada
- **Descripción:** `requirements.txt` usa `>=`, que puede traer versiones futuras
  con vulnerabilidades o cambios incompatibles.
- **Remediación:** Documentado. Recomendación: fijar versiones (`==`) antes de la
  entrega final y revisar con `pip-audit`.
- **Estado:** ⚠️ Pendiente (decisión del equipo).

### 🟢 V10 — BAJA · Métricas de alta varianza (test de 40-48 muestras)
- **Descripción:** Con un test tan pequeño y `random_state` fijo, las métricas
  tienen alta varianza y no representan generalización.
- **Remediación:** Se reporta el CV F1 (5-fold) junto al F1 de test y se documenta
  la limitación. Recomendación: validación cruzada repetida e intervalos de confianza.
- **Estado:** ⚠️ Documentado.

---

## Limitaciones Residuales (honestidad científica)

El sistema es un **prototipo académico**, no una defensa de producción:

1. **Dataset pequeño (240 muestras).** Insuficiente para generalizar. Un atacante
   con fraseo novedoso puede evadir el clasificador.
2. **TF-IDF no entiende semántica.** Paráfrasis sin las palabras clave de
   entrenamiento pueden pasar. Mejora futura: embeddings (sentence-transformers).
3. **Defensa monocapa.** Una sola línea de defensa no basta; en producción se
   combinaría con rate-limiting, validación de salida, sandboxing y monitoreo.
4. **La heurística de la Fase 2** etiqueta de forma aproximada; no es ground truth.
5. **Ofuscaciones no probadas** (p.ej. cifrados personalizados, idiomas no vistos)
   podrían evadir la normalización actual.

---

## Acciones Pendientes del Usuario

- [ ] **Revocar el token `ghp_91RA...`** en GitHub y generar uno nuevo.
- [ ] (Opcional) Fijar versiones en `requirements.txt` y correr `pip-audit`.
- [ ] (Opcional) Ampliar el dataset con fuentes externas (HackAPrompt, PromptBench).
