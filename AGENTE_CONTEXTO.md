# AGENTE_CONTEXTO.md — Registro de Errores y Aprendizaje Agéntico

> **Propósito:** Este archivo es la memoria persistente del agente de desarrollo.
> Cada error encontrado durante el desarrollo, depuración o ejecución de este proyecto
> debe registrarse aquí con su causa raíz y solución. Esto permite que Claude aprenda
> de sesión a sesión y no repita los mismos errores.
>
> **Regla:** Antes de comenzar a trabajar en cualquier fase, leer las entradas relevantes
> de este archivo para evitar errores conocidos.

---

## Formato de Entrada

```
### [ID] Título corto del error
- **Fase afectada:** phase[N]_*.py
- **Fecha:** YYYY-MM-DD
- **Síntoma:** Qué se observó (mensaje de error, comportamiento incorrecto, resultado inesperado)
- **Causa raíz:** Por qué ocurrió
- **Solución aplicada:** Qué se hizo para resolverlo
- **Lección aprendida:** Regla o patrón a recordar en el futuro
- **Archivos modificados:** lista de archivos
```

---

## Registro de Errores

### [001] Dataset por debajo del mínimo requerido (< 200 entradas)
- **Fase afectada:** `phase3_dataset.py` → `phase4_classifier.py`
- **Fecha:** 2026-06-04
- **Síntoma:** Al ejecutar Fase 3, el dataset resultante tiene solo ~88 entradas (48 maliciosas + 40 benignas), muy por debajo del mínimo de 200 requerido.
- **Causa raíz:** El banco de prompts en `phase1_prompts.py` fue diseñado con 8 prompts por categoría (6 categorías = 48 maliciosos) y solo 40 benignos. Al combinar con `attack_results.csv`, los prompts son los mismos del banco, por lo que el deduplicado en Fase 3 elimina duplicados y el total no crece significativamente.
- **Solución aplicada:** Ampliar `phase1_prompts.py` agregando al menos 52 prompts maliciosos adicionales y 60 benignos adicionales para superar las 200 entradas únicas.
- **Lección aprendida:** El banco de prompts debe diseñarse desde el inicio con suficiente volumen. El mínimo por categoría maliciosa debería ser 15-20 prompts, y los benignos deben ser al menos iguales en cantidad a los maliciosos totales.
- **Archivos modificados:** `phase1_prompts.py`

---

### [002] Chequeo de duplicados en Fase 3 usa O(n²) — lento con datasets grandes
- **Fase afectada:** `phase3_dataset.py`
- **Fecha:** 2026-06-04
- **Síntoma:** (Potencial) Al crecer el dataset, la línea `if row["prompt"] not in [e["prompt"] for e in all_entries]` reconstruye una lista completa en cada iteración.
- **Causa raíz:** Uso de búsqueda lineal en lista en lugar de lookup en set.
- **Solución aplicada:** Reemplazar la lista de prompts vistos por un `set` para obtener O(1) en las búsquedas.
- **Lección aprendida:** Para deduplicación en colecciones grandes, siempre usar `set` o `dict` en lugar de listas. En datasets de texto, hacer el lookup sobre el texto normalizado (`.strip().lower()`).
- **Archivos modificados:** `phase3_dataset.py`

---

## Patrones Conocidos del Proyecto

### Patrón P1 — Detección de evasión heurística es imprecisa
La función `detect_evasion()` en `phase2_attack.py` usa coincidencia de palabras clave. Esto genera falsos positivos cuando el modelo rechaza el ataque pero usa frases como "por supuesto, no puedo ayudarte con eso" (contiene "por supuesto" que es un indicador de evasión). Tener en cuenta al interpretar la tasa de evasión real.

### Patrón P2 — TF-IDF + Naive Bayes puede overfittear con dataset pequeño
Con menos de 200 muestras, el clasificador puede memorizar el dataset. Verificar siempre que el CV F1 (cross-validation) no sea significativamente menor que el F1 en test.

### Patrón P3 — Groq rate limit
La API de Groq aplica rate limiting. El delay de 1.5s entre requests en `phase2_attack.py` mitiga esto, pero con datasets grandes (> 200 prompts) puede ser necesario aumentarlo a 2-3s o implementar retry con backoff exponencial.

### Patrón P4 — GROQ_API_KEY no encontrada
Si se ejecuta cualquier fase que use Groq sin el archivo `.env`, el script lanza `ValueError`. Verificar siempre que `.env` existe y contiene `GROQ_API_KEY` antes de ejecutar Fases 2 y 5.

### Patrón P5 — classifier_model.pkl inexistente al ejecutar Fase 5
`phase5_evaluate.py` requiere `classifier_model.pkl`. Si se ejecuta antes de Fase 4, lanza `FileNotFoundError`. El orden correcto es siempre: 3 → 4 → 5.

---

## Sesiones de Trabajo

### Sesión 2026-06-04
- **Estado inicial:** Fases 1 y 2 completas. `attack_results.csv` con 139 registros. Fases 3-5 pendientes.
- **Trabajo realizado:**
  - Creación de `CLAUDE.md`, `AGENTE_CONTEXTO.md` y `ALGORITMO.md`
  - Expansión de `phase1_prompts.py`: 48→108 maliciosos (+ categoría `extraccion_sistema`), 40→92 benignos. Total: **200 entradas exactas**
  - Corrección O(n²)→O(1) en `phase3_dataset.py` (error [002])
  - Mejora de heurística en `phase2_attack.py`: threshold evasión de >0 a ≥2 (patrón P1)
  - Repositorio GitHub inicializado y pusheado: https://github.com/vivimahechagarcia05-spec/lenguaje-natural
- **Estado al cierre:** Fases 1-2 completas y refactorizadas. Fases 3-5 pendientes de ejecución.
- **Pendiente:** Ejecutar Fase 3 → Fase 4 → Fase 5 en orden.

---

## Checklist Antes de Cada Sesión

- [ ] Leer las entradas de error relevantes a la fase en que se va a trabajar
- [ ] Verificar que `.env` existe con `GROQ_API_KEY`
- [ ] Verificar que el entorno virtual está activado (`source venv/bin/activate`)
- [ ] Confirmar que los archivos de fases anteriores existen antes de ejecutar la fase actual
- [ ] Después de cualquier error nuevo, registrarlo aquí antes de terminar la sesión
