### F0. Preguntas e hipótesis de investigación

#### Problema

La evaluación existente en `docs/EVALUACION.md` depende de etiquetas sintéticas y no prueba conservación de calidad de priorización con ground truth independiente. El scoring principal de `agfast` y la simulación de GuardSketch no son una misma implementación integrada.

#### Objetivo principal

Caracterizar la calidad, robustez y costo de priorizar procesos sospechosos a partir de telemetría de hosts con memoria acotada, distinguiendo evidencia exacta, estadísticas aproximadas y datos incompletos.

#### RQ1. Fidelidad de priorización

¿En qué condiciones las estadísticas aproximadas modifican el ranking de procesos asociados con ataques, comparadas con un motor exacto y con reglas simples independientes?

Variables previstas: presupuesto de memoria, volumen de eventos, cardinalidad, número de procesos y configuración del sketch. Resultados: Recall@k contra etiquetas externas, Precision@k, cobertura de candidatos y divergencia del ranking. El top-k overlap entre implementaciones será secundario, nunca reemplazará el ground truth.

#### RQ2. Robustez ante perturbaciones

¿Cómo cambian las métricas de priorización cuando hay actividad benigna adicional, colisiones entre claves de un sketch compartido, señales de bajo volumen, pérdidas o retrasos de eventos?

Las transformaciones permitidas deberán preservar la semántica del episodio adversarial. La comparación se efectuará por perturbación y presupuesto, sin afirmar que una pérdida simulada sea un ataque directo al kernel.

#### RQ3. Utilidad de un motor híbrido

¿Una ruta híbrida que conserva evidencia crítica exacta y aproxima estadísticas auxiliares mejora la calidad de priorización o su estabilidad bajo presupuestos de recursos comparables?

Comparar reglas independientes, motor exacto, motor aproximado y motor híbrido. Separar experimentalmente los efectos de conservative update, hashing con semillas protegidas y verificación exacta selectiva.

#### RQ4. Transferibilidad de evidencia

¿En qué medida las conclusiones cambian al modificar el corpus, la versión de ground truth o el mecanismo de captura de eventos?

Esta pregunta se evaluará solo si existe un segundo corpus o una comparación operacional cuya equivalencia semántica pueda demostrarse. No se forzará una falsa comparación entre fuentes incompatibles.

#### Hipótesis preliminares

- `H1`: reducir memoria mediante aproximación puede degradar la selección de candidatos bajo colisiones o actividad benigna intensa.
- `H2`: preservar evidencias exactas y verificar candidatos puede limitar parte de esa degradación, a costa de memoria o tiempo adicionales.
- `H3`: la elección de las etiquetas y la omisión de eventos pueden cambiar las conclusiones incluso sin modificar el algoritmo.

Son hipótesis refutables y no resultados observados. Su aprobación definitiva depende del cierre de F0 y de la viabilidad de etiquetas en F2.

#### Unidad de evaluación y métricas

Definir identidad de proceso como algo más fuerte que el PID aislado, cuando el dataset lo permita. Distinguir etiqueta de evento, nodo, proceso, ventana y episodio. No transferir etiquetas entre niveles sin una regla explícita.

Si `M` es el conjunto de procesos maliciosos conocidos y `TopK` el conjunto de los primeros `k` candidatos, entonces:

```text
Recall@k = |TopK intersección M| / |M|
Precision@k = |TopK intersección M| / min(k, candidatos evaluables)
```

Los casos sin positivos etiquetados deberán tratarse explícitamente, no transformarse silenciosamente en cero. Reportar además AUPRC, falsos positivos por unidad de actividad, latencia, throughput, RSS real y fracción de eventos descartados o no convertidos.

Las repeticiones se agruparán por unidades de observación independientes, como host, día o campaña, según el diseño. No contar eventos correlacionados como ensayos independientes.

#### Condiciones de falsación y parada

- Si no hay ground truth verificable a nivel de proceso, no publicar métricas de proceso como evidencia principal.
- Si el modelo híbrido no mejora un criterio predefinido, conservar el resultado negativo y no introducir indefinidamente nuevas defensas.
- Si un baseline sencillo logra resultados equivalentes con menos recursos, reportarlo como hallazgo central.
- Si las etiquetas de dos datasets no son compatibles, informar transferencia limitada sin agregarlas en una sola cifra.
