### F0. Alcance del artículo y del cierre de software

#### Identidad científica provisional

Título de trabajo en inglés, no título editorial definitivo:

`Robust Host-Event Risk Prioritization under Adversarial Telemetry and Memory Constraints: An Empirical Study`

Contribución candidata: evaluación y posible mejora de la priorización de eventos de host mediante evidencia crítica exacta, estadísticas aproximadas y verificación selectiva bajo presupuestos definidos. La novedad permanece pendiente de cribado bibliográfico y resultados.

#### Alcance confirmado del software actual

`agfast` ingiere eventos JSONL/CSV, aplica políticas, mantiene resúmenes estadísticos y genera reportes de riesgo. `agentguard` contiene monitoreo con `ptrace`. GuardSketch es un MVP en espacio de usuario y no está integrado como motor de riesgo equivalente al analizador principal.

#### Desarrollo autorizado en F0

- Documentar protocolo, referencias, hipótesis, threat model y criterios de selección de datos.
- Elaborar matrices y registros reproducibles de revisión bibliográfica.
- Realizar lectura estática necesaria para identificar contratos y límites del software.

No modificar algoritmos, ejecutables, interfaces, CI, generación de datos o scripts de evaluación durante F0.

#### Desarrollo propuesto para fases posteriores

- F1: verificar ejecución, memoria, temporalidad y defectos del baseline actual.
- F2: seleccionar corpus externo con etiquetas trazables, comenzando por un piloto de THEIA E3 si resulta viable.
- F3: integrar motor exacto y aproximado con una interfaz comparable y corregir identidad temporal.
- F4: implementar baselines independientes y protocolo de métricas.
- F5: ejecutar perturbaciones A1 a A4 y probar mitigaciones mediante ablaciones.
- F6: validar fuera del corpus principal cuando haya equivalencia semántica.
- F7: congelar release y artefactos de reproducción.
- F8: redactar manuscrito, revisar revista y decidir el envío.

Esta secuencia de cierre F0-F8 no sustituye la historia documentada del roadmap de producto.

#### Exclusiones del camino crítico

- eBPF, sensor residente, agente EDR, SIEM y dashboards.
- Entrenamiento de GNN o modelos grandes.
- Diseño de una nueva familia de sketches.
- Nuevos datasets seleccionados después de conocer resultados favorables.
- Renombrado prematuro del repositorio.
- Ajustes destinados únicamente a superar una métrica concreta en test.

#### Criterios para pasar de investigación a envío

- Protocolo y revisión bibliográfica trazables.
- Código compilable y validado con pruebas que ejerciten rutas reales.
- Ground truth externo y adaptador auditado.
- Al menos un baseline externo o independiente comparable, además de la ruta exacta.
- Resultados adversariales reproducibles con límites explícitos.
- Métricas de calidad y recursos con fuentes, versiones, comandos y variabilidad.
- Evidencia que sostenga una contribución y discusión de resultados negativos.
- Revista verificada por título, ISSN, alcance, indexación y cuartil vigentes.

#### Cierre y publicación

La meta editorial es una revista indexada en Scopus o Web of Science, al menos Q4, sin garantía de aceptación ni de asignación automática de puntos RENACYT. Si los resultados no sostienen novedad suficiente, el proyecto se cerrará como software experimental con evidencia reproducible, sin agregar fases por inercia.

#### Política de cambios

Mantener el historial, documentar decisiones y trabajar en ramas de fase. No realizar merge, push, commit o cambio de nombre por el simple hecho de aplicar el parche documental. Estos actos requieren revisión explícita del estado local.
