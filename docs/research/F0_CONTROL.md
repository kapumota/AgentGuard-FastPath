### F0. Control de inicio de investigación

#### Identificación

- Proyecto: AgentGuard-FastPath.
- Repositorio: https://github.com/kapumota/AgentGuard-FastPath
- Fecha de preparación: 2026-10-13.
- Corte de literatura: 2026-10-13.
- Horizonte de planificación: 2027, sin incluir publicaciones futuras como evidencia disponible.
- Rama de trabajo prevista: `research/f0-protocolo`.
- Estado de F0: `IN_PROGRESS`.
- Estado editorial: `NOT_READY_TO_SUBMIT`.
- Referencia pública observada al preparar el parche: `2891a512e265cce07c64fc6a0367bd8a78bba3cb`.
- El usuario debe comprobar su `HEAD` local. La referencia pública no certifica el estado de su copia.

#### Objetivo

Congelar el alcance científico, el protocolo de revisión de literatura, las preguntas de investigación y el modelo de amenaza antes de modificar algoritmos o realizar experimentos definitivos.

#### Documentos de este primer parche

- `docs/research/F0_CONTROL.md`, registro de avance y decisión.
- `docs/research/PRISMA_PROTOCOL.md`, protocolo metodológico.
- `docs/research/RELATED_WORK.md`, antecedentes verificados de partida.
- `docs/research/RESEARCH_QUESTIONS.md`, preguntas e hipótesis.
- `docs/research/THREAT_MODEL.md`, capacidades y límites adversariales.
- `docs/research/PAPER_SCOPE.md`, alcance de software y artículo.
- `docs/research/REFERENCES_SEED.csv`, referencias para cribado, no corpus final.
- `docs/research/SEARCH_LOG.csv`, plantilla de trazabilidad de búsquedas.
- `docs/research/SCREENING_LOG.csv`, plantilla de decisiones de selección.

#### Relación con el roadmap histórico

Las fases F0 a F8 son el plan de cierre científico de 2026 a 2027. No reemplazan ni alteran las fases históricas ya descritas en `docs/ROADMAP.md` ni el release `v1.0.1`. Cualquier reconciliación documental posterior exigirá una decisión explícita.

#### Hechos observados en el código público

- `agfast` calcula el riesgo principal a partir del grafo y de la política, según `src/agfast_parts/risk_reports.c`.
- GuardSketch sigue siendo un prototipo autocontenido en `src/agfast_parts/guardsketch.c`, sin integración completa en el CLI principal.
- GuardSketch mantiene un CMS por ranura de PID, no un CMS compartido entre procesos.
- El indicador `network_after_file` actual usa condiciones acumuladas y requiere validar la precedencia temporal que anuncia su nombre.
- Los resultados de `docs/EVALUACION.md` usan etiquetas sintéticas y no sustituyen ground truth externo.

Estos hallazgos se consideran hipótesis de corrección y se verificarán de forma ejecutable en F1. F0 no declara defectos dinámicos confirmados.

#### Actividades necesarias para cerrar F0

- [ ] Guardar exportaciones completas de búsqueda con fecha, base, estrategia y criterios aplicados.
- [ ] Deduplicar registros y reconciliar versiones de artículos, preprints y repositorios.
- [ ] Completar el cribado de títulos, resúmenes y textos completos con razones de exclusión.
- [ ] Completar diagrama y conteos PRISMA-ScR a partir de registros reales.
- [ ] Extraer métodos, datasets, etiquetas, baselines, amenazas, métricas y limitaciones de los estudios incluidos.
- [ ] Verificar el alcance de novedad frente a los trabajos más próximos.
- [ ] Aprobar preguntas, métricas y modelo de amenaza antes de implementar F3 a F6.
- [ ] Registrar el commit local de referencia y decidir formalmente `F0 PASS` o `F0 REQUIRES_CORRECTION`.

#### Regla de cierre

F0 permanece `IN_PROGRESS` hasta documentar todas las evidencias anteriores. No se confunde la creación de plantillas y antecedentes con la terminación de una revisión sistemática.

#### Reglas editoriales y de código

- Comentarios, documentación operativa y cadenas visibles al usuario en español.
- Identificadores, parámetros, nombres de tipos y firmas de funciones en inglés.
- Encabezados Markdown con `###`, `####` y excepcionalmente `#####`.
- Prosa con puntuación ordinaria, sin guiones largos ni adornos tipográficos.
- El manuscrito podrá estar en inglés según los requisitos de la revista.
- Este parche no modifica código, pruebas, Makefile, CI ni historia Git.
- No efectuar `commit`, `push`, `merge`, etiquetado ni publicación sin revisión explícita.
