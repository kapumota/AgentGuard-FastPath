### Release v1.0.0

#### Objetivo

Cerrar una primera versión presentable de AgentGuard FastPath.

Esta versión representa una base técnica avanzada para análisis defensivo de telemetría en C, con pruebas, documentación, benchmarks, evaluación reproducible y roadmap hacia eBPF.

#### Descripción corta

AgentGuard FastPath es una herramienta C defensiva para analizar eventos JSONL/CSV, aplicar políticas configurables, calcular riesgo por proceso, generar reportes y evaluar estructuras probabilísticas aplicadas a seguridad.

#### Qué incluye

- CLI `agfast`.
- Análisis batch.
- Modo incremental `tail`.
- Reportes JSON, HTML y CSV.
- Timeline.
- Grafo proceso-archivo-red.
- Estadísticas.
- Scoring de riesgo.
- Benchmarks.
- Evaluación experimental reproducible.
- Tests de regresión.
- Tests de streaming.
- Tests unitarios en C con Unity.
- GuardSketch MVP userspace.
- Preparación eBPF opcional.
- CI/CD visible.

#### Validación final recomendada

```bash
make clean
make
make test-fastpath
make test-regression
make test-streaming
make test-guardsketch
make test-unit
bash benchmarks/run_benchmark.sh
AGFAST_EVAL_EVENTS=10000 AGFAST_EVAL_PIDS=300 bash scripts/run_evaluation.sh
make clean
```

#### Estado de eBPF

eBPF queda preparado como soporte opcional.

La versión `v1.0.0` no carga programas eBPF ni implementa GuardSketch en kernel.

#### Estado de GuardSketch

GuardSketch existe como MVP en userspace.

Esto permite validar la idea antes de llevarla a kernel.

#### Criterio de madurez

Esta versión puede presentarse como:

```text
herramienta C defensiva experimental con pruebas, benchmarks, documentación técnica, evaluación reproducible y preparación eBPF opcional
```

No debe presentarse todavía como:

```text
EDR completo
SIEM completo
producto production-ready
agente eBPF real
```

#### Texto sugerido para GitHub Release

```text
AgentGuard FastPath v1.0.0 consolida una primera versión presentable de la herramienta.

Incluye análisis de eventos JSONL/CSV, políticas configurables, scoring de riesgo, reportes JSON/HTML/CSV, timeline, grafo proceso-archivo-red, benchmarks, evaluación experimental reproducible, pruebas de regresión, pruebas unitarias en C con Unity, modo streaming, GuardSketch MVP userspace, preparación eBPF opcional y CI/CD visible.

Esta versión está orientada a evaluación técnica, portafolio avanzado e investigación experimental. No se presenta todavía como EDR completo ni como SIEM completo.
```

#### Checklist de release

- `main` actualizado.
- Validación final ejecutada.
- `git status --short` limpio.
- PR de Fase 10 fusionado.
- Tag `v1.0.0` creado sobre el merge de Fase 10.
- GitHub Release creado desde el tag `v1.0.0`.
