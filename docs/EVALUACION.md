### Evaluación experimental

#### Objetivo

La Fase 9 produce evidencia reproducible de rendimiento, memoria y calidad de detección.

El proyecto ya no debe presentarse solo con descripción técnica. Debe incluir números generados por scripts.

#### Comparaciones mínimas

La evaluación cubre tres rutas:

```text
agfast exacto o ruta principal de análisis
agfast con sketches y simulaciones existentes
GuardSketch userspace
```

#### Comparaciones opcionales

No se incluyen como requisito de esta fase:

```text
Falco
Tetragon
eBPF real
```

Estas comparaciones pueden agregarse después porque requieren configuración adicional y políticas equivalentes.

#### Entregables

```text
scripts/run_evaluation.sh
results/
benchmarks/results/
docs/EVALUACION.md
```

#### Directorio de resultados

Por defecto, el script escribe resultados en:

```text
/tmp/agfast_fase9_evaluacion
```

Esto evita ensuciar el repositorio con archivos generados.

Si se desea guardar resultados dentro del proyecto para una entrega concreta, se puede usar:

```bash
AGFAST_EVAL_DIR=results/fase9-local bash scripts/run_evaluation.sh
```

Antes de commitear, se debe revisar si esos resultados deben versionarse o mantenerse como evidencia local.

#### Métricas

La evaluación mide:

- throughput aproximado;
- tiempo de ejecución;
- memoria máxima RSS;
- precision y recall contra labels sintéticos;
- top-k overlap entre alertas y ranking exacto;
- tamaño de reportes;
- robustez ante líneas corruptas;
- estado de GuardSketch userspace.

#### Dataset

El script genera un dataset sintético etiquetado con:

- procesos maliciosos;
- procesos benignos ruidosos;
- procesos normales;
- eventos `open`;
- eventos `connect`;
- eventos `exec`;
- archivos sensibles;
- IPs bloqueadas;
- dominios bloqueados;
- líneas corruptas para robustez.

#### Ejecución

```bash
make clean
make
make test-fastpath
make test-regression
make test-streaming
make test-guardsketch
bash scripts/run_evaluation.sh
make clean
```

#### Salida esperada

El script debe imprimir una sección como:

```text
Resumen de evaluación experimental
```

También debe generar:

```text
evaluation_summary.md
evaluation_summary.json
agfast_report.json
agfast_report.html
agfast_alerts.csv
```

#### Interpretación

Precision y recall se calculan contra labels sintéticos. No sustituyen una evaluación con dataset real, pero permiten comparar comportamiento de forma reproducible.

El top-k overlap es importante porque AgentGuard FastPath busca priorizar procesos riesgosos.

El tamaño de reportes permite evaluar el costo de salida.

La prueba con líneas corruptas permite validar robustez básica.

#### Limitaciones

La evaluación sigue siendo sintética.

No representa tráfico real completo ni ataques reales con ground truth externo.

Una fase posterior debería considerar:

- ataques controlados en VM;
- datasets etiquetados;
- comparación con baselines externos;
- evaluación eBPF cuando exista captura real.

#### Criterio de aceptación

La Fase 9 se considera correcta si:

- `make` pasa;
- `make test-fastpath` pasa;
- `make test-regression` pasa;
- `make test-streaming` pasa;
- `make test-guardsketch` pasa;
- `scripts/run_evaluation.sh` genera resumen;
- no se modifican archivos de código fuente;
- los resultados son reproducibles con comandos documentados.
