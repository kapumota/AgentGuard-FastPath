### Benchmarks y validación de sketches

#### Objetivo

La Fase 4 agrega una evaluación reproducible para medir el costo y la utilidad de las estructuras probabilísticas usadas por AgentGuard FastPath.

El objetivo no es solo medir tiempo o memoria. También se busca verificar si las estimaciones aproximadas conservan señales útiles para priorizar procesos de riesgo.

#### Archivos agregados

```text
benchmarks/run_benchmark.sh
benchmarks/compare_exact_vs_sketch.py
benchmarks/rank_correlation.py
experiments/sketch_rank_simulation.py
docs/BENCHMARKS.md
docs/TEORIA_MINIMA.md
```

#### Ejecución

Desde la raíz del repositorio:

```bash
make clean
make
make test-fastpath
make test-regression
bash benchmarks/run_benchmark.sh
python3 experiments/sketch_rank_simulation.py
make clean
```

#### Resultados

Por defecto los resultados se guardan fuera del repositorio:

```text
/tmp/agfast_phase4_benchmark/
```

Archivos principales:

```text
resumen_benchmark.csv
resumen_benchmark.md
report_1000.json
report_5000.json
report_10000.json
```

#### Métricas

La evaluación reporta:

```text
tiempo de ejecución
memoria exacta estimada
memoria probabilística fija
error de HyperLogLog
top-5 overlap de procesos
top-10 overlap de procesos
correlación de ranking
```

#### Interpretación

El top-k overlap compara los procesos más frecuentes calculados de forma exacta contra los procesos principales estimados por Count-Min Sketch.

Una correlación alta indica que las estructuras aproximadas preservan señales útiles para investigación defensiva.

#### Alcance

Esta fase no modifica el núcleo de detección.

Esta fase no agrega eBPF.

Esta fase no introduce GuardSketch.

Esta fase no cambia la modularización de `agfast`.

#### Personalización

Para cambiar tamaños de dataset:

```bash
SIZES="1000 2000 5000" bash benchmarks/run_benchmark.sh
```

Para cambiar el directorio de resultados:

```bash
BENCH_DIR=/tmp/agfast_benchmark_local bash benchmarks/run_benchmark.sh
```

#### Criterio de aceptación

La fase se considera válida si pasan:

```bash
make clean
make
make test-fastpath
make test-regression
bash benchmarks/run_benchmark.sh
python3 experiments/sketch_rank_simulation.py
make clean
```

### Simulación más exigente

#### Motivación

Una simulación con pocos procesos y poca presión de colisiones puede producir resultados perfectos.

Eso no demuestra que los sketches preserven el ranking de riesgo en condiciones realistas.

#### Ajuste aplicado

La simulación de `experiments/sketch_rank_simulation.py` usa ahora:

- más procesos;
- más eventos;
- procesos benignos ruidosos;
- procesos maliciosos menos triviales;
- destinos únicos numerosos;
- escenarios con presión de colisiones;
- comparación entre configuraciones de Count-Min Sketch.

#### Métricas reportadas

La simulación reporta:

- top-5 overlap;
- top-10 overlap;
- top-25 overlap;
- Spearman top-50;
- top-5 exacto;
- top-5 aproximado;
- falso positivo teórico de Bloom para varios valores de `n`.

#### Criterio

Si `d=2, w=256` degrada demasiado el ranking, una fase posterior debe usar una configuración mayor antes de implementar el sketch en eBPF.

### Evaluación realista orientada a agfast

#### Motivación

La evaluación de Fase 4 no debe medir sketches en abstracto.

Debe medir si las estructuras probabilísticas preservan decisiones que usa AgentGuard FastPath:

- ranking de riesgo por PID;
- top-k de procesos riesgosos;
- cambios de nivel de riesgo;
- falsos positivos de Bloom sobre elementos de policy y telemetría observada;
- error de cardinalidad de HyperLogLog sobre destinos únicos.

#### Script agregado

```bash
python3 experiments/agfast_realistic_sketch_eval.py
```

#### Datos generados

El script genera un dataset JSONL y una policy JSON en `/tmp/agfast_realistic_eval`.

El dataset contiene:

- procesos maliciosos;
- procesos benignos ruidosos;
- procesos normales;
- eventos `open`;
- eventos `connect`;
- eventos `exec`;
- archivos sensibles;
- IPs bloqueadas;
- dominios bloqueados;
- patrones de red después de acceso a archivo sensible.

#### Métricas principales

La evaluación reporta:

- top-5 overlap;
- top-10 overlap;
- top-25 overlap;
- correlación top-50;
- cambios de nivel de riesgo;
- error promedio de HLL;
- error p95 de HLL;
- falsos esperados de Bloom según consultas del dataset;
- tiempo de ejecución real de `agfast` si `./bin/agfast` existe.

#### Criterio de lectura

Una configuración de sketch no se considera buena solo por usar poca memoria.

Debe preservar los procesos más riesgosos y no cambiar excesivamente los niveles de riesgo.

La configuración cercana al proyecto usa:

```text
CMS d=5,w=4096 + HLL p=14
```

Las configuraciones pequeñas se usan como límites inferiores agresivos.
