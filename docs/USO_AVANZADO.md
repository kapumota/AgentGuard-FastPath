
### Uso avanzado

#### Objetivo

Este documento reúne comandos avanzados reproducibles para AgentGuard FastPath `v1.0.1`.

Antes de ejecutar los ejemplos:

```bash
make clean
make
```

#### Versión

```bash
./bin/agfast --version
./bin/agentguard --version
```

La salida esperada debe indicar:

```text
AgentGuard FastPath 1.0.1
AgentGuard-C v1.0.0
```

#### Análisis con política

```bash
./bin/agfast analyze examples/events.jsonl --policy examples/policy.json --risk
```

#### Reporte JSON

```bash
./bin/agfast analyze examples/events.jsonl   --policy examples/policy.json   --risk   --report agfast-report.json
```

#### Reporte HTML y CSV de alertas

```bash
./bin/agfast analyze examples/events.jsonl   --policy examples/policy.json   --risk   --html agfast-report.html   --alerts-csv agfast-alerts.csv
```

#### Estadísticas

```bash
./bin/agfast stats examples/events.jsonl
```

#### Timeline

```bash
./bin/agfast timeline examples/events.jsonl
```

#### Grafo por PID reproducible

Para buscar un PID existente:

```bash
grep -o '"pid":[0-9]*' examples/events_day3.jsonl | head
```

Ejemplo de grafo:

```bash
./bin/agfast graph examples/events_day3.jsonl   --policy examples/policy.json   --pid 123   --timeline   --report agfast-graph.json
```

Si el PID `123` no existe en el fixture local, reemplazarlo por uno listado por el comando `grep`.

#### Grafo por proceso

```bash
./bin/agfast graph examples/events_day3.jsonl   --policy examples/policy.json   --process python   --timeline   --report agfast-graph-process.json
```

#### Consultas rápidas

```bash
./bin/agfast check-file /etc/passwd --policy examples/policy.json
./bin/agfast check-ip 203.0.113.10 --policy examples/policy.json
./bin/agfast check-domain malicious.example --policy examples/policy.json
```

#### Similaridad entre procesos

El comando `similarity` requiere proceso base y proceso de comparación.

```bash
./bin/agfast similarity examples/events_day3.jsonl   --process python   --compare-process bash   --policy examples/policy.json   --report agfast-similarity.json
```

#### Generación de dataset

```bash
./bin/agfast generate --events 1000 --output /tmp/agfast-events.jsonl
```

#### Modo tail

```bash
./bin/agfast tail examples/events.jsonl --policy examples/policy.json
```

#### Benchmarks

```bash
bash benchmarks/run_benchmark.sh
```

#### Evaluación reproducible

```bash
AGFAST_EVAL_EVENTS=10000 AGFAST_EVAL_PIDS=300 bash scripts/run_evaluation.sh
```

#### GuardSketch userspace

```bash
make test-guardsketch
```

#### Tests unitarios

```bash
make test-unit
```

#### Limpieza

```bash
make clean
```
