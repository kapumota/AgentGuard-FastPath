### Uso avanzado

#### Análisis con política

```bash
./bin/agfast analyze examples/events.jsonl --policy examples/policy.json --risk
```

#### Reporte JSON

```bash
./bin/agfast analyze examples/events.jsonl \
  --policy examples/policy.json \
  --risk \
  --report agfast-report.json
```

#### Reporte HTML y CSV de alertas

```bash
./bin/agfast analyze examples/events.jsonl \
  --policy examples/policy.json \
  --risk \
  --html agfast-report.html \
  --alerts-csv agfast-alerts.csv
```

#### Estadísticas

```bash
./bin/agfast stats examples/events.jsonl
```

#### Timeline

```bash
./bin/agfast timeline examples/events.jsonl
```

#### Grafo por PID

```bash
./bin/agfast graph examples/events.jsonl --pid 501
```

#### Grafo por proceso

```bash
./bin/agfast graph examples/events.jsonl --process python
```

#### Consultas rápidas

```bash
./bin/agfast check-file /etc/passwd --policy examples/policy.json
./bin/agfast check-ip 203.0.113.10 --policy examples/policy.json
./bin/agfast check-domain malicious.example --policy examples/policy.json
```

#### Similaridad

```bash
./bin/agfast similarity examples/events.jsonl
```

#### Generación de dataset

```bash
./bin/agfast generate --events 1000 --output /tmp/agfast-events.jsonl
```

#### Modo tail

```bash
./bin/agfast tail examples/events.jsonl --policy examples/policy.json
```

#### Modo tail con follow

```bash
./bin/agfast tail /tmp/agfast-stream.jsonl --policy examples/policy.json --follow
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

#### CI/CD

El workflow principal de calidad es:

```text
.github/workflows/agfast-quality.yml
```

El workflow de Valgrind es:

```text
.github/workflows/valgrind.yml
```

#### Interpretación de códigos de salida

Durante la evaluación experimental, el código `2` puede indicar alertas detectadas.

En ese contexto, el script de evaluación acepta el código `2` como hallazgo esperado si los reportes fueron generados correctamente.
