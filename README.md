### AgentGuard-C + AgentGuard FastPath

Proyecto en C con dos componentes:

- `agentguard`: monitor  basado en `ptrace` para observar procesos Linux.
- `agfast`: software CLI de análisis de eventos de seguridad en JSONL/CSV.

La parte principal para la entrega es **AgentGuard FastPath**, un analizador de telemetría que usa estructuras probabilísticas de bajo consumo de memoria para detectar frecuencias, cardinalidades, coincidencias con listas de vigilancia, relaciones proceso-archivo-red, puntajes de riesgo y líneas de tiempo.

#### Funcionalidades principales de `agfast`

- Entrada en formato JSONL y CSV.
- Archivo de políticas `policy.json`.
- Bloom Filter para listas de vigilancia.
- Cuckoo Filter demostrable con prueba de borrado.
- Count-Min Sketch para frecuencias aproximadas.
- HyperLogLog para cardinalidades aproximadas.
- Space-Saving / Misra-Gries para heavy hitters.
- Mini grafo proceso -> archivo -> red.
- Puntaje de riesgo configurable por PID/proceso.
- Timeline por PID/proceso.
- Ventanas deslizantes con `--window-events`.
- Similitud de comportamiento por proceso con Jaccard/Odd Sketch.
- Reportes JSON, HTML y CSV de alertas.
- Generación de datasets sintéticos.
- Benchmark con 10k, 100k y 1M eventos.
- Modo incremental `tail`.

#### Requisitos

Linux con:

```bash
gcc
make
openssl/libssl-dev
python3
```

En Debian/Ubuntu:

```bash
sudo apt update
sudo apt install build-essential libssl-dev python3
```

#### Compilación

```bash
make
```

Genera:

```bash
./bin/agentguard
./bin/agfast
```

Para limpiar artefactos:

```bash
make clean
```

#### Demostración rápida

```bash
./bin/agfast analyze examples/events.jsonl \
  --policy examples/policy.json \
  --risk \
  --window-events 3 \
  --report report.json \
  --html report.html \
  --alerts-csv alerts.csv
```

También se puede ver en HTML

```bash

./bin/agfast analyze examples/events.jsonl \
  --policy examples/policy.json \
  --risk \
  --html report.html \
  --report report.json \
  --alerts-csv alerts.csv
```

Luego ábrelo así:

```bash
xdg-open report.html
```

En WSL puedes usar:

```bash
explorer.exe report.html
```

En macOS:

```bash
open report.html
```

En Windows PowerShell:

```bash
start report.html
```

El HTML muestra resumen del análisis, cardinalidades estimadas, comparación de memoria, procesos de mayor riesgo, alertas principales y timeline del proceso más riesgoso.

El programa puede devolver código `2` cuando encuentra alertas. Eso es intencional para integrarlo en scripts o pipelines.

#### Comandos principales

##### Análisis con política

```bash
./bin/agfast analyze examples/events.jsonl --policy examples/policy.json --risk
```

##### Estadísticas sin política

```bash
./bin/agfast stats examples/events_day2.jsonl --report stats.json
```

##### Consulta de grafo

```bash
./bin/agfast graph examples/events_day3.jsonl --policy examples/policy.json --pid 123 --timeline
./bin/agfast graph examples/events_day3.jsonl --policy examples/policy.json --process python
```

##### Timeline

```bash
./bin/agfast timeline examples/events_day3.jsonl --policy examples/policy.json --pid 123
```

##### Verificación contra listas de vigilancia

```bash
./bin/agfast check-file /etc/passwd --policy examples/policy.json
./bin/agfast check-ip 45.90.10.2 --policy examples/policy.json --delete-test
./bin/agfast check-domain malicious.example --policy examples/policy.json
```

##### Similitud entre procesos

```bash
./bin/agfast similarity examples/events_day3.jsonl \
  --process python \
  --compare-process bash \
  --policy examples/policy.json \
  --report similarity.json
```

###### Generación de datasets sintéticos

```bash
./bin/agfast generate --events 100000 --output /tmp/events.jsonl --malicious-ratio 0.05
./bin/agfast generate --events 100000 --format csv --output /tmp/events.csv --malicious-ratio 0.05
```

##### Modo incremental

```bash
./bin/agfast tail examples/events.jsonl --policy examples/policy.json
./bin/agfast tail logs/events.jsonl --policy examples/policy.json --follow
```

#### Formato de eventos

##### JSONL

Cada línea es un evento:

```json
{"time":"2026-05-23T10:00:01Z","pid":123,"process":"python","event":"open","file":"/etc/passwd"}
{"time":"2026-05-23T10:00:02Z","pid":123,"process":"python","event":"connect","dst":"45.90.10.2"}
```

Campos soportados:

- `time`
- `pid`
- `process`
- `event`
- `file`
- `dst`
- `domain`
- `ip`

##### CSV

```csv
time,pid,process,event,file,dst,domain,ip
2026-05-23T10:00:01Z,123,python,open,/etc/passwd,,,
2026-05-23T10:00:02Z,123,python,connect,,45.90.10.2,,45.90.10.2
```

#### Formato de política

Ejemplo mínimo:

```json
{
  "sensitive_files": ["/etc/passwd", "/etc/shadow", "/home/*/.ssh/*"],
  "blocked_domains": ["malicious.example"],
  "blocked_ips": ["45.90.10.2"],
  "watched_processes": ["python", "curl", "bash"],
  "risk_weights": {
    "watched_process": 10,
    "sensitive_file": 25,
    "blocked_ip": 35,
    "blocked_domain": 35,
    "network_after_file": 30,
    "high_unique_destinations": 15,
    "high_event_volume": 10,
    "high_unique_destination_threshold": 10,
    "high_event_volume_threshold": 100
  }
}
```

##### Salidas generadas

`agfast` puede producir:

- Reporte en consola.
- Reporte JSON con métricas, riesgo, memoria y alertas.
- Reporte HTML estático.
- CSV de alertas.

Ejemplo:

```bash
./bin/agfast analyze examples/events.jsonl \
  --policy examples/policy.json \
  --risk \
  --report report.json \
  --html report.html \
  --alerts-csv alerts.csv
```

#### Uso con nuevas entradas del usuario

Un usuario puede analizar sus propios eventos sin modificar el código fuente. Solo necesita preparar un archivo de eventos en JSONL o CSV y una política `policy.json`.

##### 1. Crear eventos propios en JSONL

Crear un archivo, por ejemplo `mis_eventos.jsonl`:

```json
{"time":"2026-05-23T11:00:01Z","pid":501,"process":"python","event":"open","file":"/etc/passwd"}
{"time":"2026-05-23T11:00:04Z","pid":501,"process":"python","event":"connect","dst":"45.90.10.2","ip":"45.90.10.2"}
{"time":"2026-05-23T11:00:07Z","pid":710,"process":"nginx","event":"open","file":"/var/log/nginx/access.log"}
```

Ejecutar análisis:

```bash
./bin/agfast analyze mis_eventos.jsonl \
  --policy mi_policy.json \
  --risk \
  --report mi_reporte.json \
  --html mi_reporte.html \
  --alerts-csv mis_alertas.csv
```

##### 2. Crear eventos propios en CSV

Crear un archivo, por ejemplo `mis_eventos.csv`:

```csv
time,pid,process,event,file,dst,domain,ip
2026-05-23T11:00:01Z,501,python,open,/etc/passwd,,,
2026-05-23T11:00:04Z,501,python,connect,,45.90.10.2,,45.90.10.2
2026-05-23T11:00:07Z,710,nginx,open,/var/log/nginx/access.log,,,
```

Ejecutar análisis:

```bash
./bin/agfast analyze mis_eventos.csv \
  --policy mi_policy.json \
  --risk \
  --report mi_reporte_csv.json \
  --html mi_reporte_csv.html \
  --alerts-csv mis_alertas_csv.csv
```

##### 3. Crear una política propia

Crear un archivo `mi_policy.json`:

```json
{
  "sensitive_files": ["/etc/passwd", "/etc/shadow", "/home/*/.ssh/*"],
  "blocked_domains": ["malicious.example"],
  "blocked_ips": ["45.90.10.2"],
  "watched_processes": ["python", "curl", "bash"],
  "risk_weights": {
    "watched_process": 10,
    "sensitive_file": 25,
    "blocked_ip": 35,
    "blocked_domain": 35,
    "network_after_file": 30,
    "high_unique_destinations": 15,
    "high_event_volume": 10,
    "high_unique_destination_threshold": 10,
    "high_event_volume_threshold": 100
  }
}
```

##### 4. Consultar resultados específicos

Consultar el grafo de un PID:

```bash
./bin/agfast graph mis_eventos.jsonl --policy mi_policy.json --pid 501 --timeline
```

Consultar la línea de tiempo de un proceso:

```bash
./bin/agfast timeline mis_eventos.jsonl --policy mi_policy.json --pid 501
```

Verificar entradas individuales contra la política:

```bash
./bin/agfast check-file /etc/passwd --policy mi_policy.json
./bin/agfast check-ip 45.90.10.2 --policy mi_policy.json
./bin/agfast check-domain malicious.example --policy mi_policy.json
```

##### 5. Generar datos nuevos para pruebas

Generar un dataset JSONL:

```bash
./bin/agfast generate --events 100000 --output /tmp/mis_eventos_generados.jsonl --malicious-ratio 0.05
```

Generar un dataset CSV:

```bash
./bin/agfast generate --events 100000 --format csv --output /tmp/mis_eventos_generados.csv --malicious-ratio 0.05
```

##### 6. Limpiar el proyecto antes de entregar o subir

Eliminar artefactos de compilación:

```bash
make clean
```

Eliminar reportes generados localmente:

```bash
rm -f report.json report.html alerts.csv
rm -f mi_reporte*.json mi_reporte*.html mis_alertas*.csv
rm -f stats*.json graph*.json similarity*.json check-*.json
```


#### Pruebas y benchmark

Pruebas completas:

```bash
make test-fastpath
```

Pruebas por grupo:

```bash
make test
make test-algorithms
make test-reports
```

Benchmark JSONL:

```bash
make benchmark
```

Benchmark CSV:

```bash
make benchmark-csv
```

Los benchmarks generan datos temporales en `/tmp/agfast_bench`.

#### Estructura del proyecto

```text
.
├── Makefile
├── README.md
├── examples/
│   ├── events.jsonl
│   ├── events.csv
│   ├── events_day2.jsonl
│   ├── events_day3.jsonl
│   └── policy.json
├── include/
│   └── *.h
├── scripts/
│   ├── benchmark_fastpath.sh
│   └── generate_events.py
├── src/
│   ├── fastpath.c
│   └── *.c
└── tests/
    ├── test_agent.c
    └── test_fastpath_final.sh
```

#### Limitaciones

- Es un analizador offline/batch e incremental básico; no es un EDR completo.
- No bloquea procesos reales.
- No usa eBPF ni CUDA.
- El parser JSON/CSV es ligero y adecuado, no reemplaza una biblioteca JSON robusta.
- Las estructuras probabilísticas pueden producir aproximaciones o falsos positivos; las decisiones críticas se confirman contra listas exactas cuando aplica.

#### Licencia

MIT, para uso académico y de investigación.