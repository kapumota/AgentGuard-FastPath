### AgentGuard-C y AgentGuard FastPath

[![AgentGuard-C CI](https://github.com/kapumota/AgentGuard-FastPath/actions/workflows/ci.yml/badge.svg)](https://github.com/kapumota/AgentGuard-FastPath/actions/workflows/ci.yml)
[![AGFast Quality](https://github.com/kapumota/AgentGuard-FastPath/actions/workflows/agfast-quality.yml/badge.svg)](https://github.com/kapumota/AgentGuard-FastPath/actions/workflows/agfast-quality.yml)

![Release](https://img.shields.io/badge/release-v1.0.0-brightgreen)
![Language](https://img.shields.io/badge/language-C-blue)
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Tests](https://img.shields.io/badge/tests-regression%20%7C%20streaming%20%7C%20unit-brightgreen)
![Benchmarks](https://img.shields.io/badge/benchmarks-reproducible-blue)
![GuardSketch](https://img.shields.io/badge/GuardSketch-userspace-blueviolet)
![eBPF](https://img.shields.io/badge/eBPF-optional-lightgrey)
![Status](https://img.shields.io/badge/status-experimental%20defensive%20tool-orange)
AgentGuard FastPath es un software de análisis defensivo de eventos de seguridad escrito en C. Procesa telemetría en formato JSONL o CSV, aplica una política configurable y produce métricas, alertas, relaciones proceso-archivo-red, líneas de tiempo y puntajes de riesgo.

El repositorio contiene dos componentes:

- `agentguard`: monitor Linux basado en `ptrace` para observar procesos.
- `agfast`: CLI principal para analizar eventos de seguridad en archivos JSONL/CSV.

La parte central del proyecto es `agfast`. Su objetivo es convertir eventos crudos en información útil para detección, investigación y priorización de comportamientos sospechosos.

#### Capacidades principales

- Entrada en formato JSONL y CSV.
- Archivo de política `policy.json`.
- Bloom Filter para verificación rápida de pertenencia.
- Cuckoo Filter con prueba de borrado.
- Count-Min Sketch para frecuencias aproximadas.
- HyperLogLog para cardinalidades aproximadas.
- Space-Saving y Misra-Gries para heavy hitters.
- Odd Sketch y similitud Jaccard para comparar comportamiento.
- Grafo proceso-archivo-red.
- Puntaje de riesgo por PID o proceso.
- Timeline por PID o proceso.
- Ventanas con `--window-events`.
- Reportes en consola, JSON, HTML y CSV.
- Generación de datasets sintéticos.
- Benchmarks reproducibles.
- Modo incremental `tail`.

#### Requisitos

En Debian, Ubuntu o WSL con entorno Linux:

```bash
sudo apt update
sudo apt install build-essential libssl-dev python3 valgrind
```

Para uso básico no es obligatorio instalar Valgrind, pero sí es útil para validar fugas de memoria en CI o pruebas locales.

#### Compilación

```bash
make clean
make
```

La compilación genera:

```bash
./bin/agentguard
./bin/agfast
```

#### Pruebas mínimas

```bash
make clean
make
make test-fastpath
```

`make test-fastpath` ejecuta pruebas básicas, pruebas de algoritmos y pruebas de reportes.

#### Limpieza del repositorio

```bash
make clean
```

Este comando elimina:

- `obj/`
- `bin/`
- reportes locales generados por las demos, como `report.json`, `report.html` y `alerts.csv`

Para eliminar solo reportes locales:

```bash
make clean-reports
```

El repositorio no debe versionar binarios, objetos compilados, reportes generados, archivos temporales, salidas de benchmark ni carpetas de entorno virtual.

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

El programa puede devolver código `2` cuando encuentra alertas. Ese comportamiento es intencional y permite integrar `agfast` con scripts o pipelines.

Para abrir el reporte HTML en Linux:

```bash
xdg-open report.html
```

En WSL:

```bash
explorer.exe report.html
```

#### Comandos principales

Análisis con política:

```bash
./bin/agfast analyze examples/events.jsonl --policy examples/policy.json --risk
```

Estadísticas sin política:

```bash
./bin/agfast stats examples/events_day2.jsonl --report stats.json
```

Consulta de grafo:

```bash
./bin/agfast graph examples/events_day3.jsonl --policy examples/policy.json --pid 123 --timeline
./bin/agfast graph examples/events_day3.jsonl --policy examples/policy.json --process python
```

Timeline:

```bash
./bin/agfast timeline examples/events_day3.jsonl --policy examples/policy.json --pid 123
```

Verificación contra listas de vigilancia:

```bash
./bin/agfast check-file /etc/passwd --policy examples/policy.json
./bin/agfast check-ip 45.90.10.2 --policy examples/policy.json --delete-test
./bin/agfast check-domain malicious.example --policy examples/policy.json
```

Similitud entre procesos:

```bash
./bin/agfast similarity examples/events_day3.jsonl \
  --process python \
  --compare-process bash \
  --policy examples/policy.json \
  --report similarity.json
```

Generación de datasets sintéticos:

```bash
./bin/agfast generate --events 100000 --output /tmp/events.jsonl --malicious-ratio 0.05
./bin/agfast generate --events 100000 --format csv --output /tmp/events.csv --malicious-ratio 0.05
```

Modo incremental:

```bash
./bin/agfast tail examples/events.jsonl --policy examples/policy.json
./bin/agfast tail logs/events.jsonl --policy examples/policy.json --follow
```

#### Formato JSONL

Cada línea representa un evento:

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

#### Formato CSV

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

#### Benchmark

Benchmark JSONL:

```bash
make benchmark
```

Benchmark CSV:

```bash
make benchmark-csv
```

También se puede ejecutar el script directo:

```bash
scripts/benchmark_fastpath.sh ./bin/agfast
```

Por defecto, los benchmarks escriben datos temporales en `/tmp/agfast_bench`.

#### Documentación técnica

- `docs/ARQUITECTURA.md`: arquitectura actual del proyecto.
- `docs/USO.md`: comandos reproducibles de uso, prueba y limpieza.
- `docs/ROADMAP.md`: fases propuestas para evolucionar el proyecto.
- `docs/DECISIONES_TECNICAS.md`: decisiones de diseño y flujo de Pull Request.

#### Flujo recomendado de ramas y Pull Requests

Para cada fase:

```bash
git checkout main
git pull origin main
git checkout -b fase-1-higiene-repositorio
```

Después de modificar y probar:

```bash
make clean
make
make test-fastpath

git status
git add .
git commit -m "fase 1: ordena repositorio y documenta uso reproducible"
git push -u origin fase-1-higiene-repositorio
```

Luego se abre un Pull Request hacia `main`.

Para este proyecto se recomienda usar **Merge pull request** y no **Squash and merge** cuando cada rama representa una fase del proyecto. Así se conserva la historia completa de commits, pruebas y decisiones. Squash and merge puede usarse solo si la rama tuvo muchos commits pequeños, correcciones triviales o mensajes poco claros.

#### Release sugerido para esta fase

Después de fusionar la Fase 1 en `main`:

```bash
git checkout main
git pull origin main
git tag -a v0.1.1 -m "v0.1.1: higiene inicial del repositorio"
git push origin main --tags
```

Luego se puede crear un GitHub Release asociado al tag `v0.1.1`.

#### Licencia

Este proyecto se distribuye bajo la licencia indicada en `LICENSE`.

### Pruebas de regresión y Valgrind

#### Pruebas de regresión

La Fase 3 agrega una suite de regresión para validar comandos principales de `agfast` con fixtures pequeños y reproducibles.

Ejecución recomendada:

```bash
make clean
make
make test-fastpath
make test-regression
make clean
```

Salida esperada al final de `make test-regression`:

```text
Pruebas de regresion superadas
```

#### Instalación de Valgrind

En Ubuntu o Debian:

```bash
sudo apt update
sudo apt install -y valgrind
```

#### Ejecución con Valgrind

```bash
make test-valgrind
```

Si Valgrind está instalado, la salida debe incluir una revisión de memoria de `agfast`.

Salida esperada en una ejecución correcta:

```text
Prueba Valgrind de agfast
ERROR SUMMARY: 0 errors
```

Si Valgrind no está instalado, la prueba no detiene el flujo de trabajo y muestra:

```text
Valgrind no esta instalado; prueba omitida
```

#### Criterio de aceptación

Para esta fase, el proyecto debe pasar:

```bash
make clean
make
make test-fastpath
make test-regression
make clean
```

`make test-valgrind` es recomendable para validación local de memoria. Si Valgrind está instalado, no debe reportar errores de memoria.

<!-- fase10-release:start -->
### Estado del release v1.0.0

#### Resumen

AgentGuard FastPath `v1.0.0` consolida una primera versión presentable como herramienta C defensiva experimental para análisis de telemetría JSONL/CSV.

Incluye:

- pruebas de regresión;
- pruebas de streaming;
- tests unitarios en C con Unity;
- benchmarks;
- evaluación experimental reproducible;
- GuardSketch MVP en userspace;
- preparación eBPF opcional;
- CI/CD visible;
- documentación técnica de release.

#### Documentación principal

- `docs/INSTALACION.md`
- `docs/USO_AVANZADO.md`
- `docs/RELEASE_V1.md`
- `docs/EVALUACION.md`
- `docs/GUARDSKETCH.md`
- `docs/EBPF.md`
- `docs/CI.md`
- `CHANGELOG.md`

#### Validación recomendada

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
<!-- fase10-release:end -->
