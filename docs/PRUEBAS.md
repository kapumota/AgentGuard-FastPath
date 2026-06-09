### Pruebas de regresión y calidad

#### Objetivo

La Fase 3 agrega una base de pruebas de regresión para proteger el comportamiento actual de AgentGuard FastPath antes de incorporar nuevas funciones.

El objetivo es verificar comandos principales, formatos de entrada, reportes y casos de política sin modificar el núcleo de análisis.

#### Alcance

Esta fase cubre:

- análisis con JSONL;
- análisis con CSV;
- estadísticas;
- grafo por PID;
- grafo por nombre de proceso;
- timeline;
- verificación de archivos;
- verificación de IP;
- verificación de dominios;
- similitud entre procesos;
- generación de eventos JSONL;
- generación de eventos CSV;
- modo tail sin `--follow`;
- validación de reportes JSON;
- validación de CSV de alertas.

#### Archivos agregados

```text
tests/fixtures/events_regression.jsonl
tests/fixtures/events_regression.csv
tests/fixtures/events_tail.jsonl
tests/fixtures/policy_regression.json
tests/test_regression.sh
```

#### Fixtures

Los fixtures son pequeños y reproducibles.

Incluyen eventos benignos y eventos sospechosos para validar:

- procesos observados;
- archivos sensibles;
- IP bloqueada;
- dominio bloqueado;
- correlación entre acceso a archivo y conexión de red;
- reportes generados.

#### Ejecución

Para ejecutar la validación completa de esta fase:

```bash
make clean
make
make test-fastpath
make test-regression
make clean
```

#### Valgrind

La fase agrega el objetivo:

```bash
make test-valgrind
```

Si `valgrind` está instalado, ejecuta una revisión básica de memoria sobre `agfast`.

Si `valgrind` no está instalado, el objetivo muestra un mensaje y omite la prueba para mantener portabilidad local y en CI.

#### Criterios de aceptación

La Fase 3 se considera correcta si pasan estos comandos:

```bash
make clean
make
make test-fastpath
make test-regression
make clean
```

También debe cumplirse que no se versionen artefactos generados como:

```text
bin/
obj/
report.json
report.html
alerts.csv
```

#### Alcance excluido

Esta fase no agrega eBPF.

Esta fase no agrega GuardSketch.

Esta fase no cambia la modularización interna.

Esta fase no modifica la interfaz CLI.

Esta fase no incorpora benchmarks grandes.

#### Siguiente fase

Después de esta fase, el proyecto puede avanzar a benchmarks y validación de sketches con más seguridad, porque el comportamiento base queda protegido por pruebas de regresión.
