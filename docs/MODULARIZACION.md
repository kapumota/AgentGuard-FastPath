### Modularización interna de agfast

#### Objetivo

La Fase 2 separa el código principal de `agfast` en unidades más pequeñas y mantenibles.

El archivo original `src/fastpath.c` concentra parsing, política, estructuras probabilísticas, grafo, riesgo, reportes, comandos y la función `main`.

#### Estrategia aplicada

Esta fase aplica una modularización física inicial.

El archivo `src/fastpath.c` queda como punto de ensamblaje y carga fragmentos ubicados en:

```text
src/agfast_parts/
```

Los fragmentos separan responsabilidades sin cambiar todavía firmas de funciones ni convertir todo a objetos independientes.

#### Razón técnica

La separación se hace en dos pasos para reducir riesgo.

Primero se separa el monolito en fragmentos que conservan una sola unidad de traducción. Esto evita romper funciones `static`, orden de tipos y dependencias internas.

Después, en subpasos posteriores, cada fragmento podrá convertirse en módulo real con archivo `.h`, archivo `.c` y compilación independiente.

#### Fragmentos creados

```text
src/agfast_parts/common.c
src/agfast_parts/string_list.c
src/agfast_parts/sketches.c
src/agfast_parts/policy.c
src/agfast_parts/parser.c
src/agfast_parts/graph.c
src/agfast_parts/telemetry.c
src/agfast_parts/risk_reports.c
src/agfast_parts/commands.c
src/agfast_parts/main_cli.c
```

#### Responsabilidades

#### common.c

Contiene utilidades generales, constantes, includes, funciones de error, cadenas, hashing y escritura segura de JSON/HTML.

#### string_list.c

Contiene listas dinámicas de cadenas, inserción única, búsqueda exacta, búsqueda por patrón y liberación de memoria.

#### sketches.c

Contiene Bloom Filter, Cuckoo Filter, Count-Min Sketch, HyperLogLog, candidatos, Space-Saving y Odd Sketch.

#### policy.c

Contiene carga de política, pesos de riesgo y validaciones contra archivos sensibles, dominios, IPs y procesos observados.

#### parser.c

Contiene lectura de eventos JSONL y CSV.

#### graph.c

Contiene alertas, nodos de proceso, timeline, grafo de eventos y operaciones relacionadas.

#### telemetry.c

Contiene actualización de telemetría, conteos aproximados y estimación de memoria.

#### risk_reports.c

Contiene lógica de bloqueo de destinos, cálculo de riesgo, resúmenes, JSON, HTML y CSV.

#### commands.c

Contiene la ejecución de comandos como `analyze`, `stats`, `graph`, `timeline`, `check-file`, `check-ip`, `check-domain`, `similarity`, `tail` y `generate`.

#### main_cli.c

Contiene `print_usage` y `main`.

#### Validación obligatoria

Después de aplicar esta fase se debe ejecutar:

```bash
make clean
make
make test-fastpath
```

#### Alcance

Esta fase no cambia algoritmos.

Esta fase no agrega eBPF.

Esta fase no cambia la interfaz CLI.

Esta fase no mezcla cambios de higiene de la Fase 1.

#### Siguiente paso

El siguiente subpaso de Fase 2 debe extraer módulos reales en este orden:

```text
common.h y common.c
string_list.h y string_list.c
parser.h y parser.c
policy.h y policy.c
sketches/*.h y sketches/*.c
graph.h y graph.c
risk_engine.h y risk_engine.c
report_json.h y report_json.c
report_html.h y report_html.c
commands.h y commands.c
main_agfast.c
```
