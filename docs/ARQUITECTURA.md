### Arquitectura de AgentGuard-FastPath

#### Proposito

AgentGuard-FastPath es una herramienta defensiva escrita en C para analizar eventos de seguridad relacionados con procesos, archivos y conexiones de red.

El componente principal es `agfast`, una CLI que procesa eventos en formato JSONL o CSV, aplica una politica de seguridad y genera reportes de riesgo.

#### Componentes principales

#### agfast

`agfast` analiza eventos ya registrados. Recibe archivos de entrada, aplica una politica y calcula informacion util para investigacion defensiva.

Responsabilidades principales:

- leer eventos JSONL o CSV;
- cargar reglas desde una politica JSON;
- detectar accesos a archivos sensibles;
- detectar procesos observados;
- detectar destinos de red observados;
- construir relaciones entre procesos, archivos y red;
- calcular puntajes de riesgo;
- generar reportes JSON, HTML y CSV.

#### agentguard

`agentguard` es un componente Linux orientado al monitoreo de procesos. En esta fase se mantiene como parte del proyecto, pero la higiene inicial se concentra en dejar reproducible el flujo principal de `agfast`.

#### Estructura del repositorio

```text
examples/
include/
scripts/
src/
tests/
.github/workflows/
Makefile
README.md
docs/
```

#### Flujo general

```text
eventos JSONL o CSV
    |
    v
agfast
    |
    v
politica de seguridad
    |
    v
analisis de riesgo
    |
    v
reportes JSON, HTML y CSV
```

#### Artefactos generados

Durante la compilacion y ejecucion pueden generarse binarios, objetos y reportes locales. Estos artefactos no deben versionarse.

Ejemplos:

- `bin/`
- `obj/`
- `report.json`
- `report.html`
- `alerts.csv`
- `stats.json`
- `graph.json`
- `timeline.json`
- `similarity.json`

#### Criterio de higiene

El repositorio debe conservar solo codigo fuente, pruebas, ejemplos, documentacion y configuracion necesaria para reproducir el proyecto.

No deben subirse binarios, objetos compilados, reportes locales ni archivos temporales.
