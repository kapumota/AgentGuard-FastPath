### Roadmap de AgentGuard-FastPath

#### Objetivo general

El objetivo del proyecto es evolucionar AgentGuard-FastPath desde una herramienta funcional de analisis de eventos hacia una plataforma experimental mas solida para telemetria defensiva, analisis aproximado y evaluacion reproducible.

#### Fase 1 - Higiene profesional del repositorio

Objetivo:

- dejar el proyecto limpio;
- mejorar `.gitignore`;
- documentar compilacion, prueba y limpieza;
- separar documentacion tecnica en `docs/`;
- evitar versionar binarios y reportes generados.

Estado esperado:

- `make clean` elimina artefactos locales;
- `make` compila correctamente;
- `make test-fastpath` pasa correctamente;
- el repositorio queda listo para ramas posteriores.

#### Fase 2 - Modularizacion de agfast

Objetivo:

- separar parser, politica, riesgo, reportes, timeline, grafo y sketches;
- reducir concentracion de logica en un solo archivo;
- preparar el proyecto para futuras integraciones.

Posibles modulos:

```text
parser
policy
risk_engine
report_json
report_html
graph
timeline
sketches
```

#### Fase 3 - Pruebas de regresion

Objetivo:

- agregar fixtures estables;
- separar pruebas por parser, politica, riesgo y reportes;
- evitar regresiones al modificar el nucleo del analizador.

#### Fase 4 - Benchmarks reproducibles

Objetivo:

- medir tiempo de ejecucion;
- medir memoria;
- comparar estructuras exactas contra sketches probabilisticos;
- documentar resultados.

#### Fase 5 - Streaming y modo tail robusto

Objetivo:

- mejorar el analisis incremental;
- soportar ventanas de eventos;
- producir alertas periodicas;
- tolerar entradas parcialmente corruptas.

#### Fase 6 - Captura Linux experimental

Objetivo:

- evaluar una capa de captura de eventos del sistema;
- mantener `agfast` como motor de analisis;
- evitar acoplar prematuramente captura y analisis.

#### Fase 7 - GuardSketch experimental

Objetivo:

- explorar sketches probabilisticos para telemetria defensiva;
- reducir memoria en flujos grandes;
- comparar precision contra una linea base exacta.

#### Fase 8 - Evaluacion tecnica

Objetivo:

- medir throughput;
- medir latencia;
- medir memoria;
- medir error aproximado;
- documentar limitaciones.

#### Fase 9 - Release estable

Objetivo:

- preparar `CHANGELOG.md`;
- revisar documentacion;
- crear tag;
- crear GitHub Release;
- dejar el proyecto presentable y reproducible.

#### Estrategia de ramas

Cada fase debe usar una rama dedicada.

Ejemplo:

```text
fase-1-higiene-repositorio
fase-2-modularizacion-agfast
fase-3-pruebas-regresion
fase-4-benchmark-memoria
```
