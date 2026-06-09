### Tests unitarios en C con Unity

#### Objetivo

La Fase 9.1 agrega pruebas unitarias reales en C para fortalecer la base interna de AgentGuard FastPath antes del release `v1.0.0`.

Hasta esta fase, el proyecto ya cuenta con pruebas de integración, regresión, streaming, GuardSketch y evaluación experimental.

Esta fase agrega una capa más pequeña y controlada para validar propiedades internas.

#### Por qué Unity

Unity se usa porque:

- es liviano;
- puede versionarse en `third_party/`;
- no requiere instalación del sistema;
- funciona bien con C puro;
- es apropiado para CI;
- permite probar invariantes simples sin depender de servicios externos.

#### Estructura agregada

```text
third_party/unity/
tests/unit/
tests/unit/test_probabilistic.c
tests/unit/test_graph_model.c
tests/unit/test_risk_helpers.c
```

#### Target agregado

```bash
make test-unit
```

#### Pruebas probabilísticas

El archivo `tests/unit/test_probabilistic.c` valida modelos unitarios para:

- Bloom Filter;
- Count-Min Sketch;
- HyperLogLog;
- Space-Saving;
- Odd Sketch.

Propiedades cubiertas:

- un elemento insertado en Bloom debe encontrarse;
- Bloom no debe producir falsos negativos para elementos insertados;
- Count-Min Sketch no debe subestimar frecuencias insertadas;
- claves distintas deben seguir siendo consultables;
- HyperLogLog para conjunto vacío debe estimar cerca de cero;
- elementos repetidos no deben crecer como cardinalidad única;
- Space-Saving debe conservar elementos frecuentes;
- Odd Sketch debe dar más coincidencia para entradas similares.

#### Pruebas de grafo

El archivo `tests/unit/test_graph_model.c` valida un modelo pequeño de grafo.

Propiedades cubiertas:

- insertar nodo de proceso;
- insertar relación proceso-archivo;
- insertar relación proceso-destino;
- rechazar arista si falta un nodo;
- consultar PID inexistente;
- respetar límite de recorrido.

#### Pruebas de riesgo

El archivo `tests/unit/test_risk_helpers.c` valida helpers pequeños para scoring.

Propiedades cubiertas:

- score cero sin señales;
- score alto con archivo sensible y destino bloqueado;
- score máximo limitado a 100;
- niveles de riesgo;
- incremento por destinos únicos.

#### Alcance

Esta fase no modifica `src/`.

Esta fase no cambia el CLI.

Esta fase no cambia el motor de detección.

Esta fase no agrega dependencias del sistema.

Esta fase no integra todavía los tests con una biblioteca interna porque el proyecto aún conserva una arquitectura de binario principal.

#### Limitación honesta

Estos tests son unitarios autocontenidos y validan invariantes de diseño.

Una fase posterior puede conectar estos tests directamente a una biblioteca `libagfast` cuando el motor se separe formalmente del CLI.

#### Validación completa

```bash
make clean
make
make test-fastpath
make test-regression
make test-streaming
make test-guardsketch
make test-unit
make clean
```

#### Criterio de aceptación

La fase se considera correcta si:

- `make test-unit` compila y ejecuta las tres suites;
- no se requiere instalar Unity;
- no se rompe ninguna prueba previa;
- no se modifica el código fuente de producción.
