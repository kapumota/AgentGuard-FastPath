### CI/CD visible

#### Objetivo

La Fase 9.2 agrega validación automática con GitHub Actions.

El objetivo es que cada push y cada pull request ejecuten compilación, pruebas y evaluación mínima antes de fusionar cambios a `main`.

#### Archivo principal

```text
.github/workflows/ci.yml
```

#### Eventos del workflow

El workflow se ejecuta en:

- push a `main`;
- push a ramas `fase-*`;
- pull request hacia `main`;
- ejecución manual con `workflow_dispatch`;
- ejecución programada semanal.

#### Job principal

El job principal ejecuta:

```bash
make clean
make
make test-fastpath
make test-regression
make test-streaming
make test-guardsketch
make test-unit
bash scripts/run_evaluation.sh
make clean
```

#### Evaluación en CI

La evaluación experimental usa un dataset reducido para evitar tiempos excesivos en GitHub Actions.

Variables usadas:

```text
AGFAST_EVAL_EVENTS=10000
AGFAST_EVAL_PIDS=300
AGFAST_EVAL_DIR=/tmp/agfast_ci_evaluacion
```

Esto mantiene el flujo reproducible sin generar archivos pesados dentro del repositorio.

#### Job opcional de Valgrind

Valgrind se ejecuta en un job separado.

Ese job corre solo en:

- ejecución manual;
- ejecución programada semanal.

Motivo:

- Valgrind puede ser más lento;
- no debe bloquear cada push pequeño;
- sigue disponible para validación profunda.

Comando ejecutado:

```bash
make test-valgrind
```

#### Badge en README

El README incluye un badge de estado:

```text
CI
```

Ese badge permite verificar rápidamente si el proyecto compila y pasa pruebas.

#### Criterio de aceptación

La Fase 9.2 se considera correcta si:

- GitHub Actions aparece en la pestaña Actions;
- el workflow `CI` se ejecuta en PR;
- el job principal pasa;
- el badge aparece en README;
- Valgrind queda disponible como validación manual o programada;
- la ruta normal del proyecto no cambia.

#### Alcance

Esta fase no modifica código fuente.

Esta fase no modifica pruebas existentes.

Esta fase no agrega dependencias runtime al proyecto.

Esta fase solo agrega automatización de calidad.

### Workflows separados

#### AGFast Quality

El workflow principal de calidad es:

```text
.github/workflows/agfast-quality.yml
```

Este workflow se ejecuta en:

- push a `main`;
- pull request hacia `main`;
- ejecución manual.

No se ejecuta por push directo a ramas `fase-*` para evitar duplicados cuando ya existe un pull request abierto.

#### Valgrind

Valgrind se mueve a un workflow separado:

```text
.github/workflows/valgrind.yml
```

Este workflow se ejecuta en:

- ejecución manual;
- ejecución programada semanal.

No se ejecuta en cada pull request porque puede ser más lento que las pruebas principales.

#### Motivo del cambio

Separar Valgrind evita que GitHub muestre jobs omitidos en cada pull request.

También mantiene el PR más limpio visualmente y conserva una validación de memoria disponible para revisión profunda.

#### Resultado esperado

En un pull request normal deben aparecer checks exitosos del flujo principal.

El workflow de Valgrind queda disponible desde la pestaña Actions para ejecución manual.
