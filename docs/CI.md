
### CI/CD visible

#### Objetivo

La validación automática del proyecto se divide en tres workflows.

Esto evita mezclar seguridad, calidad del release y validación profunda de memoria en un solo flujo.

#### Workflow base

Archivo:

```text
.github/workflows/ci.yml
```

Propósito:

- compilación base;
- prueba rápida `make test-fastpath`;
- benchmark básico si está disponible;
- validación de memoria básica si está configurada;
- CodeQL;
- Semgrep.

#### Workflow principal de calidad del release

Archivo:

```text
.github/workflows/agfast-quality.yml
```

Propósito:

- compilar `agfast`;
- ejecutar pruebas de regresión;
- ejecutar pruebas de streaming;
- ejecutar pruebas de GuardSketch;
- ejecutar tests unitarios en C con Unity;
- ejecutar evaluación experimental reducida.

Comandos principales:

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

#### Workflow de Valgrind

Archivo:

```text
.github/workflows/valgrind.yml
```

Propósito:

- ejecutar validación de memoria de forma manual o programada;
- evitar jobs omitidos en cada pull request;
- mantener una ruta de revisión profunda cuando se necesite.

Eventos:

- `workflow_dispatch`;
- `schedule` semanal.

#### Criterio de aceptación

Para aceptar un cambio previo al release:

- CI base debe pasar;
- AGFast Quality debe pasar;
- no debe haber cambios sin commit;
- la evaluación experimental reducida debe generar resumen;
- Valgrind debe quedar disponible para ejecución manual o semanal.
