### Modularización de common y string_list

#### Objetivo

Esta subfase convierte las utilidades comunes y la lista dinámica de cadenas en módulos reales de `agfast`.

La subfase parte de la modularización física inicial y promueve dos fragmentos a archivos compilables independientes.

#### Archivos agregados

```text
include/common.h
include/string_list.h
src/common.c
src/string_list.c
```

#### Archivos ajustados

```text
src/fastpath.c
Makefile
src/agfast_parts/risk_reports.c
src/agfast_parts/commands.c
src/agfast_parts/main_cli.c
```

#### Responsabilidad de common

`common` concentra constantes, utilidades generales, manejo de errores, copia segura de cadenas, normalización mínima, funciones de hashing y escritura escapada para JSON y HTML.

#### Responsabilidad de string_list

`string_list` concentra listas dinámicas de cadenas usadas por política, grafo, reportes y estructuras auxiliares.

#### Cambio de versión visible

Durante la Fase 2 se reemplazó una cadena final antigua por una versión de desarrollo temporal.

La aplicación usó en esa etapa:

```text
AgentGuard FastPath 0.2.0-dev
```

Ese valor correspondía a modularización en desarrollo. En el release `v1.0.0`, la versión visible se alinea con `AGF_VERSION = "1.0.0"`.

#### Criterio técnico

Esta subfase no cambia algoritmos.

Esta subfase no modifica la interfaz CLI.

Esta subfase no agrega eBPF.

Esta subfase no mezcla cambios de higiene de la Fase 1.

#### Validación obligatoria

```bash
make clean
make
make test-fastpath
```

#### Siguiente subfase

Después de validar `common` y `string_list`, el siguiente paso recomendado es extraer `parser` como módulo real:

```text
include/parser.h
src/parser.c
```

Ese cambio debe hacerse en otra subfase para mantener commits pequeños y auditables.

<!-- release-v1-modularizacion:start -->
### Nota histórica sobre versión

#### Contexto

Durante la Fase 2, `agfast` se identificó temporalmente como:

```text
AgentGuard FastPath 0.2.0-dev
```

Ese valor fue correcto para la etapa de modularización mínima segura.

#### Release actual

En el release `v1.0.0`, la versión visible debe coincidir con:

```c
#define AGF_VERSION "1.0.0"
```

Esto alinea consola, reportes JSON, reportes HTML y documentación de release.
<!-- release-v1-modularizacion:end -->
