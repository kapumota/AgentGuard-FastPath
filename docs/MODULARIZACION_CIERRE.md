### Cierre de modularización mínima segura

#### Objetivo

Esta fase cierra la modularización mínima segura de `agfast`.

El objetivo no es extraer todos los módulos reales, sino dejar una separación física útil, verificable y mantenible sin romper el comportamiento actual.

#### Alcance

Se mantiene `src/fastpath.c` como punto de ensamblaje.

Se mantiene `src/agfast_parts/` separado por responsabilidades.

Se conserva la interfaz CLI actual.

No se agregan nuevas funcionalidades de detección.

No se introduce eBPF.

No se crea una arquitectura nueva de headers y objetos independientes.

#### Estado esperado

La estructura esperada es:

```text
src/fastpath.c
src/agfast_parts/
```

Si `common` y `string_list` ya fueron extraídos como módulos reales, también pueden existir:

```text
include/common.h
include/string_list.h
src/common.c
src/string_list.c
```

#### Corrección de versión

Se elimina el texto de versión final antigua.

La versión de desarrollo queda como:

```text
AgentGuard FastPath 0.2.0-dev
```

Esto evita presentar la fase de modularización como una versión final.

#### Criterio técnico

Esta fase es intencionalmente conservadora.

La modularización profunda queda para una versión posterior, cuando existan más pruebas de regresión y calidad automática.

#### Validación obligatoria

```bash
make clean
make
make test-fastpath
```

#### Siguiente fase

La siguiente fase recomendada es:

```text
Fase 3 - Pruebas de regresión y calidad automática
```

Antes de seguir separando módulos internos, el proyecto debe contar con pruebas suficientes para proteger el comportamiento actual.
