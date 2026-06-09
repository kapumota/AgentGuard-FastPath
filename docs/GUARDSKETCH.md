### GuardSketch MVP en userspace

#### Objetivo

La Fase 8 valida GuardSketch en userspace antes de pensar en una implementación eBPF.

El objetivo es reducir riesgo técnico: si el diseño no preserva el ranking de riesgo en userspace, no debe llevarse al kernel todavía.

#### Alcance

Esta fase agrega un prototipo mínimo en:

```text
src/agfast_parts/guardsketch.c
```

El prototipo incluye:

- Bloom por PID;
- Count-Min Sketch pequeño;
- contador de drops simulado;
- ventana corta;
- comparación entre riesgo exacto y riesgo aproximado;
- prueba autocontenida.

#### Qué no hace esta fase

Esta fase no agrega:

- eBPF;
- loader de `libbpf`;
- ring buffer;
- mapas eBPF;
- integración con el CLI principal;
- HyperLogLog;
- paralelismo;
- lock-free.

#### Por qué userspace primero

Userspace permite validar el modelo sin depender de:

- versión del kernel;
- headers del kernel;
- verifier de eBPF;
- privilegios elevados;
- herramientas como `bpftool` o `libbpf`.

#### Modelo del MVP

El MVP usa una ventana corta.

Cuando la ventana se llena, los eventos adicionales incrementan un contador de drops.

Esto simula una situación futura de presión sobre buffers o mapas.

#### Señales del MVP

El prototipo considera señales simples:

```text
evento general
archivo sensible
destino bloqueado
red después de archivo sensible
```

#### Riesgo exacto

El riesgo exacto usa contadores directos por PID.

#### Riesgo aproximado

El riesgo aproximado usa Count-Min Sketch para estimar señales por PID.

La propiedad esperada del Count-Min Sketch es que puede sobreestimar por colisiones.

Para seguridad, una sobreestimación puede generar ruido, pero es menos peligrosa que una subestimación sistemática.

#### Bloom por PID

El Bloom Filter marca PIDs observados.

Puede producir falsos positivos, pero no debería producir falsos negativos para PIDs insertados.

#### Drops simulados

El contador de drops representa presión de ventana.

En una integración futura con eBPF, un contador similar permitiría detectar pérdida de observabilidad.

#### Prueba agregada

```text
tests/test_guardsketch.sh
```

#### Comando

```bash
make test-guardsketch
```

#### Validación completa

```bash
make clean
make
make test-fastpath
make test-regression
make test-streaming
make test-guardsketch
make clean
```

#### Criterio de aceptación

La fase se considera correcta si:

- el prototipo compila de forma autocontenida;
- Bloom reconoce un PID observado;
- el contador de drops aumenta bajo presión de ventana;
- el riesgo aproximado no subestima el caso principal de prueba;
- existe top overlap entre ranking exacto y aproximado;
- no se rompe la compilación normal de `agfast`.

#### Siguiente paso

Una fase posterior puede integrar GuardSketch al flujo real de `agfast` o preparar una versión eBPF.

Eso debe hacerse solo después de validar que el MVP userspace es estable.
