### Soporte eBPF opcional

#### Objetivo

La Fase 7 prepara AgentGuard FastPath para una integración eBPF futura sin romper la ruta normal de compilación.

El objetivo no es capturar eventos del kernel todavía, sino dejar documentado y verificable el entorno necesario.

#### Principio central

eBPF debe ser opcional.

La herramienta principal `agfast` debe compilar y ejecutarse sin eBPF.

#### Ruta normal

La ruta normal del proyecto sigue siendo userspace:

```bash
make clean
make
make test-fastpath
make test-regression
make test-streaming
```

Estos comandos no deben depender de:

- headers del kernel;
- `clang`;
- `bpftool`;
- `libbpf`;
- privilegios elevados.

#### Ruta eBPF futura

La ruta eBPF futura puede requerir herramientas adicionales.

Dependencias documentadas:

```text
kernel 5.10+
clang
llvm
bpftool
libbpf-dev
linux-headers
pkg-config
```

#### Instalación sugerida en Ubuntu o Debian

```bash
sudo apt update
sudo apt install -y clang llvm bpftool libbpf-dev linux-headers-$(uname -r) pkg-config
```

#### Chequeo de entorno

La Fase 7 agrega:

```bash
make ebpf-check
```

Este target ejecuta:

```bash
ebpf/check_ebpf_env.sh
```

El chequeo no debe fallar si faltan dependencias.

Debe informar el estado del entorno y terminar correctamente.

#### Salida esperada si faltan dependencias

```text
Entorno eBPF incompleto.
Esto no afecta la compilacion normal de agfast.
```

#### Salida esperada si el entorno está listo

```text
Entorno eBPF listo para una fase futura.
```

#### Por qué no compilar eBPF todavía

No se compila eBPF en esta fase por razones de estabilidad.

Motivos:

- eBPF depende del kernel;
- los headers deben coincidir con el kernel activo;
- el verifier impone restricciones estrictas;
- `libbpf` y `bpftool` pueden variar por distribución;
- una integración prematura puede romper CI o entornos sin privilegios.

#### Criterio de diseño

La Fase 7 prepara, pero no obliga.

El proyecto debe mantener dos rutas:

```text
ruta normal: agfast userspace
ruta futura: eBPF opcional
```

#### Eventos candidatos para una fase posterior

La primera captura eBPF real debería ser mínima.

Eventos sugeridos:

```text
execve
openat
connect
```

#### Qué queda fuera de esta fase

Esta fase no agrega:

- código `.bpf.c`;
- loader eBPF;
- ring buffer;
- mapas eBPF;
- GuardSketch en kernel;
- reglas de riesgo nuevas;
- cambios en `src/`.

#### Validación de Fase 7

```bash
make clean
make
make test-fastpath
make test-regression
make test-streaming
make ebpf-check
make clean
```

#### Criterio de aceptación

La Fase 7 es correcta si:

- `make` sigue compilando sin herramientas eBPF;
- `make ebpf-check` informa el estado del entorno;
- no se rompe ninguna prueba anterior;
- no se agrega GuardSketch;
- no se exige eBPF para la ruta normal.
