### Preparación eBPF

#### Objetivo

Esta carpeta prepara el proyecto para una integración eBPF futura.

En esta fase no se compila ni se carga ningún programa eBPF.

#### Alcance

La Fase 7 solo agrega:

- estructura inicial `ebpf/`;
- chequeo opcional de herramientas;
- documentación de dependencias;
- integración no invasiva con `Makefile`.

#### Regla principal

La compilación normal debe seguir funcionando sin eBPF.

Estos comandos no deben requerir headers del kernel ni herramientas eBPF:

```bash
make clean
make
make test-fastpath
make test-regression
make test-streaming
```

#### Chequeo opcional

```bash
make ebpf-check
```

El chequeo informa si existen herramientas como:

- `clang`;
- `llvm-strip`;
- `bpftool`;
- `pkg-config`;
- `libbpf`;
- headers del kernel.

#### Dependencias futuras

En Ubuntu o Debian, una instalación posible es:

```bash
sudo apt update
sudo apt install -y clang llvm bpftool libbpf-dev linux-headers-$(uname -r) pkg-config
```

#### Qué no hace esta fase

Esta fase no agrega:

- probes eBPF;
- loader con libbpf;
- ring buffer;
- mapas eBPF;
- GuardSketch;
- captura real de syscalls.

#### Siguiente paso técnico

Una fase posterior puede agregar una captura mínima con eventos como:

```text
execve
openat
connect
```

Esa fase debe seguir manteniendo eBPF como componente opcional.
