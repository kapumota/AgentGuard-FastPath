### Instalación

#### Requisitos base

En Ubuntu o Debian:

```bash
sudo apt update
sudo apt install -y build-essential make python3
```

Si se usan validaciones adicionales:

```bash
sudo apt install -y valgrind
```

Para preparación eBPF opcional:

```bash
sudo apt install -y clang llvm bpftool libbpf-dev linux-headers-$(uname -r) pkg-config
```

#### Compilación

Desde la raíz del repositorio:

```bash
make clean
make
```

El binario principal queda en:

```text
bin/agfast
```

#### Pruebas principales

```bash
make test-fastpath
make test-regression
make test-streaming
make test-guardsketch
make test-unit
```

#### Evaluación experimental

```bash
bash scripts/run_evaluation.sh
```

Para una ejecución reducida:

```bash
AGFAST_EVAL_EVENTS=10000 AGFAST_EVAL_PIDS=300 bash scripts/run_evaluation.sh
```

#### Benchmarks

```bash
bash benchmarks/run_benchmark.sh
```

#### Limpieza

```bash
make clean
```

#### Validación completa recomendada

```bash
make clean
make
make test-fastpath
make test-regression
make test-streaming
make test-guardsketch
make test-unit
bash benchmarks/run_benchmark.sh
AGFAST_EVAL_EVENTS=10000 AGFAST_EVAL_PIDS=300 bash scripts/run_evaluation.sh
make clean
```

#### Problemas comunes

Si `make test-valgrind` indica que Valgrind no está instalado, se puede instalar con:

```bash
sudo apt install -y valgrind
```

Si `make ebpf-check` indica que falta `libbpf`, eso no afecta la compilación normal de `agfast`.

eBPF es opcional en `v1.0.0`.
