### Uso de AgentGuard-FastPath

#### Requisitos

Se recomienda usar Linux con herramientas basicas de compilacion instaladas.

Dependencias habituales:

```bash
sudo apt update
sudo apt install -y build-essential make gcc
```

#### Compilacion

Desde la raiz del repositorio:

```bash
make clean
make
```

El proceso genera binarios en:

```text
bin/
```

#### Pruebas

Para ejecutar las pruebas principales:

```bash
make test-fastpath
```

#### Ejecucion basica

Ejemplo de analisis con eventos y politica:

```bash
./bin/agfast analyze examples/events.jsonl \
  --policy examples/policy.json \
  --risk \
  --report report.json \
  --html report.html \
  --alerts-csv alerts.csv
```

#### Limpieza

Para eliminar artefactos de compilacion y reportes locales:

```bash
make clean
```

Para eliminar solo reportes locales, si el objetivo existe en el `Makefile`:

```bash
make clean-reports
```

#### Archivos que no deben versionarse

No se deben subir al repositorio:

- binarios;
- objetos compilados;
- reportes generados;
- archivos temporales;
- caches locales;
- salidas de experimentos no curadas.

#### Flujo recomendado por fase

Cada mejora importante debe trabajarse en una rama propia.

Ejemplo:

```bash
git checkout main
git pull origin main
git checkout -b fase-1-higiene-repositorio
```

Luego se validan los cambios:

```bash
make clean
make
make test-fastpath
make clean
```

Despues se realiza el commit:

```bash
git add .gitignore Makefile README.md docs
git commit -m "fase 1: ordena repositorio y documenta uso reproducible"
git push -u origin fase-1-higiene-repositorio
```
