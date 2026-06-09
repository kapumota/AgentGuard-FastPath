### Streaming robusto

#### Objetivo

La Fase 5 fortalece el modo incremental `tail` de AgentGuard FastPath.

El objetivo es que el modo `tail` sea más defendible como función operativa y no solo como una demostración básica.

#### Alcance

Esta fase agrega pruebas reproducibles para:

- lectura incremental sin `--follow`;
- archivo base con eventos válidos;
- archivo que crece por anexado de eventos;
- líneas corruptas que no deben detener el análisis;
- archivo vacío;
- uso de `--window-events`;
- emisión de alertas críticas cuando existe correlación de riesgo.

#### Por qué no se prueba `--follow` en CI

El modo `--follow` mantiene el proceso esperando nuevos eventos.

Eso es útil en operación real, pero puede bloquear una prueba automatizada si no se controla con tiempos, señales y procesos en segundo plano.

Por eso, esta fase prueba de forma reproducible el comportamiento de `tail` sin `--follow`.

La validación manual de `--follow` queda documentada para uso local.

#### Fixtures agregados

```text
tests/fixtures/stream_base.jsonl
tests/fixtures/stream_append.jsonl
```

#### Prueba agregada

```text
tests/test_streaming.sh
```

#### Comando principal

```bash
make test-streaming
```

#### Validación completa

```bash
make clean
make
make test-fastpath
make test-regression
make test-streaming
make clean
```

#### Comportamiento esperado

El archivo base contiene tres eventos válidos y una línea corrupta.

El modo `tail` debe procesar tres eventos válidos y no debe fallar por la línea corrupta.

La salida esperada debe incluir:

```text
Eventos procesados en tail: 3
```

Después de anexar nuevos eventos, el archivo contiene seis eventos válidos.

La salida esperada debe incluir:

```text
Eventos procesados en tail: 6
```

Para un archivo vacío o un archivo solo corrupto, la salida esperada debe incluir:

```text
Eventos procesados en tail: 0
```

#### Validación manual con follow

Para validar `--follow` manualmente se puede usar dos terminales.

Terminal 1:

```bash
cp tests/fixtures/stream_base.jsonl /tmp/agfast_stream.jsonl
./bin/agfast tail /tmp/agfast_stream.jsonl --policy examples/policy.json --follow
```

Terminal 2:

```bash
cat tests/fixtures/stream_append.jsonl >> /tmp/agfast_stream.jsonl
```

El proceso del primer terminal debe observar nuevos eventos cuando el archivo crece.

#### Criterio de aceptación

La Fase 5 se considera correcta si pasan:

```bash
make test-fastpath
make test-regression
make test-streaming
```

Esta fase no modifica el motor de detección.

Esta fase no agrega eBPF.

Esta fase no agrega GuardSketch.

Esta fase solo mejora la cobertura operativa del modo `tail`.
