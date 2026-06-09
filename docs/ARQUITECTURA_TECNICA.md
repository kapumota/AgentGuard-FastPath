### Arquitectura técnica

<!-- fase6:start -->
### Arquitectura técnica de AgentGuard FastPath

#### Propósito

AgentGuard FastPath es una herramienta defensiva escrita en C para analizar eventos de procesos, archivos y red.

La arquitectura actual prioriza una ruta userspace reproducible antes de avanzar hacia captura eBPF.

#### Vista general

```text
eventos JSONL o CSV
        |
        v
parser de eventos
        |
        v
policy de seguridad
        |
        v
telemetría y sketches
        |
        v
grafo proceso-archivo-red
        |
        v
motor de riesgo
        |
        v
reportes JSON, HTML, CSV y consola
```

#### Entrada

El sistema acepta eventos en JSONL o CSV.

Cada evento puede incluir:

- tiempo;
- PID;
- nombre de proceso;
- tipo de evento;
- archivo;
- destino;
- dominio;
- IP.

#### Política

La política define elementos que deben tratarse como relevantes para riesgo.

Ejemplos:

- archivos sensibles;
- dominios bloqueados;
- IPs bloqueadas;
- procesos observados;
- pesos de riesgo;
- umbrales.

#### Telemetría

La telemetría resume el flujo de eventos.

Incluye estructuras exactas y aproximadas.

Estructuras relevantes:

- Bloom Filter;
- Cuckoo Filter;
- Count-Min Sketch;
- HyperLogLog;
- Space-Saving;
- Odd Sketch.

#### Grafo de comportamiento

El grafo relaciona procesos con archivos y destinos.

El objetivo no es construir un grafo de provenance completo, sino capturar relaciones útiles para priorizar riesgo.

Ejemplos:

```text
PID 501 abre /etc/passwd
PID 501 conecta a 45.90.10.2
PID 501 recibe riesgo por network-after-file
```

#### Motor de riesgo

El motor de riesgo combina señales simples para producir score por proceso.

Señales principales:

- proceso observado;
- archivo sensible;
- IP bloqueada;
- dominio bloqueado;
- red después de archivo;
- alto número de destinos únicos;
- alto volumen de eventos.

#### Reportes

El sistema puede generar:

- salida por consola;
- reporte JSON;
- reporte HTML;
- CSV de alertas;
- timeline;
- consulta de grafo;
- estadísticas.

#### Modo batch

El modo batch analiza un archivo completo.

Es útil para:

- pruebas;
- benchmarks;
- evaluación reproducible;
- análisis post-mortem.

#### Modo tail

El modo `tail` analiza eventos de forma incremental.

Es útil para simular una operación más cercana a streaming, aunque todavía no reemplaza un agente de producción.

#### Por qué userspace primero

La ruta userspace permite:

- reproducibilidad;
- pruebas simples;
- ejecución sin privilegios;
- benchmarks controlados;
- depuración directa;
- portabilidad.

#### Por qué eBPF queda después

eBPF será útil para captura real de eventos del kernel, pero debe llegar después de tener:

- pruebas de regresión;
- benchmarks;
- teoría mínima;
- documentación de limitaciones;
- criterios de aceptación.

#### Estado de madurez

El proyecto no debe presentarse como EDR completo.

Una descripción correcta es:

```text
analizador defensivo avanzado para telemetría JSONL/CSV con estructuras probabilísticas, scoring de riesgo y evaluación reproducible
```
<!-- fase6:end -->
