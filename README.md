### AgentGuard-C + AgentGuard FastPath

AgentGuard FastPath es un software de análisis de eventos de seguridad diseñado para procesar telemetría de sistemas, aplicaciones o entornos Linux a partir de archivos en formato JSONL o CSV. Su objetivo principal es transformar grandes volúmenes de eventos en información útil para detección, investigación y priorización de comportamientos potencialmente sospechosos.

El sistema analiza eventos relacionados con procesos, archivos, direcciones IP, dominios y acciones observadas, como aperturas de archivos, conexiones de red o ejecución de procesos. A partir de esa información, construye métricas, alertas, relaciones proceso–archivo–red, líneas de tiempo y puntajes de riesgo que ayudan a entender qué ocurrió, qué entidad estuvo involucrada y qué tan relevante puede ser desde una perspectiva de seguridad.

A diferencia de una herramienta que solo enumera logs, AgentGuard FastPath aplica estructuras de datos avanzadas y técnicas de análisis eficiente para resumir telemetría, detectar patrones frecuentes, estimar cardinalidades, verificar coincidencias contra listas de vigilancia y correlacionar eventos entre sí.

#### Propósito del sistema

El propósito de AgentGuard FastPath es facilitar el análisis de eventos de seguridad en escenarios donde existe una gran cantidad de datos y se necesita extraer señales relevantes de forma rápida y con bajo consumo de memoria.

En un entorno real, los sistemas pueden generar miles o millones de eventos: procesos que acceden a archivos, servicios que se conectan a direcciones externas, comandos que se ejecutan repetidamente, rutas sensibles que son consultadas, dominios sospechosos que aparecen en conexiones salientes o procesos que presentan comportamientos poco comunes.

AgentGuard FastPath permite analizar ese flujo de eventos y responder preguntas como: qué procesos tuvieron mayor actividad, cuántos destinos únicos fueron contactados, qué archivos sensibles fueron accedidos, qué procesos se comunicaron con IPs o dominios bloqueados, qué comportamiento siguió un proceso después de acceder a información sensible y qué procesos deben priorizarse por su nivel de riesgo.

#### Funcionamiento técnico

El sistema trabaja como una herramienta de línea de comandos. Recibe eventos en JSONL o CSV, carga una política de seguridad desde un archivo `policy.json` y ejecuta un pipeline de análisis compuesto por varias etapas.

Primero, el parser interpreta cada evento y normaliza sus campos principales: tiempo, PID, nombre del proceso, tipo de evento, archivo, destino de red, dominio e IP. Luego, el motor de políticas compara esos eventos contra listas de vigilancia, como archivos sensibles, IPs bloqueadas, dominios bloqueados o procesos observados.

Después, el sistema alimenta varias estructuras probabilísticas. Bloom Filter y Cuckoo Filter se utilizan para consultas rápidas de pertenencia, Count-Min Sketch estima frecuencias, HyperLogLog estima cantidades únicas y Space-Saving o Misra-Gries ayudan a identificar elementos dominantes dentro del flujo de eventos. Estas estructuras permiten obtener resultados útiles sin guardar todo de forma exacta, reduciendo el consumo de memoria cuando el volumen de datos crece.

En paralelo, AgentGuard FastPath construye relaciones entre procesos, archivos y destinos de red. Esta capa permite pasar de eventos aislados a una representación correlacionada del comportamiento. Por ejemplo, puede identificar que un proceso abrió un archivo sensible y posteriormente estableció una conexión hacia una IP bloqueada. Esa relación es mucho más informativa que observar ambos eventos por separado.

Finalmente, el motor de riesgo asigna un puntaje por proceso o PID. Este puntaje se calcula a partir de indicadores configurables, como acceso a archivos sensibles, contacto con IPs bloqueadas, uso de procesos vigilados, volumen elevado de eventos o conexiones de red posteriores a accesos críticos.

#### Estructuras de datos utilizadas

AgentGuard FastPath incorpora varias estructuras de datos diseñadas para trabajar eficientemente con flujos grandes de información.

- **Bloom Filter** se utiliza para verificar rápidamente si un archivo, proceso, dominio o IP puede pertenecer a una lista de vigilancia. Su ventaja es que permite consultas muy rápidas usando poca memoria, aunque puede producir falsos positivos. Por eso, en casos críticos, el sistema puede complementar esta verificación con listas exactas.
- **Cuckoo Filter** cumple una función similar, pero agrega la posibilidad de eliminar elementos. Esto resulta útil para escenarios donde las listas cambian con el tiempo, por ejemplo IPs bloqueadas temporalmente o indicadores de compromiso que expiran.
- **Count-Min Sketch** permite estimar frecuencias sin mantener un contador exacto para cada elemento. Esto es útil para saber qué procesos, archivos, destinos o tipos de eventos aparecen con mayor frecuencia, incluso cuando el número de elementos distintos es grande.
- **HyperLogLog** permite estimar cardinalidades, como número de procesos únicos, archivos únicos o destinos únicos contactados. En vez de guardar todos los elementos observados, mantiene una representación compacta que permite aproximar cuántos elementos diferentes aparecieron en el flujo.
- **Space-Saving** y **Misra-Gries** se utilizan para identificar heavy hitters, es decir, elementos dominantes dentro de la telemetría. Esto permite resaltar procesos, rutas, dominios o eventos que concentran una parte importante de la actividad.

La comparación de comportamiento mediante similitud aproximada permite analizar qué tan parecido es el comportamiento de dos procesos. Esto puede utilizarse para comparar procesos normales contra procesos sospechosos, o para detectar desviaciones entre patrones de actividad.

##### Análisis de riesgo

Una de las funciones centrales del producto es el cálculo de puntajes de riesgo. El sistema no se limita a producir alertas individuales, sino que asigna una puntuación acumulada a cada proceso o PID observado.

Por ejemplo, un proceso puede recibir puntos de riesgo por acceder a un archivo sensible, contactar una IP bloqueada, comunicarse con un dominio observado, generar una cantidad elevada de eventos o conectarse a red después de haber leído información crítica. El resultado es un puntaje entre 0 y 100, acompañado de un nivel como bajo, medio, alto o crítico.

Este enfoque permite priorizar la investigación. En vez de revisar cientos de eventos en orden cronológico, el usuario puede concentrarse primero en los procesos con mayor riesgo y revisar las razones específicas que elevaron su puntuación.

Los pesos del modelo de riesgo pueden configurarse en el archivo de política. Esto permite adaptar el comportamiento del producto a distintos entornos, por ejemplo servidores, estaciones de trabajo, laboratorios, contenedores o sistemas con reglas de seguridad específicas.

##### Relaciones proceso–archivo–red

AgentGuard FastPath construye una vista relacional de la actividad observada. Esta vista permite conectar entidades de distintos tipos: procesos, archivos, IPs y dominios.

Por ejemplo, el sistema puede representar que `python[123]` abrió `/etc/passwd`, accedió a `/home/user/.ssh/id_rsa` y luego se conectó a `45.90.10.2`. Esta correlación es valiosa porque permite detectar secuencias que podrían indicar exfiltración, reconocimiento, abuso de credenciales o actividad anómala.

El grafo proceso–archivo–red permite consultar un PID o proceso específico y ver qué archivos tocó, a qué destinos se conectó, qué eventos generó y qué nivel de riesgo alcanzó. Esto convierte la telemetría cruda en una explicación estructurada del comportamiento.

##### Línea de tiempo de eventos

El producto también puede generar líneas de tiempo por proceso. Esta capacidad es importante porque en seguridad el orden de los eventos cambia la interpretación.

No es lo mismo observar que un proceso se conectó a internet y en otro momento leyó un archivo sensible, que confirmar que primero accedió al archivo sensible y después abrió una conexión hacia una IP bloqueada. La línea de tiempo permite reconstruir esa secuencia.

Con esta información, el usuario puede entender mejor el flujo de actividad de un proceso: cuándo comenzó, qué archivos tocó, en qué momento se conectó a red, si interactuó con destinos sospechosos y qué eventos provocaron el aumento del riesgo.

#### Reportes y salidas

AgentGuard FastPath genera salidas en varios formatos para distintos usos.

La salida en consola permite revisar resultados rápidamente durante la ejecución. El reporte JSON permite integrar el análisis con otros sistemas, pipelines o herramientas externas. El reporte HTML ofrece una vista visual y estática con resumen del análisis, métricas, procesos de mayor riesgo, alertas principales, comparación de memoria y timeline. El CSV de alertas permite abrir los resultados en herramientas como Excel, LibreOffice, sistemas SIEM o plataformas de análisis de datos.

Esta variedad de salidas permite usar el producto tanto en análisis manual como en flujos automatizados.

#### Generación de datos y benchmarking

El sistema incluye generación de datasets sintéticos para producir eventos normales y sospechosos en distintos volúmenes. Esto permite probar el comportamiento del producto con miles o millones de eventos sin depender de fuentes externas.

También incluye benchmarks para medir tiempo de procesamiento, comportamiento con JSONL y CSV, y comparación entre memoria exacta estimada y memoria usada por estructuras probabilísticas. Esta capacidad es útil para evaluar escalabilidad y demostrar por qué las estructuras compactas son adecuadas para telemetría masiva.


Proyecto en C con dos componentes:

- `agentguard`: monitor  basado en `ptrace` para observar procesos Linux.
- `agfast`: software CLI de análisis de eventos de seguridad en JSONL/CSV.

La parte principal para la entrega es **AgentGuard FastPath**, un analizador de telemetría que usa estructuras probabilísticas de bajo consumo de memoria para detectar frecuencias, cardinalidades, coincidencias con listas de vigilancia, relaciones proceso-archivo-red, puntajes de riesgo y líneas de tiempo.

#### Funcionalidades principales de `agfast`

- Entrada en formato JSONL y CSV.
- Archivo de políticas `policy.json`.
- Bloom Filter para listas de vigilancia.
- Cuckoo Filter demostrable con prueba de borrado.
- Count-Min Sketch para frecuencias aproximadas.
- HyperLogLog para cardinalidades aproximadas.
- Space-Saving / Misra-Gries para heavy hitters.
- Mini grafo proceso -> archivo -> red.
- Puntaje de riesgo configurable por PID/proceso.
- Timeline por PID/proceso.
- Ventanas deslizantes con `--window-events`.
- Similitud de comportamiento por proceso con Jaccard/Odd Sketch.
- Reportes JSON, HTML y CSV de alertas.
- Generación de datasets sintéticos.
- Benchmark con 10k, 100k y 1M eventos.
- Modo incremental `tail`.

#### Requisitos

Linux con:

```bash
gcc
make
openssl/libssl-dev
python3
```

En Debian/Ubuntu:

```bash
sudo apt update
sudo apt install build-essential libssl-dev python3
```

#### Compilación

```bash
make
```

Genera:

```bash
./bin/agentguard
./bin/agfast
```

Para limpiar artefactos:

```bash
make clean
```

#### Demostración rápida

```bash
./bin/agfast analyze examples/events.jsonl \
  --policy examples/policy.json \
  --risk \
  --window-events 3 \
  --report report.json \
  --html report.html \
  --alerts-csv alerts.csv
```

También se puede ver en HTML

```bash

./bin/agfast analyze examples/events.jsonl \
  --policy examples/policy.json \
  --risk \
  --html report.html \
  --report report.json \
  --alerts-csv alerts.csv
```

Luego ábrelo así:

```bash
xdg-open report.html
```

En WSL puedes usar:

```bash
explorer.exe report.html
```

En macOS:

```bash
open report.html
```

En Windows PowerShell:

```bash
start report.html
```

El HTML muestra resumen del análisis, cardinalidades estimadas, comparación de memoria, procesos de mayor riesgo, alertas principales y timeline del proceso más riesgoso.

El programa puede devolver código `2` cuando encuentra alertas. Eso es intencional para integrarlo en scripts o pipelines.

#### Comandos principales

##### Análisis con política

```bash
./bin/agfast analyze examples/events.jsonl --policy examples/policy.json --risk
```

##### Estadísticas sin política

```bash
./bin/agfast stats examples/events_day2.jsonl --report stats.json
```

##### Consulta de grafo

```bash
./bin/agfast graph examples/events_day3.jsonl --policy examples/policy.json --pid 123 --timeline
./bin/agfast graph examples/events_day3.jsonl --policy examples/policy.json --process python
```

##### Timeline

```bash
./bin/agfast timeline examples/events_day3.jsonl --policy examples/policy.json --pid 123
```

##### Verificación contra listas de vigilancia

```bash
./bin/agfast check-file /etc/passwd --policy examples/policy.json
./bin/agfast check-ip 45.90.10.2 --policy examples/policy.json --delete-test
./bin/agfast check-domain malicious.example --policy examples/policy.json
```

##### Similitud entre procesos

```bash
./bin/agfast similarity examples/events_day3.jsonl \
  --process python \
  --compare-process bash \
  --policy examples/policy.json \
  --report similarity.json
```

###### Generación de datasets sintéticos

```bash
./bin/agfast generate --events 100000 --output /tmp/events.jsonl --malicious-ratio 0.05
./bin/agfast generate --events 100000 --format csv --output /tmp/events.csv --malicious-ratio 0.05
```

##### Modo incremental

```bash
./bin/agfast tail examples/events.jsonl --policy examples/policy.json
./bin/agfast tail logs/events.jsonl --policy examples/policy.json --follow
```

#### Formato de eventos

##### JSONL

Cada línea es un evento:

```json
{"time":"2026-05-23T10:00:01Z","pid":123,"process":"python","event":"open","file":"/etc/passwd"}
{"time":"2026-05-23T10:00:02Z","pid":123,"process":"python","event":"connect","dst":"45.90.10.2"}
```

Campos soportados:

- `time`
- `pid`
- `process`
- `event`
- `file`
- `dst`
- `domain`
- `ip`

##### CSV

```csv
time,pid,process,event,file,dst,domain,ip
2026-05-23T10:00:01Z,123,python,open,/etc/passwd,,,
2026-05-23T10:00:02Z,123,python,connect,,45.90.10.2,,45.90.10.2
```

#### Formato de política

Ejemplo mínimo:

```json
{
  "sensitive_files": ["/etc/passwd", "/etc/shadow", "/home/*/.ssh/*"],
  "blocked_domains": ["malicious.example"],
  "blocked_ips": ["45.90.10.2"],
  "watched_processes": ["python", "curl", "bash"],
  "risk_weights": {
    "watched_process": 10,
    "sensitive_file": 25,
    "blocked_ip": 35,
    "blocked_domain": 35,
    "network_after_file": 30,
    "high_unique_destinations": 15,
    "high_event_volume": 10,
    "high_unique_destination_threshold": 10,
    "high_event_volume_threshold": 100
  }
}
```

##### Salidas generadas

`agfast` puede producir:

- Reporte en consola.
- Reporte JSON con métricas, riesgo, memoria y alertas.
- Reporte HTML estático.
- CSV de alertas.

Ejemplo:

```bash
./bin/agfast analyze examples/events.jsonl \
  --policy examples/policy.json \
  --risk \
  --report report.json \
  --html report.html \
  --alerts-csv alerts.csv
```

#### Uso con nuevas entradas del usuario

Un usuario puede analizar sus propios eventos sin modificar el código fuente. Solo necesita preparar un archivo de eventos en JSONL o CSV y una política `policy.json`.

##### 1. Crear eventos propios en JSONL

Crear un archivo, por ejemplo `mis_eventos.jsonl`:

```json
{"time":"2026-05-23T11:00:01Z","pid":501,"process":"python","event":"open","file":"/etc/passwd"}
{"time":"2026-05-23T11:00:04Z","pid":501,"process":"python","event":"connect","dst":"45.90.10.2","ip":"45.90.10.2"}
{"time":"2026-05-23T11:00:07Z","pid":710,"process":"nginx","event":"open","file":"/var/log/nginx/access.log"}
```

Ejecutar análisis:

```bash
./bin/agfast analyze mis_eventos.jsonl \
  --policy mi_policy.json \
  --risk \
  --report mi_reporte.json \
  --html mi_reporte.html \
  --alerts-csv mis_alertas.csv
```

##### 2. Crear eventos propios en CSV

Crear un archivo, por ejemplo `mis_eventos.csv`:

```csv
time,pid,process,event,file,dst,domain,ip
2026-05-23T11:00:01Z,501,python,open,/etc/passwd,,,
2026-05-23T11:00:04Z,501,python,connect,,45.90.10.2,,45.90.10.2
2026-05-23T11:00:07Z,710,nginx,open,/var/log/nginx/access.log,,,
```

Ejecutar análisis:

```bash
./bin/agfast analyze mis_eventos.csv \
  --policy mi_policy.json \
  --risk \
  --report mi_reporte_csv.json \
  --html mi_reporte_csv.html \
  --alerts-csv mis_alertas_csv.csv
```

##### 3. Crear una política propia

Crear un archivo `mi_policy.json`:

```json
{
  "sensitive_files": ["/etc/passwd", "/etc/shadow", "/home/*/.ssh/*"],
  "blocked_domains": ["malicious.example"],
  "blocked_ips": ["45.90.10.2"],
  "watched_processes": ["python", "curl", "bash"],
  "risk_weights": {
    "watched_process": 10,
    "sensitive_file": 25,
    "blocked_ip": 35,
    "blocked_domain": 35,
    "network_after_file": 30,
    "high_unique_destinations": 15,
    "high_event_volume": 10,
    "high_unique_destination_threshold": 10,
    "high_event_volume_threshold": 100
  }
}
```

##### 4. Consultar resultados específicos

Consultar el grafo de un PID:

```bash
./bin/agfast graph mis_eventos.jsonl --policy mi_policy.json --pid 501 --timeline
```

Consultar la línea de tiempo de un proceso:

```bash
./bin/agfast timeline mis_eventos.jsonl --policy mi_policy.json --pid 501
```

Verificar entradas individuales contra la política:

```bash
./bin/agfast check-file /etc/passwd --policy mi_policy.json
./bin/agfast check-ip 45.90.10.2 --policy mi_policy.json
./bin/agfast check-domain malicious.example --policy mi_policy.json
```

##### 5. Generar datos nuevos para pruebas

Generar un dataset JSONL:

```bash
./bin/agfast generate --events 100000 --output /tmp/mis_eventos_generados.jsonl --malicious-ratio 0.05
```

Generar un dataset CSV:

```bash
./bin/agfast generate --events 100000 --format csv --output /tmp/mis_eventos_generados.csv --malicious-ratio 0.05
```

##### 6. Limpiar el proyecto antes de entregar o subir

Eliminar artefactos de compilación:

```bash
make clean
```

Eliminar reportes generados localmente:

```bash
rm -f report.json report.html alerts.csv
rm -f mi_reporte*.json mi_reporte*.html mis_alertas*.csv
rm -f stats*.json graph*.json similarity*.json check-*.json
```


#### Pruebas y benchmark

Pruebas completas:

```bash
make test-fastpath
```

Pruebas por grupo:

```bash
make test
make test-algorithms
make test-reports
```

Benchmark JSONL:

```bash
make benchmark
```

Benchmark CSV:

```bash
make benchmark-csv
```

Los benchmarks generan datos temporales en `/tmp/agfast_bench`.

#### Estructura del proyecto

```text
.
├── Makefile
├── README.md
├── examples/
│   ├── events.jsonl
│   ├── events.csv
│   ├── events_day2.jsonl
│   ├── events_day3.jsonl
│   └── policy.json
├── include/
│   └── *.h
├── scripts/
│   ├── benchmark_fastpath.sh
│   └── generate_events.py
├── src/
│   ├── fastpath.c
│   └── *.c
└── tests/
    ├── test_agent.c
    └── test_fastpath_final.sh
```


#### Casos de uso

AgentGuard FastPath puede utilizarse para análisis de logs de seguridad, revisión de actividad de procesos, investigación de accesos a archivos sensibles, detección de conexiones hacia destinos observados, priorización de procesos por riesgo, comparación de comportamiento entre procesos y generación de reportes para revisión técnica.

También puede servir como motor de análisis dentro de un flujo más amplio de seguridad. Por ejemplo, otro sistema puede recolectar eventos desde endpoints, contenedores o servidores, y AgentGuard FastPath puede procesarlos para generar métricas, alertas y reportes.

En entornos donde se desea evaluar grandes volúmenes de telemetría sin desplegar una plataforma pesada, el producto puede actuar como una herramienta ligera de análisis batch o incremental.

#### Alcance actual

El producto está orientado al análisis de eventos ya disponibles o ingresados de forma incremental. No actúa como un EDR completo ni reemplaza una plataforma de monitoreo en tiempo real a nivel de kernel. Tampoco bloquea procesos reales por sí mismo.

Su valor principal está en el procesamiento eficiente de telemetría, la correlación de eventos, la estimación de métricas con estructuras probabilísticas, la priorización mediante puntaje de riesgo y la generación de reportes interpretables.

AgentGuard FastPath funciona como una herramienta profesional de análisis de telemetría de seguridad, orientada a transformar eventos sin procesar en información accionable para investigación, priorización y detección de comportamiento sospechoso.

#### Limitaciones

- Es un analizador offline/batch e incremental básico; no es un EDR completo.
- No bloquea procesos reales.
- No usa eBPF ni CUDA.
- El parser JSON/CSV es ligero y adecuado, no reemplaza una biblioteca JSON robusta.
- Las estructuras probabilísticas pueden producir aproximaciones o falsos positivos; las decisiones críticas se confirman contra listas exactas cuando aplica.


#### Licencia

MIT, para uso académico y de investigación.
