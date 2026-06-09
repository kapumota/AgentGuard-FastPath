### Teoría mínima de estructuras probabilísticas

#### Objetivo

Este documento resume las garantías mínimas necesarias para interpretar los resultados de Fase 4.

No reemplaza una prueba formal completa. Su propósito es documentar qué se mide y por qué es relevante para seguridad defensiva.

#### Bloom Filter

Un Bloom Filter permite consultar pertenencia con bajo costo de memoria.

Puede producir falsos positivos, pero no falsos negativos si no hay eliminaciones.

La tasa aproximada de falsos positivos es:

```text
epsilon = (1 - exp(-k n / m))^k
```

Donde:

```text
n = elementos insertados
m = bits disponibles
k = funciones hash
```

#### Count-Min Sketch

Count-Min Sketch estima frecuencias.

Su error principal es la sobreestimación por colisiones.

Para AgentGuard FastPath, el interés no es solo el error individual de una frecuencia. La pregunta más importante es si el ranking de elementos frecuentes se conserva de forma suficiente para priorizar investigación.

#### HyperLogLog

HyperLogLog estima cardinalidades únicas con memoria fija.

El error esperado depende del número de registros.

La aproximación usual es:

```text
error relativo aproximado = 1.04 / sqrt(m)
```

Donde `m` es el número de registros.

#### Space-Saving

Space-Saving permite mantener candidatos frecuentes con memoria acotada.

Su utilidad principal es identificar elementos dominantes sin conservar todos los eventos exactos.

#### Ranking de riesgo

En seguridad defensiva, una aproximación es útil si conserva decisiones.

Por eso Fase 4 mide:

```text
top-5 overlap
top-10 overlap
correlación de ranking
```

La pregunta central es:

```text
Los mismos procesos aparecen entre los más importantes al comparar conteo exacto contra estimaciones aproximadas.
```

#### Límite de esta fase

La Fase 4 valida comportamiento en userspace.

No valida todavía eBPF.

No valida todavía GuardSketch en kernel.

Esa validación queda para fases posteriores.

<!-- fase6:start -->
### Teoría mínima para evaluación avanzada

#### Propósito

Esta sección resume los fundamentos técnicos que permiten defender AgentGuard FastPath como un analizador basado en estructuras probabilísticas.

El objetivo no es convertir el proyecto en un paper completo, sino dejar explícitos los supuestos, los límites y las métricas que justifican las fases de benchmark y evaluación.

#### Modelo de eventos

AgentGuard FastPath procesa eventos de seguridad en formato JSONL o CSV.

Cada evento puede describir:

- proceso;
- PID;
- tipo de evento;
- archivo;
- destino de red;
- dominio;
- IP;
- tiempo.

El motor de análisis combina esos eventos con una política de seguridad para producir riesgo por proceso.

#### Riesgo exacto

El riesgo exacto se calcula usando conteos y conjuntos observados sin compresión probabilística.

Ejemplos de señales exactas:

- si un proceso observado aparece en la política;
- si un proceso abrió un archivo sensible;
- si un proceso contactó una IP bloqueada;
- si un proceso contactó un dominio bloqueado;
- si hubo conexión de red después de acceder a un archivo sensible;
- si un PID supera un umbral de destinos únicos;
- si un PID supera un umbral de volumen de eventos.

#### Riesgo aproximado

El riesgo aproximado reemplaza algunas estructuras exactas por sketches.

Ejemplos:

- Count-Min Sketch para frecuencias;
- Bloom Filter para pertenencia;
- HyperLogLog para cardinalidad aproximada;
- Space-Saving para elementos frecuentes;
- Odd Sketch para similitud aproximada.

La pregunta principal no es solo cuánto error matemático existe, sino si el ranking de PIDs riesgosos se conserva.

#### Memoria acotada

Una estructura exacta puede crecer con el número de eventos, archivos, procesos o destinos observados.

Un sketch usa memoria acotada por parámetros configurados.

Ejemplos:

```text
Bloom Filter: O(m)
Count-Min Sketch: O(d * w)
HyperLogLog: O(2^p)
Space-Saving: O(k)
```

Donde:

- `m` es el número de bits del Bloom Filter;
- `d` es la profundidad del Count-Min Sketch;
- `w` es el ancho del Count-Min Sketch;
- `p` es la precisión de HyperLogLog;
- `k` es el número de elementos frecuentes retenidos.

#### Falsos positivos de Bloom Filter

Bloom Filter puede decir que un elemento tal vez pertenece al conjunto aunque no pertenezca.

No produce falsos negativos si se usa correctamente.

La probabilidad aproximada de falso positivo es:

```text
p = (1 - exp(-k * n / m))^k
```

Donde:

- `n` es el número de elementos insertados;
- `m` es el número de bits;
- `k` es el número de funciones hash.

En AgentGuard FastPath esto afecta principalmente consultas de pertenencia contra listas o ventanas observadas.

#### Sobreestimación de Count-Min Sketch

Count-Min Sketch estima frecuencias.

Su propiedad principal es que tiende a sobreestimar, no a subestimar, cuando hay colisiones.

Esto es útil para seguridad porque una sobreestimación puede generar ruido, pero una subestimación sistemática podría ocultar actividad.

Riesgo principal:

```text
procesos benignos ruidosos pueden recibir score aproximado mayor
```

Por eso Fase 4 mide top-k overlap y correlación de ranking.

#### Error de HyperLogLog

HyperLogLog estima cardinalidad de elementos únicos.

En AgentGuard FastPath se usa conceptualmente para señales como destinos únicos por proceso.

Error esperado aproximado:

```text
error relativo aproximado = 1.04 / sqrt(m)
```

donde `m = 2^p`.

Con `p = 14`, se obtiene una cantidad grande de registros y un error relativo esperado bajo para estimaciones de cardinalidad.

#### Ranking de riesgo

La métrica central del proyecto es el ranking de procesos riesgosos.

Un sketch es aceptable si conserva suficientemente:

- top-5 de PIDs riesgosos;
- top-10 de PIDs riesgosos;
- top-25 de PIDs riesgosos;
- niveles de riesgo;
- alertas críticas principales.

Una configuración de sketch no se considera buena solo por ahorrar memoria.

Debe preservar decisiones útiles.

#### Comparación exacto vs aproximado

La comparación debe responder:

```text
¿Los mismos PIDs aparecen como prioritarios?
```

Métricas recomendadas:

- top-k overlap;
- correlación top-k;
- cambios de nivel de riesgo;
- falsos positivos esperados;
- error promedio y p95 de HLL;
- tiempo de ejecución;
- memoria estimada.

#### Criterio para no usar eBPF todavía

eBPF no debe introducirse antes de consolidar:

- pruebas de regresión;
- benchmarks reproducibles;
- teoría mínima;
- limitaciones explícitas;
- validación de ranking exacto vs aproximado.

Motivo:

- eBPF agrega dependencias de kernel;
- eBPF puede fallar por restricciones del verifier;
- eBPF complica depuración;
- eBPF no debe usarse para ocultar debilidades del modelo de riesgo.

#### Conclusión

La teoría mínima justifica que AgentGuard FastPath use sketches solo si estos preservan señales relevantes para seguridad.

La prioridad del proyecto es conservar decisiones defensivas, no solo reducir memoria.
<!-- fase6:end -->
