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
