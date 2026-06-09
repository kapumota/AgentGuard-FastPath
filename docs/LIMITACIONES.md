### Limitaciones técnicas

<!-- fase6:start -->
### Limitaciones técnicas

#### Propósito

Este documento registra limitaciones conocidas de AgentGuard FastPath.

Declarar limitaciones fortalece el proyecto porque evita prometer capacidades que aún no existen.

#### No es un EDR completo

AgentGuard FastPath no debe presentarse como un EDR completo.

No incluye todavía:

- agente residente endurecido;
- respuesta automática;
- aislamiento de procesos;
- integración completa con kernel;
- control centralizado;
- políticas empresariales;
- retención histórica distribuida.

#### No es un SIEM completo

El proyecto no reemplaza un SIEM.

No incluye todavía:

- ingesta distribuida;
- almacenamiento a largo plazo;
- correlación multi-host;
- consultas históricas complejas;
- dashboards operativos;
- integración con múltiples fuentes externas.

#### Dependencia de eventos de entrada

La calidad del análisis depende de los eventos disponibles.

Si un evento no está en el archivo JSONL o CSV, el motor no puede inferirlo de forma confiable.

#### Riesgo por reglas simples

El scoring de riesgo usa reglas e indicadores relativamente directos.

Esto es apropiado para una primera versión, pero no cubre todos los patrones avanzados de ataque.

#### Falsos positivos

Los falsos positivos pueden aparecer por:

- procesos benignos ruidosos;
- rutas sensibles accedidas por mantenimiento;
- dominios internos parecidos a indicadores bloqueados;
- sobreestimación de Count-Min Sketch;
- falsos positivos de Bloom Filter;
- umbrales demasiado bajos.

#### Falsos negativos

Los falsos negativos pueden aparecer si:

- faltan eventos;
- la política no contiene indicadores relevantes;
- el atacante usa rutas o dominios no bloqueados;
- el comportamiento malicioso es de bajo volumen;
- el flujo de eventos se corta;
- se pierden eventos en una futura ruta streaming real.

#### Limitaciones de Count-Min Sketch

Count-Min Sketch puede sobreestimar frecuencias por colisiones.

Esto puede elevar el score de procesos benignos ruidosos.

Por eso no basta medir memoria: se debe medir ranking de riesgo.

#### Limitaciones de HyperLogLog

HyperLogLog aproxima cardinalidades.

Puede afectar señales como destinos únicos por proceso.

El error es aceptable solo si no cambia de forma excesiva los niveles de riesgo.

#### Limitaciones de Bloom Filter

Bloom Filter no produce falsos negativos si se usa correctamente, pero puede producir falsos positivos.

En seguridad esto puede ser tolerable si se usa como filtro inicial y no como decisión final única.

#### Limitaciones de streaming actual

El modo `tail` actual fortalece análisis incremental, pero todavía no es una canalización de streaming de producción.

Limitaciones:

- no hay backpressure real;
- no hay control avanzado de rotación de logs;
- no hay persistencia de offsets;
- no hay control distribuido;
- `--follow` requiere validación cuidadosa para automatización.

#### Por qué no usar eBPF todavía

No se introduce eBPF en esta fase porque eBPF aumenta la complejidad técnica.

Riesgos de eBPF:

- dependencia de versión de kernel;
- necesidad de headers;
- necesidad de `clang`, `llvm`, `bpftool` y `libbpf`;
- restricciones del verifier;
- límites de stack;
- restricciones sobre loops;
- dificultad para depurar.

#### Criterio para avanzar a eBPF

Antes de eBPF deben estar estables:

- pruebas de regresión;
- benchmarks;
- simulaciones de ranking;
- documentación técnica;
- límites del modelo;
- comportamiento de streaming.

#### Limitación de evaluación

Los datasets sintéticos ayudan a medir comportamiento, pero no sustituyen datasets reales con ground truth.

Una fase futura debería evaluar:

- ataques controlados en VM;
- datasets etiquetados;
- comparación con baselines externos si el alcance lo permite.

#### Conclusión

Las limitaciones actuales son aceptables para una primera versión avanzada si están documentadas y si el proyecto no se presenta como una solución de producción completa.
<!-- fase6:end -->
