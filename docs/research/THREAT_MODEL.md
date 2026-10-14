### F0. Modelo de amenaza para robustez adversarial

#### Activos protegidos

Se busca preservar la utilidad de la priorización de riesgo de procesos y la trazabilidad de evidencias a partir de eventos observados. El sistema es un analizador defensivo experimental, no un EDR ni un mecanismo de prevención.

#### Capacidades separadas del adversario

- `T0`, actividad benigna normal: carga de referencia sin adversario.
- `T1`, actor con capacidad de generar actividad de proceso, archivo y red permitida por el escenario, sin controlar directamente el archivo de auditoría.
- `T2`, actor informado que conoce reglas y algoritmos públicos, pero no necesariamente claves secretas de hashing, si existen.
- `T3`, actor con conocimiento completo del estado del sketch. Se estudiará únicamente si se declara y construye un escenario white-box específico.

No asumir que `T2` desconoce el código publicado. No prometer resistencia a `T3` mediante semillas supuestamente secretas. No incluir manipulación arbitraria de logs dentro de `T1`.

#### Perturbaciones autorizadas para evaluación

- `A1`, actividad adicional que diluye o desplaza señales en el ranking.
- `A2`, colisiones entre claves cuando el CMS es compartido entre entidades, no cuando hay tablas independientes por PID.
- `A3`, pérdidas, retrasos o reordenamientos realizados sobre una copia de eventos, distinguiendo fallos de sensor de acciones del atacante.
- `A4`, secuencias de baja frecuencia que conservan sus acciones y etiquetas esenciales.

Todas las transformaciones deben conservar IDs, origen, semillas, conjunto modificado y un manifiesto que permita reproducirlas. Documentar explícitamente qué relaciones semánticas permanecen válidas.

#### Modelo defensivo propuesto

- Evidencia crítica y relaciones temporales verificadas de forma exacta cuando hay información suficiente.
- CMS compartido únicamente para medidas de frecuencia y selección auxiliar de candidatos.
- Verificación exacta selectiva, acompañada de una medición de cobertura de candidatos.
- Registro de eventos desconocidos, descartados, retrasados y de condiciones de saturación conocidas.
- Evaluación de conservative update y hashing con claves como mitigaciones parciales, no garantías generales de seguridad.

#### Riesgos específicos del código actual

- El scoring exacto reside en `risk_reports.c` y GuardSketch no es aún una ruta equivalente al CLI principal.
- La condición `network_after_file` actual no valida directamente el orden temporal que su nombre sugiere.
- El prototipo GuardSketch contiene CMS por ranura de PID y límites estáticos de capacidad y ventana.
- Un contador de drops del prototipo no representa mediciones de pérdida real de un sensor.

F1 comprobará estos riesgos con pruebas. F3 decidirá los contratos e invariantes del rediseño.

#### Fuera de alcance

- Desarrollo o ejecución de malware real.
- Alteración directa de logs de terceros.
- Compromiso del host privilegiado, bypass de kernel o captura eBPF completa.
- Respuesta automática o aislamiento de procesos.
- Garantías criptográficas formales no demostradas por el código y el threat model.

#### Criterio de evaluación adversarial

Comparar degradación de ranking y calidad de detección con el mismo ground truth y recursos comparables. Registrar condiciones en que una defensa aumenta falsos positivos, pierde candidatos o necesita más memoria. Conservar y publicar resultados negativos.
