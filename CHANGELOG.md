### Changelog

#### v1.0.0 - Primera versión presentable

Esta versión consolida AgentGuard FastPath como una herramienta defensiva experimental en C para analizar telemetría JSONL/CSV, aplicar políticas de seguridad, calcular riesgo, generar reportes y evaluar estructuras probabilísticas.

#### Cambios principales

- Higiene profesional del repositorio.
- Documentación de arquitectura, uso, decisiones técnicas y roadmap.
- Modularización mínima segura de `agfast`.
- Pruebas de regresión.
- Pruebas de streaming.
- Pruebas unitarias en C con Unity.
- Benchmarks y validación de sketches.
- Evaluación experimental reproducible.
- GuardSketch MVP en userspace.
- Preparación eBPF opcional.
- CI/CD visible con GitHub Actions.
- Documentación de instalación, uso avanzado y release.

#### Capacidades consolidadas

- Análisis de eventos JSONL y CSV.
- Política configurable.
- Reportes JSON, HTML y CSV.
- Estadísticas de telemetría.
- Timeline.
- Grafo proceso-archivo-red.
- Modo incremental `tail`.
- Bloom Filter.
- Count-Min Sketch.
- HyperLogLog.
- Space-Saving.
- Odd Sketch.
- GuardSketch userspace.
- Evaluación reproducible.

#### Limitaciones conocidas

- No es un EDR completo.
- No es un SIEM completo.
- eBPF está preparado como ruta opcional, pero no implementa captura real en esta versión.
- GuardSketch todavía no está integrado al kernel.
- La evaluación experimental usa datasets sintéticos reproducibles.
- Los tests unitarios de Fase 9.1 validan invariantes autocontenidos, no una biblioteca `libagfast` separada.

#### Tags relacionados

- `v0.1.1`: higiene inicial del repositorio.
- `v0.2.0`: modularización mínima segura.
- `v0.3.0`: pruebas de regresión y calidad básica.
- `v0.4.0`: benchmarks y validación de sketches.
- `v0.5.0`: streaming robusto.
- `v0.6.0`: teoría mínima y documentación técnica.
- `v0.7.0`: preparación eBPF opcional.
- `v0.8.0`: GuardSketch MVP userspace.
- `v0.9.0`: evaluación experimental reproducible.
- `v0.9.1`: tests unitarios en C con Unity.
- `v0.9.2`: CI de pruebas y calidad.
- `v1.0.1`: primera versión presentable.

<!-- release-v1-consistency-changelog:start -->
### Corrección de consistencia de release

#### v1.0.0

Se alinea la versión visible de `agfast` con el release `v1.0.1`.

Cambios:

- `include/common.h` usa `AGF_VERSION = "1.0.0"`;
- README enfoca el release actual;
- CI queda documentado por workflow;
- uso avanzado corrige ejemplos con argumentos completos;
- roadmap incorpora Fase 9.1, Fase 9.2 y Fase 10;
- documentos de modularización quedan como historial.
<!-- release-v1-consistency-changelog:end -->

### v1.0.1 - Corrección de consistencia post-release

#### Correcciones

- Se alinea la versión visible de `agfast` con el patch release `v1.0.1`.
- Se conserva `v1.0.0` como primer release histórico publicado.
- Se corrige documentación de release.
- Se corrige documentación de CI.
- Se corrigen ejemplos de uso avanzado.
- Se actualiza roadmap con Fase 9.1, Fase 9.2 y Fase 10.
- Se agregan documentos de seguridad y contribución.
- Se agrega `docs/HISTORIAL_FASES.md`.

#### Motivo

El release `v1.0.0` ya estaba publicado, pero `agfast --version` todavía mostraba una versión de desarrollo o una versión anterior. Esta versión corrige esa inconsistencia.
