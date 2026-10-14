### F0-04. Plan de cierre y control de evidencia

#### Estado de partida

- Rama: `research/f0-protocolo`.
- F0-01 se integró en `main` mediante el PR 19.
- F0-02 y F0-03 se encuentran en la rama de investigación.
- El catálogo dirigido contiene 15 estudios candidatos, 2 guías y 3 artefactos.
- La conciliación de las 9 referencias semilla está documentada.
- No constan en el repositorio exportaciones completas de las bases previstas.
- No constan decisiones humanas terminadas de lectura de texto completo.
- Estado de F0: `IN_PROGRESS`.

Este documento no constituye por sí mismo evidencia de una revisión completada.
No modificar las casillas PRISMA utilizando resultados supuestos.

#### Alcance del trabajo restante

El propósito de F0 es congelar un protocolo y una revisión bibliográfica verificable,
sin iniciar cambios del motor de análisis o experimentos con datasets.

El alcance vigente exige una revisión de alcance informada mediante PRISMA-ScR.
Si se decide sustituirla por una revisión estructurada más acotada, esa decisión
requiere una modificación explícita del protocolo, sus criterios de cierre y
las afirmaciones sobre exhaustividad. No reinterpretar silenciosamente los
criterios originales.

#### Gate 1. Recuperación bibliográfica

- [ ] Consultar las fuentes previstas y registrar las que no sean accesibles.
- [ ] Guardar las cadenas exactas y filtros aplicados por fuente.
- [ ] Conservar las exportaciones originales sin editarlas.
- [ ] Completar `F0_04_EXPORT_MANIFEST.csv` con conteos y SHA-256.
- [ ] Incorporar al registro de búsquedas el vínculo con cada exportación.
- [ ] Integrar los registros en un inventario común preservando el origen.
- [ ] Conciliar DOI, título, autores y versiones editoriales.
- [ ] Mantener un identificador para cada registro y otro para cada estudio.

Las exportaciones deben guardarse en `docs/research/exports/` solo si sus términos
de uso permiten distribuirlas. Cuando no sea posible versionarlas, registrar
su conservación fuera del repositorio y adaptar el procedimiento de verificación,
sin exponer datos privados ni afirmar reproducibilidad pública completa.

#### Gate 2. Selección, lectura y extracción

- [ ] Validar título y resumen de cada registro identificable.
- [ ] Guardar las exclusiones y su motivo.
- [ ] Resolver duplicados de versiones y documentar la decisión.
- [ ] Buscar los textos completos de los estudios candidatos.
- [ ] Completar `F0_04_FULLTEXT_LOG.csv`.
- [ ] Registrar un revisor humano identificable y la fecha de su decisión.
- [ ] Registrar segundo revisor o declarar de forma explícita su ausencia.
- [ ] Extraer el modelo de amenaza, datasets, etiquetas, baselines, métricas y límites.
- [ ] Completar la matriz de evidencia exclusivamente con contenido comprobado.

No equivale a lectura completa consultar únicamente el resumen editorial.
Las decisiones provisionales producidas por IA no son decisiones humanas aprobadas.

#### Gate 3. Síntesis, PRISMA y decisión científica

- [ ] Elaborar la matriz comparativa final de los estudios seleccionados.
- [ ] Actualizar `PRISMA_FLOW.md` a partir de conteos trazables.
- [ ] Verificar la conservación del número de registros a través del flujo.
- [ ] Comprobar que las guías y los artefactos no se confunden con estudios.
- [ ] Identificar el estado editorial de cada estudio y las distintas versiones.
- [ ] Establecer la brecha científica sin reclamar novedad no demostrada.
- [ ] Aprobar explícitamente preguntas, hipótesis y modelo de amenaza.
- [ ] Registrar el dictamen final en `F0_CONTROL.md` y el SHA de referencia.

#### Comprobación automatizada

Ejecutar en Git Bash:

```bash
python3 scripts/research/prisma_audit.py --check
python3 -m unittest discover -s scripts/research -p 'test_*.py' -v
python3 scripts/research/f0_closure_gate.py
```

La última orden informa `BLOQUEADO` mientras no existan las evidencias formales.
No modifica documentos ni archivos CSV. El código no realiza el trabajo
intelectual de cribado ni certifica la veracidad de las decisiones humanas.

#### Regla de cierre

- `F0 PASS`: los tres gates cuentan con evidencia revisada y validaciones satisfactorias.
- `F0 REQUIRES_CORRECTION`: existen discrepancias de trazabilidad o de método.
- `F0 BLOCKED`: faltan exportaciones, textos completos o decisiones verificadas.

F0 no pasa automáticamente por disponer de 15 artículos preseleccionados.

#### Pull Request y continuidad

Conservar los parches F0-02 y F0-03 en la rama `research/f0-protocolo`.
Comprobar en GitHub que existe un nuevo Draft PR abierto contra `main`.
No reutilizar el PR 19, que ya está fusionado.

No efectuar merge ni iniciar F1 con un estado de F0 presentado como `PASS`
si todavía hay pendientes científicos documentados.

#### Convenciones

Documentación, mensajes operativos, comentarios y commits en español.
Identificadores y firmas de código en inglés. Encabezados `###` y `####`,
sin guiones largos ni adornos tipográficos.
