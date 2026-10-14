### F0. Protocolo de revisión de alcance PRISMA-ScR

#### Estado y naturaleza

Estado: `PROTOCOL_DRAFT`, pendiente de ejecución documental y aprobación. Fecha de corte inicial: 2026-10-13. La actualización prospectiva durante 2027 deberá conservar por separado fecha, estrategia y resultados.

Se adopta PRISMA-ScR para informar una revisión de alcance sobre métodos heterogéneos y los principios de trazabilidad de PRISMA 2020. No se anunciará una revisión sistemática completada ni un metaanálisis sin haber efectuado selección, evaluación y síntesis verificables.

Fuentes metodológicas:

- Tricco et al., 2018, PRISMA-ScR, https://doi.org/10.7326/M18-0850
- Page et al., 2021, PRISMA 2020, https://doi.org/10.1136/bmj.n71

#### Objetivo y criterios PCC

- Población o evidencia: sistemas y trazas de auditoría de hosts con eventos de procesos, archivos, red o procedencia.
- Concepto: priorización de riesgo, aproximación de streaming, robustez frente a manipulación de eventos y limitaciones de observación.
- Contexto: detección o investigación defensiva en sistemas, bajo límites de memoria, latencia y disponibilidad de etiquetas.

Pregunta de alcance: ¿qué métodos y evaluaciones permiten caracterizar la fidelidad y la robustez de la priorización de riesgo de hosts ante datos adversariales, pérdidas de eventos y presupuestos limitados de recursos?

#### Periodo y fuentes

- Periodo principal: 2010 a 2026-10-13, con excepciones documentadas para contribuciones fundacionales previas.
- Fuentes primarias previstas: Scopus, Web of Science, IEEE Xplore, ACM Digital Library y DBLP.
- Fuentes complementarias: SciSpace, arXiv, editoriales, referencias hacia atrás y hacia adelante, documentación oficial de artefactos.
- Preprints y repositorios se registrarán separadamente de artículos revisados por pares.
- El acceso a cada base puede variar. Cualquier fuente no consultada debe marcarse como pendiente, no como resultado vacío.

#### Estrategias de búsqueda iniciales

Cadena A, seguridad de hosts:

```text
("host intrusion detection" OR "provenance-based intrusion detection"
 OR "system audit logs" OR "host telemetry")
AND
(adversarial OR evasion OR mimicry OR robust* OR "event loss")
```

Cadena B, estructuras aproximadas:

```text
("count-min sketch" OR "heavy hitters" OR "streaming algorithms"
 OR "approximate counting")
AND
(adversarial OR collision OR "conservative update"
 OR "memory budget" OR security)
```

Cadena C, evaluación y procedencia:

```text
("provenance graph" OR "host intrusion detection" OR "audit logs")
AND
(dataset OR benchmark OR "ground truth" OR reproducibility
 OR "false positives")
```

Cada consulta se adaptará y conservará literalmente según la sintaxis de la base. Se registrarán fecha, filtros, número de resultados, archivo exportado y checksum en `SEARCH_LOG.csv`. Las consultas exploratorias previas no sustituyen estas exportaciones.

#### Criterios de inclusión

- Publicación dentro del periodo principal o trabajo fundacional justificado.
- Estudio con contenido técnico verificable sobre una de las tres cadenas temáticas.
- Descripción de métodos, modelos adversariales, baselines, datasets o evaluación relevante para el problema.
- Información suficiente para relacionar la contribución con AgentGuard o con el diseño experimental.

#### Criterios de exclusión

- `E1`: duplicado bibliográfico o versión sustituida, conservando referencia a su publicación final.
- `E2`: fuera del problema, sin transferencia metodológica sustentable.
- `E3`: contenido sin método o evidencia técnica verificable.
- `E4`: texto inaccesible luego de registrar los intentos de recuperación.
- `E5`: fuera del periodo y sin justificación como trabajo fundacional.

No excluir por resultados negativos, bajo rendimiento, falta de código ni por no utilizar un dataset favorito. Estas características se registrarán como atributos o limitaciones.

#### Selección y deduplicación

- Conservar el registro original de cada fuente, DOI y URL, incluidos preprints.
- Normalizar DOI, títulos y autores, y agrupar versiones por obra.
- Seleccionar título y resumen, después texto completo, con razón de exclusión verificable.
- Recomendar dos revisores y reconciliación de discrepancias. Si solo hay uno, declararlo como limitación, sin inventar un segundo cribado.
- Registrar toda decisión por identificador en `SCREENING_LOG.csv`.

#### Extracción y valoración crítica

Para cada obra incluida, registrar año, tipo, revisión por pares, arquitectura, fuente de eventos, nivel de etiquetas, threat model, baselines, presupuesto de recursos, partición de datos, métricas, intervalos de confianza, disponibilidad de código, hallazgos y limitaciones.

La valoración crítica será descriptiva. Se verificará independencia del ground truth, riesgo de fuga de etiquetas, comparabilidad de condiciones, mediciones reales de memoria y tratamiento de resultados negativos. No se utilizará una puntuación agregada no validada para excluir estudios automáticamente.

#### Síntesis y flujo

Agrupar hallazgos en detección basada en procedencia, ataques adversariales, algoritmos de streaming, calidad de datasets y medición de recursos. Identificar afirmaciones ya establecidas, lagunas de evidencia y consecuencias concretas para F1 a F6.

Completar el flujo PRISMA-ScR solo a partir de los registros exportados:

```text
Identificados por base: PENDIENTE
Registros duplicados retirados: PENDIENTE
Registros examinados por título y resumen: PENDIENTE
Registros excluidos en cribado inicial: PENDIENTE
Textos completos buscados: PENDIENTE
Textos completos no recuperados: PENDIENTE
Textos completos evaluados: PENDIENTE
Exclusiones con motivo por texto completo: PENDIENTE
Estudios incluidos: PENDIENTE
```

#### Reproducibilidad y actualización

Conservar exportaciones originales, hashes, estrategias, decisiones, versiones de herramientas y fecha de corte. Una actualización en 2027 será un nuevo conjunto de registros, no una reescritura retroactiva de los conteos de 2026.

#### Criterio de aprobación

El protocolo estará aprobado cuando se documenten las fuentes accesibles, las cadenas definitivas, el procedimiento de cribado, el responsable y el registro de cambios. La revisión estará completada cuando exista una síntesis con flujo, decisiones y estudios incluidos verificables.
