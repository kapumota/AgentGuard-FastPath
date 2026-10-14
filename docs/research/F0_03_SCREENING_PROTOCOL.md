### F0-03. Procedimiento de cribado reproducible

#### Unidad de análisis y separación de etapas

- Registro: resultado bibliográfico individual procedente de una fuente y consulta registradas.
- Informe: texto que documenta un estudio, incluidas sus versiones editoriales cuando sean diferentes.
- Estudio: investigación subyacente, que puede tener varios informes asociados.

No se deben confundir resultados de búsquedas, artículos recuperados e investigaciones incluidas. Las guías de PRISMA y los artefactos técnicos sirven de apoyo, pero no son estudios candidatos del problema de seguridad.

#### Estado inicial de los 15 candidatos

`F0_03_SCREENING_FORM.csv` documenta 15 propuestas de envío a lectura completa, basadas en títulos, fichas editoriales y material de F0-02. El campo `proponente` reconoce expresamente la ayuda de IA. Los campos de validación humana, segundo revisor y texto completo permanecen como `pendiente`, sin afirmar que ya se examinó el texto completo.

Las sugerencias automáticas no constituyen una selección formal ratificada. Se necesita constancia de quién tomó cada decisión humana.

#### Procedimiento para el cribado formal

1. Registrar la fuente de cada exportación con fecha, cadena literal, filtros, número de registros y checksum del archivo original.
2. Conciliar DOI y título normalizados, conservando todas las filas de origen y separando preprints de publicaciones definitivas.
3. Aplicar a títulos y resúmenes los criterios PCC de `PRISMA_PROTOCOL.md`.
4. Registrar `incluir_para_texto_completo`, `excluir_titulo_resumen` o `duda_requiere_arbitraje`, con el criterio usado.
5. Solicitar y consultar el texto completo de los informes retenidos, anotando URL, fecha y disponibilidad.
6. Aplicar los criterios de inclusión y exclusión a cada informe, anotando un motivo principal por exclusión.
7. Conciliar informes múltiples de un estudio y extraer características técnicas, datos, etiquetas, comparadores y limitaciones.
8. Completar el flujo PRISMA únicamente después de cuadrar los registros e informes realmente inspeccionados.

#### Revisión humana

Preferir dos revisores independientes. Si solo participa un revisor humano, consignarlo de forma explícita, sin declarar revisión doble. Las decisiones producidas por IA se distinguen de la aprobación humana.

#### Criterios de exclusión

- `E1`: duplicado de registro o versión sustituida, con vínculo a la obra conservada.
- `E2`: tema ajeno sin transferencia metodológica justificable.
- `E3`: insuficiencia de método o contenido técnico verificable.
- `E4`: informe no recuperable tras intentos documentados.
- `E5`: fuera del intervalo temporal sin carácter fundacional justificado.

`E4` debe reflejarse como informe no recuperado, no como estudio leído y excluido. Los informes con resultados negativos no se excluirán por ese motivo.

#### Cómo incorporar exportaciones externas

Se conservarán las exportaciones CSV sin modificaciones en un directorio de trabajo no versionado, con su procedencia anotada en el registro. Para inspeccionar títulos y DOI mediante herramientas locales:

```bash
python3 scripts/research/prisma_audit.py \
  --inspect-exports /c/Users/kapum/Downloads/prisma_exports \
  --output /c/Users/kapum/Downloads/prisma_duplicados.csv
```

El programa admite columnas `DOI` y `Title` o `Document Title`, y sus variantes en español. Esta utilidad emite candidatos de coincidencia sin eliminar registros ni declarar decisiones finales. Otros formatos RIS y BibTeX requieren conversión documentada a CSV antes de utilizarla.

#### Condición de cierre F0-03

Se puede cerrar el subobjetivo de conciliación del catálogo dirigido después de verificar los informes generados y los vínculos pendientes. El cribado formal y el flujo PRISMA solo pueden cerrarse cuando existan exportaciones auditables y decisiones humanas registradas. F0 permanece en `IN_PROGRESS`.
