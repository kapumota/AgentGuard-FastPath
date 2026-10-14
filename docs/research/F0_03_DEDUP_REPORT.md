### F0-03. Conciliación y deduplicación del catálogo dirigido

#### Estado documental

Corte: 13 de octubre de 2026. La conciliación se refiere solamente a los archivos preparados en F0-01 y F0-02. No representa una deduplicación completa de Scopus, Web of Science, IEEE Xplore, ACM Digital Library o DBLP. No se han incorporado exportaciones originales de esas bases.

#### Entradas efectivamente reconciliadas

- `REFERENCES_SEED.csv`: 9 referencias semilla, incluidas dos guías y dos recursos de software y datos.
- `BIBLIOGRAPHIC_RECORDS.csv`: 20 fichas distintas, 15 estudios científicos candidatos, dos guías y tres artefactos.
- `F0_03_DEDUP_CROSSWALK.csv`: 9 relaciones explícitas entre referencias semilla y fichas canónicas.
- `F0_03_DEDUP_AUDIT.csv`: comprobación reproducible de coincidencia de DOI y título, sin borrar fuentes.
- `F0_03_DEDUP_SUMMARY.json`: conteos comprobados de este inventario dirigido.

La suma aritmética de referencias semilla y fichas produce 29 entradas documentales. **No equivale a 29 registros identificados por una búsqueda sistemática.** Las nueve relaciones evitan contar dos veces referencias reutilizadas de F0-01. Las 20 fichas contienen 15 candidatos a estudios y 5 referencias de apoyo que no deben contarse como estudios de seguridad.

#### Niveles de coincidencia

- `mismo_doi`: una relación respaldada por una clave DOI normalizada.
- `version_editorial`: se relaciona una prepublicación con una versión publicada, pero su equivalencia debe verificarse con el texto completo.
- `mismo_artefacto`: referencias a un mismo repositorio, no a un artículo.
- `recurso_relacionado`: relación temática documentada, no una identidad bibliográfica automática. La ruta de etiquetas de ThreaTrace permanece por verificar.

Las versiones editoriales y las claves de títulos coincidentes son candidatas a conciliación, no autorización automática para borrar informes. Un estudio puede tener varios informes. La fase de selección debe conservar la procedencia de cada uno.

#### Resultado comprobable del catálogo dirigido

- Nueve relaciones entre semilla y catálogo.
- Ningún DOI normalizado repetido dentro de las 20 fichas canónicas.
- Ningún título normalizado repetido dentro de las 20 fichas canónicas.
- Quince obras de investigación candidatas con formulario de cribado.
- Ninguna decisión definitiva de inclusión o exclusión.

Estas cifras proceden del catálogo dirigido y no ocupan todavía las casillas del diagrama PRISMA.

#### Validaciones y decisiones pendientes

- Confirmar mediante lectura que la versión publicada `R003` corresponde al preprint `S005`.
- Confirmar la ruta exacta del recurso de etiquetas `S009` y su relación con `A002`.
- Revisar el registro de todas las exportaciones formales, sin modificar los CSV originales.
- Identificar resultados de bases que compartan DOI o título, con reconciliación manual de distintas versiones.
- Documentar revisor humano, fecha, decisiones y razones específicas de exclusión antes de cerrar el cribado.

#### Interpretación

La deduplicación del catálogo semilla está auditada, **no la deduplicación de una búsqueda formal terminada**. La diferencia se mantendrá expresamente en el PR y en `PRISMA_FLOW.md`.
