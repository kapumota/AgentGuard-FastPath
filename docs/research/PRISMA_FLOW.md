### F0-02. Estado del flujo PRISMA-ScR

#### Naturaleza del registro

Este documento es un control de avance, no un diagrama PRISMA concluido. Su fecha de corte es el 13 de octubre de 2026. Los conteos siguientes corresponden solamente a un catalogo dirigido de trabajo, no a registros identificados mediante las busquedas completas de las bases previstas.

#### Inventario dirigido de F0-02

- Obras cientificas candidatas con identificador `R`: 15.
- Guias metodologicas con identificador `G`: 2.
- Artefactos, corpus y documentos de etiquetas con identificador `A`: 3.
- Fichas registradas con fuentes publicas identificadas: 20. El enlace especifico del recurso A002 requiere confirmacion.
- Obras `R` preseleccionadas por titulo y resumen o ficha: 15.
- Obras `R` seleccionadas definitivamente tras lectura completa: sin determinar.
- Registros de Scopus, Web of Science, IEEE Xplore, ACM Digital Library o DBLP exportados: ninguno aportado en este parche.

No mezclar las guias `G` y los artefactos `A` con los estudios elegibles. Tampoco sumar el conjunto semilla de F0-01 al inventario sin reconciliar identificadores, pues contiene solapamientos.

#### Flujo PRISMA formal por completar

| Casilla de flujo | Estado | Motivo |
|---|---|---|
| Registros identificados en bases | PENDIENTE | Faltan exportaciones completas y filtros reproducibles |
| Registros identificados por otras fuentes | PENDIENTE | El catalogo dirigido no es un historial exhaustivo de recuperacion |
| Duplicados eliminados antes del cribado | PENDIENTE | No existe aun la union de exportaciones originales |
| Registros cribados | PENDIENTE | La preseleccion documental no reemplaza el cribado formal |
| Registros excluidos por titulo y resumen | PENDIENTE | No hay cribado formal terminado |
| Informes buscados para recuperacion | PENDIENTE | Se requiere plan de lectura completa |
| Informes no recuperados | PENDIENTE | Registrar intentos verificables |
| Informes evaluados a texto completo | PENDIENTE | No se ha efectuado la extraccion sistematica completa |
| Informes excluidos con motivo | PENDIENTE | No atribuir razones sin lectura |
| Estudios incluidos | PENDIENTE | Solo al finalizar seleccion y conciliacion |

#### Regla de conteos

Para el flujo definitivo se deben conservar los archivos originales de cada base, consulta literal, fecha de consulta, numero recibido, DOI, clave de deduplicacion y checksum de los datos exportados. Cada registro pasa por el cribado definido en `PRISMA_PROTOCOL.md`, con decisiones y razones auditables.

Ninguna cifra de la tabla formal sera reemplazada por cero para encubrir ausencia de acceso. No inferir elegibilidad a partir de que exista DOI o de que un articulo este publicado en una conferencia.

#### Tareas restantes

1. Exportar resultados de cada fuente bibliografica accessible, identificar cobertura y conservar checksums.
2. Reconciliar catalogo dirigido, registros semilla y exportaciones por DOI, titulo y version editorial.
3. Realizar cribado y, cuando sea viable, revision humana independiente.
4. Completar lectura y extraccion de texto completo.
5. Generar diagrama y tablas definitivas a partir de registros, sin numeros manuales no trazables.

#### Actualización F0-03

La conciliación dirigida de F0-03 relacionó 9 referencias semilla con el catálogo de 20 fichas de F0-02. No se identificaron claves DOI ni títulos duplicados en las fichas canónicas de ese catálogo. Estos resultados corresponden solamente a los archivos locales de trabajo. **Todas las casillas de identificación y selección PRISMA formal continúan como PENDIENTE.**

No trasladar al diagrama PRISMA la cifra 29 (semillas más fichas) ni inferir 9 duplicados de registros de bases bibliográficas. Se trata de referencias documentales parcialmente redundantes, no de resultados identificados por consultas sistemáticas independientes.
