### F0-02. Recuperacion dirigida y trazabilidad bibliografica

#### Alcance

Parche documental preparado a partir de comprobacion de metadatos y resenas de fuentes publicas disponibles hasta el 13 de octubre de 2026. No representa exportaciones exhaustivas de Scopus, Web of Science, IEEE Xplore ni ACM Digital Library. El catalogo selecciona obras relevantes por fuentes dirigidas, por lo que existe sesgo de seleccion que se corregira con las busquedas formales.

#### Archivos y contratos

- `BIBLIOGRAPHIC_RECORDS.csv`: identificadores de obra `R`, `G` y `A`, URL primaria y referencias a semillas previas.
- `EVIDENCE_MATRIX.csv`: informacion que puede sostenerse con los resúmenes o fichas publicas, no lectura de texto completo.
- `SCREENING_LOG.csv`: una fila provisional por obra, sin decision final de inclusion.
- `SEARCH_LOG.csv`: actividad selectiva, con resultados vacios cuando no se dispone del recuento total recuperado.
- `PRISMA_FLOW.md`: control de casillas sin inventar conteos PRISMA.

#### Relaciones con referencias semilla

| F0-01 | F0-02 | Interpretacion |
|---|---|---|
| S001 | G001 | Guia PRISMA-ScR, fuera de flujo de estudios de seguridad |
| S002 | G002 | Guia PRISMA 2020, fuera de flujo de estudios de seguridad |
| S003 | R001 | CMS fundacional de 2005 |
| S004 | R004 | CMS con conservative update |
| S005 | R003 | El preprint de Ajtai tiene una version publicada en ACM PODS 2022 |
| S006 | R007 | Estudio de mimicry en NDSS |
| S007 | R013 | ProvADShield, primera publicacion editorial 2025-10-31 |
| S008 | A001 | Repositorio PIDSMaker, diferente de paper R015 |
| S009 | A002 | Documentacion del ground truth de PIDSMaker |

#### Reglas de verificacion

- Un DOI identifica una obra o version editorial, no certifica un dataset compatible.
- Si no se confirmo un DOI de publicacion final, dejar el campo vacio y citar la fuente oficial del editor o autor.
- No tratar CountSketch como Count-Min Sketch. Pueden compartir un problema adversarial sin compartir cotas.
- No equiparar documentos de repositorios ni guias PRISMA con articulos evaluados por pares.
- Los datos sobre ground truth en `EVIDENCE_MATRIX.csv` son preliminares. No confirman una etiqueta de proceso directamente utilizable.
- `preseleccion_para_texto_completo` significa que se leera mas adelante. No significa `INCLUIDO` en PRISMA.
- Las entradas `F002_Q01` a `F002_Q09` en `SEARCH_LOG.csv` contienen consultas literales realizadas en busqueda web dirigida. Son una muestra documentada y no el historial completo de busquedas, ni exportaciones de bases bibliograficas, y sus campos de recuento y checksum estan vacios intencionalmente.
- La primera clasificacion fue asistida por IA. Debe revisarse por una persona y, cuando sea posible, por un segundo revisor independiente.

#### Fuentes verificables de partida

Las URL publicas identificadas se encuentran en `BIBLIOGRAPHIC_RECORDS.csv`. La ubicacion especifica de `A002` debe verificarse; por ahora se remite al repositorio principal de PIDSMaker. Entre las fuentes primarias estan NDSS, USENIX, IEEE mediante institucion autora, ACM, PMLR, BMJ, PubMed, Wiley, el repositorio DARPA E3 y PIDSMaker.

#### Riesgo cientifico relevante

`R011` y `R015` cuestionan protocolos de evaluacion incompatibles y comparadores complejos sin una linea base justa. `R007`, `R013` y `R014` muestran que la robustez adversarial de sistemas de procedencia no es una contribucion nueva por si misma. `R001`, `R004` y `R009` condicionan la novedad de modificaciones a CMS. `R012` y `R010` exigen diferenciar una alerta de una atribucion verificable y considerar la calidad del dataset.

Esta sintesis es una interpretacion para orientar F0. Requiere confirmacion y precisiones despues de la lectura de los articulos completos.

#### Limitaciones pendientes

No se ha descargado ni cotejado sistematicamente el texto completo de estas obras. No se han descargado datasets, ni realizado medidas, ni verificado compatibilidad de campos o etiquetas con `agfast`. No se han consolidado registros duplicados provenientes de exportaciones de bases distintas. Ningun resultado de AgentGuard queda avalado por estas referencias.
