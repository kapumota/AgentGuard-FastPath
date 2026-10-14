### F0. Antecedentes y brecha de investigación

#### Estado

Matriz bibliográfica inicial verificada por fuentes públicas al 2026-10-13. No es el conjunto final de estudios incluidos por PRISMA-ScR. Cada obra debe pasar selección y extracción antes de citarse como parte de una revisión completada.

#### Algoritmos de streaming

- Cormode y Muthukrishnan, 2005, `An improved data stream summary: the count-min sketch and its applications`. Introduce Count-Min Sketch, por lo que su uso general no constituye novedad. DOI: https://doi.org/10.1016/j.jalgor.2003.12.001
- Ben Mazziane, Alouf y Neglia, 2022, `Analyzing Count Min Sketch with Conservative Updates`. Analiza las propiedades de conservative update, por lo que esa actualización tampoco debe presentarse como estructura original. DOI: https://doi.org/10.1016/j.comnet.2022.109315
- Ajtai et al., 2022, `The White-Box Adversarial Data Stream Model`. Diferencia modelos adversariales que conocen el estado interno y presenta límites y construcciones para algoritmos de streaming. Prepublicación: https://arxiv.org/abs/2204.09136

#### Detección de hosts y robustez

- Goyal et al., 2023, `Sometimes, You Aren't What You Do: Mimicry Attacks against Provenance Graph Host Intrusion Detection Systems`. Estudia ataques de imitación y muestra que la robustez de detectores de procedencia no puede asumirse. Fuente oficial: https://www.ndss-symposium.org/ndss-paper/sometimes-you-arent-what-you-do-mimicry-attacks-against-provenance-graph-host-intrusion-detection-systems/
- Lv et al., 2025, `ProvADShield: A Multimodel Ensemble Defender Against Adversarial Attacks on Provenance Graph Host Intrusion Detector`. Examina defensas con varios modelos, un enfoque distinto al análisis ligero por reglas. DOI: https://doi.org/10.1049/ise2/8625988

#### Evidencia, etiquetas y reproducibilidad

- Tricco et al., 2018, PRISMA-ScR. Referencia metodológica de revisión de alcance. DOI: https://doi.org/10.7326/M18-0850
- Page et al., 2021, PRISMA 2020. Referencia metodológica de reporte. DOI: https://doi.org/10.1136/bmj.n71
- PIDSMaker, artefacto de investigación y repositorio, https://github.com/ubc-provenance/PIDSMaker. Incluye soporte para datasets como THEIA E3 y OpTC y diferentes opciones de ground truth. No debe tratarse automáticamente como artículo ni como prueba de compatibilidad con el formato de AgentGuard.
- Ground truth de ThreaTrace en PIDSMaker, https://github.com/ubc-provenance/PIDSMaker/tree/main/Ground_Truth/threatrace. La documentación reporta diferencias importantes entre etiquetas amplias de vecindad y etiquetas restringidas a nodos de ataques. La versión de las etiquetas condiciona las métricas.

#### Afirmaciones que no se sostendrán sin pruebas adicionales

- Que AgentGuard es el primer sistema de seguridad que utiliza sketches.
- Que conservative update constituye una defensa nueva por sí misma.
- Que aumentar top-k overlap equivale a mejorar la detección de ataques.
- Que toda entrada sin etiqueta de ataque es necesariamente benigna.
- Que una conversión de dataset conserva causalidad sin auditoría del mapeo.
- Que contar bytes de estructuras equivalga a medir memoria RSS real.
- Que una simulación de drops sea una medición de pérdida de eventos de kernel.
- Que un prototipo con CMS por PID sufra colisiones dirigidas entre PID de la misma forma que un CMS global.

#### Brecha candidata, pendiente de corroboración

Se investigará si la combinación de evidencia exacta crítica, estadísticas aproximadas de uso acotado, verificación selectiva y observación explícita de incertidumbre conserva mejor la priorización defensiva que aproximar directamente las señales de riesgo, ante perturbaciones controladas y con etiquetas externas.

No se afirma originalidad confirmada. El cribado PRISMA-ScR deberá comprobar si trabajos anteriores ya evaluaron precisamente esta combinación.

#### Estudios y artefactos por ampliar

- Detección de intrusiones basada en grafos de procedencia, con comparadores sencillos y complejos.
- Robustez frente a borrado, retraso, reordenamiento e imitación de eventos.
- Mecanismos de sketching con claves, amenazas adaptativas y límites matemáticos.
- Protocolos de evaluación de THEIA E3, OpTC y opciones alternativas para datos de host.
- Guías para medición de recursos y calidad de detección con evidencia trazable.

#### Avance de matriz F0-02

`BIBLIOGRAPHIC_RECORDS.csv` registra 15 estudios candidatos, dos guias y tres artefactos. `EVIDENCE_MATRIX.csv` contiene una caracterizacion inicial de 15 estudios basada en titulos, resumenes y fichas editoriales. Estos estudios permanecen pendientes de lectura completa y decision formal.

Se identifican cuatro restricciones para la contribucion candidata:

- StreamSpot (`R002`) y CMS (`R001`) impiden reivindicar novedad general en streaming aproximado.
- Mimicry (`R007`) y defensas de grafos (`R013`, `R014`) impiden reivindicar por si sola la primera evaluacion adversarial.
- Evaluaciones comparativas (`R011`, `R015`) obligan a definir baselines sencillos y etiquetas comparables.
- Estudios de atribucion (`R012`) y calidad de logs (`R010`) obligan a separar deteccion de atribucion y a explicitar la calidad de datos.

Estas son inferencias de posicionamiento provisional. La conclusion de novedad solo se aprobara despues de revisar los textos completos y completar el protocolo.
