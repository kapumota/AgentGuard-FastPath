### Decisiones tecnicas

#### Decision 1 - Mantener main estable

`main` debe representar una version compilable, probada y demostrable del proyecto.

Antes de iniciar una fase:

```bash
git checkout main
git pull origin main
git status
```

#### Decision 2 - Trabajar por ramas de fase

Cada mejora importante debe desarrollarse en una rama independiente.

Ejemplo:

```bash
git checkout -b fase-1-higiene-repositorio
```

Esto permite revisar cambios mediante Pull Request antes de integrarlos a `main`.

#### Decision 3 - No versionar artefactos generados

No se deben versionar binarios, objetos compilados, reportes locales ni archivos temporales.

Ejemplos excluidos:

- `bin/`
- `obj/`
- `report.json`
- `report.html`
- `alerts.csv`
- archivos `.tmp`;
- caches locales.

#### Decision 4 - Usar make como interfaz principal

El proyecto debe poder validarse con comandos simples:

```bash
make clean
make
make test-fastpath
```

Esto facilita reproducibilidad local y futura integracion con CI.

#### Decision 5 - Separar documentacion tecnica en docs

La documentacion de arquitectura, uso, roadmap y decisiones tecnicas debe vivir en `docs/`.

El README debe ser una entrada rapida al proyecto, no el unico lugar donde se documenta todo.

#### Decision 6 - Mantener la Fase 1 sin cambios algoritmicos

La Fase 1 no debe modificar el nucleo de analisis ni los algoritmos probabilisticos.

Su alcance es:

- higiene;
- documentacion;
- limpieza;
- reproducibilidad;
- preparacion para fases posteriores.

<!-- fase6:start -->
### Decisiones técnicas de Fase 6

#### Decisión 1 - Mantener userspace como ruta principal

La ruta principal del proyecto sigue siendo userspace.

Motivo:

- es reproducible;
- no requiere privilegios;
- facilita pruebas;
- facilita benchmarks;
- permite validar el modelo antes de integrar captura de kernel.

#### Decisión 2 - No introducir eBPF todavía

eBPF se pospone hasta que el proyecto tenga documentación técnica y criterios claros.

Motivo:

- eBPF puede romper la portabilidad;
- eBPF requiere dependencias específicas;
- eBPF no debe agregarse antes de validar el valor del análisis.

#### Decisión 3 - Evaluar sketches por impacto en riesgo

Los sketches no deben evaluarse solo por error matemático aislado.

El criterio principal es si preservan decisiones defensivas.

Métricas relevantes:

- top-k overlap;
- cambios de nivel de riesgo;
- ranking de PIDs;
- falsos positivos esperados;
- error de cardinalidad.

#### Decisión 4 - No vender el proyecto como EDR completo

El proyecto se debe describir como analizador defensivo avanzado de telemetría.

No debe presentarse como EDR completo ni SIEM completo.

#### Decisión 5 - Mantener fases pequeñas

Cada fase debe ser verificable con cambios acotados.

La Fase 6 solo modifica documentación técnica.

No debe tocar código fuente, benchmarks ni pruebas.

#### Decisión 6 - Documentar limitaciones antes de agregar complejidad

Antes de eBPF o GuardSketch en kernel, el proyecto debe explicar sus límites.

Esto mejora la revisión técnica y evita promesas excesivas.

#### Decisión 7 - Mantener formato documental uniforme

La documentación usa:

- títulos con `###`;
- subtítulos con `####`;
- guiones simples;
- sin separadores con signos iguales;
- texto en español;
- comandos reproducibles.
<!-- fase6:end -->
