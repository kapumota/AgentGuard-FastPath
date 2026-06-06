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
