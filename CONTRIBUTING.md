
### Contributing

#### Objetivo

Este documento define una guía mínima para contribuir a AgentGuard FastPath.

#### Flujo recomendado

Trabajar siempre en ramas pequeñas:

```bash
git checkout main
git pull origin main
git checkout -b docs/nombre-del-cambio
```

#### Validación local

Antes de abrir un pull request:

```bash
make clean
make
make test-fastpath
make test-regression
make test-streaming
make test-guardsketch
make test-unit
AGFAST_EVAL_EVENTS=10000 AGFAST_EVAL_PIDS=300 bash scripts/run_evaluation.sh
make clean
```

#### Estilo documental

La documentación debe usar:

- títulos con `###`;
- subtítulos con `####`;
- guiones simples;
- sin separadores con signos iguales;
- texto en español.

#### Estilo de código

Los comentarios y cadenas de texto deben estar en español.

Las firmas y nombres de funciones deben mantenerse en inglés.

#### Pull requests

Cada pull request debe explicar:

- objetivo;
- cambios principales;
- validación ejecutada;
- alcance;
- limitaciones.

Para cambios por fase, se recomienda usar `Merge pull request` y no squash para conservar trazabilidad.
