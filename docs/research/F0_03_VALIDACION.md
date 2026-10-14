### F0-03. Verificación del parche y sus datos

#### Entorno

Rama: `research/f0-protocolo`.

Inicio documentado por el usuario: `a5b18f9`.

No ejecutar este parche en `main`. Si el repositorio tiene otros cambios, revisar primero con `git status -sb`.

#### Comprobar y aplicar en Git Bash

```bash
cd /c/Users/kapum/AgentGuard-FastPath
git status -sb
git log -1 --oneline
git apply --check /c/Users/kapum/Downloads/AgentGuard_F0_03_cribado_deduplicacion.patch
git apply /c/Users/kapum/Downloads/AgentGuard_F0_03_cribado_deduplicacion.patch
```

#### Validar informes derivados y el contenido

```bash
python3 scripts/research/prisma_audit.py --check
python3 -m unittest discover -s scripts/research -p 'test_*.py' -v
git add docs/research scripts/research
git diff --cached --check
git diff --cached --stat
git status -sb
```

Si se necesitan regenerar informes derivados después de corregir fichas de origen, ejecutar `python3 scripts/research/prisma_audit.py --generate` y repetir `--check`. No regenerar los documentos sin revisar antes el diff.

#### Criterios verificables

- 9 relaciones de referencias semilla a catálogo, sin clave ausente.
- 20 fichas canónicas de catálogo, 15 estudios, 2 guías y 3 artefactos.
- 15 filas de formulario de cribado con lectura y validación humana pendientes.
- Identificadores únicos en cada fichero y ninguna colisión exacta de DOI o título dentro del catálogo canónico.
- Cero decisiones de inclusión final inventadas.
- Casillas PRISMA formales todavía pendientes.
- Ninguna modificación del código C, de las pruebas de producción o de los workflows.

#### Integración posterior

El PR original de F0-01 se fusionó con `main` antes de incorporar el commit de F0-02. Después de aplicar F0-03 se debe crear un nuevo Draft PR desde `research/f0-protocolo` hacia `main`, para revisar conjuntamente F0-02 y F0-03. No intentar actualizar el PR anterior ya fusionado ni realizar merge sin aprobar F0.
