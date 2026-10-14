### F0-02. Verificacion local del parche

#### Alcance

Este parche solo modifica archivos documentales y registros CSV de `docs/research/`. No modifica codigo C, pruebas, Makefile ni CI.

#### Antes de aplicar

```bash
cd /c/Users/kapum/AgentGuard-FastPath
git status -sb
git rev-parse --short HEAD
git apply --check /c/Users/kapum/Downloads/AgentGuard_F0_02_matriz_PRISMA.patch
```

Se espera la rama `research/f0-protocolo`, un arbol limpio y el commit `aee21cb` o un descendiente compatible. El parche no debe aplicarse en `main`.

#### Despues de aplicar

```bash
git apply /c/Users/kapum/Downloads/AgentGuard_F0_02_matriz_PRISMA.patch
git add docs/research
git diff --cached --check
git diff --cached --stat
git status -sb
```

#### Revisiones obligatorias

1. Confirmar que `BIBLIOGRAPHIC_RECORDS.csv` tiene 20 fichas: 15 estudios, 2 guias y 3 artefactos.
2. Confirmar que `EVIDENCE_MATRIX.csv` contiene 15 estudios preliminares, sin declaraciones de inclusion final.
3. Confirmar que `SCREENING_LOG.csv` contiene 20 decisiones provisionales de clasificacion, ninguna `INCLUIDO`.
4. Confirmar que `SEARCH_LOG.csv` no contiene cantidades inventadas de resultados de las bases.
5. Confirmar que `PRISMA_FLOW.md` mantiene las casillas finales como pendientes.
6. Confirmar que F0 permanece `IN_PROGRESS`.

No ejecutar commit, push ni merge sin revisar el diff y aprobar el cambio. Los mensajes y descripciones de commit o PR deben escribirse en español.
