### Resultados experimentales

#### Propósito

Esta carpeta documenta dónde guardar resultados de evaluación cuando se decida versionar una evidencia concreta.

Por defecto, Fase 9 escribe resultados en:

```text
/tmp/agfast_fase9_evaluacion
```

Esto evita ensuciar el repositorio durante pruebas locales.

#### Uso opcional

Para escribir resultados dentro del repositorio:

```bash
AGFAST_EVAL_DIR=results/fase9-local bash scripts/run_evaluation.sh
```

Antes de commitear resultados generados, revisar tamaño, reproducibilidad y relevancia.
