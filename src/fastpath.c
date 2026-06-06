/**
 * @file fastpath.c
 * @brief Punto de ensamblaje de AgentGuard FastPath.
 *
 * Fase 2: el monolito original se separa fisicamente en fragmentos por
 * responsabilidad. En esta primera etapa se conserva una sola unidad de
 * traduccion para reducir el riesgo de romper simbolos static, orden de tipos
 * y dependencias internas.
 *
 * Los fragmentos incluidos aqui no deben compilarse de forma aislada todavia.
 * La conversion a modulos con headers publicos y objetos separados queda para
 * subpasos posteriores de la Fase 2.
 */

#include "common.h"
#include "string_list.h"

#include "agfast_parts/sketches.c"
#include "agfast_parts/policy.c"
#include "agfast_parts/parser.c"
#include "agfast_parts/graph.c"
#include "agfast_parts/telemetry.c"
#include "agfast_parts/risk_reports.c"
#include "agfast_parts/commands.c"
#include "agfast_parts/main_cli.c"
