
### Security Policy

#### Estado del proyecto

AgentGuard FastPath `v1.0.0` es una herramienta defensiva experimental.

No debe considerarse todavía un EDR completo, SIEM completo ni agente eBPF de producción.

#### Reporte de vulnerabilidades

Para reportar problemas de seguridad, abrir un issue privado si GitHub lo permite o contactar al mantenedor del repositorio.

No publicar exploits funcionales en issues públicos.

#### Alcance de seguridad

Se consideran relevantes:

- fallos de memoria;
- corrupción de archivos generados;
- errores en parsing de entradas JSONL o CSV;
- comportamiento inesperado con archivos mal formados;
- problemas en reportes;
- inconsistencias de riesgo.

#### Fuera de alcance

Quedan fuera del alcance de `v1.0.0`:

- bypass de capacidades que el proyecto no declara;
- evaluación como EDR completo;
- soporte empresarial;
- respuesta automática ante incidentes;
- captura eBPF real.
