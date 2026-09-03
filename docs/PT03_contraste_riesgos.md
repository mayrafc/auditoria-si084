# PT03 · Contraste entre severidad técnica y riesgo de negocio

## Base de evidencia

Se revisaron `reporte_greenbone_autenticado.csv` y `reporte_greenbone_no_autenticado.csv`. Ambos contienen siete detecciones: una crítica, dos medias y cuatro bajas. La columna `CVEs` está vacía en los dos archivos; por ello el registro consigna `N/D` y conserva el nombre del NVT, la IP y el reporte de origen. No se atribuyen CVE que Greenbone no haya reportado.

Los dos reportes presentan el mismo conjunto de resultados. En consecuencia, la etiqueta “autenticado” identifica la tarea ejecutada, pero la evidencia exportada no demuestra por sí sola que Greenbone haya logrado autenticarse en el sistema objetivo. Esta limitación debe mencionarse en el informe.

## Caso 1 · CVSS alto / riesgo de negocio bajo

**R-001 — Aplicación DVWA de entrenamiento.** Greenbone asignó CVSS 10.0 a la detección `Operating System (OS) End of Life (EOL) Detection` en `172.18.0.6`. Sin embargo, DVWA es un activo deliberadamente vulnerable, aislado en `audit_net`, usado solo para prácticas y sin datos reales. Se asignó probabilidad 4 e impacto 1: riesgo inherente 4, nivel Bajo.

El CVSS sigue siendo crítico como medida técnica, pero el impacto de negocio es bajo por el contexto del activo. La aceptación solo es válida mientras se mantengan el aislamiento, la ausencia de datos reales y la autorización del dueño.

## Caso 2 · CVSS medio / riesgo de negocio crítico

**R-004 — Credenciales con acceso a información restringida.** Greenbone asignó CVSS 4.8 a `Cleartext Transmission of Sensitive Information via HTTP` y detectó un campo de contraseña en `http://172.18.0.6/login.php`. Si la credencial interceptada se reutiliza para acceder al ERP o a información restringida, se asigna probabilidad 4 e impacto 5: riesgo inherente 20, nivel Crítico.

Este segundo caso es un escenario condicionado que debe validarse durante la auditoría mediante una comprobación autorizada de reutilización de credenciales. No se afirma que la reutilización ya haya sido demostrada. El riesgo aumenta por el valor del activo potencialmente alcanzable y no porque cambie el CVSS del hallazgo técnico.

## Conclusión

CVSS describe la severidad técnica del hallazgo en condiciones generales. El nivel de riesgo se obtiene al incorporar exposición, valor del activo, clasificación de la información y consecuencias para la organización. Por eso una salida cruda del escáner no sustituye al registro de riesgos.
