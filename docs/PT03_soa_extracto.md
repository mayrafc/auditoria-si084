# PT03 · Extracto de la Declaración de Aplicabilidad

| Control | Título | ¿Aplica? | Justificación | Estado | Riesgo que trata |
|---|---|---:|---|---|---|
| A.8.8 | Gestión de vulnerabilidades técnicas | Sí | Greenbone detectó un sistema operativo fuera de soporte y otras debilidades técnicas. | No implementado | R-001, R-002 |
| A.8.9 | Gestión de la configuración | Sí | Se identificaron parámetros inseguros y divulgación mediante TCP timestamps. | Parcial | R-007, R-008, R-009, R-010 |
| A.5.17 | Información de autenticación | Sí | La transmisión de credenciales por HTTP y la posible reutilización requieren controles de autenticación. | No implementado | R-004, R-005 |
| A.8.24 | Uso de criptografía | Sí | El formulario de acceso transmite información sensible sin TLS. | No implementado | R-004, R-005 |
| A.8.26 | Requisitos de seguridad de aplicaciones | Sí | Las cookies de sesión no tienen el atributo HttpOnly. | No implementado | R-006 |
| A.7.4 | Monitoreo de la seguridad física | No | El alcance evaluado es un entorno Docker virtual y no incluye instalaciones físicas. La seguridad física corresponde al proveedor o al laboratorio anfitrión. | N/A | — |

> La exclusión de A.7.4 aplica únicamente al alcance técnico de este taller. En un SGSI organizacional completo debe reevaluarse.
