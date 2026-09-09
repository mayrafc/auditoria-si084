\# Análisis de deficiencia de diseño y eficacia operativa



Durante la auditoría de configuración segura, Docker Bench identificó varios

contenedores ejecutándose con privilegios de usuario root. Entre los hallazgos

se encontró el incumplimiento del control 4.1, relacionado con la creación de

un usuario específico para la ejecución de los contenedores.



Este hallazgo se vincula con el control A.8.2 de ISO/IEC 27001:2022,

correspondiente a derechos de acceso privilegiado, y con DSS05.04 de COBIT

2019\. La ejecución de contenedores con privilegios elevados incrementa el

impacto potencial de una vulnerabilidad, ya que una explotación podría permitir

acciones con mayores permisos dentro del entorno.



El hallazgo se clasifica principalmente como una deficiencia de diseño porque

el control preventivo no fue incorporado correctamente desde la configuración

del contenedor. Las imágenes o archivos de despliegue permiten que los procesos

se ejecuten utilizando root en lugar de definir un usuario con privilegios

limitados.



Como acción correctiva, se propone modificar los Dockerfile y las

configuraciones de despliegue para crear usuarios no privilegiados, aplicar el

principio de mínimo privilegio y volver a ejecutar Docker Bench para comprobar

que el hallazgo haya sido corregido.



Por otro lado, una deficiencia de eficacia operativa se presentaría si el

control estuviera definido correctamente, por ejemplo mediante un usuario no

root, pero durante la operación dicho control fuera deshabilitado, modificado

o aplicado de manera inconsistente. En ese caso, el diseño sería adecuado,

pero su ejecución no sería efectiva.

