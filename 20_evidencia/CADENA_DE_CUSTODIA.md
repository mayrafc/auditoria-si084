# Cadena de custodia de la evidencia

| ID | Archivo | SHA-256 | Fecha y hora (UTC) | Obtenido por | Método de obtención | Sistema origen |
|----|---------|---------|--------------------|--------------|---------------------|----------------|
| E01-001 | contenedores.json | F4A1506F58BFC22006A959B6681AE384EF2ABBF81ECFE5C02F55ACC7E63D96FC | AAAA-MM-DDTHH:MM:SSZ | Mayra Chire Ramos | docker compose -f entorno/docker-compose.yml ps --format json | Entorno Docker si084-lab |
| E01-002 | imagenes.tsv | 136C9EB6F4A614E81136A30D08073F4AEF951A707ABF5E42972436231581CCFB | AAAA-MM-DDTHH:MM:SSZ | Mayra Chire Ramos | docker images --digests --format "{{.Repository}} {{.Tag}} {{.Digest}}" | Entorno Docker si084-lab |
| E01-003 | puertos.tsv | 746C8B15783D71E786DCBDF29551E964F9631E2B09A3B27781A347EEDEFF5AB8 | AAAA-MM-DDTHH:MM:SSZ | Mayra Chire Ramos | docker ps --format "{{.Names}} {{.Ports}}" | Entorno Docker si084-lab |
| E01-004 | compose_efectivo.yml | 8582E317EE2523F937137EA2BBD3B940973FFCEE5210F24EDA20E9AA76DA44B4 | AAAA-MM-DDTHH:MM:SSZ | Mayra Chire Ramos | docker compose -f entorno/docker-compose.yml config | Entorno Docker si084-lab |
| E01-005 | usuarios_postgres.txt | 9CC4835C0991E6B068BF4FAD929A2C5DFF6264B2E9707806DA12D75C1F9EAD73 | AAAA-MM-DDTHH:MM:SSZ | Mayra Chire Ramos | docker exec si084_db psql -U erp_app -d erp -c "\du" | Contenedor si084_db (PostgreSQL) |
| E01-006 | env_db.json | 3FC8985667443AFBE740747777A752292B76F0FE40BB85F61BBE2A3086D51E08 | AAAA-MM-DDTHH:MM:SSZ | Mayra Chire Ramos | docker inspect si084_db --format "{{json .Config.Env}}" | Contenedor si084_db (PostgreSQL) |