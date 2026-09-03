from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "docs" / "evidencias" / "S03" / "scan"
AUTH = SCAN / "reporte_greenbone_autenticado.csv"
NO_AUTH = SCAN / "reporte_greenbone_no_autenticado.csv"
OUT_DOCS = ROOT / "docs" / "PT03_registro_riesgos.csv"
OUT_HALLAZGOS = ROOT / "40_hallazgos" / "PT03_registro_riesgos.csv"

REQUIRED_COLUMNS = {"IP", "CVSS", "Severity", "NVT Name", "CVEs", "Task Name"}


def leer_reporte(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, encoding="utf-8-sig")
    faltantes = REQUIRED_COLUMNS.difference(df.columns)
    if faltantes:
        raise ValueError(f"{path.name}: faltan columnas {sorted(faltantes)}")
    df["fuente"] = path.name
    return df


def verificar_hallazgo(df: pd.DataFrame, ip: str, texto_nvt: str, cvss: float) -> None:
    existe = (
        df["IP"].astype(str).eq(ip)
        & df["NVT Name"].astype(str).str.contains(texto_nvt, case=False, regex=False)
        & df["CVSS"].astype(float).eq(cvss)
    ).any()
    if not existe:
        raise ValueError(f"No se encontró evidencia: {ip} / {texto_nvt} / CVSS {cvss}")


auth = leer_reporte(AUTH)
no_auth = leer_reporte(NO_AUTH)
v = pd.concat([auth, no_auth], ignore_index=True)

# Mapeo verificado con docs/evidencias/S03/salidas/objetivos.txt.
# Si Docker asigna IP distintas, actualice estas cuatro entradas antes de ejecutar.
IP_CONTENEDOR = {
    "172.18.0.5": "si084_db",
    "172.18.0.4": "si084_juiceshop",
    "172.18.0.8": "si084_portal",
    "172.18.0.6": "si084_dvwa",
}

verificar_hallazgo(v, "172.18.0.6", "Operating System (OS) End of Life", 10.0)
verificar_hallazgo(v, "172.18.0.6", "Missing HttpOnly Cookie Attribute", 5.0)
verificar_hallazgo(v, "172.18.0.6", "Cleartext Transmission", 4.8)
for ip in IP_CONTENEDOR:
    verificar_hallazgo(v, ip, "TCP Timestamps Information Disclosure", 2.6)

columnas = [
    "id_riesgo", "ip", "contenedor_origen", "activo", "dueno_del_riesgo",
    "clasificacion", "amenaza", "vulnerabilidad", "cve", "cvss",
    "severidad_tecnica", "vector_ataque", "probabilidad", "impacto",
    "riesgo_inherente", "nivel", "criterio_aceptacion", "tratamiento_propuesto",
    "control_iso", "riesgo_residual_estimado", "fuente_evidencia", "observacion",
]

rows = [
    ["R-001","172.18.0.6","si084_dvwa","Aplicación DVWA de entrenamiento","Gerencia de Operaciones","Interna","Explotación de sistema operativo sin soporte","Sistema operativo Debian 9 fuera de soporte","N/D",10.0,"Crítica","Red",4,1,4,"Bajo","Puede aceptarse con aprobación y aislamiento","Mantener aislamiento y retirar o actualizar la imagen","A.8.8",2,"Greenbone autenticado y no autenticado - Operating System EOL Detection","Caso de contraste: CVSS alto pero impacto bajo porque es un activo de práctica aislado y sin datos reales"],
    ["R-002","172.18.0.6","si084_dvwa","Servidor de aplicación legada interna","Gerencia de Operaciones","Interna","Compromiso remoto del servidor","Sistema operativo Debian 9 fuera de soporte","N/D",10.0,"Crítica","Red",4,3,12,"Alto","Requiere tratamiento","Actualizar imagen base y establecer gestión de parches","A.8.8",6,"Greenbone autenticado y no autenticado - Operating System EOL Detection","Escenario de alteración del servicio derivado de la detección crítica"],
    ["R-003","172.18.0.6","si084_dvwa","Servicio de aplicación legada","Gerencia de Operaciones","Interna","Interrupción del servicio por fallos no corregidos","Sistema operativo Debian 9 fuera de soporte","N/D",10.0,"Crítica","Red",3,3,9,"Medio","Requiere tratamiento","Migrar a versión soportada y probar recuperación","A.8.14",4,"Greenbone autenticado y no autenticado - Operating System EOL Detection","Escenario de disponibilidad distinto del compromiso de integridad de R-002"],
    ["R-004","172.18.0.6","si084_dvwa","Credenciales con acceso a información restringida","Gerencia de Finanzas","Restringida","Intercepción y reutilización de credenciales","Formulario de autenticación transmite contraseña mediante HTTP","N/D",4.8,"Media","Red",4,5,20,"Crítico","Requiere tratamiento","Forzar HTTPS y prohibir reutilización de credenciales","A.8.24 / A.5.17",6,"Greenbone autenticado y no autenticado - Cleartext Transmission via HTTP","Caso condicionado: validar si la credencial expuesta permite acceso al ERP"],
    ["R-005","172.18.0.6","si084_dvwa","Credenciales de la aplicación legada","Gerencia de Operaciones","Confidencial","Robo de credenciales mediante escucha de red","Formulario de autenticación transmite contraseña mediante HTTP","N/D",4.8,"Media","Red",3,4,12,"Alto","Requiere tratamiento","Habilitar TLS y redirigir todo HTTP a HTTPS","A.8.24",4,"Greenbone autenticado y no autenticado - Cleartext Transmission via HTTP","La evidencia identifica el campo password en http://172.18.0.6/login.php"],
    ["R-006","172.18.0.6","si084_dvwa","Sesiones de usuarios de la aplicación","Gerencia de Operaciones","Confidencial","Secuestro de sesión mediante scripts del navegador","Cookie de sesión sin atributo HttpOnly","N/D",5.0,"Media","Red",3,3,9,"Medio","Requiere tratamiento","Configurar HttpOnly Secure y SameSite en cookies de sesión","A.8.26",4,"Greenbone autenticado y no autenticado - Missing HttpOnly Cookie Attribute","Greenbone identificó PHPSESSID y security sin HttpOnly"],
    ["R-007","172.18.0.5","si084_db","Base de datos ERP","Gerencia de Finanzas","Restringida","Reconocimiento técnico previo a un ataque","Divulgación de información mediante TCP timestamps","N/D",2.6,"Baja","Red",2,5,10,"Medio","Requiere tratamiento","Deshabilitar timestamps si es viable y restringir acceso de red","A.8.20 / A.8.9",4,"Greenbone autenticado y no autenticado - TCP Timestamps Information Disclosure","La baja severidad técnica aumenta por la criticidad del activo de datos"],
    ["R-008","172.18.0.4","si084_juiceshop","Portal de clientes","Gerencia Comercial","Confidencial","Reconocimiento de infraestructura expuesta","Divulgación de información mediante TCP timestamps","N/D",2.6,"Baja","Red",3,4,12,"Alto","Requiere tratamiento","Reducir exposición y aplicar endurecimiento de red","A.8.20 / A.8.9",4,"Greenbone autenticado y no autenticado - TCP Timestamps Information Disclosure","La exposición del portal eleva la probabilidad aunque el CVSS sea bajo"],
    ["R-009","172.18.0.8","si084_portal","Portal corporativo público","Gerencia Comercial","Pública","Reconocimiento de infraestructura expuesta","Divulgación de información mediante TCP timestamps","N/D",2.6,"Baja","Red",3,1,3,"Bajo","Puede aceptarse con aprobación","Documentar aceptación y revisar durante el endurecimiento","A.8.9",2,"Greenbone autenticado y no autenticado - TCP Timestamps Information Disclosure","Activo público sin datos sensibles y con impacto limitado"],
    ["R-010","172.18.0.6","si084_dvwa","Aplicación legada interna","Gerencia de Operaciones","Interna","Reconocimiento técnico previo a explotación","Divulgación de información mediante TCP timestamps","N/D",2.6,"Baja","Red",2,3,6,"Medio","Puede aceptarse según umbral menor o igual a 6","Endurecer configuración de red en próxima actualización","A.8.9",3,"Greenbone autenticado y no autenticado - TCP Timestamps Information Disclosure","El valor 6 está dentro del criterio de aceptación definido por el laboratorio"],
]

reg = pd.DataFrame(rows, columns=columnas)
calculado = reg["probabilidad"] * reg["impacto"]
if not calculado.equals(reg["riesgo_inherente"]):
    raise ValueError("Hay valores de riesgo inherente que no coinciden con P x I")
if len(reg) < 10:
    raise ValueError("El registro debe contener como mínimo diez riesgos")

OUT_DOCS.parent.mkdir(parents=True, exist_ok=True)
OUT_HALLAZGOS.parent.mkdir(parents=True, exist_ok=True)
reg.to_csv(OUT_DOCS, index=False, encoding="utf-8-sig")
reg.to_csv(OUT_HALLAZGOS, index=False, encoding="utf-8-sig")

print(reg[["id_riesgo", "activo", "cvss", "probabilidad", "impacto", "riesgo_inherente", "nivel"]]
      .sort_values(["riesgo_inherente", "id_riesgo"], ascending=[False, True])
      .to_string(index=False))
print(f"\nGuardado: {OUT_DOCS}")
print(f"Guardado: {OUT_HALLAZGOS}")
