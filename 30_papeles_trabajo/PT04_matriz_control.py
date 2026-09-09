import csv
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
EVID = BASE / "20_evidencia" / "E04_config"
OUT = BASE / "40_hallazgos"
OUT.mkdir(parents=True, exist_ok=True)

hallazgos = []


def clasificar(texto):
    t = texto.lower()

    reglas = [
        (r"root|privileg|capab", "A.8.2", "DSS05.04"),
        (r"password|credential|secret|auth", "A.5.17", "DSS05.04"),
        (r"cve-|vulnerab|outdated|version", "A.8.8", "DSS05.07"),
        (r"log|audit|journal", "A.8.15", "DSS01.03"),
        (r"tls|ssl|cipher|encrypt|certificate", "A.8.24", "DSS05.03"),
        (r"firewall|port|network|expose", "A.8.20", "DSS05.02"),
        (r"config|default|hardening", "A.8.9", "BAI10.02"),
        (r"backup|restore", "A.8.13", "DSS04.07"),
        (r"permission|owner|ownership|chmod|file access", "A.8.3", "DSS05.04"),
        (r"container|docker|image|runtime", "A.8.9", "BAI10.02"),
        (r"service|daemon|process", "A.8.9", "DSS01.03"),
        (r"update|patch|package", "A.8.8", "DSS05.07"),
	(r"userland proxy|healthcheck", "A.8.9", "BAI10.02"),
	(r"socket", "A.8.2", "DSS05.04"),
 	(r"namespace", "A.8.2", "DSS05.04"),
	(r"trust", "A.8.9", "BAI10.02"),
	(r"mount|partition", "A.8.9", "BAI10.02"),
    ]

    for patron, iso, cobit in reglas:
        if re.search(patron, t):
            return iso, cobit

    return "Sin clasificar", "Sin clasificar"


# ==========================================================
# LYNIS
# ==========================================================
lynis = EVID / "lynis-report.dat"

if lynis.exists():
    with lynis.open(encoding="utf-8", errors="ignore") as f:
        for linea in f:
            linea = linea.strip()

            if linea.startswith("warning[]="):
                texto = linea.split("=", 1)[1]
                iso, cobit = clasificar(texto)

                hallazgos.append({
                    "herramienta": "Lynis",
                    "tipo": "Warning",
                    "hallazgo": texto,
                    "severidad": "Warning",
                    "iso27001": iso,
                    "cobit2019": cobit
                })

            elif linea.startswith("suggestion[]="):
                texto = linea.split("=", 1)[1]
                iso, cobit = clasificar(texto)

                hallazgos.append({
                    "herramienta": "Lynis",
                    "tipo": "Suggestion",
                    "hallazgo": texto,
                    "severidad": "Suggestion",
                    "iso27001": iso,
                    "cobit2019": cobit
                })


# ==========================================================
# OPENSCAP
# ==========================================================
oscap = EVID / "oscap-resultados.xml"

if oscap.exists():
    try:
        tree = ET.parse(oscap)
        root = tree.getroot()

        for elemento in root.iter():
            etiqueta = elemento.tag.split("}")[-1]

            if etiqueta == "rule-result":
                resultado = ""

                for hijo in elemento:
                    if hijo.tag.split("}")[-1] == "result":
                        resultado = (hijo.text or "").strip().lower()
                        break

                if resultado == "fail":
                    rule_id = elemento.attrib.get(
                        "idref",
                        "Regla OpenSCAP sin identificador"
                    )

                    texto = f"OpenSCAP FAIL | {rule_id}"
                    iso, cobit = clasificar(texto)

                    hallazgos.append({
                        "herramienta": "OpenSCAP",
                        "tipo": "XCCDF Fail",
                        "hallazgo": texto,
                        "severidad": "Fail",
                        "iso27001": iso,
                        "cobit2019": cobit
                    })

    except Exception as e:
        print(f"[ADVERTENCIA] No se pudo procesar OpenSCAP: {e}")


# ==========================================================
# DOCKER BENCH
# ==========================================================
docker_log = EVID / "docker-bench.log"

if docker_log.exists():
    with docker_log.open(encoding="utf-8", errors="ignore") as f:
        for linea in f:
            linea = linea.strip()

            if "[WARN]" in linea:
                texto = re.sub(
                    r"\x1b\[[0-9;]*m",
                    "",
                    linea
                )

                iso, cobit = clasificar(texto)

                hallazgos.append({
                    "herramienta": "Docker Bench",
                    "tipo": "WARN",
                    "hallazgo": texto,
                    "severidad": "Warning",
                    "iso27001": iso,
                    "cobit2019": cobit
                })


# ==========================================================
# TRIVY
# ==========================================================
for archivo in EVID.glob("trivy*.json"):

    if archivo.name.lower().startswith("sbom"):
        continue

    try:
        data = json.loads(
            archivo.read_text(
                encoding="utf-8",
                errors="ignore"
            )
        )
    except Exception as e:
        print(
            f"[ADVERTENCIA] No se pudo procesar "
            f"{archivo.name}: {e}"
        )
        continue

    for resultado in data.get("Results", []):
        target = resultado.get("Target", "")

        for vuln in resultado.get("Vulnerabilities") or []:
            vuln_id = vuln.get("VulnerabilityID", "")
            pkg = vuln.get("PkgName", "")
            severity = vuln.get("Severity", "")
            title = (
                vuln.get("Title")
                or vuln.get("Description")
                or ""
            )

            texto = (
                f"{vuln_id} | {pkg} | "
                f"{target} | {title}"
            )

            iso, cobit = clasificar(texto)

            hallazgos.append({
                "herramienta": "Trivy",
                "tipo": "Vulnerability",
                "hallazgo": texto,
                "severidad": severity,
                "iso27001": iso,
                "cobit2019": cobit
            })


# ==========================================================
# EXPORTAR CSV
# ==========================================================
csv_path = OUT / "PT04_matriz_control.csv"

campos = [
    "herramienta",
    "tipo",
    "hallazgo",
    "severidad",
    "iso27001",
    "cobit2019"
]

with csv_path.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=campos
    )

    writer.writeheader()
    writer.writerows(hallazgos)


# ==========================================================
# RESUMEN
# ==========================================================
total = len(hallazgos)

sin_clasificar = sum(
    1
    for h in hallazgos
    if h["iso27001"] == "Sin clasificar"
)

porcentaje = (
    sin_clasificar / total * 100
    if total
    else 0
)

print()
print("====================================================")
print(" MATRIZ CONSOLIDADA DE CONTROL - TALLER 04")
print("====================================================")
print(f"Total de hallazgos: {total}")
print()

for herramienta in [
    "Lynis",
    "OpenSCAP",
    "Docker Bench",
    "Trivy"
]:
    cantidad = sum(
        1
        for h in hallazgos
        if h["herramienta"] == herramienta
    )

    print(
        f"{herramienta}: {cantidad}"
    )

print()
print(
    f"Sin clasificar: "
    f"{sin_clasificar} "
    f"({porcentaje:.2f}%)"
)

print()
print("Archivo generado:")
print(csv_path)

print()
print("Estado de archivos fuente:")
print(
    f"Lynis: {'OK' if lynis.exists() else 'FALTA'}"
)
print(
    f"OpenSCAP: {'OK' if oscap.exists() else 'FALTA'}"
)
print(
    f"Docker Bench: "
    f"{'OK' if docker_log.exists() else 'FALTA'}"
)

trivy_archivos = list(EVID.glob("trivy*.json"))

print(
    f"Trivy JSON encontrados: "
    f"{len(trivy_archivos)}"
)