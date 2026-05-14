import requests
import pandas as pd
from datetime import datetime

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def obtener_vulnerabilidades():
    response = requests.get(URL, timeout=30)
    response.raise_for_status()
    data = response.json()
    return data.get("vulnerabilities", [])

def obtener_cvss(cve_id):
    try:
        response = requests.get(
            NVD_URL,
            params={"cveId": cve_id},
            timeout=30
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilidades = data.get("vulnerabilities", [])

        if not vulnerabilidades:
            return "", ""

        cve = vulnerabilidades[0].get("cve", {})
        metrics = cve.get("metrics", {})

        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:

            if version in metrics:

                cvss = metrics[version][0]

                score = cvss["cvssData"].get("baseScore", "")

                severity = cvss["cvssData"].get("baseSeverity", "")

                return score, severity

        return "", ""

    except Exception:
        return "", ""

def generar_excel(vulnerabilidades):

    registros = []

    for vuln in vulnerabilidades:

        cve_id = vuln.get("cveID", "")

        cvss, severidad = obtener_cvss(cve_id)

        registros.append({

            "CVE": cve_id,
            "Proveedor": vuln.get("vendorProject", ""),
            "Producto": vuln.get("product", ""),
            "Vulnerabilidad": vuln.get("vulnerabilityName", ""),
            "Fecha": vuln.get("dateAdded", ""),
            "Descripción": vuln.get("shortDescription", ""),
            "Acción requerida": vuln.get("requiredAction", ""),
            "CVSS": cvss,
            "Severidad": severidad,
            "Ransomware": vuln.get("knownRansomwareCampaignUse", "")

        })

    df = pd.DataFrame(registros)

    archivo = f"vulnerabilidades_cisa_cvss_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

    df.to_excel(archivo, index=False)

    print(f"Excel generado correctamente: {archivo}")
    print(f"Total vulnerabilidades: {len(df)}")

def main():

    print("Recopilando vulnerabilidades desde CISA y enriqueciendo con NVD...")

    vulnerabilidades = obtener_vulnerabilidades()

    generar_excel(vulnerabilidades)

if __name__ == "__main__":
    main()