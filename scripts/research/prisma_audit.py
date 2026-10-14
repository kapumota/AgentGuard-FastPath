#!/usr/bin/env python3
"""Audita la conciliación bibliográfica sin alterar registros originales."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path


BASE = Path(__file__).resolve().parents[2]
DATA = BASE / "docs" / "research"


def load_csv(path: Path) -> list[dict[str, str]]:
    """Carga un CSV sin modificar sus valores originales."""
    if not path.exists():
        raise ValueError(f"No existe el archivo requerido: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def normalize_doi(value: str) -> str:
    """Normaliza únicamente los prefijos reconocidos de un DOI."""
    value = value.strip().lower()
    value = re.sub(r"^https?://(?:dx\.)?doi\.org/", "", value)
    value = re.sub(r"^doi\s*:\s*", "", value)
    return value.strip()


def normalize_title(value: str) -> str:
    """Genera una clave comparable sin decidir equivalencia editorial."""
    folded = unicodedata.normalize("NFKD", value.casefold())
    folded = "".join(c for c in folded if not unicodedata.combining(c))
    return " ".join(re.findall(r"[a-z0-9]+", folded))


def ensure_unique(rows: list[dict[str, str]], key: str, label: str) -> None:
    ids = [item[key].strip() for item in rows]
    if len(ids) != len(set(ids)) or any(not value for value in ids):
        raise ValueError(f"Identificadores ausentes o repetidos en {label}: {key}")


def generate_audit() -> tuple[list[dict[str, str]], dict[str, object]]:
    """Produce resultados deterministas a partir del catálogo y la conciliación."""
    catalog = load_csv(DATA / "BIBLIOGRAPHIC_RECORDS.csv")
    seeds = load_csv(DATA / "REFERENCES_SEED.csv")
    mapping = load_csv(DATA / "F0_03_DEDUP_CROSSWALK.csv")
    screening = load_csv(DATA / "F0_03_SCREENING_FORM.csv")
    existing = load_csv(DATA / "SCREENING_LOG.csv")
    matrix = load_csv(DATA / "EVIDENCE_MATRIX.csv")
    ensure_unique(catalog, "id_obra", "catálogo bibliográfico")
    ensure_unique(seeds, "id", "semillas F0-01")
    ensure_unique(mapping, "id_semilla", "conciliación F0-03")
    ensure_unique(screening, "id_obra", "formulario F0-03")
    ensure_unique(matrix, "id_obra", "matriz de evidencia")
    ensure_unique(existing, "id_registro", "cribado anterior")
    cindex = {row["id_obra"]: row for row in catalog}
    sindex = {row["id"]: row for row in seeds}
    actual = set(cindex)
    groups = Counter(row["categoria"] for row in catalog)
    if groups != Counter({"estudio": 15, "guia_metodologica": 2, "artefacto": 3}):
        raise ValueError(f"Clasificación del catálogo distinta de la línea base: {groups}")
    if set(row["id_obra"] for row in matrix) != {key for key in actual if key.startswith("R")}:
        raise ValueError("La matriz no coincide con los estudios del catálogo")
    if set(row["id_obra"] for row in screening) != {key for key in actual if key.startswith("R")}:
        raise ValueError("El formulario F0-03 debe cubrir los 15 estudios")
    if {row["id_semilla"] for row in mapping} != set(sindex):
        raise ValueError("No se han conciliado todas las semillas de F0-01")
    if {row["id_obra"] for row in existing} != actual:
        raise ValueError("SCREENING_LOG.csv no corresponde al catálogo completo")
    for row in screening:
        if row["decision_final"].strip() or row["motivo_exclusion_final"].strip():
            raise ValueError("No registrar decisiones finales sin cribado humano documentado")
        if row["validacion_humana"] != "pendiente" or row["texto_completo"] != "pendiente":
            raise ValueError("F0-03 no certifica revisión humana ni lectura completa")
    collisions = []
    by_doi: dict[str, list[str]] = defaultdict(list)
    by_title: dict[str, list[str]] = defaultdict(list)
    for row in catalog:
        if row["doi"]:
            by_doi[normalize_doi(row["doi"])].append(row["id_obra"])
        by_title[normalize_title(row["titulo"])].append(row["id_obra"])
    for method, groupset in (("doi", by_doi), ("titulo", by_title)):
        for key, ids in groupset.items():
            if key and len(ids) > 1:
                collisions.append({"criterio": method, "clave": key, "ids": ids})
    if collisions:
        raise ValueError(f"El catálogo contiene colisiones por revisar: {collisions}")
    audit = []
    for row in mapping:
        sid, cid = row["id_semilla"], row["id_canonico"]
        if cid not in cindex:
            raise ValueError(f"El identificador canónico no existe: {cid}")
        a, b = sindex[sid], cindex[cid]
        doi_a, doi_b = normalize_doi(a["doi"]), normalize_doi(b["doi"])
        same_doi = bool(doi_a and doi_a == doi_b)
        same_title = normalize_title(a["titulo"]) == normalize_title(b["titulo"])
        if row["tipo_relacion"] == "mismo_doi" and not same_doi:
            raise ValueError(f"DOI discrepante en relación exacta: {sid} / {cid}")
        if row["tipo_relacion"] == "version_editorial" and not same_title:
            raise ValueError(f"La versión editorial requiere revisión: {sid} / {cid}")
        audit.append({
            "id_semilla": sid, "id_canonico": cid,
            "tipo_relacion": row["tipo_relacion"],
            "doi_coincidente": "si" if same_doi else "no",
            "titulo_coincidente": "si" if same_title else "no",
            "estado_documental": row["estado_documental"],
        })
    summary: dict[str, object] = {
        "alcance": "conciliacion_catalogo_dirigido_no_flujo_prisma",
        "referencias_semilla_f0_01": len(seeds),
        "fichas_catalogo_f0_02": len(catalog),
        "relaciones_semilla_catalogo": len(mapping),
        "obras_cientificas_candidatas": groups["estudio"],
        "guias_metodologicas": groups["guia_metodologica"],
        "artefactos": groups["artefacto"],
        "duplicados_por_doi_en_catalogo": 0,
        "duplicados_por_titulo_en_catalogo": 0,
        "decisiones_finales_de_inclusion": 0,
        "exportaciones_formales_integradas": 0,
        "prisma_final": "pendiente",
    }
    return audit, summary


def write_outputs(audit: list[dict[str, str]], summary: dict[str, object]) -> None:
    """Escribe únicamente los dos artefactos derivados declarados."""
    path = DATA / "F0_03_DEDUP_AUDIT.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "id_semilla", "id_canonico", "tipo_relacion", "doi_coincidente",
            "titulo_coincidente", "estado_documental",
        ], lineterminator="\n")
        writer.writeheader()
        writer.writerows(audit)
    (DATA / "F0_03_DEDUP_SUMMARY.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def verify_outputs(audit: list[dict[str, str]], summary: dict[str, object]) -> None:
    """Evita informes derivados que no concuerdan con sus fuentes."""
    path = DATA / "F0_03_DEDUP_AUDIT.csv"
    if load_csv(path) != audit:
        raise ValueError("F0_03_DEDUP_AUDIT.csv no coincide con los registros fuente")
    saved = json.loads((DATA / "F0_03_DEDUP_SUMMARY.json").read_text(encoding="utf-8"))
    if saved != summary:
        raise ValueError("F0_03_DEDUP_SUMMARY.json no coincide con los registros fuente")


def inspect_exports(directory: Path, output: Path) -> None:
    """Inspecciona exportaciones CSV independientes, sin eliminarlas ni contarlas como PRISMA final."""
    if not directory.is_dir():
        raise ValueError(f"Directorio de exportaciones inexistente: {directory}")
    files = sorted(directory.glob("*.csv"))
    if not files:
        raise ValueError("No hay archivos CSV para inspeccionar")
    records: list[dict[str, str]] = []
    for file in files:
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        with file.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                raise ValueError(f"La exportación no contiene encabezados: {file.name}")
            cols = {normalize_title(col).replace(" ", ""): col for col in reader.fieldnames}
            doi_col = cols.get("doi") or cols.get("digitalobjectidentifier")
            title_col = cols.get("title") or cols.get("documenttitle") or cols.get("titulo")
            if title_col is None:
                raise ValueError(f"No se reconoce la columna de título: {file.name}")
            for index, row in enumerate(reader, start=2):
                title = (row.get(title_col) or "").strip()
                doi = normalize_doi((row.get(doi_col) or "") if doi_col else "")
                if not title and not doi:
                    raise ValueError(f"Registro vacío en {file.name}:{index}")
                records.append({
                    "fuente_csv": file.name, "fila_original": str(index),
                    "sha256_fuente": digest, "doi": doi, "titulo": title,
                    "clave_duplicado": "doi:" + doi if doi else "titulo:" + normalize_title(title),
                })
    if not records:
        raise ValueError("Las exportaciones no contienen registros")
    count = Counter(item["clave_duplicado"] for item in records)
    for item in records:
        item["registros_misma_clave"] = str(count[item["clave_duplicado"]])
        item["decision_automatica"] = "revision_manual" if count[item["clave_duplicado"]] > 1 else "sin_colision_de_clave"
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.resolve().parent == directory.resolve():
        raise ValueError("El informe debe escribirse fuera del directorio de exportaciones originales")
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    print(f"Exportaciones inspeccionadas: {len(files)}. Registros: {len(records)}.")
    print(f"Posibles duplicados de clave: {sum(n - 1 for n in count.values() if n > 1)}.")
    print("Este conteo aún no es un diagrama PRISMA. Revisar manualmente versiones y metadatos.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Auditar referencias y relaciones de F0")
    parser.add_argument("--generate", action="store_true", help="Regenerar informes del catálogo")
    parser.add_argument("--check", action="store_true", help="Verificar consistencia de informes")
    parser.add_argument("--inspect-exports", type=Path, help="Directorio con exportaciones CSV originales")
    parser.add_argument("--output", type=Path, help="Ruta del informe de exportaciones")
    args = parser.parse_args()
    try:
        if args.inspect_exports is not None:
            if args.output is None:
                parser.error("--inspect-exports requiere --output")
            inspect_exports(args.inspect_exports, args.output)
            return 0
        if not args.generate and not args.check:
            parser.error("Indicar --check, --generate o --inspect-exports")
        audit, summary = generate_audit()
        if args.generate:
            write_outputs(audit, summary)
        if args.check:
            verify_outputs(audit, summary)
        print("Conciliación F0 comprobada.")
        print(f"Referencias semilla: {summary['referencias_semilla_f0_01']}.")
        print(f"Fichas dirigidas únicas: {summary['fichas_catalogo_f0_02']}.")
        print("Cribado completo y cifras PRISMA: pendientes.")
        return 0
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR DE VALIDACIÓN: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
