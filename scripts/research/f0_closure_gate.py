#!/usr/bin/env python3
"""Comprueba evidencias estructurales para el cierre documental de F0."""

from __future__ import annotations

import csv
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs" / "research"

PENDING = {"", "pendiente", "sin_revisar"}
FINAL_DECISIONS = {"incluir", "excluir", "no_recuperado"}


def load_csv(path: Path) -> list[dict[str, str]]:
    """Lee registros CSV sin alterar su contenido."""
    if not path.is_file():
        raise ValueError(f"Falta el archivo: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        return list(reader)


def verify_manifest(rows: list[dict[str, str]], root: Path) -> list[str]:
    """Valida los archivos conservados con hashes y procedencia."""
    findings: list[str] = []
    if not rows:
        return ["Faltan exportaciones documentadas de fuentes bibliográficas."]
    seen: set[str] = set()
    for i, row in enumerate(rows, 2):
        record_id = row.get("id_exportacion", "").strip()
        if not record_id or record_id in seen:
            findings.append(f"Identificador ausente o repetido en manifiesto, fila {i}.")
        seen.add(record_id)
        for key in ("fuente", "fecha", "cadena_literal", "registros_reportados"):
            if not row.get(key, "").strip():
                findings.append(f"Manifiesto, fila {i}, campo requerido: {key}.")
        count = row.get("registros_reportados", "").strip()
        if count and (not count.isdigit()):
            findings.append(f"Recuento inválido en manifiesto, fila {i}.")
        rel = row.get("ruta_relativa", "").strip()
        digest = row.get("sha256", "").strip().lower()
        if not rel or not digest:
            findings.append(f"Falta ruta o hash en manifiesto, fila {i}.")
            continue
        path = (root / rel).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError:
            findings.append(f"La ruta sale del repositorio, fila {i}.")
            continue
        if not path.is_file():
            findings.append(f"No se encuentra la exportación declarada: {rel}.")
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            findings.append(f"SHA-256 inválido en manifiesto, fila {i}.")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            findings.append(f"Hash distinto al declarado: {rel}.")
    return findings


def verify_fulltexts(rows: list[dict[str, str]], candidate_ids: set[str]) -> list[str]:
    """Comprueba que cada candidato tiene una decisión verificable."""
    findings: list[str] = []
    ids = [row.get("id_obra", "").strip() for row in rows]
    if len(ids) != len(set(ids)):
        findings.append("Hay identificadores repetidos en lectura de textos completos.")
    if set(ids) != candidate_ids:
        findings.append("El registro de textos completos no cubre todos los candidatos.")
    for row in rows:
        ident = row.get("id_obra", "").strip() or "sin_identificador"
        status = row.get("estado_recuperacion", "").strip().lower()
        reading = row.get("estado_lectura", "").strip().lower()
        decision = row.get("decision_final", "").strip().lower()
        reviewer = row.get("revisor_humano", "").strip()
        review_date = row.get("fecha_decision", "").strip()
        if status in PENDING:
            findings.append(f"Recuperación pendiente: {ident}.")
        if reading in PENDING:
            findings.append(f"Lectura pendiente: {ident}.")
        if decision not in FINAL_DECISIONS:
            findings.append(f"Decisión pendiente o inválida: {ident}.")
        if not reviewer or not review_date:
            findings.append(f"Falta validación humana fechada: {ident}.")
        if decision in {"excluir", "no_recuperado"} and not row.get("motivo_exclusion", "").strip():
            findings.append(f"Falta motivo de exclusión: {ident}.")
    return findings


def assess(root: Path = ROOT, docs: Path = DOCS) -> list[str]:
    """Produce una relación de bloqueos, no un dictamen científico automático."""
    problems: list[str] = []
    manifest = load_csv(docs / "F0_04_EXPORT_MANIFEST.csv")
    fulltexts = load_csv(docs / "F0_04_FULLTEXT_LOG.csv")
    catalog = load_csv(docs / "BIBLIOGRAPHIC_RECORDS.csv")
    candidates = {x["id_obra"].strip() for x in catalog if x["categoria"] == "estudio"}
    problems.extend(verify_manifest(manifest, root))
    problems.extend(verify_fulltexts(fulltexts, candidates))
    flow = (docs / "PRISMA_FLOW.md").read_text(encoding="utf-8")
    if any(re.search(r"^\|[^|]+\|\s*PENDIENTE\s*\|", line, re.I)
           for line in flow.splitlines()):
        problems.append("PRISMA_FLOW.md contiene casillas pendientes.")
    matrix = load_csv(docs / "EVIDENCE_MATRIX.csv")
    if any("titulo_y_resumen" in row.get("estado_lectura", "") for row in matrix):
        problems.append("La matriz de evidencia conserva lecturas preliminares.")
    return problems


def main() -> int:
    """Muestra si faltan evidencias estructurales para revisar F0."""
    try:
        problems = assess()
    except (ValueError, OSError, KeyError, csv.Error) as exc:
        print(f"F0 BLOQUEADO: {exc}")
        return 2
    if problems:
        print("F0 BLOQUEADO: faltan evidencias de cierre documental.")
        for item in problems:
            print(f"- {item}")
        return 1
    print("F0: comprobaciones estructurales satisfactorias.")
    print("La aprobación científica y el dictamen humano siguen siendo obligatorios.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
