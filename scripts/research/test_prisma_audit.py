"""Pruebas de consistencia para la conciliación documental de F0."""

import csv
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prisma_audit


class PrismaAuditTests(unittest.TestCase):
    """Comprueba que las claves no se conviertan en decisiones editoriales."""

    def test_normalize_doi(self):
        self.assertEqual(prisma_audit.normalize_doi("HTTPS://DOI.ORG/10.1234/AbC "), "10.1234/abc")
        self.assertEqual(prisma_audit.normalize_doi("doi:10.12/XYZ"), "10.12/xyz")

    def test_normalize_title(self):
        self.assertEqual(prisma_audit.normalize_title("Análisis: de Grafos"), "analisis de grafos")
        self.assertEqual(prisma_audit.normalize_title("Grafos - procesos"), "grafos procesos")

    def test_catalog_integrity(self):
        rows, summary = prisma_audit.generate_audit()
        self.assertEqual(len(rows), 9)
        self.assertEqual(summary["fichas_catalogo_f0_02"], 20)
        self.assertEqual(summary["obras_cientificas_candidatas"], 15)
        self.assertEqual(summary["decisiones_finales_de_inclusion"], 0)
        prisma_audit.verify_outputs(rows, summary)

    def test_original_sources_not_modified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            raw = root / "originales"
            raw.mkdir()
            csv_path = raw / "scopus.csv"
            content = 'Title,DOI\n"Título uno",10.1234/x\n"Título uno",https://doi.org/10.1234/X\n'
            csv_path.write_text(content, encoding="utf-8")
            output = root / "informe.csv"
            prisma_audit.inspect_exports(raw, output)
            self.assertEqual(csv_path.read_text(encoding="utf-8"), content)
            with output.open(newline="", encoding="utf-8") as handle:
                items = list(csv.DictReader(handle))
            self.assertEqual(len(items), 2)
            self.assertEqual([item["registros_misma_clave"] for item in items], ["2", "2"])

    def test_missing_export_headers(self):
        with tempfile.TemporaryDirectory() as temp:
            raw = Path(temp) / "originales"
            raw.mkdir()
            (raw / "sin_titulo.csv").write_text("Year,DOI\n2025,10.12/x\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "columna de título"):
                prisma_audit.inspect_exports(raw, Path(temp) / "reporte.csv")


if __name__ == "__main__":
    unittest.main()
