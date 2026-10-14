#!/usr/bin/env python3
"""Prueba controles estructurales de F0 con datos aislados."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from f0_closure_gate import verify_fulltexts, verify_manifest


class ClosureGateTest(unittest.TestCase):
    """Verifica condiciones de entrada y bloqueo."""

    def test_manifest_without_exports_is_blocked(self) -> None:
        """Sin archivos originales no se permite declarar cierre."""
        self.assertTrue(verify_manifest([], Path(".")))

    def test_manifest_with_matching_hash(self) -> None:
        """Una exportación íntegra supera el control de hash."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            content = b"registro,doi\nA,10.1000/a\n"
            (root / "export.csv").write_bytes(content)
            row = {
                "id_exportacion": "E001",
                "fuente": "fuente_de_prueba",
                "fecha": "2026-10-14",
                "cadena_literal": "consulta de prueba",
                "registros_reportados": "1",
                "ruta_relativa": "export.csv",
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            self.assertEqual([], verify_manifest([row], root))

    def test_manifest_with_modified_file_is_blocked(self) -> None:
        """El hash debe detectar cambios posteriores a la exportación."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "export.csv").write_text("contenido cambiado", encoding="utf-8")
            row = {
                "id_exportacion": "E001",
                "fuente": "fuente_de_prueba",
                "fecha": "2026-10-14",
                "cadena_literal": "consulta de prueba",
                "registros_reportados": "1",
                "ruta_relativa": "export.csv",
                "sha256": "0" * 64,
            }
            self.assertTrue(verify_manifest([row], root))

    def test_pending_fulltext_is_blocked(self) -> None:
        """El formulario vacío no acredita revisión humana."""
        self.assertTrue(verify_fulltexts([], {"R001"}))

    def test_reviewed_fulltext_requires_exclusion_reason(self) -> None:
        """Una exclusión final necesita un motivo documentado."""
        item = {
            "id_obra": "R001",
            "estado_recuperacion": "recuperado",
            "estado_lectura": "completado",
            "decision_final": "excluir",
            "motivo_exclusion": "",
            "revisor_humano": "revisor_1",
            "fecha_decision": "2026-10-14",
        }
        self.assertTrue(verify_fulltexts([item], {"R001"}))


if __name__ == "__main__":
    unittest.main()
