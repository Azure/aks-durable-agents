"""Offline artifact-builder admission tests; no Docker or cluster side effects."""
import tempfile
import unittest
from pathlib import Path

import images


class ImageInputs(unittest.TestCase):
    def test_compact_definition_retains_suite_pins_but_not_showcase_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            canvas = root / "canvas"
            layouts = canvas / "examples/release-review/layouts"
            for role in ("writer", "reviewer"):
                (layouts / role).mkdir(parents=True)
                (layouts / role / "marker").write_text(role)
            selected = images.materialize_definition(canvas, root / "artifact", "compact")
            self.assertTrue(selected.is_file())
            self.assertIn("compact-native-proof", selected.read_text())
            self.assertNotIn("schema:", selected.read_text())
            for role in ("writer", "reviewer"):
                self.assertEqual((selected.parent / "layouts" / role / "marker").read_text(), role)
            with self.assertRaises(ValueError):
                images.materialize_definition(canvas, root / "other", "unknown")

    def test_new_external_directory_and_real_canvas_layout_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            canvas = root / "canvas"
            canvas.mkdir()
            out = root / "artifacts"
            with self.assertRaises(ValueError):
                images.check_paths(canvas, out)
            (canvas / "go.mod").write_text("module fixture\n")
            (canvas / "examples/release-review").mkdir(parents=True)
            (canvas / "examples/release-review/canvas.yaml").write_text("fixture")
            images.check_paths(canvas, out)
            self.assertFalse(out.exists(), "admission mutated output")
            for invalid in (canvas / "build", images.REPO / "build", root):
                with self.subTest(path=invalid), self.assertRaises(ValueError):
                    images.check_paths(canvas, invalid)
            out.mkdir()
            with self.assertRaises(ValueError):
                images.check_paths(canvas, out)


if __name__ == "__main__":
    unittest.main()
