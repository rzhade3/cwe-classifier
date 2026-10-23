import unittest
from pathlib import Path

import nbformat

from experiment.notebook_test_support import execute_notebook


class NotebookTests(unittest.TestCase):
    def test_committed_notebooks_have_no_stale_outputs(self):
        for path in Path("experiment").glob("*.ipynb"):
            notebook = nbformat.read(path, as_version=4)
            nbformat.validate(notebook)
            for cell in notebook.cells:
                if cell.cell_type == "code":
                    self.assertEqual(cell.outputs, [], str(path))
                    self.assertIsNone(cell.execution_count, str(path))

    def test_hypotheses_run_without_api_calls_or_prepared_benchmark(self):
        notebook = nbformat.read("experiment/hypotheses.ipynb", as_version=4)
        execute_notebook(notebook, Path.cwd())
