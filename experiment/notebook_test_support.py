"""Execute all cells, using a fresh kernel where kernel sockets are permitted."""

import os
from pathlib import Path


def execute_notebook(notebook, root):
    use_kernel = os.environ.get("CWE_NOTEBOOK_TEST_MODE") != "inprocess"
    if not use_kernel:
        # Restricted runners cannot start Jupyter sockets. Execute every plain
        # Python cell in order; CI with sockets uses a real kernel below.
        from IPython.display import display

        scope = {"display": display}
        previous = Path.cwd()
        try:
            os.chdir(root)
            for index, cell in enumerate(notebook.cells):
                if cell.cell_type == "code":
                    exec(
                        compile(cell.source, f"<notebook-cell-{index}>", "exec"), scope
                    )
        finally:
            os.chdir(previous)
        return scope
    from nbclient import NotebookClient

    NotebookClient(
        notebook,
        timeout=120,
        kernel_name="python3",
        resources={"metadata": {"path": str(root)}},
    ).execute()
    return None
