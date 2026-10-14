"""Print __version__ from misp-scraper.py, for the release workflow.

It parses the file rather than running it: running it needs the requirements
installed and a scraper.py to import.
"""
import ast
from pathlib import Path

source = Path(__file__).resolve().parent.parent / "misp-scraper.py"
for node in ast.parse(source.read_text()).body:
    if isinstance(node, ast.Assign) and [getattr(t, "id", None) for t in node.targets] == ["__version__"]:
        print(ast.literal_eval(node.value))
        break
else:
    raise SystemExit("misp-scraper.py has no __version__")
