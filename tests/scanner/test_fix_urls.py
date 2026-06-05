"""Ověř, že žádný scanner modul nedrží hardcoded /guide/#anchor — vše jde přes guide_url()."""
import re
from pathlib import Path


SCANNER_MODULES_DIR = Path(__file__).parent.parent.parent / "scanner" / "modules"


class TestNoHardcodedGuideUrls:
    def test_no_hardcoded_guide_anchor_strings(self):
        """Žádný .py soubor v scanner/modules nesmí obsahovat string '/guide/#'."""
        pattern = re.compile(r'"/guide/#')
        offenders = []
        for py in SCANNER_MODULES_DIR.glob("*.py"):
            if py.name in ("__init__.py", "base.py"):
                continue
            text = py.read_text()
            if pattern.search(text):
                offenders.append(py.name)
        assert not offenders, (
            f"Tyto moduly mají hardcoded fix_url='/guide/#…' a měly by používat guide_url(): "
            f"{offenders}"
        )

    def test_guide_url_helper_imported_where_needed(self):
        """Každý modul, který používá guide_url(...), si ho musí naimportovat."""
        for py in SCANNER_MODULES_DIR.glob("*.py"):
            if py.name in ("__init__.py", "base.py"):
                continue
            text = py.read_text()
            if "guide_url(" in text:
                # Accept both 'from .base import ... guide_url' and 'from scanner.modules.base import ... guide_url'
                has_import = (
                    ("from .base import" in text or "from scanner.modules.base import" in text)
                    and "guide_url" in text.split("class ")[0]  # import must appear before first class
                )
                assert has_import, f"{py.name} používá guide_url() ale neimportuje ho"
