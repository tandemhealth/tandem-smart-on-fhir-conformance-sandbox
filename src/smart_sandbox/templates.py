from pathlib import Path

from fastapi.templating import Jinja2Templates

# Jinja2 autoescaping stays on (the default for .html): everything rendered
# into the report pages is partner-supplied and untrusted.
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
