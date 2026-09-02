import sys
from pathlib import Path

project_home = Path('/home/YOUR_USERNAME/agency-flow')
if str(project_home) not in sys.path:
    sys.path.insert(0, str(project_home))

from wsgi import application
