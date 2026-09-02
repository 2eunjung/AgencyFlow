# Agency Flow PythonAnywhere Deployment

## Files to upload
Upload the contents of this `outputs` folder to your PythonAnywhere project directory.

Required runtime files:
- `wsgi.py`
- `sqlite_server.py`
- `templates/`
- `pages/`
- `static/`
- `projects.sqlite3`
- `projects.secret`

Keep these private and do not put them in a public GitHub repository:
- `projects.sqlite3`
- `projects.secret`

## PythonAnywhere Web setup
1. Create a PythonAnywhere account.
2. Go to **Web**.
3. Add a new web app.
4. Choose **Manual configuration**.
5. Choose Python 3.x.
6. In the WSGI configuration file, replace the contents with:

```python
import sys
from pathlib import Path

project_home = Path('/home/YOUR_USERNAME/agency-flow')
if str(project_home) not in sys.path:
    sys.path.insert(0, str(project_home))

from wsgi import application
```

Change `YOUR_USERNAME` and `agency-flow` to your actual PythonAnywhere path.

## Static files
In the PythonAnywhere **Web > Static files** section, add:

- URL: `/static/`
- Directory: `/home/YOUR_USERNAME/agency-flow/static/`

The WSGI app can also serve `/static/`, but the PythonAnywhere static mapping is faster and cheaper.

## Database
This deployment keeps SQLite.

- Main DB file: `projects.sqlite3`
- Encryption secret: `projects.secret`

Back up both files together. If `projects.secret` is lost, encrypted user IDs/names cannot be recovered.

## Reload
After uploading files or changing WSGI settings, click **Reload** on the PythonAnywhere Web page.

## URL
Open:

`https://YOUR_USERNAME.pythonanywhere.com/agencyflow.html`

## Notes
- Login sessions are stored in server memory, so they reset when PythonAnywhere reloads the app.
- SQLite is suitable for small internal use. If many users edit at the same time, move to PostgreSQL later.
- Change the default admin password after first login.
