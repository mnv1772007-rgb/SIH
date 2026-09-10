"""Convenience launcher and app re-export for the Email Threat Forensics platform.

Importing this module exposes the ``app`` FastAPI instance so tests can do::

    from main import app

Running ``python main.py`` starts the development server.
"""

from Backend.main import app  # noqa: F401 – re-export for test imports

import uvicorn


if __name__ == "__main__":
    uvicorn.run("Backend.main:app", host="127.0.0.1", port=8000, reload=True)
