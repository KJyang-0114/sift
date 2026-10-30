import os
from pathlib import Path


def read(user_path, base, name):
    # ruleid: sift.path-traversal-file-op
    open(user_path)
    # ruleid: sift.path-traversal-file-op
    os.path.join(base, name)
    # ok: sift.path-traversal-file-op
    open("settings.json")
    # ok: sift.path-traversal-file-op
    os.path.join(os.path.dirname(__file__), "static")
    # ok: sift.path-traversal-file-op
    open(Path(__file__).parent / "settings.json")
