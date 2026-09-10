"""
ml/ namespace package shim.
Allows importing ml.features, ml.models, ml.eval, ml.scoring, ml.serve, ml.data
directly from the repository root.
"""
from pathlib import Path

__path__ = [str(Path(__file__).parent.parent.resolve())]
