import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_conformance_matrix_passes():
    """Slow, but this is the check the whole format governance strategy rests on."""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts/conformance_matrix.py")],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,  # a non-zero exit is the thing under test
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
