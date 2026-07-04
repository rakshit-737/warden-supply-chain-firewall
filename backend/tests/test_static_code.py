from app.analysis.analyzers.base import PackageContext, SourceFile
from app.analysis.analyzers.static_code import StaticCodeAnalyzer
from app.analysis.signals import Code

analyzer = StaticCodeAnalyzer()


def _ctx(text: str, name="mod.py") -> PackageContext:
    return PackageContext(
        ecosystem="pypi", name="x", version="1.0",
        files=[SourceFile(relpath=name, text=text, size=len(text))],
    )


def _codes(signals):
    return {s.code for s in signals}


def test_detects_credential_harvesting():
    src = "import os\nsecret = os.environ['AWS_SECRET_ACCESS_KEY']\n"
    codes = _codes(analyzer.analyze(_ctx(src)))
    assert Code.ENV_HARVEST in codes


def test_detects_subprocess_and_network():
    src = (
        "import subprocess, requests\n"
        "subprocess.Popen(['sh','-c','id'])\n"
        "requests.post('http://x/y', data={})\n"
    )
    codes = _codes(analyzer.analyze(_ctx(src)))
    assert Code.SUBPROCESS_EXEC in codes
    assert Code.NETWORK_EGRESS in codes


def test_detects_dynamic_exec():
    codes = _codes(analyzer.analyze(_ctx("exec('print(1)')\neval('2')\n")))
    assert Code.DYNAMIC_EXEC in codes


def test_clean_code_has_no_high_severity_signals():
    src = "def add(a, b):\n    return a + b\n"
    signals = analyzer.analyze(_ctx(src))
    assert Code.ENV_HARVEST not in _codes(signals)
    assert Code.SUBPROCESS_EXEC not in _codes(signals)
    assert Code.DYNAMIC_EXEC not in _codes(signals)


def test_unparseable_file_is_signal_not_crash():
    # Deliberately broken syntax must not raise.
    signals = analyzer.analyze(_ctx("def (:\n  pass"))
    assert Code.UNPARSEABLE in _codes(signals)


def test_sensitive_path_reference():
    src = "open('/home/user/.ssh/id_rsa').read()\n"
    assert Code.FS_SENSITIVE in _codes(analyzer.analyze(_ctx(src)))
