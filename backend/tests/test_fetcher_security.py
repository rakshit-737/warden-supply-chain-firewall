"""Security tests for the archive-extraction guards (Zip-Slip, bombs, symlinks)."""

import io
import tarfile
import zipfile

import pytest

from app.analysis.fetcher import RegistryFetcher, _is_unsafe_path
from app.core.errors import AnalysisError


def _tar_with(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_path_traversal_helper():
    assert _is_unsafe_path("../../etc/passwd")
    assert _is_unsafe_path("/abs/path")
    assert not _is_unsafe_path("pkg-1.0/mod.py")


def test_tar_path_traversal_rejected():
    fetcher = RegistryFetcher()
    archive = _tar_with([("pkg/../../evil.py", b"import os\n")])
    with pytest.raises(AnalysisError):
        fetcher._extract_tar(archive)


def test_tar_file_count_bomb_rejected(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "MAX_EXTRACTED_FILES", 5)
    fetcher = RegistryFetcher()
    archive = _tar_with([(f"pkg/f{i}.py", b"x=1\n") for i in range(20)])
    with pytest.raises(AnalysisError):
        fetcher._extract_tar(archive)


def test_tar_size_bomb_rejected(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "MAX_EXTRACTED_BYTES", 100)
    fetcher = RegistryFetcher()
    archive = _tar_with([("pkg/big.py", b"A" * 5000)])
    with pytest.raises(AnalysisError):
        fetcher._extract_tar(archive)


def test_only_interesting_files_kept():
    fetcher = RegistryFetcher()
    archive = _tar_with([
        ("pkg/mod.py", b"x=1\n"),
        ("pkg/data.bin", b"\x00\x01\x02"),
        ("pkg/README.md", b"# hi"),
    ])
    files = fetcher._extract_tar(archive)
    names = {f.relpath for f in files}
    assert "mod.py" in names
    assert "data.bin" not in names  # binary ignored


def test_zip_extraction_and_traversal():
    fetcher = RegistryFetcher()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("pkg/../evil.py", "import os")
    with pytest.raises(AnalysisError):
        fetcher._extract_zip(buf.getvalue())
