"""Offline image analysis over synthetic docker-save and OCI archives (built in memory)."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile

import pytest

from app.containers.image import ImageAnalyzer

FAKE_TOKEN = "gh" + "p_" + "F" * 36

DPKG = (
    "Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.36-9\n\n"
    "Package: removed-pkg\nStatus: deinstall ok config-files\nVersion: 1.0\n\n"
    "Package: openssl\nStatus: install ok installed\nVersion: 3.0.15-1\n"
)
APK = "P:busybox\nV:1.36.1-r29\n\nP:musl\nV:1.2.5-r0\n"
METADATA = "Metadata-Version: 2.1\nName: Requests\nVersion: 2.32.3\n\nlong description Name: bogus\n"


def tar_bytes(members: list[tuple], *, compress: bool = False) -> bytes:
    """members: (name, data | None, mode, type) with type in {"file", "dir", "symlink"}."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data, mode, kind in members:
            info = tarfile.TarInfo(name)
            info.mode = mode
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = data
                tar.addfile(info)
            else:
                payload = data if isinstance(data, bytes) else data.encode()
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
    raw = buffer.getvalue()
    return gzip.compress(raw) if compress else raw


def f(name, data="", mode=0o644):
    return (name, data, mode, "file")


def docker_save(layers: list[bytes], config: dict, tags=("demo:1.0",)) -> bytes:
    config_bytes = json.dumps(config).encode()
    config_name = hashlib.sha256(config_bytes).hexdigest() + ".json"
    members = [f(config_name, config_bytes)]
    layer_names = []
    for i, layer in enumerate(layers):
        name = f"layer{i}/layer.tar"
        members.append(f(name, layer))
        layer_names.append(name)
    manifest = [{"Config": config_name, "RepoTags": list(tags), "Layers": layer_names}]
    members.append(f("manifest.json", json.dumps(manifest)))
    return tar_bytes(members)


def base_config(user="app", env=()):
    return {"architecture": "amd64", "os": "linux",
            "config": {"User": user, "Env": list(env), "ExposedPorts": {"8080/tcp": {}}}}


def codes(report):
    return sorted(x.code for x in report.findings)


def test_packages_config_and_clean_verdict():
    layer0 = tar_bytes([f("var/lib/dpkg/status", DPKG), f("lib/apk/db/installed", APK)])
    layer1 = tar_bytes([f("usr/lib/python3/site-packages/requests-2.32.3.dist-info/METADATA", METADATA)])
    report = ImageAnalyzer().analyze(docker_save([layer0, layer1], base_config()))
    assert report.complete and codes(report) == []
    assert report.image_refs == ["demo:1.0"] and report.architecture == "amd64" and report.user == "app"
    assert report.exposed_ports == ["8080/tcp"] and report.layer_count == 2
    assert report.config_digest.startswith("sha256:")
    names = {(c.type, c.name, c.version) for c in report.components}
    assert names == {("deb", "libc6", "2.36-9"), ("deb", "openssl", "3.0.15-1"), ("apk", "busybox", "1.36.1-r29"),
                     ("apk", "musl", "1.2.5-r0"), ("pypi", "Requests", "2.32.3")}
    purls = {c.purl for c in report.components}
    assert "pkg:pypi/requests@2.32.3" in purls and "pkg:deb/debian/libc6@2.36-9?arch=amd64" in purls
    assert report.to_dict()["component_counts"] == {"apk": 2, "deb": 2, "pypi": 1}


def test_root_user_and_environment_secrets_are_reported_without_values():
    config = base_config(user="", env=["PATH=/usr/bin", f"GH_TOKEN={FAKE_TOKEN}", "DB_PASSWORD=hunter2hunter2"])
    report = ImageAnalyzer().analyze(docker_save([tar_bytes([f("etc/hostname", "x")])], config))
    assert codes(report) == ["DOCKERFILE_ROOT_USER", "DOCKERFILE_SECRET_IN_ENV", "DOCKERFILE_SECRET_IN_ENV"]
    dumped = json.dumps(report.to_dict())
    assert FAKE_TOKEN not in dumped and "hunter2" not in dumped


def test_whiteouts_remove_packages_from_earlier_layers():
    layer0 = tar_bytes([
        f("usr/lib/python3/site-packages/requests-2.32.3.dist-info/METADATA", METADATA),
        f("opt/app/lib/site-packages/evil-1.0.dist-info/METADATA", "Name: evil\nVersion: 1.0\n"),
        f("var/lib/dpkg/status", DPKG),
    ])
    layer1 = tar_bytes([
        f("usr/lib/python3/site-packages/.wh.requests-2.32.3.dist-info"),
        f("opt/app/lib/.wh..wh..opq"),
    ])
    report = ImageAnalyzer().analyze(docker_save([layer0, layer1], base_config()))
    assert {c.type for c in report.components} == {"deb"}


def test_later_package_database_replaces_earlier_one():
    layer0 = tar_bytes([f("lib/apk/db/installed", APK)])
    layer1 = tar_bytes([f("lib/apk/db/installed", "P:musl\nV:1.2.5-r1\n")])
    report = ImageAnalyzer().analyze(docker_save([layer0, layer1], base_config()))
    assert [(c.name, c.version, c.layer) for c in report.components] == [("musl", "1.2.5-r1", 1)]


def test_secrets_in_files_and_setuid_binaries():
    layer = tar_bytes([
        f("app/settings.py", f"TOKEN = '{FAKE_TOKEN}'\n"),
        f("usr/bin/su", b"\x7fELF" + b"\0" * 20, mode=0o4755),
        f("usr/share/doc/readme.txt", "nothing here"),
    ])
    report = ImageAnalyzer().analyze(docker_save([layer], base_config()))
    by_code = {x.code: x for x in report.findings}
    assert by_code["SECRET_DETECTED"].location.file == "app/settings.py"
    assert by_code["CONTAINER_MISCONFIG"].evidence["paths"] == ["usr/bin/su"]
    assert FAKE_TOKEN not in json.dumps(report.to_dict())


def test_hostile_layer_marks_the_report_incomplete():
    evil = tar_bytes([f("../../etc/cron.d/x", "* * * * * root sh")])
    report = ImageAnalyzer().analyze(docker_save([evil], base_config()))
    assert not report.complete and "EXTRACTION_ABORTED" in codes(report)


def test_oversized_layer_is_not_silently_skipped():
    big = tar_bytes([f("blob.bin", b"\0" * 300_000)])
    report = ImageAnalyzer(max_layer_bytes=100_000).analyze(docker_save([big], base_config()))
    assert not report.complete
    assert any(x.evidence.get("reason") == "layer_not_retained" for x in report.findings)


@pytest.mark.parametrize("payload", [b"not an archive", tar_bytes([f("readme.md", "hello")])],
                         ids=["garbage", "plain-tar"])
def test_non_image_input_fails_closed(payload):
    report = ImageAnalyzer().analyze(payload)
    assert not report.complete and codes(report) == ["EXTRACTION_ABORTED"]


def test_size_limit_is_enforced_before_reading():
    report = ImageAnalyzer(max_image_bytes=10).analyze(b"x" * 11)
    assert not report.complete and report.findings[0].evidence["reason"] == "image_too_large"


def test_oci_layout_with_gzip_layers():
    layer = tar_bytes([f("lib/apk/db/installed", APK)], compress=True)
    config = json.dumps(base_config(user="1000")).encode()

    def blob(data: bytes) -> tuple[str, str]:
        digest = hashlib.sha256(data).hexdigest()
        return f"sha256:{digest}", f"blobs/sha256/{digest}"

    layer_digest, layer_path = blob(layer)
    config_digest, config_path = blob(config)
    manifest = json.dumps({"schemaVersion": 2, "config": {"digest": config_digest},
                           "layers": [{"digest": layer_digest}]}).encode()
    manifest_digest, manifest_path = blob(manifest)
    index = {"schemaVersion": 2, "manifests": [{
        "digest": manifest_digest, "annotations": {"org.opencontainers.image.ref.name": "demo:oci"}}]}
    archive = tar_bytes([
        f("oci-layout", '{"imageLayoutVersion": "1.0.0"}'), f("index.json", json.dumps(index)),
        f(manifest_path, manifest), f(config_path, config), f(layer_path, layer),
    ])
    report = ImageAnalyzer().analyze(archive, "image.tar")
    assert report.complete, report.findings
    assert report.image_refs == ["demo:oci"] and report.user == "1000"
    assert [c.name for c in report.components] == ["busybox", "musl"]
    assert codes(report) == []
