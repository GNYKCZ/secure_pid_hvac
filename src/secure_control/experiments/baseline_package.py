"""人工基线的有界ZIP结果容器；只读取白名单文件，不解包执行内容。"""

import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path

ALLOWED = {"plan.json", "manifest.json", "Client.json", "P1.json", "P2.json",
           "metrics.json", "metrics-failure.json", "native.etl", "native-owner.json"}
LIMIT = 384 * 1024**2


def publish_package(directory, target, identity):
    """退出后流式封装原件，临时文件原子发布；不覆盖现有包。"""
    directory, target = Path(directory), Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError(target)
    entries = {}
    for path in directory.iterdir():
        if path.name not in ALLOWED or not path.is_file() or path.is_symlink():
            raise ValueError("结果目录存在非白名单成员。")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024**2), b""):
                digest.update(block)
        entries[path.name] = {"bytes": path.stat().st_size, "sha256": digest.hexdigest()}
    if sum(e["bytes"] for e in entries.values()) > LIMIT:
        raise ValueError("结果包原件超限。")
    descriptor, temporary = tempfile.mkstemp(dir=target.parent, prefix=".baseline-", suffix=".partial")
    os.close(descriptor)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
            for name in entries:
                archive.write(directory / name, name)
            archive.writestr("package.json", json.dumps({"schema": "baseline-package-v1",
                              "identity": identity, "files": entries}, allow_nan=False))
        os.link(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return str(target)


def read_package(path, identity):
    """校验所有成员的声明与实际长度/摘要；ETL仅流式hash，不重新解析。"""
    records = {}
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if (len(names) != len(set(names)) or not set(names) <= ALLOWED | {"package.json"}
                or "package.json" not in names or len(names) > 10
                or sum(i.file_size for i in archive.infolist()) > LIMIT + 65536
                or archive.getinfo("package.json").file_size > 65536):
            raise ValueError("结果包成员或容量无效。")
        package = json.loads(archive.read("package.json"))
        actual_identity = package.get("identity", {})
        if "index" in actual_identity and type(actual_identity["index"]) is not int:
            raise ValueError("组号必须是严格整数。")
        if (package.get("schema") != "baseline-package-v1" or package.get("identity") != identity
                or set(package.get("files", {})) != set(names) - {"package.json"}):
            raise ValueError("结果包身份或成员清单不符。")
        for name, expected in package["files"].items():
            if type(expected.get("bytes")) is not int or not 0 <= expected["bytes"] <= LIMIT:
                raise ValueError("成员长度无效。")
            digest, count, chunks = hashlib.sha256(), 0, []
            with archive.open(name) as source:
                for block in iter(lambda: source.read(1024**2), b""):
                    count += len(block)
                    if count > expected["bytes"] or name.endswith(".json") and count > 32 * 1024**2:
                        raise ValueError("成员实际长度超限。")
                    digest.update(block)
                    if name.endswith(".json"):
                        chunks.append(block)
            if count != expected["bytes"] or digest.hexdigest() != expected["sha256"]:
                raise ValueError("成员摘要或长度不符。")
            if chunks:
                records[name] = json.loads(b"".join(chunks))
        manifest = records.get("manifest.json", {})
        if set(manifest.get("files", {})) != set(package["files"]) - {"manifest.json"}:
            raise ValueError("运行manifest未完整列出包内原件。")
        for name, digest in manifest.get("files", {}).items():
            if name not in package["files"] or package["files"][name]["sha256"] != digest:
                raise ValueError("运行manifest与包成员摘要不一致。")
    records["_verified_inventory"] = package["files"]
    return records, sum(e["bytes"] for e in package["files"].values())
