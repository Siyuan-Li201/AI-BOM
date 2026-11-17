#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
02_third_party_component_identify.py

Unified Stage 02 v4 of the SSCS AI-firmware pipeline.
Includes Linux/rootfs native libraries, Android JNI + DEX/Gradle evidence,
MCU source trees/static libraries, and conservative source version recovery.

Stage 02 of the SSCS AI-firmware pipeline.

Purpose:
  stage-01 raw SDK/library evidence + extracted firmware tree + retained libraries
  -> cleaned firmware-level precise component inventory
  -> broader firmware-level review inventory

Default outputs (only two files):
  third_party_components_precise.csv
  third_party_components_broad.csv

Design principles:
1. Component identity for native libraries is derived only from basename and SONAME.
   Full paths and NEEDED dependencies are evidence, never identity sources.
2. Recursive extraction duplicates are removed with FirmwareID + Component_ID + SHA256.
3. Version is filled only when the candidate contains at least one digit.
4. Direct binary banners / exact metadata have higher priority than weaker candidates.
5. Source headers and build files are scanned for explicit numeric version macros.
6. ABI-only SONAME suffixes remain candidates and do not automatically become upstream releases.
7. --debug writes one optional raw-evidence CSV; default mode writes only two inventories.

This script is static only. It does not execute firmware binaries.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import shutil
import subprocess
import tarfile
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Pattern, Sequence, Set, Tuple


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

SKIP_DIRS = {
    ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "node_modules",
    ".gradle", "build", "dist", ".idea", "__MACOSX", "target",
}
NATIVE_SUFFIXES = {".so", ".a", ".ko", ".dll", ".dylib", ".elf", ".exe", ".bin"}
METADATA_NAMES = {
    "requirements.txt", "requirements-dev.txt", "requirements-prod.txt", "constraints.txt",
    "pyproject.toml", "setup.py", "setup.cfg", "poetry.lock", "uv.lock", "pdm.lock",
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "vcpkg.json", "conanfile.txt",
    "build.gradle", "build.gradle.kts", "gradle.properties", "libs.versions.toml",
    "pom.properties", "pom.xml",
    "idf_component.yml", "idf_component.yaml", "METADATA", "PKG-INFO", "status",
}
UNKNOWN_VALUES = {"", "unknown", "none", "nan", "null", "n/a", "na", "-"}
MAX_TEXT_BYTES = 4_000_000
MAX_STRINGS_BYTES = 8_000_000


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: List[Dict[str, str]], fields: List[str]) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fields,
            extrasaction="ignore",
            quoting=csv.QUOTE_ALL,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def iter_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return
    for cur, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in files:
            path = Path(cur) / fn
            if path.is_file():
                yield path


def run_cmd(cmd: Sequence[str], timeout: int = 60) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            [str(x) for x in cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="ignore",
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return 1, "", str(exc)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_sha256(path: Path) -> str:
    try:
        return sha256_file(path)
    except Exception:
        return ""


def read_text(path: Path, limit: int = MAX_TEXT_BYTES) -> str:
    try:
        if path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def strings_text(path: Path, limit: int = MAX_STRINGS_BYTES) -> str:
    try:
        if shutil.which("strings"):
            code, out, _ = run_cmd(["strings", "-a", "-n", "4", str(path)], timeout=90)
            if code == 0 and out:
                return out[:limit]
        return path.read_bytes()[:limit].decode("latin1", errors="ignore")
    except Exception:
        return ""


def clean_join(values: Iterable[str], limit_items: int = 12, limit_chars: int = 3000) -> str:
    out: List[str] = []
    seen: Set[str] = set()
    for value in values:
        value = re.sub(r"\s+", " ", str(value or "").strip())
        if value and value not in seen:
            seen.add(value)
            out.append(value)
        if len(out) >= limit_items:
            break
    return " | ".join(out)[:limit_chars]


def relative_or_string(path: Path, root: Optional[Path]) -> str:
    if root:
        try:
            return str(path.relative_to(root)).replace("\\", "/")
        except Exception:
            pass
    return str(path).replace("\\", "/")


def canonical_extracted_firmware_dir_name(name: str) -> str:
    """Normalize recovered-source directory names to the Stage-01 FirmwareID.

    Git-LFS source recoveries commonly use <FirmwareID>.git_lfs.  Component
    inventories and GT rows use the original FirmwareID without that suffix.
    """
    value = str(name or "")
    for suffix in (".git_lfs", ".git-lfs"):
        if value.endswith(suffix):
            return value[:-len(suffix)]
    return value


def firmware_id_from_extracted_path(path: Path, extracted_root: Path) -> str:
    try:
        return canonical_extracted_firmware_dir_name(path.relative_to(extracted_root).parts[0])
    except Exception:
        return ""


def resolve_extracted_firmware_root(extracted_root: Path, fid: str) -> Path:
    """Resolve normal and Git-LFS recovered extracted directory spellings."""
    direct = extracted_root / fid
    if direct.exists():
        return direct
    for suffix in (".git_lfs", ".git-lfs"):
        candidate_path = extracted_root / f"{fid}{suffix}"
        if candidate_path.exists():
            return candidate_path
    return direct


def parse_retained_firmware_id(path: Path, retained_root: Path) -> str:
    try:
        return path.relative_to(retained_root).parts[0]
    except Exception:
        return ""


def recover_retained_basename(path: Path) -> str:
    """Recover original basename from stage-01 retained artifact names.

    stage-01 stores files as <flattened_original_path>__<12hex><suffix>.
    The final basename before the hash is the original basename.
    """
    name = path.name
    # Remove copied-file hash while preserving the original shared-library suffix.
    m = re.match(r"^(.*)__[0-9a-fA-F]{12}(\.[A-Za-z0-9_.+-]+)$", name)
    stem = m.group(1) if m else path.stem
    # Flattened original paths use __. Keep only final segment.
    return stem.split("__")[-1] if "__" in stem else stem


def parse_model_version_from_firmware_id(fid: str) -> Tuple[str, str]:
    parts = fid.split("__")
    model = parts[0].replace("_", " ") if parts else fid
    version = parts[1] if len(parts) > 1 else ""
    return model, version


def dependency_scope(path_text: str) -> str:
    s = str(path_text or "").lower().replace("\\", "/")
    if any(x in s for x in ["/test/", "/tests/", "requirements-dev", "dev-requirements", "test_"]):
        return "test"
    if any(x in s for x in ["/docs/", "/doc/", "sphinx", "mkdocs"]):
        return "doc"
    if any(x in s for x in ["/example/", "/examples/", "/demo/", "/demos/"]):
        return "example"
    if any(x in s for x in ["/toolchain/", "/tools/", "/cmake/"]):
        return "build"
    return "runtime_or_source"


# ---------------------------------------------------------------------------
# Component registry
# ---------------------------------------------------------------------------

@dataclass
class ComponentSpec:
    cid: str
    name: str
    category: str
    cpe: str = ""
    packages: Set[str] = field(default_factory=set)
    file_patterns: List[Pattern[str]] = field(default_factory=list)
    broad_file_patterns: List[Pattern[str]] = field(default_factory=list)
    banner_patterns: List[Pattern[str]] = field(default_factory=list)


SPECS: Dict[str, ComponentSpec] = {}
PACKAGE_TO_COMPONENT: Dict[str, str] = {}


def _compile_patterns(patterns: Iterable[str]) -> List[Pattern[str]]:
    return [re.compile(x, re.I) for x in patterns]


def register(
    cid: str,
    name: str,
    category: str,
    *,
    cpe: str = "",
    packages: Iterable[str] = (),
    files: Iterable[str] = (),
    broad_files: Iterable[str] = (),
    banners: Iterable[str] = (),
) -> None:
    spec = ComponentSpec(
        cid=cid,
        name=name,
        category=category,
        cpe=cpe,
        packages={x.lower().replace("_", "-") for x in packages},
        file_patterns=_compile_patterns(files),
        broad_file_patterns=_compile_patterns(broad_files),
        banner_patterns=_compile_patterns(banners),
    )
    SPECS[cid] = spec
    for pkg in spec.packages:
        PACKAGE_TO_COMPONENT[pkg] = cid


# Common native / OS components.
register("linux_kernel", "Linux kernel", "os_kernel", cpe="cpe:2.3:o:linux:linux_kernel:")
register("busybox", "BusyBox", "system_utility", cpe="cpe:2.3:a:busybox:busybox:", packages=["busybox"], files=[r"^busybox(?:$|[._-])"], banners=[r"\bBusyBox\s+v?([0-9][0-9A-Za-z.+_-]*)"])
register("openssl", "OpenSSL", "crypto_library", cpe="cpe:2.3:a:openssl:openssl:", packages=["openssl", "libssl", "libcrypto"], files=[r"^libssl(?:\.so(?:\..*)?|\.a)$", r"^libcrypto(?:\.so(?:\..*)?|\.a)$", r"^openssl$"], banners=[r"\bOpenSSL\s+([0-9][0-9A-Za-z.+_-]*)"])
register("mbedtls", "Mbed TLS", "crypto_library", cpe="cpe:2.3:a:arm:mbed_tls:", packages=["mbedtls", "mbed-tls"], files=[r"^libmbed(?:tls|crypto|x509)(?:\.so(?:\..*)?|\.a)$"], banners=[r"\b(?:Mbed\s+TLS|mbed\s*TLS)[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("zlib", "zlib", "compression_library", cpe="cpe:2.3:a:zlib:zlib:", packages=["zlib"], files=[r"^libz\.so(?:\..*)?$", r"^libz\.a$"], banners=[r"\b(?:deflate|inflate|zlib)\s+([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("zstd", "Zstandard", "compression_library", packages=["zstandard", "zstd", "libzstd"], files=[r"^libzstd(?:\.so(?:\..*)?|\.a)$"], banners=[r"\b(?:zstd|Zstandard)[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("curl", "curl / libcurl", "network_library", cpe="cpe:2.3:a:haxx:libcurl:", packages=["curl", "libcurl"], files=[r"^libcurl(?:\.so(?:\..*)?|\.a)$", r"^curl$"], banners=[r"\b(?:libcurl|curl)[ /]([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("sqlite", "SQLite", "database_library", cpe="cpe:2.3:a:sqlite:sqlite:", packages=["sqlite", "sqlite3"], files=[r"^libsqlite3?(?:\.so(?:\..*)?|\.a)$", r"^sqlite3?$"], banners=[r"\bSQLite\s+([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("json_c", "json-c", "serialization_library", packages=["json-c", "json_c"], files=[r"^libjson-c(?:\.so(?:\..*)?|\.a)$"], banners=[r"(?m)^([0-9]+(?:\.[0-9A-Za-z]+){1,5})$", r"\bJSONC_([0-9]+(?:\.[0-9A-Za-z]+){1,5})\b"])
register("libyaml", "libyaml", "serialization_library", packages=["libyaml", "yaml"], files=[r"^libyaml(?:-0)?(?:\.so(?:\..*)?|\.a)$"], banners=[r"(?m)^([0-9]+(?:\.[0-9A-Za-z]+){1,5})$"])
register("protobuf", "Protobuf", "serialization_library", cpe="cpe:2.3:a:google:protobuf:", packages=["protobuf", "google-protobuf"], files=[r"^libprotobuf(?:-lite)?(?:\.so(?:\..*)?|\.a)$"], banners=[r"\b(?:protobuf|libprotobuf)[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("flatbuffers", "FlatBuffers", "serialization_library", packages=["flatbuffers"], files=[r"^libflatbuffers(?:\.so(?:\..*)?|\.a)$"])
register("grpc", "gRPC", "rpc_library", packages=["grpc", "grpcio"], files=[r"^libgrpc(?:\+\+)?(?:\.so(?:\..*)?|\.a)$"], banners=[r"\bgRPC[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("libevent", "libevent", "event_loop_library", packages=["libevent"], files=[r"^libevent(?:_core|_extra|_pthreads|_openssl|_mbedtls)?(?:-[0-9.]+)?\.so(?:\..*)?$", r"^libevent(?:\.a|_core\.a|_extra\.a|_pthreads\.a)$"], banners=[r"\blibevent[- /]([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("libnl", "libnl", "network_library", packages=["libnl", "libnl3"], files=[r"^libnl(?:-3|-route-3|-nf-3|-xfrm-3|-genl-3|-idiag-3)?\.so(?:\..*)?$"], banners=[r"\blibnl[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("libogg", "libogg", "audio_codec_library", packages=["libogg", "ogg"], files=[r"^libogg(?:\.so(?:\..*)?|\.a)$"], banners=[r"\blibogg[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("opus", "Opus codec", "audio_codec_library", packages=["opus", "libopus"], files=[r"^libopus(?:\.so(?:\..*)?|\.a)$"], banners=[r"\blibopus\s+([0-9]+(?:\.[0-9A-Za-z_-]+){1,5})"])
register("lame", "LAME MP3 encoder", "audio_codec_library", packages=["lame", "libmp3lame"], files=[r"^libmp3lame(?:\.so(?:\..*)?|\.a)$", r"^lame$"], banners=[r"\bLAME(?:\s+version)?[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("flac", "FLAC", "audio_codec_library", packages=["flac", "libflac"], files=[r"^libFLAC(?:\.so(?:\..*)?|\.a)$"], banners=[r"\bFLAC[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("mosquitto", "Mosquitto MQTT client library", "mqtt_library", packages=["mosquitto", "libmosquitto", "paho-mqtt"], files=[r"^libmosquitto(?:pp)?(?:\.so(?:\..*)?|\.a)$", r"^mosquitto$"], banners=[r"\bmosquitto(?:\s+version)?[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("miniupnpc", "miniupnpc", "network_library", packages=["miniupnpc", "libminiupnpc"], files=[r"^libminiupnpc(?:\.so(?:\..*)?|\.a)$"], banners=[r"\bMiniUPnPc[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("libnatpmp", "libnatpmp", "network_library", packages=["libnatpmp"], files=[r"^libnatpmp(?:\.so(?:\..*)?|\.a)$"], banners=[r"\blibnatpmp[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("libwebsockets", "libwebsockets", "realtime_websocket_library", packages=["libwebsockets"], files=[r"^libwebsockets(?:\.so(?:\..*)?|\.a)$"], banners=[r"\blibwebsockets[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("live555", "LIVE555", "media_streaming_library", cpe="cpe:2.3:a:live555:live555:", packages=["live555"], files=[r"^(?:lib)?liveMedia(?:\.so(?:\..*)?|\.a)$", r"^liblive555(?:\.so(?:\..*)?|\.a)$"], banners=[r"\b([0-9]{4}\.[0-9]{2}\.[0-9]{2})\b"])
register("iptables_xtables", "iptables / Xtables userspace extensions", "network_firewall_tool", packages=["iptables", "xtables"], files=[r"^libxtables(?:\.so(?:\..*)?|\.a)$", r"^lib(?:xt|ipt|ip6t)_[A-Za-z0-9_+.-]+\.so(?:\..*)?$", r"^libip[46]tc(?:\.so(?:\..*)?|\.a)$", r"^iptables$"], banners=[r"\biptables\s+v?([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("openwrt_libubox", "OpenWrt libubox suite", "openwrt_system_library", packages=["libubox"], files=[r"^lib(?:ubox|blobmsg_json|json_script)(?:\.so(?:\..*)?|\.a)$"])
register("securec", "Secure C library", "secure_c_runtime", packages=["securec"], files=[r"^libsecurec(?:\.so(?:\..*)?|\.a)$"], banners=[r"\bsecurec[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("uclibc_compat_runtime", "uClibc Compatibility Runtime", "libc_runtime", files=[r"^libuclibc-compat(?:\.so(?:\..*)?|\.a)$", r"^ld-uClibc(?:\.so(?:\..*)?)?$", r"^libuClibc(?:\.so(?:\..*)?)?$"])
register("libc_runtime_unknown", "C library runtime family", "libc_runtime", broad_files=[r"^(?:libc|libm|libpthread|librt|libdl)\.so(?:\..*)?$"])
register("libjpeg", "libjpeg / libjpeg-turbo", "image_processing_library", packages=["libjpeg", "libjpeg-turbo"], files=[r"^libjpeg(?:\.so(?:\..*)?|\.a)$", r"^libturbojpeg(?:\.so(?:\..*)?|\.a)$"])
register("libpng", "libpng", "image_processing_library", cpe="cpe:2.3:a:libpng:libpng:", packages=["libpng"], files=[r"^libpng(?:[0-9]+)?(?:\.so(?:\..*)?|\.a)$"], banners=[r"\blibpng[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("libtiff", "libtiff", "image_processing_library", cpe="cpe:2.3:a:libtiff:libtiff:", packages=["libtiff"], files=[r"^libtiff(?:\.so(?:\..*)?|\.a)$"], banners=[r"\bLIBTIFF[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("libwebp", "libwebp", "image_processing_library", cpe="cpe:2.3:a:webmproject:libwebp:", packages=["libwebp"], files=[r"^libwebp(?:decoder|demux|mux)?(?:\.so(?:\..*)?|\.a)$"], banners=[r"\blibwebp[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("libxml2", "libxml2", "xml_library", cpe="cpe:2.3:a:xmlsoft:libxml2:", packages=["libxml2"], files=[r"^libxml2(?:\.so(?:\..*)?|\.a)$"], banners=[r"\blibxml2[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("expat", "Expat", "xml_library", cpe="cpe:2.3:a:libexpat:expat:", packages=["expat", "libexpat"], files=[r"^libexpat(?:\.so(?:\..*)?|\.a)$"], banners=[r"\bexpat(?:_)?([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("freetype", "FreeType", "font_library", cpe="cpe:2.3:a:freetype:freetype:", packages=["freetype"], files=[r"^libfreetype(?:\.so(?:\..*)?|\.a)$"], banners=[r"\bFreeType[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("libusb", "libusb", "usb_library", packages=["libusb"], files=[r"^libusb(?:-[0-9.]+)?(?:\.so(?:\..*)?|\.a)$"], banners=[r"\blibusb[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("libyuv", "libyuv", "image_processing_library", packages=["libyuv"], files=[r"^libyuv(?:\.so(?:\..*)?|\.a)$"])
register("ffmpeg", "FFmpeg", "media_library", cpe="cpe:2.3:a:ffmpeg:ffmpeg:", packages=["ffmpeg"], files=[r"^lib(?:avcodec|avformat|avutil|swscale|swresample)(?:\.so(?:\..*)?|\.a)$", r"^ffmpeg$"], banners=[r"\bffmpeg\s+version\s+([0-9][0-9A-Za-z.+_-]*)"])
register("pyav", "PyAV", "python_media_binding", packages=["pyav", "av"])
register("gstreamer", "GStreamer", "media_library", cpe="cpe:2.3:a:gstreamer:gstreamer:", packages=["gstreamer"], files=[r"^libgst(?:reamer)?-[0-9.]+\.so(?:\..*)?$", r"^libgst[A-Za-z0-9_+.-]+\.so(?:\..*)?$"], banners=[r"\bGStreamer[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])

# AI / accelerator runtimes.
register("tensorflow", "TensorFlow / TensorFlow Lite", "ai_framework_or_runtime", cpe="cpe:2.3:a:google:tensorflow:", packages=["tensorflow", "tensorflow-cpu", "tensorflow-gpu", "tensorflow-lite", "tflite-runtime"], files=[r"^libtensorflow(?:lite)?(?:\.so(?:\..*)?|\.a)$"], banners=[r"\b(?:TensorFlow|TFLite)(?:\s+Lite)?[ /_-]*v?([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("tensorflow_lite_micro", "TensorFlow Lite Micro", "tinyml_runtime", packages=["tensorflow-lite-micro", "tflite-micro"], files=[r"^libtensorflow(?:-lite-micro|-microlite)(?:\.a|\.so(?:\..*)?)$"])
register("onnxruntime", "ONNX Runtime", "ai_runtime", cpe="cpe:2.3:a:microsoft:onnxruntime:", packages=["onnxruntime", "onnxruntime-gpu"], files=[r"^libonnxruntime(?:\.so(?:\..*)?|\.a)$"], banners=[r"\bonnxruntime(?:\s+version)?[ /:_-]*v?([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("pytorch", "PyTorch / LibTorch", "ai_framework_or_runtime", cpe="cpe:2.3:a:pytorch:pytorch:", packages=["torch", "pytorch", "libtorch", "torchvision", "torchaudio"], files=[r"^libtorch(?:_cpu|_cuda)?(?:\.so(?:\..*)?|\.a)$"], banners=[r"\b(?:PyTorch|LibTorch|Torch)[ /_-]*v?([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("opencv", "OpenCV", "computer_vision_library", cpe="cpe:2.3:a:opencv:opencv:", packages=["opencv", "opencv-python", "opencv-contrib-python"], files=[r"^libopencv_[A-Za-z0-9_+.-]+(?:\.so(?:\..*)?|\.a)$"], banners=[r"\bOpenCV[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("rknn", "RKNN Runtime / Toolkit", "vendor_ai_runtime", packages=["rknn", "rknn-toolkit2", "rkllm"], files=[r"^librknn(?:rt)?(?:\.so(?:\..*)?|\.a)$", r"^librkllm(?:\.so(?:\..*)?|\.a)$"], banners=[r"\bRKNN[ /_-]*v?([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("tensorrt", "TensorRT", "ai_runtime", packages=["tensorrt", "tensorrt-cu12", "nvidia-tensorrt"], files=[r"^libnvinfer(?:_plugin)?(?:\.so(?:\..*)?|\.a)$", r"^libnvonnxparser(?:\.so(?:\..*)?|\.a)$"], banners=[r"\b(?:TensorRT|nvinfer)[ /_-]*v?([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("openvino", "OpenVINO", "ai_runtime", packages=["openvino"], files=[r"^libopenvino(?:_[A-Za-z0-9_+.-]+)?(?:\.so(?:\..*)?|\.a)$", r"^libinference_engine(?:\.so(?:\..*)?|\.a)$"], banners=[r"\bOpenVINO[ /_-]*v?([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("depthai", "DepthAI / Luxonis", "ai_camera_sdk", packages=["depthai", "blobconverter"], files=[r"^libdepthai(?:\.so(?:\..*)?|\.a)$"])
register("edgetpu", "Google Coral / Edge TPU", "ai_runtime", packages=["pycoral", "libedgetpu"], files=[r"^libedgetpu(?:\.so(?:\..*)?|\.a)$"])
register("cuda", "NVIDIA CUDA Runtime / Toolkit", "gpu_compute_runtime", packages=["cuda", "cuda-python", "nvidia-cuda-runtime-cu11", "nvidia-cuda-runtime-cu12"], files=[r"^libcudart(?:\.so(?:\..*)?|\.a)$", r"^libcuda(?:\.so(?:\..*)?)$"])
register("cudnn", "NVIDIA cuDNN", "ai_acceleration_library", packages=["cudnn", "nvidia-cudnn-cu11", "nvidia-cudnn-cu12"], files=[r"^libcudnn(?:_[A-Za-z0-9_+.-]+)?(?:\.so(?:\..*)?|\.a)$"])
register("vitis_ai", "Xilinx Vitis AI", "vendor_ai_runtime", packages=["vitis-ai"], files=[r"^lib(?:vart|xir)(?:\.so(?:\..*)?|\.a)$"])
register("hailo", "Hailo Runtime", "vendor_ai_runtime", packages=["hailo"], files=[r"^libhailo(?:rt)?(?:\.so(?:\..*)?|\.a)$"])
register("snpe", "Qualcomm SNPE", "vendor_ai_runtime", packages=["snpe"], files=[r"^libSNPE(?:\.so(?:\..*)?|\.a)$"])
register("cmsis_core", "CMSIS Core", "embedded_sdk", packages=["cmsis", "cmsis-core"])
register("cmsis_nn", "CMSIS-NN", "optimized_kernel", packages=["cmsis-nn"])
register("cmsis_dsp", "CMSIS-DSP", "signal_processing_library", packages=["cmsis-dsp"])
register("freertos", "FreeRTOS Kernel", "rtos_kernel", packages=["freertos"], banners=[r"tskKERNEL_VERSION_NUMBER[^0-9]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])

# OpenIPC / embedded vendor normalizers. These rules are basename-only.
register("vendor_audio_processing_sdk", "Vendor Audio Processing SDK", "vendor_audio_sdk", files=[r"^(?:libdnvqe|libupvqe|libvoice_engine)(?:\.so(?:\..*)?|\.a)$"], banners=[r"SDK_AUDIO_VERSION[_ -]*V?([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("goke_multimedia_sdk", "Goke Multimedia / ISP SDK", "vendor_multimedia_sdk", files=[r"^libgk_[A-Za-z0-9_+.-]+(?:\.so(?:\..*)?|\.a)$"], broad_files=[r"^lib(?:dehaze|drc|ir_auto|ldci|adi|image)(?:\.so(?:\..*)?|\.a)$", r"^media\.ko$"])
register("hisi_compatible_media_sdk", "HiSilicon-compatible Media SDK", "vendor_multimedia_sdk", files=[r"^libhi_[A-Za-z0-9_+.-]+(?:\.so(?:\..*)?|\.a)$", r"^lib(?:mpi|nnie|isp|ive|md)(?:\.so(?:\..*)?|\.a)$"])
register("vendor_sensor_driver_plugins", "Vendor Sensor Driver Plugins", "vendor_sensor_plugins", files=[r"^libsns_[A-Za-z0-9_+.-]+(?:\.so(?:\..*)?|\.a)$"])
register("sigmastar_mi", "SigmaStar MI Platform SDK", "vendor_platform_sdk", files=[r"^libmi_[A-Za-z0-9_+.-]+(?:\.so(?:\..*)?|\.a)$", r"^(?:mi|mhal)(?:_[A-Za-z0-9_+.-]+)?\.ko$"])
register("xmedia_sdk", "XMedia Multimedia / ISP SDK", "vendor_multimedia_sdk", files=[r"^libxmedia_[A-Za-z0-9_+.-]+(?:\.so(?:\..*)?|\.a)$"], banners=[r"\b(?:MPP|ISP)_V?([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("isp_algorithm_plugins", "ISP Algorithm Plugins", "vendor_isp_algorithm_plugins", broad_files=[r"^lib(?:ae|awb|bcd)(?:\.so(?:\..*)?|\.a)$"])
register("kvs_lws_runtime", "KVS Common LWS Runtime", "cloud_streaming_runtime", files=[r"^libkvsCommonLws(?:\.so(?:\..*)?|\.a)$"])

# Broad package ecosystem from enhanced-v3. Manifest exact-name matching only.
for _cid, _name, _cat, _pkgs in [
    ("numpy", "NumPy", "python_numeric_library", ["numpy"]),
    ("scipy", "SciPy", "python_scientific_library", ["scipy"]),
    ("pandas", "pandas", "python_data_library", ["pandas"]),
    ("pillow", "Pillow", "image_processing_library", ["pillow", "pil"]),
    ("transformers", "transformers", "ai_model_library", ["transformers"]),
    ("tokenizers", "tokenizers", "ai_model_library", ["tokenizers"]),
    ("safetensors", "safetensors", "ai_model_library", ["safetensors"]),
    ("sentencepiece", "SentencePiece", "nlp_library", ["sentencepiece"]),
    ("huggingface_hub", "huggingface-hub", "ai_model_library", ["huggingface-hub", "huggingface_hub"]),
    ("ctranslate2", "CTranslate2", "ai_runtime", ["ctranslate2"]),
    ("librosa", "librosa", "audio_processing_library", ["librosa"]),
    ("soundfile", "SoundFile", "audio_processing_library", ["soundfile", "pysoundfile"]),
    ("requests", "Requests", "python_network_library", ["requests"]),
    ("urllib3", "urllib3", "python_network_library", ["urllib3"]),
    ("aiohttp", "aiohttp", "python_network_library", ["aiohttp"]),
    ("fastapi", "FastAPI", "python_web_framework", ["fastapi"]),
    ("starlette", "Starlette", "python_web_framework", ["starlette"]),
    ("uvicorn", "Uvicorn", "python_web_server", ["uvicorn"]),
    ("django", "Django", "python_web_framework", ["django"]),
    ("flask", "Flask", "python_web_framework", ["flask"]),
    ("cryptography", "cryptography", "python_crypto_library", ["cryptography"]),
    ("pyopenssl", "pyOpenSSL", "python_crypto_library", ["pyopenssl"]),
    ("pycryptodome", "PyCryptodome", "python_crypto_library", ["pycryptodome"]),
    ("zmq", "ZeroMQ / pyzmq", "messaging_library", ["pyzmq", "zmq", "zeromq"]),
    ("casadi", "CasADi", "optimization_library", ["casadi"]),
    ("wyoming", "Wyoming", "voice_service_runtime", ["wyoming"]),
    ("piper", "Piper", "voice_runtime", ["piper", "piper-phonemize"]),
    ("micropython_runtime", "MicroPython Runtime", "runtime", ["micropython"]),
    ("lvgl", "LVGL", "gui_library", ["lvgl"]),
    ("libdrm", "libdrm", "graphics_library", ["libdrm"]),
    ("vulkan", "Vulkan", "graphics_runtime", ["vulkan"]),
]:
    if _cid not in SPECS:
        register(_cid, _name, _cat, packages=_pkgs)
    else:
        for _pkg in _pkgs:
            PACKAGE_TO_COMPONENT[_pkg.lower().replace("_", "-")] = _cid



# Additional conservative native-library rules and manifest-only ecosystem entries.
# These broaden recall without using full-path context for native identity.
for _cid, _name, _cat, _cpe, _pkgs, _files in [
    ("libuuid", "libuuid", "system_library", "", ["libuuid", "util-linux"], [r"^libuuid(?:\.so(?:\..*)?|\.a)$"]),
    ("libtirpc", "libtirpc", "rpc_library", "", ["libtirpc"], [r"^libtirpc(?:\.so(?:\..*)?|\.a)$"]),
    ("wolfssl", "wolfSSL", "crypto_library", "cpe:2.3:a:wolfssl:wolfssl:", ["wolfssl"], [r"^libwolfssl(?:\.so(?:\..*)?|\.a)$"]),
    ("gnutls", "GnuTLS", "crypto_library", "cpe:2.3:a:gnutls:gnutls:", ["gnutls"], [r"^libgnutls(?:\.so(?:\..*)?|\.a)$"]),
    ("libssh2", "libssh2", "network_library", "cpe:2.3:a:libssh2:libssh2:", ["libssh2"], [r"^libssh2(?:\.so(?:\..*)?|\.a)$"]),
    ("c_ares", "c-ares", "network_library", "cpe:2.3:a:c-ares_project:c-ares:", ["c-ares", "cares"], [r"^libcares(?:\.so(?:\..*)?|\.a)$"]),
    ("nghttp2", "nghttp2", "network_library", "cpe:2.3:a:nghttp2:nghttp2:", ["nghttp2"], [r"^libnghttp2(?:\.so(?:\..*)?|\.a)$"]),
    ("libpcap", "libpcap", "network_library", "cpe:2.3:a:tcpdump:libpcap:", ["libpcap"], [r"^libpcap(?:\.so(?:\..*)?|\.a)$"]),
    ("libarchive", "libarchive", "archive_library", "cpe:2.3:a:libarchive:libarchive:", ["libarchive"], [r"^libarchive(?:\.so(?:\..*)?|\.a)$"]),
    ("bzip2", "bzip2", "compression_library", "cpe:2.3:a:bzip:bzip2:", ["bzip2", "libbz2"], [r"^libbz2(?:\.so(?:\..*)?|\.a)$"]),
    ("xz", "XZ Utils / liblzma", "compression_library", "cpe:2.3:a:tukaani:xz:", ["xz", "liblzma"], [r"^liblzma(?:\.so(?:\..*)?|\.a)$"]),
    ("pcre", "PCRE", "regex_library", "cpe:2.3:a:pcre:pcre:", ["pcre", "libpcre"], [r"^libpcre(?:posix|cpp)?(?:\.so(?:\..*)?|\.a)$"]),
    ("pcre2", "PCRE2", "regex_library", "cpe:2.3:a:pcre:pcre2:", ["pcre2", "libpcre2"], [r"^libpcre2-[0-9]+(?:\.so(?:\..*)?|\.a)$"]),
    ("glib", "GLib", "system_library", "cpe:2.3:a:gnome:glib:", ["glib", "glib2"], [r"^libglib-2\.0(?:\.so(?:\..*)?|\.a)$"]),
    ("libffi", "libffi", "system_library", "cpe:2.3:a:libffi_project:libffi:", ["libffi"], [r"^libffi(?:\.so(?:\..*)?|\.a)$"]),
    ("readline", "GNU Readline", "system_library", "cpe:2.3:a:gnu:readline:", ["readline"], [r"^libreadline(?:\.so(?:\..*)?|\.a)$"]),
    ("ncurses", "ncurses", "system_library", "cpe:2.3:a:gnu:ncurses:", ["ncurses"], [r"^libncursesw?(?:\.so(?:\..*)?|\.a)$"]),
    ("alsa", "ALSA lib", "audio_library", "", ["alsa-lib", "alsa"], [r"^libasound(?:\.so(?:\..*)?|\.a)$"]),
    ("speex", "Speex", "audio_codec_library", "", ["speex", "libspeex"], [r"^libspeex(?:\.so(?:\..*)?|\.a)$"]),
    ("speexdsp", "SpeexDSP", "audio_processing_library", "", ["speexdsp", "libspeexdsp"], [r"^libspeexdsp(?:\.so(?:\..*)?|\.a)$"]),
    ("vorbis", "libvorbis", "audio_codec_library", "", ["libvorbis", "vorbis"], [r"^libvorbis(?:enc|file)?(?:\.so(?:\..*)?|\.a)$"]),
    ("libcap", "libcap", "system_library", "", ["libcap"], [r"^libcap(?:\.so(?:\..*)?|\.a)$"]),
    ("libunwind", "libunwind", "system_library", "", ["libunwind"], [r"^libunwind(?:-[A-Za-z0-9_+.-]+)?(?:\.so(?:\..*)?|\.a)$"]),
    ("libdaemon", "libdaemon", "system_library", "", ["libdaemon"], [r"^libdaemon(?:\.so(?:\..*)?|\.a)$"]),
    ("libical", "libical", "calendar_library", "", ["libical"], [r"^libical(?:\.so(?:\..*)?|\.a)$"]),
    ("libstdcpp_runtime", "GNU libstdc++ runtime", "cpp_runtime", "", ["libstdc++"], [r"^libstdc\+\+(?:\.so(?:\..*)?|\.a)$"]),
]:
    if _cid not in SPECS:
        register(_cid, _name, _cat, cpe=_cpe, packages=_pkgs, files=_files)

for _cid, _name, _cat, _pkgs in [
    ("edge_impulse", "Edge Impulse SDK", "tinyml_sdk", ["edge-impulse-sdk", "edge_impulse_sdk"]),
    ("esp_idf", "ESP-IDF", "vendor_platform_sdk", ["esp-idf"]),
    ("esp_adf", "ESP-ADF", "vendor_multimedia_sdk", ["esp-adf"]),
    ("esp_sr", "ESP-SR", "vendor_ai_sdk", ["esp-sr"]),
    ("esp_dl", "ESP-DL", "vendor_ai_sdk", ["esp-dl"]),
    ("esp_nn", "ESP-NN", "optimized_kernel", ["esp-nn"]),
    ("esp_dsp", "ESP-DSP", "signal_processing_library", ["esp-dsp"]),
    ("novatek_nvt", "Novatek / NVT HDAL AI Runtime", "vendor_ai_runtime_or_platform_sdk", ["novatek", "nvt"]),
    ("pycoral", "PyCoral", "ai_runtime_binding", ["pycoral"]),
    ("triton", "Triton", "ai_inference_server_or_compiler", ["triton", "tritonserver"]),
    ("torchvision", "TorchVision", "ai_framework_extension", ["torchvision"]),
    ("torchaudio", "Torchaudio", "ai_framework_extension", ["torchaudio"]),
    ("soxr", "soxr", "audio_processing_library", ["soxr"]),
    ("pycuda", "PyCUDA", "gpu_compute_binding", ["pycuda"]),
    ("pyjwt", "PyJWT", "python_security_library", ["pyjwt"]),
    ("capnproto", "Cap'n Proto", "serialization_library", ["capnp", "capnproto", "pycapnp"]),
    ("boost", "Boost", "cpp_library", ["boost"]),
    ("eigen", "Eigen", "math_library", ["eigen", "eigen3"]),
    ("paho_mqtt", "paho-mqtt", "mqtt_library", ["paho-mqtt", "paho_mqtt"]),
    ("gunicorn", "Gunicorn", "python_web_server", ["gunicorn"]),
    ("tuya_armino", "Tuya T5AI / Beken Armino Platform SDK", "vendor_platform_sdk", ["tuyaopen", "tuyaos", "armino"]),
    ("maixpy", "MaixPy", "vendor_ai_runtime", ["maixpy", "maixcam"]),
    ("openmv_tf", "OpenMV TensorFlow Library", "ai_runtime", ["openmv-tf"]),
    ("sony_spresense_dnnrt", "Sony Spresense DNNRT", "vendor_ai_runtime", ["dnnrt"]),
    ("nnabla_nnb_runtime", "NNabla / NNB Runtime", "vendor_ai_runtime", ["nnabla"]),
    ("sensiml", "SensiML Knowledge Pack", "tinyml_sdk", ["sensiml"]),
    ("arcmli", "Synopsys ARC MLI Runtime", "vendor_ai_runtime", ["arcmli"]),
    ("ppcs_p2p", "PPCS P2P API", "p2p_network_library", ["ppcs"]),
    ("cs2_p2p", "CS2 P2P Client", "p2p_network_library", ["cs2p2p"]),
    ("airkiss", "SmartConfig / AirKiss", "iot_provisioning_library", ["airkiss"]),
    ("bk_wifi", "BK Wi-Fi Platform Library", "vendor_platform_sdk", ["bk-wifi"]),
    ("bk_bluetooth", "BK Bluetooth Controller / Host Stack", "vendor_platform_sdk", ["bk-bluetooth"]),
    ("djangorestframework", "Django REST framework", "python_web_framework", ["djangorestframework", "django-rest-framework"]),
    ("daphne", "Daphne", "python_web_server", ["daphne"]),
    ("redis_python", "redis-py", "python_database_client", ["redis"]),
    ("go2rtc", "go2rtc", "video_streaming_service", ["go2rtc"]),
    ("webrtc", "WebRTC", "realtime_media_library", ["webrtc"]),
    ("openai_python_sdk", "OpenAI Python SDK", "python_ai_service_sdk", ["openai"]),
    ("instructor", "Instructor", "python_ai_service_sdk", ["instructor"]),
    ("langfuse", "Langfuse", "llm_observability_library", ["langfuse"]),
    ("pixelmatch", "pixelmatch", "image_diff_library", ["pixelmatch"]),
    ("pngjs", "pngjs", "image_processing_library", ["pngjs"]),
    ("electron", "Electron", "desktop_runtime", ["electron"]),
]:
    if _cid not in SPECS:
        register(_cid, _name, _cat, packages=_pkgs)
    else:
        for _pkg in _pkgs:
            PACKAGE_TO_COMPONENT[_pkg.lower().replace("_", "-")] = _cid



# ---------------------------------------------------------------------------
# MCU source packages, static runtimes, and embedded-camera normalizers
# ---------------------------------------------------------------------------
# These remain conservative: binary identity comes from exact basename/SONAME;
# source identity comes from explicit directory, header, or version-file
# signatures in scan_mcu_source_components().
register("edge_impulse_sdk", "Edge Impulse SDK", "tinyml_sdk_runtime", packages=["edge-impulse-sdk"])
register("synopsys_arc_mli_runtime", "Synopsys ARC MLI runtime", "tinyml_inference_runtime", files=[r"^libmli\.a$"])
register("sensiml_knowledge_pack", "SensiML Knowledge Pack", "tinyml_sdk_runtime", files=[r"^libsensiml\.a$"])
register("arm_ethos_u_core_driver", "Arm Ethos-U Core Driver", "mcu_npu_driver", packages=["ethos-u-core-driver"])
register("lvgl", "LVGL", "gui_library", packages=["lvgl"])
register("esp_idf", "ESP-IDF", "embedded_platform_sdk", packages=["esp-idf"])

# Thingino / Ingenic camera-firmware families.  Exact basenames prevent the
# rules from leaking into unrelated vendor trees.
register("everest_tls_helper", "Everest TLS helper", "tls_helper", files=[r"^libeverest(?:\.so(?:\..*)?|\.a)$"])
register("faac", "FAAC encoder", "audio_codec_library", packages=["faac"], files=[r"^libfaac(?:\.so(?:\..*)?|\.a)$"])
register("flac_lite", "FLAC-lite codec", "audio_codec_library", files=[r"^libflac-lite(?:\.so(?:\..*)?|\.a)$"], banners=[r"\bFLAC(?:__VERSION_STRING)?[ /:_-]*([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
register("helix_aac_decoder", "Helix AAC decoder", "audio_codec_library", files=[r"^libhelix-aac(?:\.so(?:\..*)?|\.a)$"])
register("helix_mp3_decoder", "Helix MP3 decoder", "audio_codec_library", files=[r"^libhelix-mp3(?:\.so(?:\..*)?|\.a)$"])
register("ingenic_alog_runtime", "Ingenic alog runtime", "vendor_runtime", files=[r"^libalog(?:\.so(?:\..*)?|\.a)$"])
register("ingenic_audio_processing_sdk", "Ingenic audio processing SDK", "vendor_audio_sdk", files=[r"^libaudioProcess(?:\.so(?:\..*)?|\.a)$"], banners=[r"(?:Ingenic\s+AEC\s+Version|audioProcess)[^0-9]*([0-9]+(?:[._-][0-9A-Za-z]+){1,5})"])
register("ingenic_avpu_driver", "Ingenic AVPU driver", "vendor_video_driver", files=[r"^avpu\.ko$"])
register("ingenic_imp_sdk", "Ingenic IMP multimedia SDK", "vendor_multimedia_sdk", files=[r"^libimp(?:\.so(?:\..*)?|\.a)$"])
register("ingenic_sensor_plugins", "Ingenic sensor driver plugins", "vendor_sensor_plugins", files=[r"^sensor_[A-Za-z0-9_+.-]+\.ko$"])
register("ingenic_tx_isp_driver", "Ingenic TX-ISP driver", "vendor_isp_driver", files=[r"^tx-isp-[A-Za-z0-9_+.-]+\.ko$"])
register("jct_json_runtime", "JCT JSON runtime", "serialization_runtime", files=[r"^libjct(?:\.so(?:\..*)?|\.a)$"])
register("mdnsd", "mDNS daemon library", "network_discovery_library", packages=["mdnsd"], files=[r"^libmdnsd(?:\.so(?:\..*)?|\.a)$", r"^mdnsd$"])
register("muslshim_runtime", "musl compatibility shim", "libc_runtime", files=[r"^libmuslshim(?:\.so(?:\..*)?|\.a)$"])
register("openwrt_ustream_ssl", "OpenWrt ustream-ssl", "openwrt_tls_library", packages=["ustream-ssl"], files=[r"^libustream-ssl(?:\.so(?:\..*)?|\.a)$"])
register("p256m_ecc_helper", "P-256 ECC helper", "crypto_helper", files=[r"^libp256m(?:\.so(?:\..*)?|\.a)$"])
register("schrift", "schrift font rendering library", "font_library", packages=["schrift", "libschrift"], files=[r"^libschrift(?:\.so(?:\..*)?|\.a)$"])
register("vendor_sysutils_runtime", "Vendor sysutils runtime", "vendor_runtime", files=[r"^libsysutils(?:\.so(?:\..*)?|\.a)$"])
register("wireguard", "WireGuard kernel module", "kernel_network_module", files=[r"^wireguard\.ko$"], banners=[r"\bWireGuard(?:\s+version)?[ /:_-]*v?([0-9]+(?:[._-][0-9A-Za-z]+){1,5})", r"\bversion[=: ]+([0-9]+(?:[._-][0-9A-Za-z]+){1,5})"])
register("exfat_kernel_module", "exFAT kernel module", "kernel_filesystem_module", files=[r"^exfat\.ko$"])
register("wireless_driver_plugins", "Wireless driver plugins", "kernel_wireless_driver", files=[r"^bcmdhd\.ko$"])

# Source-dependency packages observed in SDK/example archives.
for _cid, _name, _cat, _pkgs in [
    ("onnx", "ONNX", "ai_model_format_library", ["onnx"]),
    ("aiortc", "aiortc", "python_webrtc_library", ["aiortc"]),
    ("gson", "Gson", "serialization_library", ["gson"]),
    ("okhttp", "OkHttp", "android_network_library", ["okhttp", "okhttp3"]),
    ("glide", "Glide", "android_image_library", ["glide"]),
    ("dagger", "Dagger", "dependency_injection_library", ["dagger"]),
    ("kotlin_runtime", "Kotlin Runtime", "android_language_runtime", ["kotlin", "kotlin-stdlib", "kotlin-stdlib-jdk7", "kotlin-stdlib-jdk8"]),
    ("kotlinx_coroutines", "Kotlinx Coroutines", "android_async_runtime", ["kotlinx-coroutines", "kotlinx-coroutines-core", "kotlinx-coroutines-android"]),
    ("firebase_android_sdk", "Firebase Android SDK", "android_cloud_service_sdk", ["firebase"]),
    ("google_play_services", "Google Play Services", "android_platform_service_sdk", ["play-services"]),
    ("camera_x", "AndroidX CameraX", "android_camera_library", ["camera-x", "camerax"]),
]:
    if _cid not in SPECS:
        register(_cid, _name, _cat, packages=_pkgs)
    else:
        for _pkg in _pkgs:
            PACKAGE_TO_COMPONENT[_pkg.lower().replace("_", "-")] = _cid


# ---------------------------------------------------------------------------
# Android / JNI native-library normalizers
# ---------------------------------------------------------------------------
#
# Android APKs usually bundle native libraries under lib/<ABI>/*.so.
# Identity stays conservative: basename / SONAME only. ABI paths, NEEDED
# dependencies and arbitrary strings are evidence, never identity sources.
#
# Generic names such as libnative-lib.so and libapp.so are intentionally not
# mapped because they do not identify a reusable third-party component.

def extend_native_rules(
    cid: str,
    *,
    files: Iterable[str] = (),
    broad_files: Iterable[str] = (),
    packages: Iterable[str] = (),
) -> None:
    spec = SPECS[cid]
    spec.file_patterns.extend(_compile_patterns(files))
    spec.broad_file_patterns.extend(_compile_patterns(broad_files))
    for pkg in packages:
        normalized = pkg.lower().replace("_", "-")
        spec.packages.add(normalized)
        PACKAGE_TO_COMPONENT[normalized] = cid


# AI / CV runtimes.
register(
    "tensorflow_lite",
    "TensorFlow Lite Android Runtime",
    "android_ai_runtime",
    cpe="cpe:2.3:a:google:tensorflow:",
    packages=["tensorflow-lite", "tflite-runtime"],
    files=[
        r"^libtensorflowlite(?:_[A-Za-z0-9.+-]+)*_jni(?:\.so(?:\..*)?)$",
        r"^libtensorflowlite_gpu_jni(?:\.so(?:\..*)?)$",
        r"^libtensorflowlite_flex_jni(?:\.so(?:\..*)?)$",
    ],
    banners=[r"\b(?:TensorFlow\s+Lite|TFLite)[ /_-]*v?([0-9]+(?:\.[0-9A-Za-z]+){1,5})"],
)
register(
    "google_arcore",
    "Google ARCore SDK",
    "android_ar_sdk",
    packages=["arcore", "com.google.ar.core"],
    files=[r"^libarcore_sdk_(?:c|jni)(?:\.so(?:\..*)?)$"],
)
register(
    "mediapipe_android",
    "MediaPipe Android Runtime",
    "android_ai_runtime",
    packages=["mediapipe"],
    files=[r"^libmediapipe(?:_jni)?(?:\.so(?:\..*)?)$", r"^libmediapipe_tasks_vision_jni(?:\.so(?:\..*)?)$"],
)
register("ncnn", "ncnn Mobile Inference Runtime", "mobile_ai_runtime", packages=["ncnn"], files=[r"^libncnn(?:_jni)?(?:\.so(?:\..*)?)$"])
register("mnn", "MNN Mobile Inference Runtime", "mobile_ai_runtime", packages=["mnn"], files=[r"^libMNN(?:_Express)?(?:\.so(?:\..*)?)$", r"^libmnn(?:_jni)?(?:\.so(?:\..*)?)$"])
register("xnnpack", "XNNPACK", "optimized_kernel", packages=["xnnpack"], files=[r"^libXNNPACK(?:\.so(?:\..*)?)$", r"^libxnnpack(?:\.so(?:\..*)?)$"])
register("openni2", "OpenNI2", "computer_vision_runtime", packages=["openni2", "openni"], files=[r"^libOpenNI2(?:\.so(?:\..*)?)$", r"^libopenni2(?:\.so(?:\..*)?)$"])

extend_native_rules("onnxruntime", files=[r"^libonnxruntime4j_jni(?:\.so(?:\..*)?)$", r"^libonnxruntime_jni(?:\.so(?:\..*)?)$"])
extend_native_rules("pytorch", files=[r"^libpytorch_jni(?:\.so(?:\..*)?)$", r"^libtorchvision_ops(?:\.so(?:\..*)?)$", r"^libtorch-code-gen(?:\.so(?:\..*)?)$"])
extend_native_rules("opencv", files=[r"^libopencv_java[0-9]*(?:\.so(?:\..*)?)$", r"^libopencv_world[0-9]*(?:\.so(?:\..*)?)$"])
extend_native_rules("protobuf", files=[r"^libprotobuf_jni(?:\.so(?:\..*)?)$", r"^libprotobuf-lite(?:\.so(?:\..*)?|\.a)$"])
extend_native_rules("grpc", files=[r"^libgrpc_jni(?:\.so(?:\..*)?)$", r"^libgrpc_csharp_ext(?:\.so(?:\..*)?)$"])

# Realtime communication / media.
register(
    "webrtc_native_runtime",
    "WebRTC Native Runtime",
    "android_realtime_media_library",
    packages=["webrtc", "org.webrtc"],
    files=[r"^libjingle_peerconnection_so(?:\.so(?:\..*)?)$", r"^libwebrtc(?:_jni)?(?:\.so(?:\..*)?)$", r"^libpeerconnection(?:_jni)?(?:\.so(?:\..*)?)$"],
)
register("android_gif_drawable", "Android GIF Drawable", "android_image_library", packages=["android-gif-drawable", "pl.droidsonroids.gif"], files=[r"^libpl_droidsonroids_gif(?:\.so(?:\..*)?)$"])
register("ffmpegkit", "FFmpegKit", "android_media_library", packages=["ffmpeg-kit", "ffmpegkit"], files=[r"^libffmpegkit(?:\.so(?:\..*)?)$", r"^libmobileffmpeg(?:\.so(?:\..*)?)$"])
register("vlc_android", "VLC Android Native Runtime", "android_media_library", packages=["vlc-android", "libvlc"], files=[r"^libvlcjni(?:\.so(?:\..*)?)$", r"^libvlc(?:\.so(?:\..*)?)$"])
register("fmod", "FMOD", "audio_library", packages=["fmod"], files=[r"^libfmod(?:L)?(?:\.so(?:\..*)?)$", r"^libfmodstudio(?:L)?(?:\.so(?:\..*)?)$"])
register("openal", "OpenAL", "audio_library", packages=["openal"], files=[r"^libopenal(?:\.so(?:\..*)?)$"])

# Android runtimes and framework bridges.
register("android_ndk_cpp_runtime", "Android NDK C++ Runtime", "android_runtime", files=[r"^libc\+\+_shared(?:\.so(?:\..*)?)$", r"^libgnustl_shared(?:\.so(?:\..*)?)$"])
register("flutter_engine", "Flutter Engine", "android_app_runtime", packages=["flutter"], files=[r"^libflutter(?:\.so(?:\..*)?)$"])
register("react_native_runtime", "React Native Runtime", "android_app_runtime", packages=["react-native"], files=[r"^libreactnativejni(?:\.so(?:\..*)?)$", r"^libreactnative(?:\.so(?:\..*)?)$", r"^libjsi(?:\.so(?:\..*)?)$"])
register("hermes_runtime", "Hermes JavaScript Runtime", "javascript_runtime", packages=["hermes", "hermes-engine"], files=[r"^libhermes(?:\.so(?:\..*)?)$", r"^libhermes-executor-(?:debug|release)(?:\.so(?:\..*)?)$"])
register("fbjni", "Facebook JNI Helpers", "android_jni_support_library", packages=["fbjni"], files=[r"^libfbjni(?:\.so(?:\..*)?)$"])
register("folly_runtime", "Folly Runtime", "cpp_library", packages=["folly"], files=[r"^libfolly_runtime(?:\.so(?:\..*)?)$", r"^libfolly(?:\.so(?:\..*)?)$"])
register("glog", "glog", "logging_library", packages=["glog"], files=[r"^libglog(?:\.so(?:\..*)?)$"])
register("gflags", "gflags", "cpp_library", packages=["gflags"], files=[r"^libgflags(?:\.so(?:\..*)?)$"])
register("unity_runtime", "Unity Runtime", "android_app_runtime", packages=["unity"], files=[r"^libunity(?:\.so(?:\..*)?)$", r"^libil2cpp(?:\.so(?:\..*)?)$"])

# Android networking / crypto / storage SDKs.
register("conscrypt", "Conscrypt", "android_crypto_library", packages=["conscrypt"], files=[r"^libconscrypt_jni(?:\.so(?:\..*)?)$", r"^libconscrypt_openjdk_jni(?:\.so(?:\..*)?)$"])
register("boringssl", "BoringSSL", "crypto_library", packages=["boringssl"], files=[r"^libboringssl(?:\.so(?:\..*)?)$", r"^libsslwrapper_jni(?:\.so(?:\..*)?)$"])
register("cronet", "Chromium Cronet", "android_network_library", packages=["cronet"], files=[r"^libcronet\.[0-9.]+(?:\.so(?:\..*)?)$", r"^libcronet(?:_jni)?(?:\.so(?:\..*)?)$"])
register("realm", "Realm Database", "android_database_library", packages=["realm", "realm-android"], files=[r"^librealm-jni(?:\.so(?:\..*)?)$", r"^librealm(?:\.so(?:\..*)?)$"])
register("sqlcipher", "SQLCipher", "database_library", packages=["sqlcipher"], files=[r"^libsqlcipher(?:\.so(?:\..*)?)$"])
register("mmkv", "MMKV", "android_database_library", packages=["mmkv"], files=[r"^libmmkv(?:\.so(?:\..*)?)$"])
register("mapbox_gl_native", "Mapbox GL Native", "android_map_sdk", packages=["mapbox-gl", "mapbox"], files=[r"^libmapbox-gl(?:\.so(?:\..*)?)$", r"^libmapbox_maps(?:\.so(?:\..*)?)$"])
register("firebase_cpp_sdk", "Firebase C++ SDK", "cloud_service_sdk", packages=["firebase"], files=[r"^libfirebase_[A-Za-z0-9_+.-]+(?:\.so(?:\..*)?)$"])
register("android_game_sdk", "Android Game SDK", "android_game_runtime", packages=["android-game-sdk", "swappy"], files=[r"^libswappy(?:_frame_pacing)?(?:\.so(?:\..*)?)$", r"^libtuningfork(?:\.so(?:\..*)?)$"])

ANDROID_JNI_COMPONENTS: Set[str] = {
    "tensorflow_lite", "google_arcore", "mediapipe_android", "ncnn", "mnn",
    "xnnpack", "openni2", "webrtc_native_runtime", "android_gif_drawable",
    "ffmpegkit", "vlc_android", "fmod", "openal", "android_ndk_cpp_runtime",
    "flutter_engine", "react_native_runtime", "hermes_runtime", "fbjni",
    "folly_runtime", "glog", "gflags", "unity_runtime", "conscrypt",
    "boringssl", "cronet", "realm", "sqlcipher", "mmkv", "mapbox_gl_native",
    "firebase_cpp_sdk", "android_game_sdk",
}


# Explicit Android Java/Kotlin package namespaces found in classes.dex.  These
# are precise package identities, not fuzzy keyword searches.
ANDROID_DEX_PREFIXES: Dict[str, Tuple[bytes, ...]] = {
    "tensorflow_lite": (b"org/tensorflow/lite/",),
    "google_arcore": (b"com/google/ar/core/",),
    "webrtc_native_runtime": (b"org/webrtc/",),
    "android_gif_drawable": (b"pl/droidsonroids/gif/",),
    "firebase_android_sdk": (b"com/google/firebase/",),
    "google_play_services": (b"com/google/android/gms/",),
    "okhttp": (b"okhttp3/",),
    "gson": (b"com/google/gson/",),
    "protobuf": (b"com/google/protobuf/",),
    "grpc": (b"io/grpc/",),
    "glide": (b"com/bumptech/glide/",),
    "dagger": (b"dagger/",),
    "kotlin_runtime": (b"kotlin/",),
    "kotlinx_coroutines": (b"kotlinx/coroutines/",),
    "camera_x": (b"androidx/camera/",),
    "mediapipe_android": (b"com/google/mediapipe/",),
}

ANDROID_FULL_COMPONENTS: Set[str] = set(ANDROID_DEX_PREFIXES) | ANDROID_JNI_COMPONENTS
MCU_SOURCE_COMPONENTS: Set[str] = {
    "cmsis_core", "cmsis_dsp", "cmsis_nn", "edge_impulse_sdk",
    "synopsys_arc_mli_runtime", "tensorflow_lite_micro",
    "arm_ethos_u_core_driver", "sensiml_knowledge_pack", "freertos", "lvgl",
}




# ---------------------------------------------------------------------------
# Version handling
# ---------------------------------------------------------------------------

VERSION_RE = re.compile(r"(?<![A-Za-z0-9])v?([0-9]+(?:[._-][0-9A-Za-z]+){1,6}(?:[+.-][0-9A-Za-z]+)*)")
KERNEL_TREE_RE = re.compile(r"(?:^|/)lib/modules/([^/]+)/")
SONAME_ABI_RE = re.compile(r"\.so\.([0-9]+(?:\.[0-9A-Za-z]+){0,5})$")
FILE_RELEASE_RE = re.compile(r"[-_]v?([0-9]+(?:\.[0-9A-Za-z]+){1,5})(?:[-_+.][A-Za-z0-9]+)*\.(?:whl|egg|jar|ipk|deb|rpm|zip|tar|gz|xz)$", re.I)
DEP_RE = re.compile(r"\b(?P<name>[A-Za-z0-9_.+\-/]+)(?:\[.*?\])?\s*(?P<op>==|=|>=|<=|~=|>|<)\s*v?(?P<ver>[0-9][A-Za-z0-9_.+\-]*)")

VERSION_PRIORITY = {
    "binary_banner": 100,
    "kernel_tree": 100,
    "exact_metadata": 95,
    "source_version_file": 98,
    "source_header_version": 97,
    "android_gradle_dependency": 96,
    "source_version_macro": 94,
    "exact_dependency": 90,
    "module_banner": 85,
    "filename_release": 70,
    "range_dependency": 45,
    "soname_abi": 20,
    "unknown": 0,
}
STRICT_VERSION_KINDS = {"binary_banner", "kernel_tree", "source_version_file", "source_header_version", "android_gradle_dependency", "exact_metadata", "source_version_macro", "exact_dependency", "module_banner", "filename_release"}


def normalize_version(value: str) -> str:
    value = str(value or "").strip().strip('"').strip("'")
    value = re.sub(r"^[vV]", "", value)
    value = value.rstrip(".,;:)")
    value = value.replace("_", ".")
    return value[:120]


def valid_numeric_version(value: str) -> bool:
    value = normalize_version(value)
    if not value or not re.search(r"[0-9]", value):
        return False
    if re.search(r"\s", value):
        return False
    return bool(re.fullmatch(r"[0-9][0-9A-Za-z.+_-]{0,119}", value))


def candidate(value: str, kind: str, evidence: str) -> Optional[Tuple[str, str, int, str]]:
    value = normalize_version(value)
    if not valid_numeric_version(value):
        return None
    return value, kind, VERSION_PRIORITY.get(kind, 0), re.sub(r"\s+", " ", evidence)[:500]


def filename_version(name: str) -> Optional[Tuple[str, str, int, str]]:
    m = FILE_RELEASE_RE.search(name)
    return candidate(m.group(1), "filename_release", f"filename={name}") if m else None


def soname_abi_version(soname: str) -> Optional[Tuple[str, str, int, str]]:
    m = SONAME_ABI_RE.search(soname or "")
    return candidate(m.group(1), "soname_abi", f"soname={soname}") if m else None


def extract_banner_versions(cid: str, text: str) -> List[Tuple[str, str, int, str]]:
    spec = SPECS.get(cid)
    if not spec or not text:
        return []
    out: List[Tuple[str, str, int, str]] = []
    kind = "module_banner" if cid in {"vendor_audio_processing_sdk", "xmedia_sdk", "ingenic_audio_processing_sdk", "wireguard"} else "binary_banner"
    for rg in spec.banner_patterns:
        for m in rg.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            item = candidate(value, kind, m.group(0))
            if item:
                out.append(item)
    return out


# Some libraries expose a version API symbol and store the release as an isolated
# printable string. This mirrors the manual retained-library inspection workflow:
# readelf -d for SONAME/NEEDED plus strings -a filtered by component-specific clues.
# We deliberately restrict standalone-number extraction to components for which the
# API anchor is strong enough; blindly collecting every numeric string causes noise.
VERSION_API_ANCHORS: Dict[str, Tuple[str, ...]] = {
    "json_c": ("json_c_version", "json_c_version_num"),
    "libyaml": ("yaml_get_version_string", "yaml_get_version"),
}
STANDALONE_RELEASE_LINE_RE = re.compile(r"(?m)^\s*([0-9]+(?:\.[0-9A-Za-z_-]+){1,5})\s*$")


def extract_api_anchored_versions(cid: str, text: str) -> List[Tuple[str, str, int, str]]:
    anchors = VERSION_API_ANCHORS.get(cid, ())
    if not text or not anchors:
        return []
    matched_anchor = next((x for x in anchors if x in text), "")
    if not matched_anchor:
        return []
    out: List[Tuple[str, str, int, str]] = []
    for m in STANDALONE_RELEASE_LINE_RE.finditer(text):
        item = candidate(m.group(1), "binary_banner", f"api_anchor={matched_anchor}; standalone_version={m.group(1)}")
        if item:
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# Native identity and metadata
# ---------------------------------------------------------------------------

@dataclass
class NativeMeta:
    soname: str = ""
    needed: str = ""
    architecture: str = ""
    machine: str = ""
    build_id: str = ""


def readelf_metadata(path: Path) -> NativeMeta:
    out = NativeMeta()
    if shutil.which("file"):
        _, stdout, _ = run_cmd(["file", str(path)], timeout=20)
        out.architecture = stdout.strip().split(":", 1)[-1].strip()[:400] if stdout else ""
    if not shutil.which("readelf"):
        return out
    _, stdout, _ = run_cmd(["readelf", "-h", str(path)], timeout=30)
    for line in stdout.splitlines():
        if line.strip().startswith("Machine:"):
            out.machine = line.split(":", 1)[1].strip()
    _, stdout, _ = run_cmd(["readelf", "-d", str(path)], timeout=30)
    needed: List[str] = []
    for line in stdout.splitlines():
        m = re.search(r"\[(.*?)\]", line)
        if "(SONAME)" in line and m:
            out.soname = m.group(1)
        elif "(NEEDED)" in line and m:
            needed.append(m.group(1))
    out.needed = ";".join(dict.fromkeys(needed))[:2000]
    _, stdout, _ = run_cmd(["readelf", "-n", str(path)], timeout=30)
    m = re.search(r"Build ID:\s*([0-9A-Fa-f]+)", stdout)
    out.build_id = m.group(1) if m else ""
    return out


def detect_native_component(basename: str, soname: str = "") -> Tuple[str, str]:
    """Return (component_id, certainty).

    Identity is intentionally basename/SONAME-only. Full paths and NEEDED are not used.
    """
    names = [str(basename or "").strip(), str(soname or "").strip()]
    for cid, spec in SPECS.items():
        for name in names:
            if name and any(rg.search(name) for rg in spec.file_patterns):
                return cid, "precise"
    for cid, spec in SPECS.items():
        for name in names:
            if name and any(rg.search(name) for rg in spec.broad_file_patterns):
                return cid, "broad"
    return "", ""


def map_package(name: str) -> str:
    raw = str(name or "").strip().lower().replace("_", "-")
    raw = raw.split("/")[-1] if raw.startswith("espressif/") else raw
    return PACKAGE_TO_COMPONENT.get(raw, "")


def normalize_package_release(cid: str, package_name: str, version: str) -> str:
    """Normalize package build versions to upstream releases where justified."""
    cid = str(cid or "")
    package = str(package_name or "").strip().lower()
    value = normalize_version(version)
    if cid == "opencv" and package.startswith("opencv-"):
        # Python wheels append a packaging build component: 4.5.5.62 -> 4.5.5.
        m = re.fullmatch(r"(\d+\.\d+\.\d+)\.\d+", value)
        if m:
            return m.group(1)
    if cid == "pytorch" and package in {"torch", "torchvision", "torchaudio"}:
        return value.split("+", 1)[0]
    return value


MAVEN_COORD_RE = re.compile(
    r"(?P<group>[A-Za-z0-9_.-]+):(?P<artifact>[A-Za-z0-9_.-]+):(?P<version>[0-9][A-Za-z0-9_.+\-]*)"
)


def map_maven_coordinate(group: str, artifact: str) -> str:
    group = str(group or "").strip()
    artifact = str(artifact or "").strip()
    exact = {
        ("org.tensorflow", "tensorflow-lite"): "tensorflow_lite",
        ("org.tensorflow", "tensorflow-lite-gpu"): "tensorflow_lite",
        ("org.tensorflow", "tensorflow-lite-support"): "tensorflow_lite",
        ("com.google.ar", "core"): "google_arcore",
        ("pl.droidsonroids.gif", "android-gif-drawable"): "android_gif_drawable",
        ("com.github.bumptech.glide", "glide"): "glide",
        ("com.google.code.gson", "gson"): "gson",
        ("com.squareup.okhttp3", "okhttp"): "okhttp",
        ("com.google.dagger", "dagger"): "dagger",
        ("org.webrtc", "google-webrtc"): "webrtc_native_runtime",
    }
    if (group, artifact) in exact:
        return exact[(group, artifact)]
    if group == "com.google.firebase":
        return "firebase_android_sdk"
    if group == "com.google.android.gms" and artifact.startswith("play-services"):
        return "google_play_services"
    if group == "androidx.camera" and artifact.startswith("camera-"):
        return "camera_x"
    if group == "org.jetbrains.kotlin" and artifact.startswith("kotlin-"):
        return "kotlin_runtime"
    if group == "org.jetbrains.kotlinx" and artifact.startswith("kotlinx-coroutines"):
        return "kotlinx_coroutines"
    if group == "io.grpc" and artifact.startswith("grpc-"):
        return "grpc"
    if group == "com.google.protobuf" and artifact.startswith("protobuf-"):
        return "protobuf"
    return ""




# ---------------------------------------------------------------------------
# Evidence model
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    firmware_id: str
    model: str
    firmware_version: str
    component_id: str
    presence: str                   # precise | broad
    evidence_type: str
    file_name: str = ""
    file_path: str = ""
    sha256: str = ""
    soname: str = ""
    needed: str = ""
    version_candidates: List[Tuple[str, str, int, str]] = field(default_factory=list)
    note: str = ""
    scope: str = "runtime_or_source"


def component_meta(cid: str) -> ComponentSpec:
    return SPECS.get(cid, ComponentSpec(cid, cid, "unknown"))


def add_candidate_unique(items: List[Tuple[str, str, int, str]], item: Optional[Tuple[str, str, int, str]]) -> None:
    if not item:
        return
    key = (item[0], item[1])
    if not any((x[0], x[1]) == key for x in items):
        items.append(item)


def select_version(evidence_rows: List[Evidence]) -> Tuple[str, str, str, str]:
    candidates: List[Tuple[str, str, int, str]] = []
    for ev in evidence_rows:
        for item in ev.version_candidates:
            if not any((x[0], x[1], x[3]) == (item[0], item[1], item[3]) for x in candidates):
                candidates.append(item)
    if not candidates:
        return "unknown", "unknown", "", ""

    candidates.sort(key=lambda x: (x[2], x[1], x[0]), reverse=True)
    strict = [x for x in candidates if x[1] in STRICT_VERSION_KINDS]
    if strict:
        top_priority = max(x[2] for x in strict)
        top_versions = sorted({x[0] for x in strict if x[2] == top_priority})
        if len(top_versions) == 1:
            chosen = next(x for x in strict if x[2] == top_priority and x[0] == top_versions[0])
            return chosen[0], chosen[1], clean_join([x[0] for x in candidates], 20, 1500), chosen[3]
        # Conflicting equally strong versions: do not invent a single release.
        return "unknown", "conflict", clean_join([x[0] for x in candidates], 20, 1500), "multiple equally strong version candidates"

    # ABI/range-only clues remain candidates; Version stays unknown.
    return "unknown", candidates[0][1], clean_join([x[0] for x in candidates], 20, 1500), candidates[0][3]


def evidence_key(ev: Evidence) -> Tuple[str, ...]:
    # SHA removes recursive extraction duplicates. If no SHA, use evidence path.
    stable = ev.sha256 or ev.file_path or ev.note
    return (ev.firmware_id, ev.component_id, stable, ev.evidence_type, ev.presence)


# ---------------------------------------------------------------------------
# Scan raw stage-01 rows
# ---------------------------------------------------------------------------


def extract_dependency_version(row: Dict[str, str]) -> Tuple[str, str]:
    blob = " ".join([row.get("Version_String", ""), row.get("Evidence", ""), row.get("SDK_Name", "")])
    m = DEP_RE.search(blob)
    if m:
        kind = "exact_dependency" if m.group("op") in {"==", "="} else "range_dependency"
        return m.group("ver"), kind
    # Stage-01 Version_String can already contain a clean numeric value.
    raw = normalize_version(row.get("Version_String", ""))
    if valid_numeric_version(raw):
        return raw, "exact_dependency"
    return "", "unknown"


def raw_rows_to_evidence(raw_rows: List[Dict[str, str]], extracted_root: Path) -> Tuple[List[Evidence], Dict[str, Tuple[str, str]]]:
    out: List[Evidence] = []
    fw_meta: Dict[str, Tuple[str, str]] = {}
    strings_cache: Dict[str, str] = {}

    for row in raw_rows:
        fid = (row.get("FirmwareID") or "").strip()
        model = (row.get("Model") or "").strip()
        fwver = (row.get("Version") or "").strip()
        if fid:
            fw_meta[fid] = (model, fwver)

        evidence_type = (row.get("Evidence_Type") or "").strip().lower()
        file_path = (row.get("File_Path") or "").strip().replace("\\", "/")
        basename = Path(file_path).name or Path(row.get("Retained_Path", "")).name
        sha = (row.get("SHA256") or "").strip()
        soname = (row.get("SONAME") or "").strip()
        needed = (row.get("NEEDED") or "").strip()

        if evidence_type == "dependency_manifest" or (row.get("File_Type") or "").lower() == "dependency_manifest":
            cid = map_package(row.get("SDK_Name", ""))
            if not cid:
                continue
            ver, kind = extract_dependency_version(row)
            candidates: List[Tuple[str, str, int, str]] = []
            add_candidate_unique(candidates, candidate(ver, kind, row.get("Evidence", "")))
            presence = "precise" if dependency_scope(file_path) == "runtime_or_source" else "broad"
            out.append(Evidence(
                firmware_id=fid, model=model, firmware_version=fwver, component_id=cid,
                presence=presence, evidence_type="dependency_manifest", file_name=basename,
                file_path=file_path, sha256=sha, version_candidates=candidates,
                note=row.get("Evidence", ""), scope=dependency_scope(file_path),
            ))
            continue

        # Kernel version is independent from the individual module identity.
        km = KERNEL_TREE_RE.search(file_path)
        if km:
            kval = candidate(km.group(1), "kernel_tree", f"path={file_path}")
            out.append(Evidence(
                firmware_id=fid, model=model, firmware_version=fwver,
                component_id="linux_kernel", presence="precise", evidence_type="kernel_module_tree",
                file_name=basename, file_path=file_path, sha256="",
                version_candidates=[kval] if kval else [], note=f"/lib/modules/{km.group(1)}",
            ))

        cid, presence = detect_native_component(basename, soname)
        if not cid:
            # Conservative fallback for stage-01 normalized AI/runtime names.
            cid = map_package(row.get("SDK_Name", ""))
            presence = "broad" if cid else ""
        if not cid:
            continue

        candidates: List[Tuple[str, str, int, str]] = []
        add_candidate_unique(candidates, filename_version(basename))
        add_candidate_unique(candidates, soname_abi_version(soname))

        blob = (row.get("Version_String") or "") + "\n" + (row.get("Evidence") or "")
        for item in extract_banner_versions(cid, blob):
            add_candidate_unique(candidates, item)

        # Scan actual extracted file if available. Cache by SHA/path.
        actual = resolve_extracted_firmware_root(extracted_root, fid) / file_path if fid and file_path else Path("")
        if actual and actual.exists() and actual.is_file() and cid:
            cache_key = sha or str(actual)
            if cache_key not in strings_cache:
                strings_cache[cache_key] = strings_text(actual)
            for item in extract_banner_versions(cid, strings_cache[cache_key]):
                add_candidate_unique(candidates, item)
            for item in extract_api_anchored_versions(cid, strings_cache[cache_key]):
                add_candidate_unique(candidates, item)

        out.append(Evidence(
            firmware_id=fid, model=model, firmware_version=fwver, component_id=cid,
            presence=presence or "broad", evidence_type="stage01_native_row", file_name=basename,
            file_path=file_path, sha256=sha, soname=soname, needed=needed,
            version_candidates=candidates, note=row.get("Evidence", ""),
        ))

    return out, fw_meta


# ---------------------------------------------------------------------------
# Scan retained libraries and extracted tree
# ---------------------------------------------------------------------------


def scan_retained_libraries(retained_root: Path, fw_meta: Dict[str, Tuple[str, str]]) -> List[Evidence]:
    out: List[Evidence] = []
    if not retained_root.exists():
        return out
    metadata_cache: Dict[str, NativeMeta] = {}
    text_cache: Dict[str, str] = {}
    sha_cache: Dict[str, str] = {}

    for path in iter_files(retained_root):
        fid = parse_retained_firmware_id(path, retained_root)
        model, fwver = fw_meta.get(fid, parse_model_version_from_firmware_id(fid))
        basename = recover_retained_basename(path)
        path_str = relative_or_string(path, retained_root)
        sha = safe_sha256(path)
        cache_key = sha or str(path)
        if cache_key not in metadata_cache:
            metadata_cache[cache_key] = readelf_metadata(path)
        meta = metadata_cache[cache_key]
        cid, presence = detect_native_component(basename, meta.soname)
        if not cid:
            continue
        if cache_key not in text_cache:
            text_cache[cache_key] = strings_text(path)
        candidates: List[Tuple[str, str, int, str]] = []
        add_candidate_unique(candidates, filename_version(basename))
        add_candidate_unique(candidates, soname_abi_version(meta.soname))
        for item in extract_banner_versions(cid, text_cache[cache_key]):
            add_candidate_unique(candidates, item)
        for item in extract_api_anchored_versions(cid, text_cache[cache_key]):
            add_candidate_unique(candidates, item)
        out.append(Evidence(
            firmware_id=fid, model=model, firmware_version=fwver,
            component_id=cid, presence=presence or "broad", evidence_type="retained_native_binary",
            file_name=basename, file_path=path_str, sha256=sha, soname=meta.soname,
            needed=meta.needed, version_candidates=candidates,
            note=f"retained library; soname={meta.soname}",
        ))
    return out


def is_native_file(path: Path) -> bool:
    name = path.name
    if ".so" in name:
        return True
    return path.suffix.lower() in NATIVE_SUFFIXES


def scan_extracted_native(extracted_root: Path, fw_meta: Dict[str, Tuple[str, str]]) -> List[Evidence]:
    """Direct native scan for recall. Deduplication later prevents recursive-path inflation."""
    out: List[Evidence] = []
    metadata_cache: Dict[str, NativeMeta] = {}
    text_cache: Dict[str, str] = {}
    for path in iter_files(extracted_root):
        if not is_native_file(path):
            continue
        fid = firmware_id_from_extracted_path(path, extracted_root)
        if not fid:
            continue
        model, fwver = fw_meta.get(fid, parse_model_version_from_firmware_id(fid))
        basename = path.name
        relpath = relative_or_string(path, extracted_root / fid)
        sha = safe_sha256(path)
        cache_key = sha or str(path)
        if cache_key not in metadata_cache:
            metadata_cache[cache_key] = readelf_metadata(path)
        meta = metadata_cache[cache_key]
        cid, presence = detect_native_component(basename, meta.soname)
        if not cid:
            # Kernel tree is still useful even if generic .ko has no component.
            km = KERNEL_TREE_RE.search(relpath)
            if km:
                kval = candidate(km.group(1), "kernel_tree", f"path={relpath}")
                out.append(Evidence(
                    firmware_id=fid, model=model, firmware_version=fwver,
                    component_id="linux_kernel", presence="precise", evidence_type="kernel_module_tree",
                    file_name=basename, file_path=relpath,
                    version_candidates=[kval] if kval else [], note=f"/lib/modules/{km.group(1)}",
                ))
            continue
        candidates: List[Tuple[str, str, int, str]] = []
        add_candidate_unique(candidates, filename_version(basename))
        add_candidate_unique(candidates, soname_abi_version(meta.soname))
        if cache_key not in text_cache:
            text_cache[cache_key] = strings_text(path)
        for item in extract_banner_versions(cid, text_cache[cache_key]):
            add_candidate_unique(candidates, item)
        for item in extract_api_anchored_versions(cid, text_cache[cache_key]):
            add_candidate_unique(candidates, item)
        out.append(Evidence(
            firmware_id=fid, model=model, firmware_version=fwver,
            component_id=cid, presence=presence or "broad", evidence_type="direct_native_binary",
            file_name=basename, file_path=relpath, sha256=sha, soname=meta.soname,
            needed=meta.needed, version_candidates=candidates,
            note=f"direct native scan; soname={meta.soname}",
        ))
        km = KERNEL_TREE_RE.search(relpath)
        if km:
            kval = candidate(km.group(1), "kernel_tree", f"path={relpath}")
            out.append(Evidence(
                firmware_id=fid, model=model, firmware_version=fwver,
                component_id="linux_kernel", presence="precise", evidence_type="kernel_module_tree",
                file_name=basename, file_path=relpath,
                version_candidates=[kval] if kval else [], note=f"/lib/modules/{km.group(1)}",
            ))
    return out


# ---------------------------------------------------------------------------
# Metadata scanning
# ---------------------------------------------------------------------------

PY_META_NAME = re.compile(r"(?mi)^Name:\s*([^\n]+)")
PY_META_VERSION = re.compile(r"(?mi)^Version:\s*v?([0-9][A-Za-z0-9_.+\-]*)")
PC_VERSION = re.compile(r"(?mi)^Version:\s*v?([0-9][A-Za-z0-9_.+\-]*)")
PC_NAME = re.compile(r"(?mi)^(?:Name|Description):\s*([^\n]+)")
PKG_STATUS = re.compile(r"(?ms)^Package:\s*([^\n]+)\n.*?^Version:\s*([^\n]+)")


def add_manifest_evidence(
    out: List[Evidence], fid: str, model: str, fwver: str, cid: str,
    version: str, kind: str, path_text: str, note: str,
) -> None:
    item = candidate(version, kind, note)
    out.append(Evidence(
        firmware_id=fid, model=model, firmware_version=fwver,
        component_id=cid, presence="precise" if dependency_scope(path_text) == "runtime_or_source" else "broad",
        evidence_type="metadata", file_name=Path(path_text).name, file_path=path_text,
        version_candidates=[item] if item else [], note=note, scope=dependency_scope(path_text),
    ))


def scan_metadata(extracted_root: Path, fw_meta: Dict[str, Tuple[str, str]]) -> List[Evidence]:
    out: List[Evidence] = []
    for path in iter_files(extracted_root):
        name = path.name
        lower_path = str(path).lower().replace("\\", "/")
        if name not in METADATA_NAMES and path.suffix.lower() not in {".pc"} and not lower_path.endswith((".dist-info/metadata", ".egg-info/pkg-info")):
            continue
        text = read_text(path)
        if not text:
            continue
        fid = firmware_id_from_extracted_path(path, extracted_root)
        if not fid:
            continue
        model, fwver = fw_meta.get(fid, parse_model_version_from_firmware_id(fid))
        relpath = relative_or_string(path, extracted_root / fid)

        # requirement-like lines
        for line in text.splitlines():
            m = DEP_RE.search(line)
            if not m:
                continue
            cid = map_package(m.group("name"))
            if not cid:
                continue
            kind = "exact_dependency" if m.group("op") in {"==", "="} else "range_dependency"
            normalized = normalize_package_release(cid, m.group("name"), m.group("ver"))
            add_manifest_evidence(out, fid, model, fwver, cid, normalized, kind, relpath, line.strip())

        # Python METADATA / PKG-INFO
        if name in {"METADATA", "PKG-INFO"} or lower_path.endswith((".dist-info/metadata", ".egg-info/pkg-info")):
            mn, mv = PY_META_NAME.search(text), PY_META_VERSION.search(text)
            if mn and mv:
                cid = map_package(mn.group(1))
                if cid:
                    normalized = normalize_package_release(cid, mn.group(1), mv.group(1))
                    add_manifest_evidence(out, fid, model, fwver, cid, normalized, "exact_metadata", relpath, f"Name={mn.group(1)}; Version={mv.group(1)}")

        # pkg-config
        if path.suffix.lower() == ".pc":
            mv = PC_VERSION.search(text)
            ctx = " ".join(x.group(1) for x in PC_NAME.finditer(text)) + " " + path.stem
            cid = map_package(path.stem)
            if not cid:
                for token in re.split(r"[^A-Za-z0-9_.+\-]+", ctx):
                    cid = map_package(token)
                    if cid:
                        break
            if cid and mv:
                add_manifest_evidence(out, fid, model, fwver, cid, mv.group(1), "exact_metadata", relpath, f"pkg-config {path.name}: Version={mv.group(1)}")

        # dpkg/opkg status
        if name == "status" and ("dpkg" in lower_path or "opkg" in lower_path):
            for m in PKG_STATUS.finditer(text):
                cid = map_package(m.group(1).strip())
                if cid:
                    add_manifest_evidence(out, fid, model, fwver, cid, m.group(2).strip().split()[0], "exact_metadata", relpath, f"Package={m.group(1)}; Version={m.group(2)}")
    return out


# ---------------------------------------------------------------------------
# Source/header/build-file version macro scanning
# ---------------------------------------------------------------------------

# Explicit component-specific macro/variable names. Identity comes from the macro
# name itself, never from a long path or generic surrounding text.
SOURCE_VERSION_MACROS: Dict[str, Tuple[str, ...]] = {
    "busybox": ("BUSYBOX_VERSION", "BB_VER"),
    "openssl": ("OPENSSL_VERSION_TEXT", "OPENSSL_VERSION_STR", "OPENSSL_VERSION"),
    "mbedtls": ("MBEDTLS_VERSION_STRING_FULL", "MBEDTLS_VERSION_STRING", "MBEDTLS_OPENIPC_VERSION"),
    "zlib": ("ZLIB_VERSION",),
    "curl": ("LIBCURL_VERSION", "CURL_VERSION", "LIBCURL_OPENIPC_VERSION"),
    "json_c": ("JSON_C_VERSION", "JSONC_VERSION"),
    "libyaml": ("LIBYAML_VERSION", "YAML_VERSION_STRING", "YAML_VERSION"),
    "libevent": ("LIBEVENT_VERSION", "EVENT__VERSION", "LIBEVENT_OPENIPC_VERSION"),
    "libnl": ("LIBNL_VERSION",),
    "libogg": ("LIBOGG_VERSION", "OGG_VERSION", "LIBOGG_OPENIPC_VERSION"),
    "opus": ("OPUS_VERSION", "OPUS_OPENIPC_VERSION"),
    "lame": ("LAME_VERSION", "LAME_OPENIPC_VERSION"),
    "mosquitto": ("MOSQUITTO_VERSION",),
    "miniupnpc": ("MINIUPNPC_VERSION", "LIBMINIUPNPC_VERSION"),
    "libnatpmp": ("LIBNATPMP_VERSION", "NATPMP_VERSION"),
    "libwebsockets": ("LIBWEBSOCKETS_VERSION", "LWS_LIBRARY_VERSION", "LIBWEBSOCKETS_OPENIPC_VERSION"),
    "iptables_xtables": ("IPTABLES_VERSION", "XTABLES_VERSION"),
    "sqlite": ("SQLITE_VERSION", "SQLITE_VERSION_NUMBER"),
    "protobuf": ("PROTOBUF_VERSION",),
    "opencv": ("CV_VERSION", "OPENCV_VERSION"),
    "ffmpeg": ("FFMPEG_VERSION",),
    "linux_kernel": ("UTS_RELEASE",),
    "freertos": ("tskKERNEL_VERSION_NUMBER",),
    "edge_impulse_sdk": ("EI_SDK_VERSION", "EI_SDK_VERSION_STRING", "EDGE_IMPULSE_SDK_VERSION", "EDGE_IMPULSE_SDK_VERSION_STRING"),
    "synopsys_arc_mli_runtime": ("ARC_MLI_VERSION", "ARC_MLI_VERSION_STRING", "MLI_VERSION", "MLI_API_VERSION"),
    "tensorflow_lite_micro": ("TF_LITE_VERSION_STRING", "TFLITE_VERSION", "TFLITE_VERSION_STRING", "TENSORFLOW_VERSION", "TENSORFLOW_VERSION_STRING"),
    "arm_ethos_u_core_driver": ("ETHOS_U_CORE_DRIVER_VERSION",),
    "lvgl": ("LVGL_VERSION",),
}

# A few projects split the release across major/minor/patch macros.
SOURCE_VERSION_PARTS: Dict[str, Tuple[str, str, str]] = {
    "mbedtls": ("MBEDTLS_VERSION_MAJOR", "MBEDTLS_VERSION_MINOR", "MBEDTLS_VERSION_PATCH"),
    "sqlite": ("SQLITE_VERSION_MAJOR", "SQLITE_VERSION_MINOR", "SQLITE_VERSION_PATCH"),
    "lvgl": ("LVGL_VERSION_MAJOR", "LVGL_VERSION_MINOR", "LVGL_VERSION_PATCH"),
}

SOURCE_TEXT_SUFFIXES = {
    ".h", ".hpp", ".hh", ".c", ".cc", ".cpp", ".cxx", ".mk", ".cmake",
    ".txt", ".in", ".cfg", ".ini", ".toml", ".yml", ".yaml", ".json",
    ".gradle", ".kts", ".properties",
}
SOURCE_TEXT_NAMES = {"Makefile", "makefile", "CMakeLists.txt", "Config.in"}
MACRO_ASSIGN_RE = re.compile(
    r"(?m)^[ \t]*(?:#[ \t]*define[ \t]+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:[ \t]*(?:=|:=|\?=|\+=)[ \t]*|[ \t]+)"
    r"[\"']?v?(?P<value>[0-9][0-9A-Za-z.+_-]{0,119})[\"']?[ \t]*(?:$|/\*|#)",
)


def _source_text_candidate(path: Path) -> bool:
    return path.name in SOURCE_TEXT_NAMES or path.suffix.lower() in SOURCE_TEXT_SUFFIXES


def _macro_assignments(text: str) -> Dict[str, List[Tuple[str, str]]]:
    out: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    for m in MACRO_ASSIGN_RE.finditer(text):
        out[m.group("name")].append((m.group("value"), m.group(0).strip()))
    return out


def scan_source_version_macros(extracted_root: Path, fw_meta: Dict[str, Tuple[str, str]]) -> List[Evidence]:
    """Recover explicit versions from source headers and build files.

    Examples:
      #define ZLIB_VERSION "1.3.1"
      MBEDTLS_OPENIPC_VERSION = 2.25.0
      #define UTS_RELEASE "5.10.61"

    Values without digits or values such as refs/pull/... are filtered by candidate().
    """
    out: List[Evidence] = []
    for path in iter_files(extracted_root):
        if not _source_text_candidate(path):
            continue
        text = read_text(path)
        if not text:
            continue
        assignments = _macro_assignments(text)
        if not assignments:
            continue
        fid = firmware_id_from_extracted_path(path, extracted_root)
        if not fid:
            continue
        model, fwver = fw_meta.get(fid, parse_model_version_from_firmware_id(fid))
        relpath = relative_or_string(path, extracted_root / fid)

        for cid, names in SOURCE_VERSION_MACROS.items():
            for name in names:
                for value, line in assignments.get(name, []):
                    item = candidate(value, "source_version_macro", line)
                    if item:
                        out.append(Evidence(
                            firmware_id=fid, model=model, firmware_version=fwver,
                            component_id=cid, presence="precise", evidence_type="source_version_macro",
                            file_name=path.name, file_path=relpath,
                            version_candidates=[item], note=line,
                            scope=dependency_scope(relpath),
                        ))

        for cid, (maj_name, min_name, patch_name) in SOURCE_VERSION_PARTS.items():
            if assignments.get(maj_name) and assignments.get(min_name) and assignments.get(patch_name):
                maj = assignments[maj_name][0][0]
                min_ = assignments[min_name][0][0]
                patch = assignments[patch_name][0][0]
                value = f"{maj}.{min_}.{patch}"
                item = candidate(value, "source_version_macro", f"{maj_name}={maj}; {min_name}={min_}; {patch_name}={patch}")
                if item:
                    out.append(Evidence(
                        firmware_id=fid, model=model, firmware_version=fwver,
                        component_id=cid, presence="precise", evidence_type="source_version_macro_parts",
                        file_name=path.name, file_path=relpath,
                        version_candidates=[item], note=item[3],
                        scope=dependency_scope(relpath),
                    ))
    return out


# ---------------------------------------------------------------------------
# Direct source-archive metadata scanning
# ---------------------------------------------------------------------------

ARCHIVE_METADATA_BASENAMES = {
    "requirements.txt", "requirements-dev.txt", "requirements-prod.txt",
    "constraints.txt", "pyproject.toml", "setup.py", "setup.cfg",
    "uv.lock", "poetry.lock", "pdm.lock", "package.json", "package-lock.json",
    "build.gradle", "build.gradle.kts", "libs.versions.toml", "gradle.properties",
    "pom.properties", "pom.xml", "status",
}


def archive_firmware_id(path: Path) -> str:
    name = path.name
    for suffix in (".tar.gz", ".tar.xz", ".tgz", ".zip", ".apk", ".aar"):
        if name.lower().endswith(suffix):
            return name[:-len(suffix)]
    return path.stem


def _archive_entry_is_metadata(name: str) -> bool:
    base = Path(name).name.lower()
    return (
        base in ARCHIVE_METADATA_BASENAMES
        or base.startswith("requirements") and base.endswith(".txt")
        or name.lower().endswith((".dist-info/metadata", ".egg-info/pkg-info"))
    )


def _archive_text_entries(path: Path) -> Iterable[Tuple[str, str]]:
    lower = path.name.lower()
    if lower.endswith((".zip", ".apk", ".aar")):
        try:
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.is_dir() or info.file_size > MAX_TEXT_BYTES or not _archive_entry_is_metadata(info.filename):
                        continue
                    try:
                        yield info.filename, zf.read(info.filename).decode("utf-8", errors="ignore")
                    except Exception:
                        continue
        except Exception:
            return
    elif lower.endswith((".tar.gz", ".tar.xz", ".tgz")):
        try:
            with tarfile.open(path, "r:*") as tf:
                for member in tf.getmembers():
                    if not member.isfile() or member.size > MAX_TEXT_BYTES or not _archive_entry_is_metadata(member.name):
                        continue
                    f = tf.extractfile(member)
                    if not f:
                        continue
                    try:
                        yield member.name, f.read().decode("utf-8", errors="ignore")
                    except Exception:
                        continue
        except Exception:
            return


def scan_archive_metadata_components(archive_root: Path, fw_meta: Dict[str, Tuple[str, str]]) -> List[Evidence]:
    """Read dependency manifests directly inside source ZIP/TGZ archives."""
    out: List[Evidence] = []
    if not archive_root.exists():
        return out
    for archive in iter_files(archive_root):
        if not archive.name.lower().endswith((".zip", ".tar.gz", ".tar.xz", ".tgz", ".apk", ".aar")):
            continue
        fid = archive_firmware_id(archive)
        model, fwver = fw_meta.get(fid, parse_model_version_from_firmware_id(fid))
        for entry, body in _archive_text_entries(archive):
            for line in body.splitlines():
                m = DEP_RE.search(line)
                if not m:
                    continue
                cid = map_package(m.group("name"))
                if not cid:
                    continue
                kind = "exact_dependency" if m.group("op") in {"==", "="} else "range_dependency"
                value = normalize_package_release(cid, m.group("name"), m.group("ver"))
                note = f"{archive.name}:{entry}: {line.strip()}"
                out.append(_source_evidence(fid, model, fwver, cid, "archive_dependency_manifest", Path(entry).name, f"{archive.name}:{entry}", value=value, kind=kind, note=note))
            for m in MAVEN_COORD_RE.finditer(body):
                cid = map_maven_coordinate(m.group("group"), m.group("artifact"))
                if not cid:
                    continue
                value = normalize_package_release(cid, m.group("artifact"), m.group("version"))
                note = f"{archive.name}:{entry}: {m.group(0)}"
                out.append(_source_evidence(fid, model, fwver, cid, "archive_gradle_dependency", Path(entry).name, f"{archive.name}:{entry}", value=value, kind="android_gradle_dependency", note=note))
    return out


# ---------------------------------------------------------------------------
# Android full-scope and MCU source-tree scanning
# ---------------------------------------------------------------------------

def _source_evidence(
    fid: str, model: str, fwver: str, cid: str, evidence_type: str,
    file_name: str, file_path: str, *, value: str = "", kind: str = "unknown",
    note: str = "", presence: str = "precise",
) -> Evidence:
    item = candidate(value, kind, note) if value else None
    return Evidence(
        firmware_id=fid, model=model, firmware_version=fwver,
        component_id=cid, presence=presence, evidence_type=evidence_type,
        file_name=file_name, file_path=file_path,
        version_candidates=[item] if item else [], note=note,
        scope=dependency_scope(file_path),
    )


def _firmware_roots(extracted_root: Path) -> Iterable[Tuple[str, Path]]:
    if not extracted_root.exists():
        return
    for root in sorted(p for p in extracted_root.iterdir() if p.is_dir()):
        yield canonical_extracted_firmware_dir_name(root.name), root


def _first_matching_version(text: str, patterns: Iterable[str]) -> Tuple[str, str]:
    for pattern in patterns:
        m = re.search(pattern, text, re.I | re.M)
        if m:
            return normalize_version(m.group(1)), m.group(0).strip()
    return "", ""


def scan_mcu_source_components(extracted_root: Path, fw_meta: Dict[str, Tuple[str, str]]) -> List[Evidence]:
    """Recognize reusable MCU components from explicit source-tree signatures."""
    out: List[Evidence] = []
    for fid, root in _firmware_roots(extracted_root):
        model, fwver = fw_meta.get(fid, parse_model_version_from_firmware_id(fid))

        # CMSIS Core: tolerate parentheses and U/L suffixes.
        for path in root.rglob("cmsis_version.h"):
            body = read_text(path)
            main = re.search(r"__CM_CMSIS_VERSION_MAIN\s+\(?\s*(\d+)\s*[UuLl]*\s*\)?", body)
            sub = re.search(r"__CM_CMSIS_VERSION_SUB\s+\(?\s*(\d+)\s*[UuLl]*\s*\)?", body)
            if main and sub:
                value = f"{main.group(1)}.{sub.group(1)}"
                note = f"__CM_CMSIS_VERSION_MAIN={main.group(1)}; __CM_CMSIS_VERSION_SUB={sub.group(1)}"
                out.append(_source_evidence(fid, model, fwver, "cmsis_core", "mcu_source_header", path.name, relative_or_string(path, root), value=value, kind="source_header_version", note=note))
                break

        # CMSIS-DSP main header version.  Require a CMSIS/DSP path.
        dsp_paths = [p for p in root.rglob("arm_math.h") if "/cmsis/dsp/" in p.as_posix().lower()]
        dsp_paths += [p for p in root.rglob("arm_math_types.h") if "/cmsis/dsp/" in p.as_posix().lower()]
        dsp_paths = sorted(dsp_paths, key=lambda p: (0 if p.name == "arm_math.h" else 1, len(p.as_posix())))
        for path in dsp_paths:
            value, matched = _first_matching_version(read_text(path), [r"@version\s+[Vv]?(\d+\.\d+\.\d+)"])
            if value:
                out.append(_source_evidence(fid, model, fwver, "cmsis_dsp", "mcu_source_header", path.name, relative_or_string(path, root), value=value, kind="source_header_version", note=matched))
                break

        # CMSIS-NN main header version.
        nn_paths = [p for p in root.rglob("arm_nn_math_types.h") if "/cmsis/nn/" in p.as_posix().lower()]
        nn_paths += [p for p in root.rglob("arm_nnfunctions.h") if "/cmsis/nn/" in p.as_posix().lower()]
        nn_paths = sorted(nn_paths, key=lambda p: (0 if p.name == "arm_nn_math_types.h" else 1, len(p.as_posix())))
        for path in nn_paths:
            value, matched = _first_matching_version(read_text(path), [r"@version\s+[Vv]?(\d+\.\d+\.\d+)"])
            if value:
                out.append(_source_evidence(fid, model, fwver, "cmsis_nn", "mcu_source_header", path.name, relative_or_string(path, root), value=value, kind="source_header_version", note=matched))
                break

        # Edge Impulse SDK and its bundled subcomponents.
        edge_dirs = sorted(p for p in root.rglob("edge-impulse-sdk") if p.is_dir())
        if edge_dirs:
            edge = edge_dirs[0]
            out.append(_source_evidence(fid, model, fwver, "edge_impulse_sdk", "mcu_source_tree", edge.name, relative_or_string(edge, root), note="explicit edge-impulse-sdk source directory"))

            mli_dirs = sorted(p for p in edge.rglob("arc_mli_package") if p.is_dir())
            mli_libs = sorted(p for p in edge.rglob("libmli.a") if p.is_file())
            if mli_dirs or mli_libs:
                sample = (mli_libs or mli_dirs)[0]
                out.append(_source_evidence(fid, model, fwver, "synopsys_arc_mli_runtime", "mcu_source_tree", sample.name, relative_or_string(sample, root), note="explicit arc_mli_package/libmli.a evidence"))

            micro_dirs = sorted(p for p in edge.rglob("micro") if p.is_dir() and "/tensorflow/lite/micro" in p.as_posix().lower())
            if micro_dirs:
                out.append(_source_evidence(fid, model, fwver, "tensorflow_lite_micro", "mcu_source_tree", micro_dirs[0].name, relative_or_string(micro_dirs[0], root), note="explicit tensorflow/lite/micro source directory"))

        # Static-library signatures also work for SensiML and retained source trees.
        for path in root.rglob("libmli.a"):
            out.append(_source_evidence(fid, model, fwver, "synopsys_arc_mli_runtime", "mcu_static_library", path.name, relative_or_string(path, root), note="exact basename libmli.a"))
        for path in root.rglob("libtensorflow-microlite.a"):
            out.append(_source_evidence(fid, model, fwver, "tensorflow_lite_micro", "mcu_static_library", path.name, relative_or_string(path, root), note="exact basename libtensorflow-microlite.a"))
        for path in root.rglob("libsensiml.a"):
            body = strings_text(path)
            constraint = ""
            if "min_runtime_version" in body:
                m = re.search(r"(?i)min_runtime_version.{0,240}?(\d+\.\d+\.\d+)", body, re.S)
                if m:
                    constraint = f"min_runtime_version={m.group(1)}"
            out.append(_source_evidence(fid, model, fwver, "sensiml_knowledge_pack", "mcu_static_library", path.name, relative_or_string(path, root), note=("exact basename libsensiml.a" + (f"; {constraint}" if constraint else ""))))

        # Arm Ethos-U core driver has an explicit dedicated version file.
        for path in root.rglob("version.txt"):
            if "ethos-core-driver" not in path.as_posix().lower():
                continue
            value, matched = _first_matching_version(read_text(path), [r"\b[Vv]?(\d+\.\d+\.\d+)\b"])
            if value:
                out.append(_source_evidence(fid, model, fwver, "arm_ethos_u_core_driver", "mcu_source_version_file", path.name, relative_or_string(path, root), value=value, kind="source_version_file", note=matched))
                break

        # FreeRTOS source version.
        for path in root.rglob("FreeRTOS.h"):
            value, matched = _first_matching_version(read_text(path), [r"tskKERNEL_VERSION_NUMBER\s+[\"']?([0-9]+(?:\.[0-9A-Za-z]+){1,5})"])
            if value:
                out.append(_source_evidence(fid, model, fwver, "freertos", "mcu_source_header", path.name, relative_or_string(path, root), value=value, kind="source_header_version", note=matched))
                break
    return out


def _dex_blobs_from_path(path: Path) -> Iterable[Tuple[str, bytes]]:
    if path.name.lower().endswith(".dex"):
        try:
            yield path.name, path.read_bytes()
        except Exception:
            return
    elif path.suffix.lower() in {".apk", ".zip", ".aar"}:
        try:
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    if re.fullmatch(r"(?:.*/)?classes(?:[0-9]+)?\.dex", name):
                        yield name, zf.read(name)
        except Exception:
            return


def _scan_android_path(path: Path, fid: str, model: str, fwver: str, relpath: str) -> List[Evidence]:
    out: List[Evidence] = []
    for dex_name, blob in _dex_blobs_from_path(path):
        for cid, prefixes in ANDROID_DEX_PREFIXES.items():
            matched = next((prefix for prefix in prefixes if prefix in blob), b"")
            if matched:
                note = f"DEX prefix={matched.decode('ascii', errors='ignore')}"
                out.append(_source_evidence(fid, model, fwver, cid, "android_dex_prefix", dex_name, relpath, note=note))

    lower_name = path.name.lower()
    if lower_name in {"build.gradle", "build.gradle.kts", "libs.versions.toml", "pom.properties", "pom.xml"}:
        body = read_text(path)
        for m in MAVEN_COORD_RE.finditer(body):
            cid = map_maven_coordinate(m.group("group"), m.group("artifact"))
            if not cid:
                continue
            value = normalize_package_release(cid, m.group("artifact"), m.group("version"))
            out.append(_source_evidence(fid, model, fwver, cid, "android_gradle_dependency", path.name, relpath, value=value, kind="android_gradle_dependency", note=m.group(0)))
    return out


def scan_android_full_components(
    extracted_root: Path,
    fw_meta: Dict[str, Tuple[str, str]],
    archive_root: Optional[Path] = None,
) -> List[Evidence]:
    """Scan explicit DEX namespaces and Gradle/Maven coordinates.

    archive_root is optional and is particularly useful for Android APK samples
    after extracted trees have been cleaned.  APK filenames are expected to use
    the Stage-01 FirmwareID convention: <FirmwareID>.apk.
    """
    out: List[Evidence] = []
    if extracted_root.exists():
        for path in iter_files(extracted_root):
            fid = firmware_id_from_extracted_path(path, extracted_root)
            if not fid:
                continue
            model, fwver = fw_meta.get(fid, parse_model_version_from_firmware_id(fid))
            root = resolve_extracted_firmware_root(extracted_root, fid)
            relpath = relative_or_string(path, root)
            out.extend(_scan_android_path(path, fid, model, fwver, relpath))

    if archive_root and archive_root.exists():
        for path in iter_files(archive_root):
            if path.suffix.lower() not in {".apk", ".aar", ".zip"}:
                continue
            fid = path.stem
            model, fwver = fw_meta.get(fid, parse_model_version_from_firmware_id(fid))
            out.extend(_scan_android_path(path, fid, model, fwver, str(path)))
    return out




# ---------------------------------------------------------------------------
# Aggregation and cleanup
# ---------------------------------------------------------------------------

PRECISE_FIELDS = [
    "FirmwareID", "Model", "Firmware_Version", "Component_ID", "Component_Name",
    "Component_Category", "Version", "Version_Status", "CPE_Prefix", "Confidence",
    "Evidence_Count", "Native_Evidence_Count", "Evidence_Types", "File_Examples",
    "Path_Examples", "SHA256_Examples", "All_Version_Candidates", "Version_Evidence",
    "Review_Flags",
]
BROAD_FIELDS = PRECISE_FIELDS + ["Presence_Status"]
DEBUG_FIELDS = [
    "FirmwareID", "Model", "Firmware_Version", "Component_ID", "Presence", "Evidence_Type",
    "File_Name", "File_Path", "SHA256", "SONAME", "NEEDED", "Version_Candidates", "Note", "Scope",
]


def dedupe_evidence(rows: List[Evidence]) -> List[Evidence]:
    best: Dict[Tuple[str, ...], Evidence] = {}
    for row in rows:
        key = evidence_key(row)
        old = best.get(key)
        if not old:
            best[key] = row
            continue
        # Prefer precise presence and richer evidence.
        score_old = (old.presence == "precise", len(old.version_candidates), bool(old.sha256), bool(old.soname))
        score_new = (row.presence == "precise", len(row.version_candidates), bool(row.sha256), bool(row.soname))
        if score_new > score_old:
            best[key] = row
    return list(best.values())


def build_inventory(rows: List[Evidence], include_broad: bool) -> List[Dict[str, str]]:
    grouped: Dict[Tuple[str, str], List[Evidence]] = defaultdict(list)
    for row in rows:
        if not include_broad and row.presence != "precise":
            continue
        if not include_broad and row.component_id == "depthai" and (
            "depthai" in row.firmware_id.lower() or "luxonis" in row.model.lower()
        ):
            continue
        if row.firmware_id and row.component_id:
            grouped[(row.firmware_id, row.component_id)].append(row)

    out: List[Dict[str, str]] = []
    for (fid, cid), evs in sorted(grouped.items()):
        meta = component_meta(cid)
        version, version_status, all_candidates, version_evidence = select_version(evs)
        native_count = sum(1 for x in evs if "native" in x.evidence_type or "kernel" in x.evidence_type or "stage01" in x.evidence_type)
        flags: List[str] = []
        if version_status in {"conflict", "soname_abi", "range_dependency"}:
            flags.append(version_status)
        if any(x.presence == "broad" for x in evs):
            flags.append("contains_broad_evidence")
        if cid in {"goke_multimedia_sdk", "isp_algorithm_plugins", "libc_runtime_unknown"}:
            flags.append("manual_review_recommended")
        if cid in {"vendor_audio_processing_sdk", "xmedia_sdk"} and version != "unknown":
            flags.append("observed_module_version")
        if cid in ANDROID_JNI_COMPONENTS:
            flags.append("android_jni_native_component")
        if cid in ANDROID_FULL_COMPONENTS:
            flags.append("android_full_scope_component")
        if cid in MCU_SOURCE_COMPONENTS:
            flags.append("mcu_source_or_static_component")
        if cid == "depthai" and ("depthai" in fid.lower() or "luxonis" in model.lower()):
            flags.append("first_party_candidate")

        # The CPE is emitted only when Version is numeric and not an ABI-only clue.
        cpe = meta.cpe if meta.cpe and version != "unknown" and version_status not in {"soname_abi", "range_dependency", "conflict"} else ""
        presence_status = "precise" if any(x.presence == "precise" for x in evs) else "broad"
        confidence = "high" if presence_status == "precise" else "medium"
        model, fwver = next(((x.model, x.firmware_version) for x in evs if x.model or x.firmware_version), parse_model_version_from_firmware_id(fid))
        out.append({
            "FirmwareID": fid,
            "Model": model,
            "Firmware_Version": fwver,
            "Component_ID": cid,
            "Component_Name": meta.name,
            "Component_Category": meta.category,
            "Version": version,
            "Version_Status": version_status,
            "CPE_Prefix": cpe,
            "Confidence": confidence,
            "Evidence_Count": str(len(evs)),
            "Native_Evidence_Count": str(native_count),
            "Evidence_Types": clean_join([x.evidence_type for x in evs], 20, 1500),
            "File_Examples": clean_join([x.file_name for x in evs], 20, 2000),
            "Path_Examples": clean_join([x.file_path for x in evs], 8, 3000),
            "SHA256_Examples": clean_join([x.sha256 for x in evs], 8, 2000),
            "All_Version_Candidates": all_candidates,
            "Version_Evidence": version_evidence,
            "Review_Flags": clean_join(flags, 10, 1000),
            "Presence_Status": presence_status,
        })
    return out


def debug_rows(rows: List[Evidence]) -> List[Dict[str, str]]:
    out = []
    for x in rows:
        out.append({
            "FirmwareID": x.firmware_id,
            "Model": x.model,
            "Firmware_Version": x.firmware_version,
            "Component_ID": x.component_id,
            "Presence": x.presence,
            "Evidence_Type": x.evidence_type,
            "File_Name": x.file_name,
            "File_Path": x.file_path,
            "SHA256": x.sha256,
            "SONAME": x.soname,
            "NEEDED": x.needed,
            "Version_Candidates": clean_join([f"{a}:{b}" for a, b, _, _ in x.version_candidates], 20, 1500),
            "Note": x.note,
            "Scope": x.scope,
        })
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description="Identify and normalize third-party firmware components")
    ap.add_argument("--sdk-raw", required=True, help="third_party_sdk_inventory_raw.csv from stage 01")
    ap.add_argument("--extract-dir", required=True, help="extracted firmware root from stage 01")
    ap.add_argument("--retained-dir", default="", help="optional retained_sdk_libs directory from stage 01")
    ap.add_argument("--archive-dir", default="", help="optional original APK/ZIP/AAR directory for Android DEX scanning")
    ap.add_argument("-o", "--out-dir", required=True)
    ap.add_argument("--no-direct-tree-scan", action="store_true", help="skip direct extracted-tree native scan")
    ap.add_argument("--no-metadata-scan", action="store_true", help="skip pkg-config / package metadata scan")
    ap.add_argument("--no-source-macro-scan", action="store_true", help="skip source/header/build-file version macro scan")
    ap.add_argument("--no-mcu-source-scan", action="store_true", help="skip MCU source/static-library recognition branch")
    ap.add_argument("--no-android-full-scan", action="store_true", help="skip Android DEX and Gradle/Maven recognition branch")
    ap.add_argument("--debug", action="store_true", help="write raw_component_evidence_debug.csv")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    ensure_dir(out_dir)
    extracted_root = Path(args.extract_dir)
    retained_root = Path(args.retained_dir) if args.retained_dir else Path("")
    archive_root = Path(args.archive_dir) if args.archive_dir else None
    raw_rows = read_csv(Path(args.sdk_raw))
    if not raw_rows:
        raise SystemExit(f"no raw SDK rows loaded from {args.sdk_raw}")
    extracted_available = extracted_root.exists()
    retained_available = bool(args.retained_dir) and retained_root.exists()
    archive_available = bool(archive_root) and archive_root.exists()
    if not extracted_available and not retained_available and not archive_available:
        raise SystemExit(
            f"none of extract dir, retained dir, or archive dir is available: "
            f"extract={extracted_root}; retained={retained_root}; archive={archive_root}"
        )
    if not extracted_available:
        print(
            f"[INFO] extract dir not found; continuing with stage01 raw rows "
            f"and retained libraries only: {extracted_root}"
        )

    evidence, fw_meta = raw_rows_to_evidence(raw_rows, extracted_root)
    print(f"[INFO] stage01 raw rows: {len(raw_rows)}")
    print(f"[INFO] evidence from stage01 raw: {len(evidence)}")

    if args.retained_dir and retained_root.exists():
        retained_rows = scan_retained_libraries(retained_root, fw_meta)
        evidence.extend(retained_rows)
        print(f"[INFO] evidence from retained libraries: {len(retained_rows)}")

    if not args.no_direct_tree_scan and extracted_available:
        direct_rows = scan_extracted_native(extracted_root, fw_meta)
        evidence.extend(direct_rows)
        print(f"[INFO] evidence from extracted-tree native scan: {len(direct_rows)}")
    elif not args.no_direct_tree_scan:
        print("[INFO] evidence from extracted-tree native scan: skipped (extract dir unavailable)")

    if not args.no_metadata_scan and extracted_available:
        metadata_rows = scan_metadata(extracted_root, fw_meta)
        evidence.extend(metadata_rows)
        print(f"[INFO] evidence from metadata scan: {len(metadata_rows)}")
    elif not args.no_metadata_scan:
        print("[INFO] evidence from metadata scan: skipped (extract dir unavailable)")

    if not args.no_source_macro_scan and extracted_available:
        macro_rows = scan_source_version_macros(extracted_root, fw_meta)
        evidence.extend(macro_rows)
        print(f"[INFO] evidence from source/version macro scan: {len(macro_rows)}")
    elif not args.no_source_macro_scan:
        print("[INFO] evidence from source/version macro scan: skipped (extract dir unavailable)")

    if not args.no_mcu_source_scan and extracted_available:
        mcu_rows = scan_mcu_source_components(extracted_root, fw_meta)
        evidence.extend(mcu_rows)
        print(f"[INFO] evidence from MCU source/static scan: {len(mcu_rows)}")
    elif not args.no_mcu_source_scan:
        print("[INFO] evidence from MCU source/static scan: skipped (extract dir unavailable)")

    if not args.no_android_full_scan and (extracted_available or (archive_root and archive_root.exists())):
        android_rows = scan_android_full_components(extracted_root, fw_meta, archive_root)
        evidence.extend(android_rows)
        print(f"[INFO] evidence from Android DEX/Gradle scan: {len(android_rows)}")
    elif not args.no_android_full_scan:
        print("[INFO] evidence from Android DEX/Gradle scan: skipped (extract/archive dir unavailable)")

    if archive_root and archive_root.exists():
        archive_rows = scan_archive_metadata_components(archive_root, fw_meta)
        evidence.extend(archive_rows)
        print(f"[INFO] evidence from source-archive metadata scan: {len(archive_rows)}")

    evidence = dedupe_evidence(evidence)
    precise = build_inventory(evidence, include_broad=False)
    broad = build_inventory(evidence, include_broad=True)

    precise_path = out_dir / "third_party_components_precise.csv"
    broad_path = out_dir / "third_party_components_broad.csv"
    write_csv(precise_path, precise, PRECISE_FIELDS)
    write_csv(broad_path, broad, BROAD_FIELDS)
    if args.debug:
        write_csv(out_dir / "raw_component_evidence_debug.csv", debug_rows(evidence), DEBUG_FIELDS)

    print("\n========== Stage 02 complete ==========")
    print(f"precise inventory: {precise_path}")
    print(f"broad inventory:   {broad_path}")
    print(f"deduped evidence rows: {len(evidence)}")
    print(f"precise firmware-component rows: {len(precise)}")
    print(f"broad firmware-component rows:   {len(broad)}")
    print(f"predefined components: {len(SPECS)}")
    print(f"package aliases: {len(PACKAGE_TO_COMPONENT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
