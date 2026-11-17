#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
01_ai_firmware_extract_profile.py

Stage 1 of the AI firmware pipeline:
  firmware CSV -> download/materialize -> extract -> model extraction/profile -> SDK/runtime inventory

Required input CSV columns:
  Model, Version, DownloadLink

Final outputs in --out-dir:
  model_extraction_results.csv       # model extraction + model profile result
  third_party_sdk_inventory_raw.csv  # raw SDK/runtime/library evidence for vulnerability matching

Retained artifacts:
  retained_models/
  retained_static_models/
  retained_sdk_libs/

This script is a static-analysis helper. It does not execute firmware or load unsafe
pickle-based PyTorch checkpoints.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

USER_AGENT = "ai-firmware-extract-profile/1.0"
DEFAULT_LFS_INCLUDE = "*.tflite,*.onnx,*.pb,*.pbtxt,*.pt,*.pth,*.ptl,*.torchscript,*.caffemodel,*.prototxt,*.h5,*.keras,*.rknn,*.blob,*.nnb,*.kmodel,*.xmodel,*.dlc,*.om,*.bmodel,*.hef,*.engine,*.plan,*.trt,*.xclbin,*.compiled"

ARCHIVE_EXTS = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".apk", ".aar", ".whl", ".ipk", ".deb", ".rpm")
MODEL_FORMATS = {
    ".tflite": "TFLite", ".onnx": "ONNX", ".pb": "TensorFlow PB", ".pbtxt": "TensorFlow PBText",
    ".lite": "Lite Model", ".pt": "PyTorch", ".pth": "PyTorch", ".ptl": "PyTorch Mobile",
    ".torchscript": "TorchScript", ".mlmodel": "CoreML", ".ckpt": "Checkpoint", ".weights": "Weights",
    ".param": "Param/NCNN", ".caffemodel": "Caffe Model", ".prototxt": "Caffe/Model Prototxt",
    ".h5": "Keras H5", ".keras": "Keras Model", ".mnn": "MNN Model", ".npz": "NumPy Model/Weights",
    ".pkl": "Pickle Model", ".joblib": "Joblib Model", ".safetensors": "SafeTensors", ".gguf": "GGUF LLM",
    ".ggml": "GGML LLM", ".mar": "TorchServe MAR",
    ".rknn": "RKNN", ".blob": "DepthAI/OpenVINO Blob", ".mud": "MUD Model", ".nnb": "Sony Spresense NNB",
    ".kmodel": "Kendryte KModel", ".xmodel": "Xilinx XModel", ".dlc": "Qualcomm SNPE DLC", ".om": "Ascend OM",
    ".bmodel": "BModel", ".hef": "Hailo HEF", ".nb": "Network Binary", ".ms": "MindSpore Model",
    ".tmfile": "Tengine/TMFile", ".axmodel": "AXera Model", ".cvimodel": "CVITEK Model", ".wk": "NNIE WK",
    ".har": "Hailo Archive", ".hbm": "Horizon BPU Model", ".nbg": "Network Binary Graph",
    ".engine": "TensorRT Engine", ".plan": "TensorRT Plan", ".trt": "TensorRT Engine", ".etlt": "TensorRT ETLT",
    ".uff": "TensorRT UFF", ".xclbin": "Xilinx XCLBIN", ".compiled": "Compiled Model",
}
STANDARD_EXTS = {".tflite", ".onnx", ".pb", ".pbtxt", ".lite", ".mlmodel", ".pt", ".pth", ".ptl", ".torchscript", ".ckpt", ".weights", ".param", ".caffemodel", ".prototxt", ".h5", ".keras", ".mnn", ".npz", ".pkl", ".joblib", ".safetensors", ".gguf", ".ggml", ".mar"}
PRIVATE_EXTS = {".rknn", ".blob", ".mud", ".nnb", ".xmodel", ".dlc", ".kmodel", ".om", ".bmodel", ".hef", ".nb", ".ms", ".tmfile", ".axmodel", ".cvimodel", ".wk", ".har", ".hbm", ".nbg"}
OPTIMIZED_EXTS = {".engine", ".plan", ".trt", ".etlt", ".uff", ".xclbin", ".compiled"}
MODEL_CANDIDATE_EXTS = {".bin", ".dat", ".model"}
OPENVINO_XML_HINTS = ("openvino", "ir_model", "model.xml", "network.xml")
PRIVATE_NAME_HINTS = (
    "rknn", "depthai", "myriad", "kpu", "nnb", "vitis", "xmodel", "snpe", "dlc", "npu", "dpu", "tidl", "nnie",
    "wk", "hisilicon", "hisi", "esp-dl", "esp_dl", "esp-sr", "esp_sr", "wakenet", "multinet", "edgetpu", "edge_tpu",
    "coral", "hailo", "hef", "sophon", "bmodel", "cvitek", "cvimodel", "axera", "axmodel", "horizon", "hbdnn",
    "hbm", "ascend", "aclmdl", "cambricon", "magicmind", "nbg", "cnnlib", "kflow", "ai_net"
)
OPT_NAME_HINTS = ("tensorrt", "trt", "engine", "tvm", "nvinfer", "nnie", "npu", "dpu", "openvino", "compiled", "xclbin", "hef", "bmodel", "cvimodel", "axmodel", "dla", "aclmdl")
LIB_EXTS = {
    ".so": "shared_library", ".a": "static_library", ".ko": "kernel_module", ".dll": "dynamic_library",
    ".dylib": "dynamic_library", ".jar": "java_archive", ".aar": "android_archive", ".whl": "python_wheel",
    ".egg": "python_package", ".ipk": "openwrt_package", ".deb": "debian_package", ".rpm": "rpm_package",
}
DEPENDENCY_FILES = {"requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.py", "setup.cfg", "poetry.lock", "Pipfile", "Pipfile.lock", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "build.gradle", "build.gradle.kts", "settings.gradle", "pom.xml", "CMakeLists.txt", "Makefile", "makefile", "go.mod", "Cargo.toml", "Cargo.lock", "conanfile.txt", "conanfile.py", "vcpkg.json", "idf_component.yml", "component.mk"}
TEXT_EXTS = {".py", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".ino", ".java", ".kt", ".js", ".ts", ".go", ".rs", ".sh", ".cmake", ".mk", ".txt", ".md", ".rst", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".gradle", ".xml", ".service", ".conf"}
SKIP_DIRS = {".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "node_modules", ".gradle", "build", "dist"}
MAX_TEXT_BYTES = 2_000_000
STATIC_MIN_BYTES = 512

SDK_ALIASES = {
    "tensorflow": ("TensorFlow / TensorFlow Lite", "ai_framework"), "tensorflow-cpu": ("TensorFlow / TensorFlow Lite", "ai_framework"),
    "tflite-runtime": ("TensorFlow Lite Runtime", "ai_runtime"), "onnxruntime": ("ONNX Runtime", "ai_runtime"),
    "onnxruntime-gpu": ("ONNX Runtime", "ai_runtime"), "onnx": ("ONNX", "model_toolkit"),
    "torch": ("PyTorch / LibTorch", "ai_framework"), "opencv-python": ("OpenCV", "computer_vision_library"),
    "opencv-contrib-python": ("OpenCV", "computer_vision_library"), "depthai": ("DepthAI / Luxonis", "ai_camera_sdk"),
    "blobconverter": ("DepthAI / Luxonis", "model_conversion_tool"), "pycoral": ("Google Coral / Edge TPU", "ai_runtime"),
    "piper-phonemize": ("Piper", "voice_component"), "scikit-learn": ("scikit-learn", "ml_library"),
    "numpy": ("NumPy", "numeric_dependency"), "scipy": ("SciPy", "numeric_dependency"), "requests": ("Requests", "network_dependency"),
    "urllib3": ("urllib3", "network_dependency"),
}
SDK_HINTS = {
    "edge-impulse-sdk": ("Edge Impulse SDK", "tinyml_sdk"), "tensorflow/lite/micro": ("TensorFlow Lite Micro", "tinyml_runtime"),
    "tflite_runtime": ("TensorFlow Lite Runtime", "ai_runtime"), "onnxruntime": ("ONNX Runtime", "ai_runtime"),
    "rknn": ("RKNN Runtime / Toolkit", "vendor_ai_runtime"), "rkllm": ("RKLLM Runtime", "vendor_ai_runtime"),
    "depthai": ("DepthAI / Luxonis", "ai_camera_sdk"), "blobconverter": ("DepthAI / Luxonis", "model_conversion_tool"),
    "openvino": ("OpenVINO", "ai_runtime"), "tensorrt": ("TensorRT", "ai_runtime"), "nvinfer": ("TensorRT", "ai_runtime"),
    "libedgetpu": ("Google Coral / Edge TPU", "ai_runtime"), "pycoral": ("Google Coral / Edge TPU", "ai_runtime"),
    "cmsis": ("CMSIS-NN / CMSIS-DSP", "optimized_kernel"), "esp-dl": ("ESP-DL", "vendor_ai_sdk"), "esp_sr": ("ESP-SR", "vendor_ai_sdk"),
    "dnnrt": ("Sony Spresense DNNRT", "vendor_ai_runtime"), "maixpy": ("MaixPy / KPU", "vendor_ai_runtime"), "kpu": ("MaixPy / KPU", "vendor_ai_runtime"),
    "vitis": ("Xilinx Vitis AI", "vendor_ai_runtime"), "snpe": ("Qualcomm SNPE", "vendor_ai_runtime"), "opencv": ("OpenCV", "computer_vision_library"),
    "piper": ("Piper", "voice_runtime"), "wyoming": ("Wyoming", "voice_service_runtime"),
    # Reolink / IPC vendor runtimes
    "kdrv_ai": ("Novatek/NVT HDAL AI Runtime", "vendor_ai_runtime"), "kflow_cnn": ("Novatek/NVT HDAL AI Runtime", "vendor_ai_runtime"),
    "kflow_ai_net": ("Novatek/NVT HDAL AI Runtime", "vendor_ai_runtime"), "cnnlib": ("Novatek/NVT CNNLib Runtime", "vendor_ai_runtime"),
    "nvtpack": ("Novatek/NVT Platform SDK", "vendor_platform_sdk"), "na51055": ("Novatek/NVT Platform SDK", "vendor_platform_sdk"),
    "novatek": ("Novatek/NVT Platform SDK", "vendor_platform_sdk"), "nvt_linux_smp": ("Novatek/NVT Platform SDK", "vendor_platform_sdk"),
    "libmi_sed": ("SigmaStar MI IPU/SED Runtime", "vendor_ai_runtime"), "libmi_ipu": ("SigmaStar MI IPU Runtime", "vendor_ai_runtime"),
    "libmi_vdf": ("SigmaStar MI VDF/SED Pipeline", "vendor_ai_runtime"), "mi_ipu_": ("SigmaStar MI IPU Runtime", "vendor_ai_runtime"),
    "mi_sed_": ("SigmaStar MI SED Runtime", "vendor_ai_runtime"), "sed_cnn": ("SigmaStar MI IPU/SED Runtime", "vendor_ai_runtime"),
    "cnnobjdetect": ("SigmaStar MI CNN Object Detection Runtime", "vendor_ai_runtime"), "sigmastar": ("SigmaStar MI Platform SDK", "vendor_platform_sdk"),
}

CALL_PATTERNS = {
    "model_reference": [r"\.tflite\b", r"\.onnx\b", r"\.pb\b", r"\.ptl\b", r"\.rknn\b", r"\.blob\b", r"\.engine\b", r"model[_-]?path", r"load[_-]?model"],
    "tflite_api": [r"tflite_runtime\.interpreter", r"tf\.lite\.Interpreter", r"Interpreter\(", r"allocate_tensors", r"set_tensor", r"invoke\(", r"get_tensor", r"MicroInterpreter", r"tflite::GetModel"],
    "onnx_api": [r"onnxruntime", r"InferenceSession", r"Ort::Session", r"session\.run", r"\.Run\(", r"->Run\("],
    "vendor_api": [r"rknn_init", r"rknn_run", r"depthai", r"dai\.Pipeline", r"NeuralNetwork", r"nvinfer", r"TensorRT", r"DNNRT", r"libedgetpu", r"kdrv_ai", r"kflow_cnn", r"kflow_ai_net", r"CNNLib", r"MI_IPU_Invoke", r"MI_IPU_GetOutputTensors", r"MI_IPU_GetInOutTensorDesc", r"MI_SED_StartDetector", r"SED_CNN_WorkThread", r"CNNObjDetect", r"_MI_SED_DoCNNObjDetect"],
    "input_camera": [r"camera", r"VideoCapture", r"image", r"resize", r"picamera", r"libcamera"],
    "input_audio": [r"microphone", r"pyaudio", r"sounddevice", r"audio", r"wav", r"pcm", r"i2s", r"mel", r"mfcc", r"spectrogram"],
    "input_sensor": [r"accelerometer", r"gyroscope", r"imu", r"sensor", r"temperature", r"humidity", r"pressure", r"vibration"],
    "preprocess": [r"preprocess", r"normalize", r"resize", r"crop", r"mean", r"stddev", r"mfcc", r"mel", r"spectrogram", r"resample", r"features?"],
    "postprocess": [r"postprocess", r"softmax", r"argmax", r"threshold", r"score", r"confidence", r"probability", r"nms", r"bbox", r"boxes", r"classes", r"labels", r"anomaly", r"wakeword"],
    "output_network": [r"mqtt", r"requests\.post", r"http", r"websocket", r"grpc", r"upload", r"cloud"],
    "output_control": [r"gpio", r"motor", r"servo", r"pwm", r"uart", r"serial", r"control", r"command", r"trigger", r"alarm", r"alert"],
    "static_model_array": [r"model_data\s*\[", r"g_model\s*\[", r"trained_model\s*\[", r"model_weights\s*\[", r"\w+_model_data\s*\[", r"const\s+unsigned\s+char", r"alignas\s*\(", r"PROGMEM"],
}
COMPILED_CALL = {k: [re.compile(p, re.I) for p in v] for k, v in CALL_PATTERNS.items()}

AI_SYMBOL_RE = re.compile(r"(tflite|TfLite|MicroInterpreter|onnx|Ort[A-Z_]|InferenceSession|rknn_|RKNN|nvinfer|TensorRT|DNNRT|depthai|NeuralNetwork|hailo|edgetpu|cmsis|esp[_-]?(dl|sr)|nnie|aclmdl|AX_ENGINE|hbDNN|xir|vart|snpe|opencv|openvino|MNN|NCNN|KPU|kpu|kmodel|kdrv_ai|kflow_cnn|kflow_ai_net|CNNLib|MI_IPU_|MI_SED_|SED_CNN|CNNObjDetect|ObjDetect|DoCNN|InferenceFDA|Sigmastar|Novatek|NVT)", re.I)
VERSION_LINE_RE = re.compile(r"(version|ver\.|release|build|tensorflow|tflite|onnxruntime|rknn|openvino|tensorrt|depthai|opencv|hailo|snpe|vitis|dnnrt|sigmastar|novatek|nvt|mi_sed|mi_ipu|mi_vdf|kdrv_ai|kflow_cnn|kflow_ai_net|openssl|mbed\s*tls|live555|busybox)", re.I)
STATIC_ARRAY_DECL_RE = re.compile(r"(?P<decl>(?:alignas\s*\([^)]*\)\s*)?(?:static\s+)?(?:const\s+)?(?:unsigned\s+char|uint8_t|uint8|byte|char)\s+(?:PROGMEM\s+)?)(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*(?:PROGMEM\s*)?=\s*\{", re.I | re.M)
STATIC_ARRAY_NAME_RE = re.compile(r"(?:model_data|g_model|trained_model|model_weights|\w+_model_data|\w*model\w*|\w*weights\w*)", re.I)
TASK_KEYWORDS = {
    "语音唤醒/关键词识别": ["wake", "wakeword", "keyword", "kws", "alexa", "hey", "speech", "voice", "openwakeword"],
    "目标检测": ["yolo", "ssd", "detect", "detection", "object", "boxes", "scores", "classes", "ppvd", "cnnobj"],
    "姿态估计": ["pose", "posenet", "keypoint", "movenet", "landmark"],
    "图像分类": ["classify", "classification", "mobilenet", "efficientnet", "imagenet", "resnet", "class.bin"],
    "异常检测/预测维护": ["anomaly", "fault", "leak", "maintenance", "predictive", "vibration"],
    "手势/运动分类": ["gesture", "motion", "imu", "accelerometer", "gait", "activity"],
}


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def safe_name(s: str, max_len: int = 120) -> str:
    s = re.sub(r"[^A-Za-z0-9_.\-（）()一-龥]+", "_", str(s or "").strip()).strip("_")
    return s[:max_len] if s else "item"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha1_short(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()[:10]


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)


def run_cmd(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 600) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except Exception as e:
        return 1, "", str(e)


def infer_ext(url: str) -> str:
    path = urllib.parse.urlparse(url).path.lower()
    for ext in [".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tgz", ".tbz2", ".txz", ".apk", ".aar", ".whl", ".ipk", ".deb", ".rpm"]:
        if path.endswith(ext):
            return ext
    for ext in sorted(set(MODEL_FORMATS) | set(LIB_EXTS) | {".bin", ".uf2", ".hex", ".elf", ".img", ".pak"}, key=len, reverse=True):
        if path.endswith(ext):
            return ext
    if "/archive/" in path or "/zipball/" in path:
        return ".zip"
    return Path(path).suffix or ".bin"


def download_url(url: str, out_path: Path, redownload: bool = False) -> Path:
    ensure_dir(out_path.parent)
    if out_path.exists() and out_path.stat().st_size > 0 and not redownload:
        return out_path
    tmp = out_path.with_suffix(out_path.suffix + ".part")
    if tmp.exists():
        tmp.unlink()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=240) as r, tmp.open("wb") as f:
        shutil.copyfileobj(r, f)
    tmp.replace(out_path)
    return out_path


def strip_archive_suffix(name: str) -> str:
    for suf in [".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tgz", ".tbz2", ".txz", ".tar"]:
        if name.lower().endswith(suf):
            return name[:-len(suf)]
    return name


def normalize_version_as_ref(value: str) -> str:
    v = (value or "").strip()
    if not v or v.lower() in {"unknown", "latest", "global", "none", "na", "n/a", "-"} or any(ch.isspace() for ch in v):
        return ""
    return v


def parse_github_source_url(url: str, version_hint: str = "") -> Optional[Tuple[str, str, str]]:
    try:
        u = urllib.parse.urlparse(url)
    except Exception:
        return None
    host = (u.netloc or "").lower()
    parts = [p for p in (u.path or "").strip("/").split("/") if p]
    if host == "api.github.com" and len(parts) >= 5 and parts[0] == "repos" and parts[3] in {"zipball", "tarball"}:
        return parts[1], parts[2], strip_archive_suffix("/".join(parts[4:]))
    if host not in {"github.com", "www.github.com"} or len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    if len(parts) >= 4 and parts[2] == "releases" and parts[3] == "download":
        return None
    if len(parts) >= 3 and parts[2] == "archive":
        if len(parts) >= 6 and parts[3] == "refs" and parts[4] in {"tags", "heads"}:
            ref = strip_archive_suffix("/".join(parts[5:]))
        else:
            ref = strip_archive_suffix("/".join(parts[3:])) if len(parts) >= 4 else normalize_version_as_ref(version_hint)
        return owner, repo, ref
    if len(parts) == 2:
        return owner, repo, normalize_version_as_ref(version_hint)
    return None


def run_checked(cmd: List[str], cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None, timeout: int = 1800) -> None:
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip()[:1000]
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)} :: {msg}")


def clone_github_with_lfs(owner: str, repo: str, ref: str, out_dir: Path, reextract: bool = False, lfs_include: str = DEFAULT_LFS_INCLUDE) -> Path:
    marker = out_dir / ".git_lfs_ok"
    if marker.exists() and not reextract:
        return out_dir
    if not shutil.which("git"):
        raise RuntimeError("git not installed")
    if out_dir.exists():
        shutil.rmtree(out_dir)
    ensure_dir(out_dir.parent)
    repo_url = f"https://github.com/{owner}/{repo}.git"
    env = os.environ.copy(); env["GIT_TERMINAL_PROMPT"] = "0"; env["GIT_LFS_SKIP_SMUDGE"] = "1"
    if ref:
        try:
            run_checked(["git", "clone", "--depth", "1", "--branch", ref, repo_url, str(out_dir)], env=env, timeout=1800)
        except Exception:
            if out_dir.exists(): shutil.rmtree(out_dir)
            run_checked(["git", "clone", "--depth", "1", repo_url, str(out_dir)], env=env, timeout=1800)
            try:
                run_checked(["git", "fetch", "--depth", "1", "origin", ref], cwd=out_dir, env=env, timeout=1800)
                run_checked(["git", "checkout", "FETCH_HEAD"], cwd=out_dir, env=env, timeout=600)
            except Exception:
                run_checked(["git", "checkout", ref], cwd=out_dir, env=env, timeout=600)
    else:
        run_checked(["git", "clone", "--depth", "1", repo_url, str(out_dir)], env=env, timeout=1800)
    try:
        run_checked(["git", "lfs", "install", "--local"], cwd=out_dir, timeout=300)
    except Exception:
        pass
    lfs_cmd = ["git", "lfs", "pull"]
    if lfs_include:
        lfs_cmd.append(f"--include={lfs_include}")
    run_checked(lfs_cmd, cwd=out_dir, timeout=3600)
    marker.write_text("ok", encoding="utf-8")
    return out_dir


def reset_dir(out_dir: Path) -> None:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    ensure_dir(out_dir)


def extract_archive(archive: Path, out_dir: Path, reextract: bool = False) -> Path:
    marker = out_dir / ".extracted_ok"
    if marker.exists() and not reextract:
        return out_dir
    name = archive.name.lower()
    errors: List[str] = []

    def attempt(label: str, fn) -> bool:
        reset_dir(out_dir)
        try:
            fn()
            marker.write_text("ok", encoding="utf-8")
            return True
        except Exception as e:
            errors.append(f"{label}:{e}")
            return False

    if name.endswith((".zip", ".apk", ".aar", ".whl")):
        methods = [("python_zipfile", lambda: zipfile.ZipFile(archive).extractall(out_dir))]
        if shutil.which("unzip"): methods.append(("unzip", lambda: subprocess.run(["unzip", "-o", "-q", str(archive), "-d", str(out_dir)], check=True)))
        if shutil.which("7z"): methods.append(("7z", lambda: subprocess.run(["7z", "x", "-y", f"-o{out_dir}", str(archive)], check=True)))
        if shutil.which("7zz"): methods.append(("7zz", lambda: subprocess.run(["7zz", "x", "-y", f"-o{out_dir}", str(archive)], check=True)))
        for label, fn in methods:
            if attempt(label, fn): return out_dir
    elif name.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
        methods = [("python_tarfile", lambda: tarfile.open(archive, "r:*").extractall(out_dir))]
        if shutil.which("tar"): methods.append(("tar", lambda: subprocess.run(["tar", "-xf", str(archive), "-C", str(out_dir)], check=True)))
        if shutil.which("7z"): methods.append(("7z", lambda: subprocess.run(["7z", "x", "-y", f"-o{out_dir}", str(archive)], check=True)))
        for label, fn in methods:
            if attempt(label, fn): return out_dir
    else:
        reset_dir(out_dir)
        shutil.copy2(archive, out_dir / archive.name)
        marker.write_text("ok", encoding="utf-8")
        return out_dir
    raise RuntimeError(f"extract failed: {archive}: {' | '.join(errors)}")


def binwalk_extract(root: Path, recursive: bool = True) -> None:
    if not shutil.which("binwalk"):
        return
    candidates = []
    for p in list(iter_files(root)):
        if p.stat().st_size < 1024 * 64:
            continue
        name_lower = p.name.lower()
        if (
            p.suffix.lower() in {
                ".pak", ".bin", ".img", ".fw",
                ".ubifs", ".squashfs", ".uimage"
            }
            or "firmware" in name_lower
            or "squashfs" in name_lower
            or name_lower.startswith("uimage")
        ):
            candidates.append(p)
    for p in candidates[:30]:
        out = p.parent / ("_binwalk_" + safe_name(p.name, 80))
        if (out / ".binwalk_done").exists():
            continue
        ensure_dir(out)
        cmd = ["binwalk", "-e", "--run-as=root", "-C", str(out), str(p)] if os.geteuid() == 0 else ["binwalk", "-e", "-C", str(out), str(p)]
        if recursive:
            cmd.insert(1, "-M")
        code, stdout, stderr = run_cmd(cmd, timeout=1800)
        (out / ".binwalk_done").write_text(f"exit={code}\n{stdout[:1000]}\n{stderr[:1000]}", encoding="utf-8", errors="ignore")


def iter_files(root: Path) -> Iterable[Path]:
    for cur, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for f in files:
            p = Path(cur) / f
            if p.is_file():
                yield p


def read_text(path: Path, max_bytes: int = MAX_TEXT_BYTES) -> str:
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def is_text_candidate(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTS or path.name in DEPENDENCY_FILES


def is_git_lfs_pointer(path: Path) -> bool:
    try:
        if path.stat().st_size > 4096:
            return False
        text = path.read_text(encoding="utf-8", errors="ignore")
        return text.startswith("version https://git-lfs.github.com/spec/v1") and "oid sha256:" in text
    except Exception:
        return False


def model_kind(ext: str) -> str:
    if ext in STANDARD_EXTS: return "standard_model"
    if ext in PRIVATE_EXTS: return "private_model"
    if ext in OPTIMIZED_EXTS: return "optimized_model"
    return "model"


def detect_model_artifact(path: Path, root: Path) -> Tuple[str, str]:
    ext = path.suffix.lower()
    rpath = rel(path, root).lower().replace("\\", "/")
    name = path.name.lower()
    if ext == ".xml":
        return ("OpenVINO IR XML", "standard_model") if any(h in rpath for h in OPENVINO_XML_HINTS) else ("", "")

    # BEGIN PATCH: skip tiny text .pb false positives
    # 有些仓库中存在 test.pb 这类占位文本文件，并不是真实 TensorFlow GraphDef。
    # 如果 .pb 文件很小且内容基本是可打印文本，则不作为模型文件记录。
    if ext == ".pb":
        try:
            if path.stat().st_size < 4096:
                head = path.read_bytes()[:512]
                if head.startswith(b"version https://git-lfs.github.com/spec/v1"):
                    return MODEL_FORMATS[ext], model_kind(ext)
                if head:
                    printable = sum((32 <= b < 127) or b in (9, 10, 13) for b in head) / float(len(head))
                    if printable > 0.90:
                        return "", ""
        except Exception:
            pass
    # END PATCH: skip tiny text .pb false positives

    if ext in MODEL_FORMATS:
        return MODEL_FORMATS[ext], model_kind(ext)
    if ext in MODEL_CANDIDATE_EXTS:
        text = f"{rpath}/{name}"
        if "cnnlib/para/" in text or "/cnnlib/" in text:
            if name in {"ppvd.bin", "class.bin", "cds.bin"} or any(x in name for x in ["ppvd", "cds"]):
                return "Reolink Private CNN Parameter Binary", "private_model"
        if ext == ".bin" and ("cnn" in text or "nnie" in text or "npu" in text or "ai_net" in text or "kflow" in text) and any(x in text for x in ["/para/", "/model", "/weights", "/network", "/param"]):
            return "Candidate Private CNN/NPU Binary Model", "private_model"
        if any(h in text for h in PRIVATE_NAME_HINTS):
            return "Candidate Vendor Binary Model", "private_model"
        if any(h in text for h in OPT_NAME_HINTS):
            return "Candidate Optimized Binary Model", "optimized_model"
        if any(h in text for h in ("model", "weights", "network", "param")):
            return "Candidate Binary Model", "optimized_model"
    return "", ""


def copy_artifact(src: Path, root: Path, base_dir: Path, sample_key: str) -> str:
    try:
        h = sha256_file(src)[:12]
        safe_rel = safe_name(rel(src, root).replace("/", "__"), 180)
        dst = base_dir / sample_key / f"{safe_rel}__{h}{src.suffix}"
        ensure_dir(dst.parent)
        if not dst.exists():
            shutil.copy2(src, dst)
        return str(dst)
    except Exception:
        return ""


def guess_task_from_name(name: str) -> str:
    s = name.lower()
    scores = Counter()
    for task, kws in TASK_KEYWORDS.items():
        for kw in kws:
            if kw in s:
                scores[task] += 1
    return scores.most_common(1)[0][0] if scores else "未知"


def empty_profile(status: str) -> Dict[str, str]:
    return {"input_shapes": "", "output_shapes": "", "input_output_dtypes": "", "tensor_count": "", "quantization": "", "operators_top": "", "arch_guess": "", "profile_status": status}


def json_short(obj: Any, max_len: int = 20000) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False)[:max_len]
    except Exception:
        return ""


def tflite_profile(path: Path) -> Dict[str, str]:
    out = empty_profile("no_tflite_interpreter")
    Interpreter = None
    try:
        from tflite_runtime.interpreter import Interpreter as TFLI  # type: ignore
        Interpreter = TFLI
    except Exception:
        try:
            import tensorflow as tf  # type: ignore
            Interpreter = tf.lite.Interpreter
        except Exception:
            pass
    if Interpreter is None:
        return out
    try:
        itp = Interpreter(model_path=str(path))
        try: itp.allocate_tensors()
        except Exception: pass
        ins, outs, tensors = itp.get_input_details(), itp.get_output_details(), itp.get_tensor_details()
        def shape(x):
            try: return list(x.get("shape", []))
            except Exception: return []
        out.update({
            "input_shapes": json_short([shape(x) for x in ins]),
            "output_shapes": json_short([shape(x) for x in outs]),
            "input_output_dtypes": ";".join(sorted({str(x.get("dtype", "")) for x in ins + outs})),
            "tensor_count": str(len(tensors)),
            "profile_status": "ok",
        })
        qcnt = 0
        for t in tensors:
            q = t.get("quantization_parameters", {}) or {}
            try:
                if len(q.get("scales", [])) > 0: qcnt += 1
            except Exception: pass
        out["quantization"] = "quantized_or_partial" if qcnt else "not_obvious"
        raw = path.read_bytes().decode("latin1", errors="ignore").upper()
        ops = Counter()
        for op in ["CONV_2D", "DEPTHWISE_CONV_2D", "FULLY_CONNECTED", "RESHAPE", "ADD", "MUL", "RELU", "SOFTMAX", "LSTM", "SVDF", "DETECTION_POSTPROCESS", "BATCH_MATMUL", "UNIDIRECTIONAL_SEQUENCE_LSTM"]:
            if op in raw: ops[op] = raw.count(op)
        out["operators_top"] = ";".join(f"{k}:{v}" for k, v in ops.most_common(20))
        keys = set(ops)
        if {"LSTM", "SVDF", "UNIDIRECTIONAL_SEQUENCE_LSTM"} & keys: out["arch_guess"] = "RNN/LSTM-like"
        elif "BATCH_MATMUL" in keys: out["arch_guess"] = "Transformer/Attention-like（弱推测）"
        elif "CONV_2D" in keys or "DEPTHWISE_CONV_2D" in keys: out["arch_guess"] = "CNN-like"
        elif "FULLY_CONNECTED" in keys: out["arch_guess"] = "MLP/DNN-like"
        else: out["arch_guess"] = "未知"
    except Exception as e:
        out["profile_status"] = f"tflite_profile_failed:{e}"

    # BEGIN PATCH: fallback to FlatBuffer direct metadata read
    # EdgeTPU / CUSTOM op 模型可能无法通过 Interpreter 完整 allocate，
    # 但 FlatBuffer 仍可直接读取输入输出 tensor shape 和算子列表。
    if not out.get("input_shapes") or not out.get("output_shapes"):
        fb = tflite_flatbuffer_profile(path)
        if fb.get("input_shapes") or fb.get("output_shapes") or fb.get("operators_top"):
            return fb
    # END PATCH: fallback to FlatBuffer direct metadata read
    return out



# BEGIN PATCH: TFLite FlatBuffer fallback profile
def tflite_flatbuffer_profile(path: Path) -> Dict[str, str]:
    out = empty_profile("tflite_flatbuffer_profile_failed")
    try:
        from tensorflow.lite.python import schema_py_generated as schema_fb  # type: ignore
        from collections import Counter
    except Exception as e:
        out["profile_status"] = f"tflite_flatbuffer_schema_missing:{e}"
        return out

    try:
        type_map = {}
        for name in dir(schema_fb.TensorType):
            if name.isupper():
                try:
                    type_map[getattr(schema_fb.TensorType, name)] = name
                except Exception:
                    pass

        op_map = {}
        for name in dir(schema_fb.BuiltinOperator):
            if name.isupper():
                try:
                    op_map[getattr(schema_fb.BuiltinOperator, name)] = name
                except Exception:
                    pass

        buf = path.read_bytes()
        model = schema_fb.Model.GetRootAsModel(buf, 0)

        if model.SubgraphsLength() == 0:
            out["profile_status"] = "tflite_flatbuffer_no_subgraph"
            return out

        sg = model.Subgraphs(0)

        def tensor_info(idx):
            t = sg.Tensors(idx)
            name = t.Name()
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="ignore")
            shape = [t.Shape(i) for i in range(t.ShapeLength())]
            return {
                "name": name,
                "shape": shape,
                "dtype": type_map.get(t.Type(), str(t.Type())),
            }

        inputs = [tensor_info(sg.Inputs(i)) for i in range(sg.InputsLength())]
        outputs = [tensor_info(sg.Outputs(i)) for i in range(sg.OutputsLength())]

        ops = []
        for i in range(sg.OperatorsLength()):
            op = sg.Operators(i)
            opcode = model.OperatorCodes(op.OpcodeIndex())
            ops.append(op_map.get(opcode.BuiltinCode(), str(opcode.BuiltinCode())))

        cnt = Counter(ops)

        out.update({
            "input_shapes": json_short(inputs),
            "output_shapes": json_short(outputs),
            "input_output_dtypes": ";".join(sorted({str(x.get("dtype", "")) for x in inputs + outputs})),
            "tensor_count": str(sg.TensorsLength()),
            "operators_top": ";".join(f"{k}:{v}" for k, v in cnt.most_common(30)),
            "profile_status": "ok_flatbuffer",
        })

        keys = set(cnt)
        if {"LSTM", "SVDF", "UNIDIRECTIONAL_SEQUENCE_LSTM"} & keys:
            out["arch_guess"] = "RNN/LSTM-like"
        elif "BATCH_MATMUL" in keys:
            out["arch_guess"] = "Transformer/Attention-like（弱推测）"
        elif "CONV_2D" in keys or "DEPTHWISE_CONV_2D" in keys or "CUSTOM" in keys:
            out["arch_guess"] = "CNN/EdgeTPU-like"
        elif "FULLY_CONNECTED" in keys:
            out["arch_guess"] = "MLP/DNN-like"
        else:
            out["arch_guess"] = "未知"

        return out

    except Exception as e:
        out["profile_status"] = f"tflite_flatbuffer_profile_failed:{e}"
        return out
# END PATCH: TFLite FlatBuffer fallback profile


def onnx_profile(path: Path) -> Dict[str, str]:
    out = empty_profile("onnx_profile_skipped")
    try:
        import onnx  # type: ignore
        model = onnx.load(str(path), load_external_data=False)
        ops = Counter(n.op_type for n in model.graph.node)
        def vi_summary(vs):
            arr = []
            for v in vs:
                dims = []
                try:
                    for d in v.type.tensor_type.shape.dim:
                        dims.append(d.dim_value if d.dim_value else d.dim_param)
                except Exception: pass
                arr.append({"name": v.name, "shape": dims})
            return json_short(arr)
        out.update({
            "input_shapes": vi_summary(model.graph.input),
            "output_shapes": vi_summary(model.graph.output),
            "tensor_count": str(len(model.graph.initializer)),
            "operators_top": ";".join(f"{k}:{v}" for k, v in ops.most_common(20)),
            "profile_status": "ok",
        })
        keys = set(ops)
        if "LSTM" in keys or "RNN" in keys: out["arch_guess"] = "RNN/LSTM-like"
        elif "Conv" in keys: out["arch_guess"] = "CNN-like"
        elif "Gemm" in keys or "MatMul" in keys: out["arch_guess"] = "MLP/DNN/Transformer-like"
        else: out["arch_guess"] = "未知"
    except Exception as e:
        out["profile_status"] = f"onnx_profile_skipped_or_failed:{e}"
    return out


def caffe_prototxt_profile(path: Path) -> Dict[str, str]:
    out = empty_profile("caffe_prototxt_basic")
    text = read_text(path, max_bytes=10_000_000)
    if not text:
        out["profile_status"] = "caffe_prototxt_empty_or_too_large"; return out
    dims = [int(x) for x in re.findall(r"\binput_dim\s*:\s*(-?\d+)", text)]
    shapes = []
    if dims:
        shapes.extend([dims[i:i+4] for i in range(0, len(dims), 4)] if len(dims) % 4 == 0 else [dims])
    for block in re.findall(r"\b(?:input_shape|shape)\s*\{([^{}]*)\}", text, flags=re.S):
        ds = [int(x) for x in re.findall(r"\bdim\s*:\s*(-?\d+)", block)]
        if ds and ds not in shapes: shapes.append(ds)
    layers = Counter(re.findall(r"\btype\s*:\s*\"([^\"]+)\"", text))
    out["input_shapes"] = json_short(shapes); out["operators_top"] = ";".join(f"{k}:{v}" for k, v in layers.most_common(30))
    if layers:
        keys = set(layers)
        if any(k in keys for k in ["Convolution", "Pooling", "Deconvolution"]): out["arch_guess"] = "CNN-like"
        elif any(k in keys for k in ["LSTM", "RNN", "Recurrent"]): out["arch_guess"] = "RNN/LSTM-like"
        elif any(k in keys for k in ["InnerProduct", "Embed"]): out["arch_guess"] = "MLP/DNN-like"
    out["profile_status"] = "ok" if shapes or layers else "caffe_prototxt_no_shape_found"
    return out


def basic_profile(path: Path, fmt: str) -> Dict[str, str]:
    if is_git_lfs_pointer(path): return empty_profile("git_lfs_pointer_not_real_model")

    # BEGIN PATCH: extended standard model profilers
    # 先调用扩展解析器，覆盖 .pb/.pbtxt/.pth/.pt/.ckpt/.npz/.h5/.keras/.safetensors/.mlmodel/.xml 等标准模型。
    # 如果扩展解析器返回 None，再回退到原始轻量解析逻辑。
    try:
        from model_profile_ext import enhanced_profile  # type: ignore
        enhanced = enhanced_profile(path, fmt)
        if enhanced is not None:
            return enhanced
    except Exception as _profile_ext_error:
        # 扩展解析器失败时回退，避免单个模型影响整批固件。
        pass
    # END PATCH: extended standard model profilers

    ext = path.suffix.lower()
    if ext == ".tflite": return tflite_profile(path)
    if ext == ".onnx": return onnx_profile(path)
    if ext == ".prototxt": return caffe_prototxt_profile(path)
    if ext == ".caffemodel":
        proto = next(iter(path.parent.glob("*.prototxt")), None)
        return caffe_prototxt_profile(proto) if proto else empty_profile("caffemodel_no_related_prototxt_shape_unknown")
    if ext == ".param":
        # NCNN param lightweight parse
        out = empty_profile("ncnn_param_basic")
        text = read_text(path, max_bytes=10_000_000)
        ops, inputs = Counter(), []
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#") or s.startswith("7767517"): continue
            parts = s.split()
            if len(parts) >= 2:
                ops[parts[0]] += 1
                if parts[0].lower() == "input":
                    params = {m.group(1): int(m.group(2)) for m in re.finditer(r"(\d+)=(-?\d+)", s)}
                    shape = [params[2], params[1], params[0]] if {0,1,2}.issubset(params) else [params[k] for k in sorted(params)]
                    inputs.append({"name": parts[1], "shape": shape})
        out["input_shapes"] = json_short(inputs); out["operators_top"] = ";".join(f"{k}:{v}" for k,v in ops.most_common(30)); out["profile_status"] = "ok" if ops else "ncnn_param_no_layers_found"
        return out
    if "Private CNN" in fmt or "CNN/NPU" in fmt or "CNNLib" in str(path):
        out = empty_profile("private_cnn_binary_detected_shape_unknown")
        out["operators_top"] = "private_vendor_binary"; out["arch_guess"] = "CNN-like（基于路径/文件名弱推测）"; out["quantization"] = "unknown_private_binary"
        return out
    return empty_profile(f"basic_only_for_{fmt}")


def strip_c_comments(s: str) -> str:
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)
    return re.sub(r"//.*", " ", s)


def find_matching_brace(text: str, open_pos: int) -> int:
    depth = 0; in_str = in_chr = esc = False
    for i in range(open_pos, len(text)):
        ch = text[i]
        if esc: esc = False
        elif ch == "\\": esc = True
        elif in_str:
            if ch == '"': in_str = False
        elif in_chr:
            if ch == "'": in_chr = False
        elif ch == '"': in_str = True
        elif ch == "'": in_chr = True
        elif ch == "{": depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0: return i
    return -1


def bytes_from_c_array_body(body: str) -> bytes:
    body = strip_c_comments(body); vals = []
    for m in re.finditer(r"0x[0-9A-Fa-f]{1,2}|(?<![A-Za-z0-9_])\d{1,3}(?![A-Za-z0-9_])", body):
        tok = m.group(0)
        try: val = int(tok, 16) if tok.lower().startswith("0x") else int(tok, 10)
        except Exception: continue
        if 0 <= val <= 255: vals.append(val)
    return bytes(vals)


def recover_static_models(root: Path, out_dir: Path, sample_key: str, no_retain: bool, min_bytes: int) -> List[Dict[str, Any]]:
    rows, seen = [], set()
    for p in iter_files(root):
        if p.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".ino"}: continue
        text = read_text(p, max_bytes=5_000_000)
        if not text: continue
        low = text.lower(); has_hint = any(h in low for h in ["microinterpreter", "tflite::getmodel", "tensor_arena", "edge-impulse", "progmem"])
        for m in STATIC_ARRAY_DECL_RE.finditer(text):
            name, decl = m.group("name"), m.group("decl")
            if not (STATIC_ARRAY_NAME_RE.search(name) or has_hint or any(x in decl.lower() for x in ["progmem", "alignas"])): continue
            open_pos = text.find("{", m.end() - 1); close_pos = find_matching_brace(text, open_pos) if open_pos >= 0 else -1
            if close_pos < 0: continue
            data = bytes_from_c_array_body(text[open_pos+1:close_pos])
            if len(data) < min_bytes and b"TFL3" not in data[:4096]: continue
            h = hashlib.sha256(data).hexdigest()
            if h in seen: continue
            seen.add(h)
            fmt, suffix, kind = ("TFLite", ".tflite", "static_embedded_model") if b"TFL3" in data[:4096] else ("Recovered Static Binary Model", ".bin", "static_embedded_model")
            retained = ""
            if not no_retain:
                dst = out_dir / sample_key / f"{safe_name(rel(p, root).replace('/', '__'), 120)}__{safe_name(name, 60)}__{h[:12]}{suffix}"
                ensure_dir(dst.parent); dst.write_bytes(data); retained = str(dst)
            prof = basic_profile(Path(retained), fmt) if retained and fmt == "TFLite" else empty_profile("static_recovered_basic")
            rows.append({"Model_File": f"{name}{suffix}", "Model_Format": fmt, "Model_Kind": kind, "Source_Path": rel(p, root), "Retained_Model_Path": retained, "Size_Bytes": str(len(data)), "SHA256": h, "Task_Guess": guess_task_from_name(f"{name} {p}"), "Input_Shapes": prof.get("input_shapes", ""), "Output_Shapes": prof.get("output_shapes", ""), "DTypes": prof.get("input_output_dtypes", ""), "Operators_Top": prof.get("operators_top", ""), "Arch_Guess": prof.get("arch_guess", ""), "Quantization": prof.get("quantization", ""), "Profile_Status": prof.get("profile_status", ""), "Extraction_Method": "source_static_array_recovery"})
    return rows


def shlex_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def grep_strings_version(path: Path) -> str:
    if not shutil.which("strings"): return ""
    cmd = f"strings -a {shlex_quote(str(path))} 2>/dev/null | grep -Ei 'version|ver\\.|release|build|tensorflow|tflite|onnxruntime|rknn|openvino|tensorrt|depthai|opencv|sigmastar|novatek|nvt|mi_sed|mi_ipu|mi_vdf|kdrv_ai|kflow_cnn|kflow_ai_net|OpenSSL [0-9]|mbed TLS [0-9]|Mbed TLS [0-9]|LIVE555|BusyBox v?[0-9]' | head -n 50"
    code, stdout, stderr = run_cmd(["bash", "-lc", cmd], timeout=40)
    lines = []
    for line in stdout.splitlines():
        line = line.strip()
        if 4 <= len(line) <= 240 and VERSION_LINE_RE.search(line): lines.append(line)
    return " | ".join(dict.fromkeys(lines))[:2500]


def analyze_binary_metadata(path: Path) -> Dict[str, str]:
    out = {"Architecture":"", "ELF_Class":"", "Machine":"", "SONAME":"", "NEEDED":"", "RPATH":"", "BuildID":"", "Exported_AI_Symbols":"", "Version_String":""}
    code, stdout, stderr = run_cmd(["file", str(path)], timeout=20)
    if stdout.strip():
        out["Architecture"] = stdout.strip().split(":", 1)[-1].strip()[:400]
    if shutil.which("readelf"):
        code, stdout, stderr = run_cmd(["readelf", "-h", str(path)], timeout=30)
        for line in stdout.splitlines():
            s = line.strip()
            if s.startswith("Class:"): out["ELF_Class"] = s.split(":",1)[1].strip()
            elif s.startswith("Machine:"): out["Machine"] = s.split(":",1)[1].strip()
        code, stdout, stderr = run_cmd(["readelf", "-d", str(path)], timeout=30)
        needed, rpaths = [], []
        for line in stdout.splitlines():
            if "(SONAME)" in line:
                m = re.search(r"\[(.*?)\]", line); out["SONAME"] = m.group(1) if m else out["SONAME"]
            elif "(NEEDED)" in line:
                m = re.search(r"\[(.*?)\]", line); needed.append(m.group(1)) if m else None
            elif "(RPATH)" in line or "(RUNPATH)" in line:
                m = re.search(r"\[(.*?)\]", line); rpaths.append(m.group(1)) if m else None
        out["NEEDED"] = ";".join(dict.fromkeys(needed))[:2000]; out["RPATH"] = ";".join(dict.fromkeys(rpaths))[:1000]
        code, stdout, stderr = run_cmd(["readelf", "-n", str(path)], timeout=30)
        m = re.search(r"Build ID:\s*([0-9A-Fa-f]+)", stdout); out["BuildID"] = m.group(1) if m else ""
        code, stdout, stderr = run_cmd(["readelf", "-Ws", str(path)], timeout=60)
        syms = []
        for line in stdout.splitlines():
            if AI_SYMBOL_RE.search(line):
                parts = line.split(); syms.append((parts[-1] if parts else line.strip())[:160])
                if len(syms) >= 100: break
        out["Exported_AI_Symbols"] = ";".join(dict.fromkeys(syms))[:5000]
    out["Version_String"] = grep_strings_version(path)
    return out


def sdk_for_name(name: str) -> Tuple[str, str]:
    low = (name or "").lower()
    if low in SDK_ALIASES: return SDK_ALIASES[low]
    for hint, val in SDK_HINTS.items():
        if hint in low: return val
    return "", ""


def classify_vendor_runtime(path_text: str, metadata: Dict[str, str]) -> Tuple[str, str, str, str]:
    blob = " ".join([path_text, metadata.get("SONAME", ""), metadata.get("NEEDED", ""), metadata.get("Exported_AI_Symbols", ""), metadata.get("Version_String", "")]).lower().replace("\\", "/")
    if any(x in blob for x in ["kdrv_ai", "kflow_cnn", "kflow_ai_net"]): return "Novatek/NVT HDAL AI Runtime", "vendor_ai_runtime", "kdrv_ai/kflow_cnn/kflow_ai_net", "high"
    if "cnnlib" in blob: return "Novatek/NVT CNNLib Runtime", "vendor_ai_runtime", "CNNLib", "high"
    if any(x in blob for x in ["novatek", "nvt_linux_smp", "nvtpack", "na51055"]): return "Novatek/NVT Platform SDK", "vendor_platform_sdk", "Novatek/NVT platform string", "medium"
    if "libmi_sed" in blob or "mi_sed_" in blob or "sed_cnn" in blob or "cnnobjdetect" in blob or "_mi_sed_docnnobjdetect" in blob: return "SigmaStar MI IPU/SED Runtime", "vendor_ai_runtime", "libmi_sed/MI_SED/CNNObjDetect", "high"
    if "libmi_ipu" in blob or "mi_ipu_" in blob: return "SigmaStar MI IPU Runtime", "vendor_ai_runtime", "libmi_ipu/MI_IPU", "high"
    if "libmi_vdf" in blob or "mi_vdf_" in blob: return "SigmaStar MI VDF/SED Pipeline", "vendor_ai_runtime", "libmi_vdf/MI_VDF", "medium"
    if "sigmastar" in blob: return "SigmaStar MI Platform SDK", "vendor_platform_sdk", "Sigmastar string", "medium"
    return "", "", "", ""



# BEGIN PATCH: normalize TensorRT dependency version
TENSORRT_DEP_VERSION_RE = re.compile(
    r"\btensorrt(?:[-_]?cu\d+)?\s*(?:==|=|>=|<=|~=|>|<)?\s*v?([0-9]+(?:\.[0-9]+){1,4})",
    re.I,
)

def normalize_dependency_identity(dep: str, ver: str, evidence: str) -> Tuple[str, str, str]:
    blob = " ".join([str(dep or ""), str(ver or ""), str(evidence or "")])
    m = TENSORRT_DEP_VERSION_RE.search(blob)
    if m:
        return "TensorRT", "vendor_ai_runtime_or_platform_sdk", m.group(1)
    return "", "", ""
# END PATCH: normalize TensorRT dependency version

def parse_deps(path: Path) -> List[Tuple[str, str, str]]:
    text = read_text(path)
    if not text: return []
    deps: List[Tuple[str, str, str]] = []
    if path.name.startswith("requirements"):
        for line in text.splitlines():
            s = line.strip().split(";", 1)[0]
            m = re.match(r"([A-Za-z0-9_.\-/]+)(?:\[.*?\])?\s*(==|>=|<=|~=|>|<|=)\s*([^;,\s]+)", s)
            if m: deps.append((m.group(1), m.group(2)+m.group(3), line.strip()))
    elif path.name == "package.json":
        try:
            data = json.loads(text)
            for sec in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]:
                for k, v in (data.get(sec) or {}).items(): deps.append((k, str(v), sec))
        except Exception: pass
    elif path.name in {"pyproject.toml", "setup.py", "setup.cfg"}:
        for q in re.findall(r"['\"]([A-Za-z0-9_.\-/]+\s*(?:==|>=|<=|~=|>|<|=)\s*[^'\"]+)['\"]", text):
            m = re.match(r"([A-Za-z0-9_.\-/]+)\s*(==|>=|<=|~=|>|<|=)\s*([^;,\s]+)", q)
            if m: deps.append((m.group(1), m.group(2)+m.group(3), q))
    low = text.lower()
    for hint, (sdk, cat) in SDK_HINTS.items():
        if hint in low: deps.append((sdk, "", f"keyword:{hint}"))
    # dedupe
    uniq, seen = [], set()
    for d in deps:
        if d not in seen:
            seen.add(d); uniq.append(d)
    return uniq


def scan_callpath(root: Path) -> Dict[str, str]:
    counts = Counter(); examples = defaultdict(list)
    for p in iter_files(root):
        if not is_text_candidate(p): continue
        text = read_text(p)
        if not text: continue
        for i, line in enumerate(text.splitlines(), 1):
            for cat, regs in COMPILED_CALL.items():
                for rg in regs:
                    m = rg.search(line)
                    if m:
                        counts[cat] += 1
                        if len(examples[cat]) < 5:
                            ctx = re.sub(r"\s+", " ", line.strip())[:220]
                            examples[cat].append(f"{rel(p, root)}:{i}:{ctx}")
                        break
    api = []
    if counts["tflite_api"]: api.append("TFLite")
    if counts["onnx_api"]: api.append("ONNX Runtime")
    if counts["vendor_api"]: api.append("vendor_runtime")
    input_guess = "未知"
    if counts["input_audio"] >= max(counts["input_camera"], counts["input_sensor"]): input_guess = "麦克风/音频" if counts["input_audio"] else input_guess
    if counts["input_camera"] > max(counts["input_audio"], counts["input_sensor"]): input_guess = "摄像头/图像"
    if counts["input_sensor"] > max(counts["input_audio"], counts["input_camera"]): input_guess = "IMU/传感器"
    output = []
    if counts["postprocess"]: output.append("分类/检测/评分")
    if counts["output_control"]: output.append("控制/告警")
    if counts["output_network"]: output.append("网络/服务输出")
    return {
        "API_Summary": "+".join(api) if api else "未知",
        "Input_Source_Guess": input_guess,
        "Output_Usage_Guess": "+".join(output) if output else "未知",
        "Model_Load_Evidence": " | ".join(examples["model_reference"] + examples["tflite_api"] + examples["onnx_api"] + examples["vendor_api"]),
        "Preprocess_Evidence": " | ".join(examples["preprocess"]),
        "Postprocess_Evidence": " | ".join(examples["postprocess"]),
    }


def scan_sdk(root: Path, sample: Dict[str, str], retained_libs_dir: Path, sample_key: str, no_retain: bool, retain_all_libs: bool) -> List[Dict[str, str]]:
    rows, seen = [], set()
    for p in iter_files(root):
        rp, ext = rel(p, root), p.suffix.lower()
        if ext in LIB_EXTS:
            sdk, cat = sdk_for_name(rp)
            item = {"FirmwareID": sample_key, "Model": sample.get("Model", ""), "Version": sample.get("Version", ""), "SDK_Name": sdk or p.stem, "SDK_Category": cat or "binary/library", "Evidence_Type": "binary_library", "File_Type": LIB_EXTS[ext], "File_Path": rp, "Retained_Path": "", "Size_Bytes": str(p.stat().st_size), "SHA256": sha256_file(p), "Evidence": p.name, "Confidence": "high" if sdk else "medium", "Architecture": "", "Machine": "", "SONAME": "", "NEEDED": "", "BuildID": "", "Version_String": ""}
            if ext in {".so", ".ko", ".dll", ".dylib", ".a"}:
                meta = analyze_binary_metadata(p); item.update({k: meta.get(k, "") for k in ["Architecture", "Machine", "SONAME", "NEEDED", "BuildID", "Version_String"]}); item["Exported_AI_Symbols"] = meta.get("Exported_AI_Symbols", "")
                v_sdk, v_cat, v_ev, v_conf = classify_vendor_runtime(rp, meta)
                if v_sdk:
                    item.update({"SDK_Name": v_sdk, "SDK_Category": v_cat, "Evidence": v_ev, "Confidence": v_conf})
                elif meta.get("Exported_AI_Symbols") and not sdk:
                    item.update({"SDK_Name": f"AI-related binary: {p.stem}", "SDK_Category": "ai_binary_runtime_evidence", "Confidence": "high"})
            if not no_retain and (retain_all_libs or item["SDK_Category"] not in {"", "binary/library", "dependency"}):
                item["Retained_Path"] = copy_artifact(p, root, retained_libs_dir, sample_key)
            key = (item["SDK_Name"], item["File_Path"], item["SHA256"])
            if key not in seen:
                seen.add(key); rows.append(item)
        if p.name in DEPENDENCY_FILES:
            for dep, ver, ev in parse_deps(p):
                norm_sdk, norm_cat, norm_ver = normalize_dependency_identity(dep, ver, ev)
                sdk, cat = sdk_for_name(dep)
                if norm_sdk:
                    sdk, cat, ver = norm_sdk, norm_cat, norm_ver
                item = {"FirmwareID": sample_key, "Model": sample.get("Model", ""), "Version": sample.get("Version", ""), "SDK_Name": sdk or dep, "SDK_Category": cat or "dependency", "Evidence_Type": "dependency_manifest", "File_Type": "dependency_manifest", "File_Path": rp, "Retained_Path": "", "Size_Bytes": str(p.stat().st_size), "SHA256": sha256_file(p), "Evidence": ev, "Confidence": "high" if sdk else "low", "Architecture": "", "Machine": "", "SONAME": "", "NEEDED": "", "BuildID": "", "Version_String": ver}
                key = (item["SDK_Name"], item["File_Path"], item["Version_String"])
                if key not in seen:
                    seen.add(key); rows.append(item)
    return rows


def write_csv(path: Path, rows: List[Dict[str, Any]], fields: List[str]) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        # BEGIN PATCH: quote all CSV fields
        w = csv.DictWriter(
            f,
            fieldnames=fields,
            extrasaction="ignore",
            quoting=csv.QUOTE_ALL,
            lineterminator="\n",
        )
        # END PATCH: quote all CSV fields
        w.writeheader(); w.writerows(rows)




# BEGIN PATCH: distinct model file + shape summary
# 统计“不同模型文件”时，默认按 SHA256 + 输入/输出 shape + dtype 去重。
# 这样可以避免同一固件/同一模型在多个版本中重复计数；如果同名模型 shape 不同，也会被计为不同模型。
def _norm_profile_text(v: Any) -> str:
    s = str(v or "").strip()
    if not s or s in {"[]", "{}", "null", "None"}:
        return ""
    return re.sub(r"\s+", "", s)[:8000]


def _model_shape_signature(row: Dict[str, Any]) -> str:
    inp = _norm_profile_text(row.get("Input_Shapes", ""))
    out = _norm_profile_text(row.get("Output_Shapes", ""))
    dt = _norm_profile_text(row.get("DTypes", ""))
    return f"input={inp}|output={out}|dtype={dt}"


def _distinct_model_key(row: Dict[str, Any]) -> str:
    sha = str(row.get("SHA256", "")).strip().lower()
    fmt = str(row.get("Model_Format", "")).strip()
    sig = _model_shape_signature(row)
    # 优先按内容 hash 去重；shape/dtype 同时进入 key，保证 shape 不同会分开计数。
    if sha:
        return f"sha_shape::{sha}::{fmt}::{sig}"
    # 静态恢复或异常情况下没有 hash 时，用路径 + shape 兜底。
    return "path_shape::" + "::".join([
        str(row.get("FirmwareID", "")),
        str(row.get("Model_File", "")),
        str(row.get("Source_Path", "")),
        fmt,
        sig,
    ])


def _short_unique(vals: Iterable[Any], limit: int = 20, max_len: int = 4000) -> str:
    out: List[str] = []
    seen = set()
    for v in vals:
        s = str(v or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= limit:
            break
    return " | ".join(out)[:max_len]


def write_distinct_model_summary(out_dir: Path, model_rows: List[Dict[str, Any]]) -> None:
    valid_rows = [
        r for r in model_rows
        if str(r.get("Model_Kind", "")) != "not_found"
        and (r.get("Model_File") or r.get("Source_Path") or r.get("SHA256"))
    ]

    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in valid_rows:
        groups[_distinct_model_key(r)].append(r)

    distinct_rows: List[Dict[str, Any]] = []
    for idx, (key, rows) in enumerate(sorted(groups.items()), 1):
        first = rows[0]
        distinct_rows.append({
            "Distinct_Model_ID": f"DM{idx:05d}",
            "Occurrence_Count": str(len(rows)),
            "Model_Format": first.get("Model_Format", ""),
            "Model_Kind": first.get("Model_Kind", ""),
            "Model_Files": _short_unique([r.get("Model_File", "") for r in rows]),
            "SHA256": first.get("SHA256", ""),
            "Size_Bytes_Examples": _short_unique([r.get("Size_Bytes", "") for r in rows], limit=8),
            "Input_Shapes": first.get("Input_Shapes", ""),
            "Output_Shapes": first.get("Output_Shapes", ""),
            "DTypes": first.get("DTypes", ""),
            "Shape_Signature": _model_shape_signature(first),
            "Operators_Top": first.get("Operators_Top", ""),
            "Arch_Guess": first.get("Arch_Guess", ""),
            "Quantization": first.get("Quantization", ""),
            "Task_Guess": _short_unique([r.get("Task_Guess", "") for r in rows], limit=8),
            "Profile_Status": _short_unique([r.get("Profile_Status", "") for r in rows], limit=8),
            "FirmwareIDs": _short_unique([r.get("FirmwareID", "") for r in rows], limit=30),
            "Models": _short_unique([r.get("Model", "") for r in rows], limit=20),
            "Versions": _short_unique([r.get("Version", "") for r in rows], limit=30),
            "Example_Source_Paths": _short_unique([r.get("Source_Path", "") for r in rows], limit=12, max_len=6000),
            "Example_Retained_Paths": _short_unique([r.get("Retained_Model_Path", "") for r in rows], limit=8, max_len=6000),
        })

    distinct_fields = [
        "Distinct_Model_ID", "Occurrence_Count", "Model_Format", "Model_Kind", "Model_Files", "SHA256",
        "Size_Bytes_Examples", "Input_Shapes", "Output_Shapes", "DTypes", "Shape_Signature",
        "Operators_Top", "Arch_Guess", "Quantization", "Task_Guess", "Profile_Status",
        "FirmwareIDs", "Models", "Versions", "Example_Source_Paths", "Example_Retained_Paths",
    ]
    write_csv(out_dir / "distinct_model_files.csv", distinct_rows, distinct_fields)

    shape_sigs = { _model_shape_signature(r) for r in valid_rows if _model_shape_signature(r) != "input=|output=|dtype=" }
    summary_rows: List[Dict[str, Any]] = [
        {"Category": "overall", "Label": "total_model_result_rows", "Count": str(len(model_rows)), "Note": "model_extraction_results.csv 总行数，包含 not_found 行"},
        {"Category": "overall", "Label": "valid_model_artifact_rows", "Count": str(len(valid_rows)), "Note": "实际发现的模型文件/静态恢复模型记录数"},
        {"Category": "overall", "Label": "distinct_model_files_by_sha_and_shape", "Count": str(len(distinct_rows)), "Note": "按 SHA256 + input_shape + output_shape + dtype 去重；shape 不同会分开计数"},
        {"Category": "overall", "Label": "distinct_io_shape_signatures", "Count": str(len(shape_sigs)), "Note": "不同输入/输出/dtype 组合数量；不含完全空 shape"},
    ]
    for k, v in Counter(r.get("Model_Format", "") for r in valid_rows if r.get("Model_Format")).most_common():
        summary_rows.append({"Category": "model_format_rows", "Label": k, "Count": str(v), "Note": "未去重的模型记录数"})
    for k, v in Counter(r.get("Model_Format", "") for r in distinct_rows if r.get("Model_Format")).most_common():
        summary_rows.append({"Category": "model_format_distinct", "Label": k, "Count": str(v), "Note": "按 SHA256 + shape 去重后的模型数"})
    for k, v in Counter(r.get("Profile_Status", "") for r in valid_rows if r.get("Profile_Status")).most_common():
        summary_rows.append({"Category": "profile_status_rows", "Label": k, "Count": str(v), "Note": "未去重的解析状态统计"})
    write_csv(out_dir / "distinct_model_file_summary.csv", summary_rows, ["Category", "Label", "Count", "Note"])

    print("\n========== Distinct model summary ==========")
    print(f"valid model artifact rows: {len(valid_rows)}")
    print(f"distinct model files by SHA+shape: {len(distinct_rows)}")
    print(f"distinct IO shape signatures: {len(shape_sigs)}")
    print(f"distinct model files CSV: {out_dir / 'distinct_model_files.csv'}")
    print(f"distinct summary CSV: {out_dir / 'distinct_model_file_summary.csv'}")
# END PATCH: distinct model file + shape summary


def materialize(row: Dict[str, str], downloads: Path, extracted: Path, redownload: bool, reextract: bool, use_git_lfs: bool, lfs_include: str, lfs_fallback: bool, keep_downloads: bool = False) -> Tuple[Path, Path, str]:
    url = row.get("DownloadLink", "")
    key = f"{safe_name(row.get('Model','sample'))}__{safe_name(row.get('Version','unknown'))}__{sha1_short(url)}"
    root = extracted / key
    gh = parse_github_source_url(url, row.get("Version", "")) if use_git_lfs else None
    if gh:
        # BEGIN PATCH: use cached Git-LFS snapshot zip
        cached_zip = downloads / f"{key}.git_lfs.zip"
        if keep_downloads and cached_zip.exists() and cached_zip.stat().st_size > 0 and not redownload:
            if root.exists() and reextract:
                shutil.rmtree(root)
            if (not root.exists()) or reextract:
                extract_archive(cached_zip, root, reextract=True)
            return cached_zip, root, key
        # END PATCH: use cached Git-LFS snapshot zip

        try:
            clone_github_with_lfs(gh[0], gh[1], gh[2], root, reextract=reextract, lfs_include=lfs_include)
            dl: Path = root

            # BEGIN PATCH: keep Git-LFS materialized source snapshot
            # Git LFS 模式不是普通“下载一个 zip”，而是 clone + lfs pull。
            # 当 --keep-files 开启时，把已拉到真实模型文件的目录打包保存到 downloads/。
            if keep_downloads:
                ensure_dir(downloads)
                cached_zip = downloads / f"{key}.git_lfs.zip"
                if redownload or reextract or (not cached_zip.exists()) or cached_zip.stat().st_size == 0:
                    tmp_base = downloads / f".{key}.git_lfs_tmp"
                    tmp_zip = Path(str(tmp_base) + ".zip")
                    if tmp_zip.exists():
                        tmp_zip.unlink()
                    shutil.make_archive(str(tmp_base), "zip", root_dir=str(root))
                    tmp_zip.replace(cached_zip)
                dl = cached_zip
            # END PATCH: keep Git-LFS materialized source snapshot

            return dl, root, key
        except Exception as e:
            if not lfs_fallback: raise
            print(f"[warn] git-lfs failed for {url}: {e}; fallback to URL download", file=sys.stderr)
    ext = infer_ext(url)
    dl = downloads / f"{key}{ext}"
    download_url(url, dl, redownload)
    if ext in ARCHIVE_EXTS:
        extract_archive(dl, root, reextract)
    else:
        if root.exists() and reextract: shutil.rmtree(root)
        ensure_dir(root); dst = root / dl.name
        if not dst.exists() or reextract: shutil.copy2(dl, dst)
    return dl, root, key


def main() -> int:
    ap = argparse.ArgumentParser(description="AI firmware download/extract/model-profile/SDK inventory")
    ap.add_argument("-i", "--input", required=True, help="CSV with Model, Version, DownloadLink")
    ap.add_argument("-o", "--out-dir", default="ai_profile_result")
    ap.add_argument("--download-dir", default="downloads")
    ap.add_argument("--extract-dir", default="extracted")
    ap.add_argument("--redownload", action="store_true")
    ap.add_argument("--reextract", action="store_true")
    ap.add_argument("--no-git-lfs", action="store_true")
    ap.add_argument("--lfs-include", default=DEFAULT_LFS_INCLUDE)
    ap.add_argument("--no-lfs-fallback", action="store_true")
    ap.add_argument("--binwalk", action="store_true", help="after ordinary extraction, run binwalk -eM on firmware-like inner files if binwalk is installed")
    ap.add_argument("--keep-files", action="store_true", help="keep downloads/extracted tree; recommended for later vuln matching")
    ap.add_argument("--no-retain-artifacts", action="store_true")
    ap.add_argument("--retain-all-libs", action="store_true")
    ap.add_argument("--static-min-bytes", type=int, default=STATIC_MIN_BYTES)
    ap.add_argument("--max-samples", type=int, default=0)
    ap.add_argument("--debug", action="store_true", help="also write scan_status.csv and summary.csv")
    args = ap.parse_args()

    out_dir = Path(args.out_dir); downloads = Path(args.download_dir); extracted = Path(args.extract_dir)
    ensure_dir(out_dir); ensure_dir(downloads); ensure_dir(extracted)
    retained_models = out_dir / "retained_models"; retained_static = out_dir / "retained_static_models"; retained_libs = out_dir / "retained_sdk_libs"

    with open(args.input, "r", encoding="utf-8-sig", newline="") as f:
        targets = list(csv.DictReader(f))
    if args.max_samples: targets = targets[:args.max_samples]
    missing = {"Model", "Version", "DownloadLink"} - set(targets[0].keys() if targets else [])
    if missing:
        raise SystemExit(f"input CSV missing required columns: {sorted(missing)}")

    model_rows: List[Dict[str, Any]] = []
    sdk_rows: List[Dict[str, Any]] = []
    status_rows: List[Dict[str, Any]] = []
    for idx, row in enumerate(targets, 1):
        print(f"[{idx}/{len(targets)}] {row.get('Model','')} {row.get('Version','')}", flush=True)
        try:
            dl, root, sample_key = materialize(row, downloads, extracted, args.redownload, args.reextract, not args.no_git_lfs, args.lfs_include, not args.no_lfs_fallback, args.keep_files)
            if args.binwalk:
                binwalk_extract(root)
            call_summary = scan_callpath(root)
            found = 0
            for p in iter_files(root):
                fmt, kind = detect_model_artifact(p, root)
                if not fmt: continue
                prof = basic_profile(p, fmt)
                retained = "" if args.no_retain_artifacts else copy_artifact(p, root, retained_models, sample_key)
                h = sha256_file(p); found += 1
                model_rows.append({"FirmwareID": sample_key, "Model": row.get("Model", ""), "Version": row.get("Version", ""), "Model_File": p.name, "Model_Format": fmt, "Model_Kind": kind, "Source_Path": rel(p, root), "Retained_Model_Path": retained, "Size_Bytes": str(p.stat().st_size), "SHA256": h, "Input_Shapes": prof.get("input_shapes", ""), "Output_Shapes": prof.get("output_shapes", ""), "DTypes": prof.get("input_output_dtypes", ""), "Operators_Top": prof.get("operators_top", ""), "Arch_Guess": prof.get("arch_guess", ""), "Quantization": prof.get("quantization", ""), "Task_Guess": guess_task_from_name(str(p)), "Input_Source_Guess": call_summary.get("Input_Source_Guess", ""), "Output_Usage_Guess": call_summary.get("Output_Usage_Guess", ""), "API_Summary": call_summary.get("API_Summary", ""), "Model_Load_Evidence": call_summary.get("Model_Load_Evidence", ""), "Preprocess_Evidence": call_summary.get("Preprocess_Evidence", ""), "Postprocess_Evidence": call_summary.get("Postprocess_Evidence", ""), "Profile_Status": prof.get("profile_status", ""), "Extraction_Method": "file_artifact_copy"})
            for sr in recover_static_models(root, retained_static, sample_key, args.no_retain_artifacts, args.static_min_bytes):
                sr.update({"FirmwareID": sample_key, "Model": row.get("Model", ""), "Version": row.get("Version", ""), "Input_Source_Guess": call_summary.get("Input_Source_Guess", ""), "Output_Usage_Guess": call_summary.get("Output_Usage_Guess", ""), "API_Summary": call_summary.get("API_Summary", ""), "Model_Load_Evidence": call_summary.get("Model_Load_Evidence", ""), "Preprocess_Evidence": call_summary.get("Preprocess_Evidence", ""), "Postprocess_Evidence": call_summary.get("Postprocess_Evidence", "")})
                model_rows.append(sr); found += 1
            if found == 0:
                model_rows.append({"FirmwareID": sample_key, "Model": row.get("Model", ""), "Version": row.get("Version", ""), "Model_File": "", "Model_Format": "", "Model_Kind": "not_found", "Source_Path": "", "Retained_Model_Path": "", "Size_Bytes": "", "SHA256": "", "Input_Shapes": "", "Output_Shapes": "", "DTypes": "", "Operators_Top": "", "Arch_Guess": "", "Quantization": "", "Task_Guess": "", "Input_Source_Guess": call_summary.get("Input_Source_Guess", ""), "Output_Usage_Guess": call_summary.get("Output_Usage_Guess", ""), "API_Summary": call_summary.get("API_Summary", ""), "Model_Load_Evidence": call_summary.get("Model_Load_Evidence", ""), "Preprocess_Evidence": call_summary.get("Preprocess_Evidence", ""), "Postprocess_Evidence": call_summary.get("Postprocess_Evidence", ""), "Profile_Status": "no_model_file_found", "Extraction_Method": "not_found"})
            sdks = scan_sdk(root, row, retained_libs, sample_key, args.no_retain_artifacts, args.retain_all_libs)
            sdk_rows.extend(sdks)
            status_rows.append({"FirmwareID": sample_key, "Model": row.get("Model", ""), "Version": row.get("Version", ""), "Status": "ok", "Message": f"models={found}, sdk_rows={len(sdks)}", "Root": str(root)})
            if not args.keep_files:
                # Vulnerability stage needs extracted files, so default pipeline passes --keep-files.
                try: shutil.rmtree(root)
                except Exception: pass
                try:
                    if isinstance(dl, Path) and dl.exists() and dl.is_file(): dl.unlink()
                except Exception: pass
        except Exception as e:
            status_rows.append({"FirmwareID": "", "Model": row.get("Model", ""), "Version": row.get("Version", ""), "Status": "error", "Message": str(e), "Root": ""})
            print(f"[error] {row.get('Model','')} {row.get('Version','')}: {e}", file=sys.stderr)

    model_fields = ["FirmwareID", "Model", "Version", "Model_File", "Model_Format", "Model_Kind", "Source_Path", "Retained_Model_Path", "Size_Bytes", "SHA256", "Input_Shapes", "Output_Shapes", "DTypes", "Operators_Top", "Arch_Guess", "Quantization", "Task_Guess", "Input_Source_Guess", "Output_Usage_Guess", "API_Summary", "Model_Load_Evidence", "Preprocess_Evidence", "Postprocess_Evidence", "Profile_Status", "Extraction_Method"]
    sdk_fields = ["FirmwareID", "Model", "Version", "SDK_Name", "SDK_Category", "Evidence_Type", "File_Type", "File_Path", "Retained_Path", "Size_Bytes", "SHA256", "Architecture", "Machine", "SONAME", "NEEDED", "BuildID", "Version_String", "Evidence", "Confidence"]
    write_csv(out_dir / "model_extraction_results.csv", model_rows, model_fields)
    write_distinct_model_summary(out_dir, model_rows)
    write_csv(out_dir / "third_party_sdk_inventory_raw.csv", sdk_rows, sdk_fields)
    if args.debug:
        write_csv(out_dir / "scan_status.csv", status_rows, ["FirmwareID", "Model", "Version", "Status", "Message", "Root"])
        summary = []
        for label, rows in [("models", model_rows), ("sdk_rows", sdk_rows), ("status_rows", status_rows)]:
            summary.append({"category": "total", "label": label, "count": str(len(rows))})
        for k, v in Counter(r.get("Model_Format", "") for r in model_rows if r.get("Model_Format")).most_common(): summary.append({"category":"model_format", "label":k, "count":str(v)})
        for k, v in Counter(r.get("SDK_Name", "") for r in sdk_rows if r.get("SDK_Name")).most_common(): summary.append({"category":"sdk", "label":k, "count":str(v)})
        write_csv(out_dir / "summary.csv", summary, ["category", "label", "count"])
    print("\n========== Stage 1 complete ==========")
    print(f"model results: {out_dir / 'model_extraction_results.csv'}")
    print(f"sdk raw inventory: {out_dir / 'third_party_sdk_inventory_raw.csv'}")
    print(f"retained models: {retained_models}")
    print(f"retained sdk libs: {retained_libs}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
