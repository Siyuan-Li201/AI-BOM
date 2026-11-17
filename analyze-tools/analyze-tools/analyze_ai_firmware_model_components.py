#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import hashlib
import os
import re
import shutil
import sys
import subprocess
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

INPUT_CSV = "firmware_versions.csv"
OUTPUT_CSV = "ai_firmware_analysis.csv"
DETAIL_CSV = "ai_firmware_analysis_details.csv"
DOWNLOAD_DIR = "downloads"
EXTRACT_DIR = "extracted"
REGION_DEFAULT = "Global"
USER_AGENT = "ai-firmware-static-analyzer/1.0"
MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_BINARY_BYTES = 8 * 1024 * 1024
BINARY_CHUNK_BYTES = 4 * 1024 * 1024
BINARY_CHUNK_OVERLAP = 4096
MAX_BINARY_SCAN_BYTES = 128 * 1024 * 1024
MAX_ONNX_VERIFY_BYTES = 64 * 1024 * 1024

#可读文本/源码类文件
SOURCE_EXTS = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".ino",
    ".py", ".rs", ".go", ".java", ".js", ".ts", ".cmake", ".mk", ".m4",
    ".S", ".s", ".asm", ".ld", ".yaml", ".yml", ".json", ".toml", ".xml",
    ".md", ".txt", ".sh", ".bat", ".ps1",
    ".cfg", ".conf", ".ini", ".config", ".service", ".rules", ".desktop",
    ".proto", ".pbtxt", ".names", ".labels", ".launch", ".urdf", ".xacro",
    ".lua", ".dockerfile"
}
#标准/通用模型文件后缀
STANDARD_MODEL_EXTS = {
    ".tflite", ".onnx", ".pb", ".pbtxt", ".lite", ".mlmodel", ".pt", ".pth",
    ".torchscript", ".ckpt", ".weights", ".param",
    ".caffemodel", ".prototxt", ".h5", ".keras", ".mnn", ".npz", ".pkl",
    ".joblib", ".safetensors", ".gguf", ".ggml", ".mar"
}
#已知厂商私有模型格式
PRIVATE_MODEL_EXTS = {
    ".rknn", ".blob", ".mud", ".nnb", ".xmodel", ".dlc", ".kmodel", ".om",
    ".bmodel", ".hef", ".nb", ".ms", ".tmfile", ".axmodel", ".cvimodel", ".wk",
    ".har", ".hbm", ".nbg", ".cambricon", ".offline"
}
#编译优化模型/二进制载体后缀
OPTIMIZED_MODEL_EXTS = {
    ".engine", ".plan", ".trt", ".etlt", ".uff", ".xclbin", ".so", ".a", ".ko",
    ".elf", ".uf2", ".hex", ".bin", ".compiled"
}
#可解包压缩包后缀
ARCHIVE_EXTS = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")

#源码/静态嵌入模型识别正则
STATIC_MODEL_PATTERNS = [
    re.compile(r"\b(?:const\s+)?(?:unsigned\s+char|uint8_t|int8_t|uint16_t|int16_t|float|q7_t)\s+(?:g_)?(?:model|model_data|trained_model|weights|tensor|input|output|ei_)[A-Za-z0-9_]*\s*\[", re.I),
    re.compile(r"\b(?:g_model|model_data|trained_model|tflite_model|ei_model|ei_classifier|model_weights)\b", re.I),
    re.compile(r"\b(?:EI_CLASSIFIER|run_classifier|ei_run_classifier|signal_t|ei_impulse_result_t)\b"),
    re.compile(r"\b(?:MicroInterpreter|tflite::GetModel|tensor_arena|AllOpsResolver|MicroMutableOpResolver)\b"),
]

#边缘AI SDK/推理框架关键词
EDGE_AI_SDK_PATTERNS = [
    "edge-impulse-sdk", "run_classifier", "ei_run_classifier", "EI_CLASSIFIER", "ei_impulse_result_t",
    "tflite::Micro", "MicroInterpreter", "tensor_arena", "cmsis_nn", "CMSIS-NN", "arm_nn_",
    "esp-z", "esp_dl", "esp-sr", "esp_sr", "rknn", "ncnn", "MNN", "paddle_lite",
    "TensorRT", "nvinfer", "onnxruntime", "Ort::Session", "OpenVINO", "InferenceEngine",
    "TIDL", "Vitis AI", "xir::", "vart::", "DPU", "DepthAI", "blobconverter",
    "SNPE", "DLC", "NNIE", "KPU", "NPU", "ethosu", "Ethos", "TFLM",

    #TFLite / OpenCV DNN / OpenVINO variants
    "TensorFlow Lite", "TfLite", "TfLiteInterpreter", "TfLiteDelegate", "cv::dnn", "cv2.dnn",
    "readNetFromONNX", "readNetFromCaffe", "ov::Core", "OpenVINO Runtime",

    #Hailo / SOPHGO / CVITEK / AXera / Horizon / Ascend / Cambricon
    "HailoRT", "hailo", "hef", "InferVStreams", "DeGirum", "degirum",
    "bmruntime", "bmrt", "bmcv", "sophon.sail", "sail.Engine", "BModel",
    "CVI_NN", "CVI_TDL", "cvitdl", "cvimodel", "TPU_SDK",
    "AX_ENGINE", "AXCL", "axcl", "axmodel", "pyaxcl",
    "hbDNN", "hbrt", "Horizon", "BPU",
    "AscendCL", "aclmdl", "aclrt", "CANN",
    "cnrt", "MagicMind", "Cambricon",

    #Emerging embedded runtimes
    "ExecuTorch", "MediaPipe", "CoreML", "MLModel", "ggml", "llama.cpp", "whisper.cpp"
]
#直接推理API调用关键词
DIRECT_API_PATTERNS = [
    "tf.lite.Interpreter", "tflite::Interpreter", "Interpreter.invoke", "Interpreter::Invoke",
    "Ort::Session", "onnxruntime.InferenceSession", "InferenceSession", "ncnn::Net",
    "MNN::Interpreter", "paddle::lite", "rknn_init", "rknn_run", "TfLiteInterpreterInvoke",
    "cv::dnn::readNet", "cv2.dnn.readNet", "readNetFromONNX", "readNetFromCaffe",
    "ov::Core", "compile_model", "create_infer_request",
    "bmrt_load_bmodel", "bmrt_launch_tensor", "sail.Engine",
    "CVI_NN_RegisterModel", "CVI_NN_Forward", "CVI_MODEL_LoadModel",
    "AX_ENGINE_CreateHandle", "AX_ENGINE_RunSync",
    "hbDNNInitializeFromFiles", "hbDNNInfer", "hbDNNRelease",
    "aclmdlLoadFromFile", "aclmdlExecute",
    "cnrtLoadModel", "cnrtInvokeRuntimeContext",
    "hailo_infer", "InferVStreams", "Hef(",
    "mediapipe.CalculatorGraph"
]
#服务化/代理式推理关键词
SERVICE_PATTERNS = [
    "Flask", "FastAPI", "uvicorn", "grpc", "mqtt", "mosquitto", "zeromq", "websocket",
    "HTTPServer", "aiohttp", "requests.post", "/predict", "inference_server", "systemd", "dbus",
    "REST API", "api_server", "inference_api", "model_server", "Triton Inference Server",
    "tritonserver", "tensorflow_model_server", "torchserve", "gunicorn", "nginx",
    "grpc_server", "grpcio", "ZeroMQ", "rabbitmq", "kafka", "redis", "Dockerfile",
    "docker-compose"
]
#数据流/管线型处理关键词
PIPELINE_PATTERNS = [
    "gstreamer", "gst_", "gst-launch", "DeepStream", "nvstreammux", "pipeline",
    "ros::", "rclcpp", "ROS2", "nodelet", "OpenVX", "media graph",

    # GStreamer / DeepStream concrete elements.
    "gst_parse_launch", "GstPipeline", "GstElement", "appsink", "appsrc", "rtspsrc",
    "v4l2src", "nvarguscamerasrc", "nvinfer", "nvinferserver", "nvtracker", "nvdsosd",
    "nvvideoconvert", "nvstreamdemux", "nvmsgconv", "nvmsgbroker",

    # ROS / robotics vision pipeline evidence.
    "image_transport", "sensor_msgs::msg::Image", "sensor_msgs/Image", "cv_bridge",
    "message_filters", "camera_info_manager", "isaac_ros", "NitrosImage",

    # Video/ISP/media pipeline evidence often used around edge AI.
    "ffmpeg", "libavformat", "av_read_frame", "RTSP", "MPP", "RK_MPI", "VI_PIPE",
    "VPSS", "VENC", "MediaPipe", "CalculatorGraph"
]
#云端相关关键词
CLOUD_PATTERNS = [
    "api.openai.com", "AWS Rekognition", "Amazon Rekognition", "Google Cloud Vision", "Azure Cognitive",
    "Azure OpenAI", "cloud inference", "cloud_model", "Firebase ML", "remote inference",
    "inference endpoint", "SageMaker", "Bedrock", "Vertex AI", "Vision API",
    "Baidu AI", "Aliyun", "Tencent Cloud", "Huawei Cloud", "http://", "https://"
]
#强云端AI证据
# Strong cloud-side AI signals.  Generic http(s) links are intentionally excluded
# here because README/license/download links otherwise create many false positives.
CLOUD_STRONG_PATTERNS = [
    "api.openai.com", "AWS Rekognition", "Amazon Rekognition", "Google Cloud Vision", "Azure Cognitive",
    "Azure AI Vision", "Azure ML", "Azure OpenAI", "Cognitive Services", "cloud inference",
    "cloud_model", "Firebase ML", "remote inference", "inference endpoint",
    "SageMaker", "Bedrock", "Vertex AI", "Vision API", "PredictionServiceClient",
    "predict endpoint", "prediction endpoint", "Baidu AI", "Aliyun", "Tencent Cloud",
    "Huawei Cloud ModelArts"
]

#普通URL提取正则
URL_RE = re.compile(r"https?://[^\s\"'<>\)\]}]+", re.I)
#疑似AI云端接口URL正则
CLOUD_AI_ENDPOINT_RE = re.compile(
    r"https?://[^\s\"'<>\)\]}]*(?:predict|prediction|infer|inference|classify|classification|detect|detection|recognition|vision|cognitive|ml|ai|model|embedding|chat|completion|ocr|asr|tts|llm)[^\s\"'<>\)\]}]*",
    re.I,
)

#私有模型文件名/路径提示词
PRIVATE_NAME_HINTS = [
    "rknn", "depthai", "myriad", "kpu", "nnb", "vitis", "xmodel",
    "snpe", "dlc", "npu", "dpu", "tidl", "nnie",

    # HiSilicon / Hikvision / NNIE
    "wk", "hisilicon", "hisi", "hi351", "hi355", "hi3798", "nnie",

    # Espressif ESP-DL / ESP-SR / ESP-WHO
    "esp-z", "esp_dl", "esp-sr", "esp_sr", "wakenet", "multinet",

    # Edge TPU / Coral compiled tflite naming hints
    "edgetpu", "edge_tpu", "coral",

    # Hailo / SOPHGO / CVITEK / AXera / Horizon / Ascend / Cambricon
    "hailo", "hef", "har", "sophon", "bmodel", "cvitek", "cvimodel",
    "axera", "axmodel", "horizon", "hbdnn", "hbm", "ascend", "aclmdl",
    "cambricon", "magicmind", "nbg", "tim-vx", "vipnanoq"
]

#编译优化模型/加速器产物文件名/路径提示词
OPT_NAME_HINTS = [
    "tensorrt", "trt", "engine", "tvm", "nvinfer", "nnie", "npu", "dpu",
    "openvino", "compiled",

    # Edge TPU / Coral
    "edgetpu", "edge_tpu", "coral",

    # FPGA / Vitis AI / DPU deployment artifact
    "xclbin", "bitstream", "dpu",

    # Runtime/compiler caches and accelerator-specific compiled graphs.
    "opencl", "cache", "hbm", "hef", "bmodel", "cvimodel", "axmodel",
    "magicmind", "cambricon", "nbg", "dla", "aclmdl", "ov_compiled"
]


#针对二进制文件扫描的强AI证据关键词
BINARY_STRONG_AI_KEYWORDS = [
    "TFL3", "ONNX", "TensorFlow Lite", "Edge Impulse", "EI_CLASSIFIER",
    "MicroInterpreter", "TFLM", "TfLiteInterpreter", "TfLiteInterpreterInvoke",
    "RKNN", "rknn_init", "rknn_run", "nvinfer", "TensorRT",
    "OpenVINO", "InferenceEngine", "OpenVINO Runtime", "ov::Core",
    "onnxruntime", "Ort::Session", "onnxruntime.InferenceSession",
    "HailoRT", "InferVStreams", "BModel", "bmruntime", "bmrt",
    "CVI_NN", "CVI_TDL", "cvimodel", "AX_ENGINE", "AX_ENGINE_RunSync", "axmodel",
    "hbDNN", "hbDNNInfer", "aclmdl", "aclmdlExecute", "AscendCL", "CANN",
    "cnrtLoadModel", "cnrtInvokeRuntimeContext", "MagicMind", "Cambricon",
    "SNPE", "ncnn", "paddle_lite", "CoreML", "ggml", "llama.cpp", "whisper.cpp"
]

#针对二进制文件扫描的弱AI证据关键词，须结合文件名/路径或附近上下文确认
BINARY_WEAK_AI_KEYWORDS = [
    "NPU", "DPU", "KPU", "DLC", "HEF", "MNN", "NNIE", "ethosu", "Ethos",
    "bmcv", "hbm", "nbg", "TPU", "BPU"
]

#弱关键词上下文提示词
BINARY_WEAK_CONTEXT_HINTS = [
    "model", "models", "infer", "inference", "runtime", "engine", "tensor",
    "network", "neural", "weights", "classifier", "classify", "detect", "detector",
    "vision", "dnn", "cnn", "accelerator", "delegate", "graph", "compiled",
    "quant", "onnx", "tflite", "rknn", "bmodel", "axmodel", "cvimodel"
]

#针对二进制文件扫描的静态嵌入提示词，同时可作为源码/静态集成的辅助证据
BINARY_STATIC_HINT_KEYWORDS = {
    "TFL3", "TensorFlow Lite", "Edge Impulse", "EI_CLASSIFIER", "MicroInterpreter", "TFLM"
}

#针对二进制文件扫描的直接推理API提示词，命中后同时计入direct_api_hits
BINARY_DIRECT_API_KEYWORDS = {
    "rknn_init", "rknn_run", "TfLiteInterpreterInvoke", "Ort::Session",
    "onnxruntime.InferenceSession", "AX_ENGINE_RunSync", "hbDNNInfer",
    "aclmdlExecute", "cnrtInvokeRuntimeContext", "InferVStreams"
}

#源码文件后缀
SOURCE_CODE_EXTS_FOR_CLASSIFY = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".ino",
    ".py", ".rs", ".go", ".java", ".js", ".ts", ".S", ".s", ".asm"
}
#配置文件、文档文件后缀
CONFIG_DOC_EXTS_FOR_CLASSIFY = {
    ".yaml", ".yml", ".json", ".toml", ".xml", ".md", ".txt", ".cfg", ".conf",
    ".ini", ".config", ".service", ".rules", ".desktop", ".proto", ".pbtxt",
    ".names", ".labels", ".launch", ".urdf", ".xacro", ".lua", ".dockerfile"
}
#构建/工程描述文件
BUILD_FILE_NAMES_FOR_CLASSIFY = {"makefile", "cmakelists.txt", "setup.py", "pyproject.toml", "package.json"}
#配置/文档类特殊文件
CONFIG_DOC_NAMES_FOR_CLASSIFY = {
    "license", "readme", "readme.md", "dockerfile", "docker-compose.yml",
    "docker-compose.yaml", "requirements.txt", "model.json", "labels.txt"
}
#源码/静态集成强相关SDK关键词
STATIC_SDK_HINTS_FOR_CLASSIFY = {
    "edge-impulse-sdk", "run_classifier", "ei_run_classifier", "EI_CLASSIFIER",
    "ei_impulse_result_t", "tflite::Micro", "MicroInterpreter", "tensor_arena",
    "TensorFlow Lite", "TfLite", "TFLM", "TFL3"
}
#端侧弱证据关键词
WEAK_LOCAL_KEYWORDS_FOR_CLASSIFY = set(BINARY_WEAK_AI_KEYWORDS) | {"NPU", "DPU", "KPU", "DLC", "HEF", "MNN", "NNIE"}

@dataclass
class Evidence:
    source_files: int = 0
    source_code_files: int = 0
    config_doc_files: int = 0
    license_files: int = 0
    standard_models: List[str] = field(default_factory=list)
    standard_tflite_models: List[str] = field(default_factory=list)
    standard_onnx_models: List[str] = field(default_factory=list)
    standard_other_models: List[str] = field(default_factory=list)
    private_models: List[str] = field(default_factory=list)
    optimized_models: List[str] = field(default_factory=list)
    static_hits: List[str] = field(default_factory=list)
    sdk_hits: Counter = field(default_factory=Counter)
    direct_api_hits: Counter = field(default_factory=Counter)
    service_hits: Counter = field(default_factory=Counter)
    pipeline_hits: Counter = field(default_factory=Counter)
    service_evidence: List[str] = field(default_factory=list)
    pipeline_evidence: List[str] = field(default_factory=list)
    cloud_hits: Counter = field(default_factory=Counter)
    cloud_strong_hits: Counter = field(default_factory=Counter)
    local_evidence: List[str] = field(default_factory=list)
    cloud_evidence: List[str] = field(default_factory=list)
    cloud_evidence_files: List[str] = field(default_factory=list)
    cloud_urls: List[str] = field(default_factory=list)
    binary_hits: List[str] = field(default_factory=list)
    files_scanned: int = 0
    text_files_scanned: int = 0
    bytes_scanned: int = 0

#文件名清洗
def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("_")[:120] or "item"

#生成唯一文件夹标识
def sha1_short(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()[:10]

#确保目录存在
def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

#下载固件文件
def download(url: str, out_path: Path, redownload: bool = False, retries: int = 3) -> Path:
    ensure_dir(out_path.parent)
    if out_path.exists() and out_path.stat().st_size > 0 and not redownload:
        return out_path
    tmp_path = out_path.with_suffix(out_path.suffix + ".part")
    headers = {"User-Agent": USER_AGENT}
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=90) as resp, open(tmp_path, "wb") as f:
                shutil.copyfileobj(resp, f)
            tmp_path.replace(out_path)
            return out_path
        except Exception as e:
            if i + 1 == retries:
                raise RuntimeError(f"download failed: {url}: {e}")
            time.sleep(2 ** i)
    return out_path

#推断文件后缀
def infer_file_ext(url: str) -> str:
    path = urllib.parse.urlparse(url).path.lower()
    for ext in [".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tgz", ".tbz2", ".txz", ".uf2", ".bin", ".hex", ".elf", ".img"]:
        if path.endswith(ext):
            return ext
    if "/archive/" in path or "/zipball/" in path:
        return ".zip"
    return Path(path).suffix or ".bin"

#检查解压路径是否安全
def is_within_directory(base: Path, target: Path) -> bool:
    try:
        base = base.resolve()
        target = target.resolve()
        return str(target).startswith(str(base))
    except Exception:
        return False

#调用系统解压工具
def run_external_extract(cmd: List[str], timeout: int = 900) -> None:
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, timeout=timeout)
    except FileNotFoundError as e:
        raise RuntimeError(f"missing external extractor: {cmd[0]}") from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"extract timeout after {timeout}s: {' '.join(cmd)}") from e
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or b'').decode('utf-8', errors='replace')[:500]
        raise RuntimeError(f"external extractor failed: {' '.join(cmd)}: {msg}") from e


#闭源固件外部解包工具入口
def run_firmware_extract_tools(firmware_path: Path, extract_to: Path, timeout: int = 1800) -> Tuple[bool, List[str]]:
    ensure_dir(extract_to)
    tool_root = extract_to / "_external_extract"
    ensure_dir(tool_root)
    logs: List[str] = []

    def count_files(path: Path) -> int:
        try:
            return sum(1 for p in path.rglob("*") if p.is_file())
        except Exception:
            return 0

    def run_optional_tool(tool_name: str, cmd: List[str], out_dir: Path, tool_timeout: int = timeout) -> bool:
        if not shutil.which(cmd[0]):
            logs.append(f"[missing] {tool_name}: {cmd[0]}")
            return False
        ensure_dir(out_dir)
        before = count_files(out_dir)
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=tool_timeout,
            )
            stdout = (proc.stdout or b"").decode("utf-8", errors="replace")[:500]
            stderr = (proc.stderr or b"").decode("utf-8", errors="replace")[:500]
            after = count_files(out_dir)
            if proc.returncode == 0 and after > before:
                logs.append(f"[ok] {tool_name}: extracted_files={after - before}")
                return True
            logs.append(f"[skip] {tool_name}: returncode={proc.returncode}; stdout={normalize_snippet(stdout)}; stderr={normalize_snippet(stderr)}")
            return False
        except subprocess.TimeoutExpired:
            logs.append(f"[timeout] {tool_name}: timeout={tool_timeout}s")
            return False
        except Exception as e:
            logs.append(f"[error] {tool_name}: {e}")
            return False

    ok = False

    #binwalk递归解包，适合闭源固件镜像中的squashfs/ubi/cpio等嵌入文件系统
    ok = run_optional_tool(
        "binwalk",
        ["binwalk", "-e", "-M", "-C", str(tool_root / "binwalk"), str(firmware_path)],
        tool_root / "binwalk",
    ) or ok

    #p7zip-full提供7z，适合部分自解压/压缩容器和后缀不标准的归档文件
    ok = run_optional_tool(
        "7z",
        ["7z", "x", "-y", f"-o{tool_root / '7z'}", str(firmware_path)],
        tool_root / "7z",
        tool_timeout=900,
    ) or ok

    #squashfs-tools提供unsquashfs，适合输入本身就是squashfs镜像的情况
    ok = run_optional_tool(
        "unsquashfs",
        ["unsquashfs", "-f", "-d", str(tool_root / "unsquashfs"), str(firmware_path)],
        tool_root / "unsquashfs",
        tool_timeout=900,
    ) or ok

    #unzip/tar用于处理后缀不标准但实际是zip/tar的固件包
    ok = run_optional_tool(
        "unzip",
        ["unzip", "-q", str(firmware_path), "-d", str(tool_root / "unzip")],
        tool_root / "unzip",
        tool_timeout=900,
    ) or ok
    ok = run_optional_tool(
        "tar",
        ["tar", "-xf", str(firmware_path), "-C", str(tool_root / "tar")],
        tool_root / "tar",
        tool_timeout=900,
    ) or ok

    if shutil.which("readelf"):
        logs.append("[available] readelf: used later for ELF dependency/symbol evidence")
    else:
        logs.append("[missing] readelf: install binutils to enable ELF dependency/symbol evidence")

    return ok, logs

def run_nested_firmware_extract_tools(root: Path, timeout: int = 1800) -> None:
    nested_exts = {".bin", ".img", ".upg", ".pak", ".paks"}
    candidates = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        parts = set(path.relative_to(root).parts)
        if "_external_extract" in parts or "_nested_extract" in parts:
            continue
        if path.suffix.lower() in nested_exts:
            candidates.append(path)

    if not candidates:
        return

    all_logs: List[str] = []
    nested_root = root / "_nested_extract"
    ensure_dir(nested_root)

    for firmware_path in candidates:
        rpath = rel(firmware_path, root)
        out_dir = nested_root / safe_name(rpath)
        ok, logs = run_firmware_extract_tools(firmware_path, out_dir, timeout=timeout)
        all_logs.append(f"[{rpath}] ok={ok}")
        all_logs.extend(logs)

    (root / ".nested_extract_log.txt").write_text("\n".join(all_logs), encoding="utf-8")

#解压下载好的固件包
def extract_archive(archive_path: Path, extract_to: Path, reextract: bool = False, use_binwalk: bool = False) -> Path:
    ensure_dir(extract_to.parent)
    marker = extract_to / ".extracted_ok"
    if marker.exists() and not reextract:
        return extract_to
    if extract_to.exists():
        shutil.rmtree(extract_to)
    ensure_dir(extract_to)

    lower = archive_path.name.lower()
    try:
        if lower.endswith(".zip"):
            try:
                with zipfile.ZipFile(archive_path) as zf:
                    for member in zf.infolist():
                        target = extract_to / member.filename
                        if not is_within_directory(extract_to, target):
                            continue
                        zf.extract(member, extract_to)
            except Exception as py_zip_error:
                if shutil.which("unzip"):
                    run_external_extract(["unzip", "-q", str(archive_path), "-d", str(extract_to)])
                elif shutil.which("7z"):
                    run_external_extract(["7z", "x", "-y", f"-o{extract_to}", str(archive_path)])
                else:
                    raise RuntimeError(f"python zip extract failed ({py_zip_error}); install unzip or p7zip-full")
            if use_binwalk:
                run_nested_firmware_extract_tools(extract_to)
        elif lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
            try:
                with tarfile.open(archive_path) as tf:
                    for member in tf.getmembers():
                        target = extract_to / member.name
                        if not is_within_directory(extract_to, target):
                            continue
                        tf.extract(member, extract_to)
            except Exception as py_tar_error:
                if shutil.which("tar"):
                    run_external_extract(["tar", "-xf", str(archive_path), "-C", str(extract_to)])
                else:
                    raise RuntimeError(f"python tar extract failed ({py_tar_error}); install tar")
        else:
            #非zip/tar固件在启用--binwalk时尝试外部工具解包
            if use_binwalk:
                ok, logs = run_firmware_extract_tools(archive_path, extract_to)
                shutil.copy2(archive_path, extract_to / archive_path.name)
                (extract_to / ".external_extract_log.txt").write_text("\n".join(logs), encoding="utf-8")
                if not ok:
                    (extract_to / ".external_extract_failed.txt").write_text("no external extractor produced files; original firmware kept for binary scan", encoding="utf-8")
            else:
                shutil.copy2(archive_path, extract_to / archive_path.name)
    except Exception as e:
        raise RuntimeError(f"extract failed: {archive_path}: {e}")
    marker.write_text("ok", encoding="utf-8")
    return extract_to

#遍历解压目录中的文件
def iter_files(root: Path) -> Iterable[Path]:
    #跳过无关目录
    skip_dirs = {".git", ".svn", ".hg", "node_modules", ".venv", "venv", "__pycache__", ".pio", "build", "dist"}
    for cur, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
        for name in files:
            p = Path(cur) / name
            if p.is_file():
                yield p

#读取文本文件样本
def read_text_sample(path: Path) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_TEXT_BYTES)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""

#读取二进制文件样本
def read_binary_sample(path: Path) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(MAX_BINARY_BYTES)
    except Exception:
        return b""

#生成相对路径作为证据路径
def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)

#控制证据链长度
def add_if_limited(items: List[str], value: str, limit: int = 30) -> None:
    if len(items) < limit and value not in items:
        items.append(value)

#整理证据片段
def normalize_snippet(text: str, limit: int = 180) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    if len(text) > limit:
        return text[:limit - 3] + "..."
    return text

#截取关键词附近的上下文
def keyword_snippet(text: str, keyword: str, span: int = 80) -> str:
    lower_text = text.lower()
    idx = lower_text.find(keyword.lower())
    if idx < 0:
        return ""
    start = max(0, idx - span)
    end = min(len(text), idx + len(keyword) + span)
    return normalize_snippet(text[start:end])

#截取正则匹配附近的上下文
def match_snippet(text: str, match: re.Match, span: int = 80) -> str:
    start = max(0, match.start() - span)
    end = min(len(text), match.end() + span)
    return normalize_snippet(text[start:end])

#统一格式添加证据
def add_evidence(items: List[str], kind: str, rpath: str, detail: str = "", limit: int = 40) -> None:
    value = f"{kind}@{rpath}"
    if detail:
        value += f" :: {normalize_snippet(detail)}"
    add_if_limited(items, value, limit=limit)

#添加端侧证据
def add_local_evidence(ev: Evidence, kind: str, rpath: str, detail: str = "") -> None:
    add_evidence(ev.local_evidence, kind, rpath, detail, limit=50)

#添加云端证据，云端易误判，故同时记录证据文件路径
def add_cloud_evidence(ev: Evidence, kind: str, rpath: str, detail: str = "") -> None:
    add_if_limited(ev.cloud_evidence_files, rpath, limit=50)
    add_evidence(ev.cloud_evidence, kind, rpath, detail, limit=50)

#添加服务化部署证据
def add_service_evidence(ev: Evidence, kind: str, rpath: str, detail: str = "") -> None:
    add_evidence(ev.service_evidence, kind, rpath, detail, limit=50)

#添加管线型证据
def add_pipeline_evidence(ev: Evidence, kind: str, rpath: str, detail: str = "") -> None:
    add_evidence(ev.pipeline_evidence, kind, rpath, detail, limit=50)

#记录标准模型文件，并区分子类型
def add_standard_model_file(ev: Evidence, rpath: str, suffix: str, evidence_kind: str = "standard_model_file") -> None:
    suffix = (suffix or "").lower()
    add_if_limited(ev.standard_models, rpath)
    if suffix == ".tflite":
        add_if_limited(ev.standard_tflite_models, rpath)
        subtype = "tflite"
    elif suffix == ".onnx":
        add_if_limited(ev.standard_onnx_models, rpath)
        subtype = "onnx"
    else:
        add_if_limited(ev.standard_other_models, rpath)
        subtype = "other"
    add_local_evidence(ev, evidence_kind, rpath, f"{suffix or 'unknown'}; subtype={subtype}")

#过滤本地地址，避免把本地服务误判成云端服务
def is_remote_url(url_value: str) -> bool:
    try:
        host = urllib.parse.urlparse(url_value).hostname or ""
    except Exception:
        return True
    host = host.lower()
    if not host:
        return True
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return False
    if host.startswith("127.") or host.startswith("10.") or host.startswith("192.168."):
        return False
    if re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", host):
        return False
    return True

#计算端侧证据分数
def local_score(ev: Evidence) -> int:
    score = len(ev.standard_models) + len(ev.private_models) + len(ev.optimized_models)
    score += static_source_hit_score(ev)
    strong_keywords = set(BINARY_STRONG_AI_KEYWORDS) | set(STATIC_SDK_HINTS_FOR_CLASSIFY)
    for item in ev.local_evidence:
        head, detail = item, ""
        if " :: " in item:
            head, detail = item.split(" :: ", 1)
        if "@" not in head:
            continue
        kind, rpath = head.split("@", 1)
        suffix = Path(rpath).suffix.lower()
        name = Path(rpath).name.lower()
        is_source_code = suffix in SOURCE_CODE_EXTS_FOR_CLASSIFY or name in BUILD_FILE_NAMES_FOR_CLASSIFY
        is_binary_or_model = (
            suffix in STANDARD_MODEL_EXTS
            or suffix in PRIVATE_MODEL_EXTS
            or suffix in OPTIMIZED_MODEL_EXTS
            or suffix in {".bin", ".uf2", ".elf", ".so", ".a", ".ko", ".tflite", ".onnx", ".pb"}
        )
        if not (is_source_code or is_binary_or_model):
            continue
        if kind in {"local_inference_api_keyword", "binary_ai_string_strong", "readelf_ai_symbol_or_needed", "binary_model_magic", "binary_model_verify"}:
            score += 1
            continue
        if kind == "edge_ai_sdk_keyword":
            detail_lower = detail.lower()
            has_strong_keyword = any(kw.lower() in detail_lower for kw in strong_keywords)
            has_weak_keyword = any(kw.lower() in detail_lower for kw in WEAK_LOCAL_KEYWORDS_FOR_CLASSIFY)
            if has_strong_keyword and not has_weak_keyword:
                score += 1

    return score

#计算强云端证据分数（强云端关键词+AI远程接口URL）
def strong_cloud_score(ev: Evidence) -> int:
    strong = sum(ev.cloud_strong_hits.values())
    strong += len(ev.cloud_urls)
    return strong

def static_source_hit_score(ev: Evidence) -> int:
    score = 0
    for rpath in ev.static_hits:
        suffix = Path(rpath).suffix.lower()
        if suffix in SOURCE_CODE_EXTS_FOR_CLASSIFY:
            score += 1
    return score

#统计源码或固件二进制中的静态集成强线索
def static_integration_score(ev: Evidence) -> int:
    score = static_source_hit_score(ev)
    static_keywords = set(STATIC_SDK_HINTS_FOR_CLASSIFY)
    for item in ev.local_evidence:
        head, detail = item, ""
        if " :: " in item:
            head, detail = item.split(" :: ", 1)
        if "@" not in head:
            continue
        kind, rpath = head.split("@", 1)
        suffix = Path(rpath).suffix.lower()
        name = Path(rpath).name.lower()
        is_source_code = suffix in SOURCE_CODE_EXTS_FOR_CLASSIFY or name in BUILD_FILE_NAMES_FOR_CLASSIFY
        is_firmware_binary = suffix in {".bin", ".uf2", ".elf", ".hex"}
        if not (is_source_code or is_firmware_binary):
            continue
        if kind in {"edge_ai_sdk_keyword", "binary_ai_string_strong", "static_model_pattern"}:
            detail_lower = detail.lower()
            if any(kw.lower() in detail_lower for kw in static_keywords):
                score += 1
    return score


#按块读取二进制文件
def iter_binary_chunks(path: Path,
                       chunk_size: int = BINARY_CHUNK_BYTES,
                       overlap: int = BINARY_CHUNK_OVERLAP,
                       max_bytes: int = MAX_BINARY_SCAN_BYTES) -> Iterable[Tuple[bytes, int]]:
    if chunk_size <= 0:
        return
    overlap = max(0, min(overlap, chunk_size // 2))
    scanned = 0
    tail = b""
    try:
        with open(path, "rb") as f:
            while scanned < max_bytes:
                to_read = min(chunk_size, max_bytes - scanned)
                raw = f.read(to_read)
                if not raw:
                    break
                scanned += len(raw)
                data = tail + raw if tail else raw
                yield data, len(raw)
                tail = data[-overlap:] if overlap else b""
                if len(raw) < to_read:
                    break
    except Exception:
        return

#提取连续可打印ASCII字符串
def extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    try:
        pattern = rb"[ -~]{%d,}" % max(1, min_len)
        return [s.decode("ascii", errors="ignore") for s in re.findall(pattern, data)]
    except Exception:
        return []

#短关键词必须在路径或附近上下文中出现模型/推理相关提示词才计入
def binary_keyword_has_context(text: str, keyword: str, rpath: str, span: int = 120) -> bool:
    lower_path = (rpath or "").lower()
    if any(h in lower_path for h in BINARY_WEAK_CONTEXT_HINTS):
        return True
    lower_text = (text or "").lower()
    lower_keyword = keyword.lower()
    idx = lower_text.find(lower_keyword)
    if idx < 0:
        return False
    start = max(0, idx - span)
    end = min(len(lower_text), idx + len(lower_keyword) + span)
    context = lower_text[start:end]
    return any(h in context for h in BINARY_WEAK_CONTEXT_HINTS)

#记录二进制文件中的AI字符串证据
def add_binary_ai_keyword(ev: Evidence, keyword: str, rpath: str, evidence_kind: str, detail: str = "") -> None:
    ev.sdk_hits[keyword] += 1
    if keyword in BINARY_DIRECT_API_KEYWORDS:
        ev.direct_api_hits[keyword] += 1
    evidence_detail = f"{keyword}: {detail}" if detail else keyword
    add_local_evidence(ev, evidence_kind, rpath, evidence_detail)
    if keyword in BINARY_STATIC_HINT_KEYWORDS:
        add_if_limited(ev.static_hits, rpath)

#检查.tflite文件内是否包含TFL3标识
def has_tflite_magic(data: bytes) -> bool:
    if len(data) < 8:
        return False
    if data[4:8] == b"TFL3":
        return True
    idx = data[:8192].find(b"TFL3")
    if idx < 0:
        return False
    return idx >= 4

#判断文件是否符合UF2固件文件的magic
def has_uf2_magic(data: bytes) -> bool:
    return len(data) >= 8 and data[:4] == b"UF2\n" and data[4:8] == b"WQ]\x9e"

#判断文件是否ELF格式
def has_elf_magic(data: bytes) -> bool:
    return data.startswith(b"\x7fELF")

#验证.onnx文件是否真的可以被ONNX库加载
def verify_onnx_model_file(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_ONNX_VERIFY_BYTES:
            return ""
    except Exception:
        return ""
    try:
        import onnx
    except Exception:
        return ""
    try:
        model = onnx.load_model(str(path), load_external_data=False)
        #检查ONNX模型结构是否合法
        onnx.checker.check_model(model)
        graph_name = getattr(model.graph, "name", "") or "unnamed_graph"
        node_count = len(getattr(model.graph, "node", []))
        input_count = len(getattr(model.graph, "input", []))
        output_count = len(getattr(model.graph, "output", []))

        return (
            f"onnx_check_ok; "
            f"ir_version={getattr(model, 'ir_version', 'unknown')}; "
            f"graph={graph_name}; "
            f"nodes={node_count}; "
            f"inputs={input_count}; "
            f"outputs={output_count}"
        )
    except Exception:
        return ""

#使用readelf提取ELF动态依赖和符号表中的AI相关线索
def collect_readelf_ai_evidence(path: Path, limit: int = 8) -> List[Tuple[str, str]]:
    if not shutil.which("readelf"):
        return []
    results: List[Tuple[str, str]] = []
    commands = [
        ["readelf", "-d", str(path)],
        ["readelf", "-Ws", str(path)],
    ]
    strong_keywords = BINARY_STRONG_AI_KEYWORDS + DIRECT_API_PATTERNS
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=30)
            output = proc.stdout.decode("utf-8", errors="ignore")
        except Exception:
            continue
        for line in output.splitlines():
            lower_line = line.lower()
            #强关键词扫描
            for kw in strong_keywords:
                if kw.lower() in lower_line:
                    results.append((kw, normalize_snippet(line)))
                    break
            else:
                #弱关键词须满足上下文提示词
                for kw in BINARY_WEAK_AI_KEYWORDS:
                    if kw.lower() in lower_line and any(h in lower_line or h in str(path).lower() for h in BINARY_WEAK_CONTEXT_HINTS):
                        results.append((kw, normalize_snippet(line)))
                        break
            if len(results) >= limit:
                return results
    return results

#二进制文件扫描入口，对常见模型/固件二进制做基础格式验证，并补充结构化证据
def add_binary_format_evidence(ev: Evidence, path: Path, rpath: str, suffix: str, first_chunk: bytes,
                               recorded_keywords: Set[str]) -> None:
    if suffix == ".tflite" and has_tflite_magic(first_chunk):
        add_local_evidence(ev, "binary_model_magic", rpath, "tflite_flatbuffer_magic=TFL3")
        if "tfl3" not in recorded_keywords:
            add_binary_ai_keyword(ev, "TFL3", rpath, "binary_ai_string_strong", "tflite_flatbuffer_magic=TFL3")
            recorded_keywords.add("tfl3")
    if suffix == ".onnx":
        detail = verify_onnx_model_file(path)
        if detail:
            add_local_evidence(ev, "binary_model_verify", rpath, detail)
            if "onnx" not in recorded_keywords:
                add_binary_ai_keyword(ev, "ONNX", rpath, "binary_ai_string_strong", detail)
                recorded_keywords.add("onnx")
    if suffix == ".uf2" and has_uf2_magic(first_chunk):
        add_local_evidence(ev, "binary_container_magic", rpath, "uf2_block_magic=UF2")
    if suffix in {".elf", ".so", ".ko"} and has_elf_magic(first_chunk):
        add_local_evidence(ev, "binary_container_magic", rpath, "elf_magic=ELF")
        for kw, detail in collect_readelf_ai_evidence(path):
            key = kw.lower()
            if key not in recorded_keywords:
                add_binary_ai_keyword(ev, kw, rpath, "readelf_ai_symbol_or_needed", detail)
                recorded_keywords.add(key)

#生成部署判定证据摘要文本
def build_deployment_evidence_summary(ev: Evidence, deployment: str) -> str:
    local = local_score(ev)
    cloud = strong_cloud_score(ev)
    parts = [f"判定={deployment}", f"local_score={local}", f"strong_cloud_score={cloud}"]
    if ev.standard_models:
        subtype_parts = []
        if ev.standard_tflite_models:
            subtype_parts.append(f"tflite={len(ev.standard_tflite_models)}")
        if ev.standard_onnx_models:
            subtype_parts.append(f"onnx={len(ev.standard_onnx_models)}")
        if ev.standard_other_models:
            subtype_parts.append(f"other={len(ev.standard_other_models)}")
        subtype_text = f" ({', '.join(subtype_parts)})" if subtype_parts else ""
        parts.append(f"标准模型文件={len(ev.standard_models)}{subtype_text}")
    if ev.private_models:
        parts.append(f"私有模型文件={len(ev.private_models)}")
    if ev.optimized_models:
        parts.append(f"编译/优化模型二进制={len(ev.optimized_models)}")
    if ev.static_hits:
        parts.append(f"源码/静态模型证据文件={len(ev.static_hits)}")
    if ev.sdk_hits:
        parts.append(f"端侧SDK关键词={top_counter(ev.sdk_hits, 5)}")
    if ev.direct_api_hits:
        parts.append(f"本地推理API关键词={top_counter(ev.direct_api_hits, 5)}")
    if ev.cloud_strong_hits:
        parts.append(f"云端强证据关键词={top_counter(ev.cloud_strong_hits, 5)}")
    if ev.cloud_urls:
        parts.append(f"AI远程URL={len(ev.cloud_urls)}")
    return " | ".join(parts)

#主扫描函数
def scan_tree(root: Path, url: str = "") -> Evidence:
    ev = Evidence()
    for path in iter_files(root):
        ev.files_scanned += 1
        suffix = path.suffix.lower()
        name = path.name.lower()
        rpath = rel(path, root)
        #统计源码/配置/文本类文件数量
        if suffix in SOURCE_EXTS or name in {
            "makefile", "cmakelists.txt", "license", "readme", "readme.md",
            "dockerfile", "docker-compose.yml", "docker-compose.yaml", "requirements.txt",
            "setup.py", "pyproject.toml", "package.json", "model.json", "labels.txt"
        }:
            ev.source_files += 1
            if suffix in SOURCE_CODE_EXTS_FOR_CLASSIFY or name in BUILD_FILE_NAMES_FOR_CLASSIFY:
                ev.source_code_files += 1
            elif suffix in CONFIG_DOC_EXTS_FOR_CLASSIFY or name in CONFIG_DOC_NAMES_FOR_CLASSIFY:
                ev.config_doc_files += 1
        #识别license文件，判断开源项目
        if name.startswith("license") or name in {"copying", "notice"}:
            ev.license_files += 1
        #识别标准模型文件
        if suffix in STANDARD_MODEL_EXTS:
            add_standard_model_file(ev, rpath, suffix, "standard_model_file")
        #识别OpenVINO IR模型
        if suffix == ".xml" and any(h in rpath.lower() for h in ("openvino", "ir_model", "model.xml", "network.xml")):
            add_standard_model_file(ev, rpath, suffix, "standard_model_file_openvino_ir")
        #识别厂商私有模型文件，后缀直接命中或普通后缀满足文件名提示词
        if suffix in PRIVATE_MODEL_EXTS or any(h in name for h in PRIVATE_NAME_HINTS) and suffix in {".bin", ".dat", ".model"}:
            add_if_limited(ev.private_models, rpath)
            add_local_evidence(ev, "private_model_file", rpath, suffix)
        #识别编译优化模型或二进制模型
        if suffix in OPTIMIZED_MODEL_EXTS:
            #明确的优化模型后缀
            if suffix in {".engine", ".plan", ".trt", ".etlt", ".uff", ".xclbin", ".uf2", ".elf", ".hex", ".compiled"}:
                add_if_limited(ev.optimized_models, rpath)
                add_local_evidence(ev, "optimized_binary_model", rpath, suffix)
            #普通二进制后缀，但文件名有AI编译提示词
            elif suffix in {".so", ".a", ".ko", ".bin"} and any(h in name or h in rpath.lower() for h in OPT_NAME_HINTS):
                add_if_limited(ev.optimized_models, rpath)
                add_local_evidence(ev, "optimized_binary_model", rpath, suffix)
            #普通库文件只作为binary线索
            elif suffix in {".so", ".a", ".ko"}:
                add_if_limited(ev.binary_hits, rpath)
        #判断是否可按文本方式读取
        should_read_text = suffix in SOURCE_EXTS or name in {"makefile", "cmakelists.txt", "readme", "readme.md", "license"}
        if should_read_text:
            text = read_text_sample(path)
            ev.text_files_scanned += 1
            ev.bytes_scanned += len(text)
            if text:
                #在文本里识别静态模型模式
                for pat in STATIC_MODEL_PATTERNS:
                    m = pat.search(text)
                    if m:
                        add_if_limited(ev.static_hits, rpath)
                        add_local_evidence(ev, "static_model_pattern", rpath, match_snippet(text, m))
                        break
                lower_text = text.lower()
                #在文本里扫描AI SDK关键词
                for kw in EDGE_AI_SDK_PATTERNS:
                    if kw.lower() in lower_text:
                        ev.sdk_hits[kw] += 1
                        add_local_evidence(ev, "edge_ai_sdk_keyword", rpath, f"{kw}: {keyword_snippet(text, kw)}")
                #扫描直接推理API关键词
                for kw in DIRECT_API_PATTERNS:
                    if kw.lower() in lower_text:
                        ev.direct_api_hits[kw] += 1
                        add_local_evidence(ev, "local_inference_api_keyword", rpath, f"{kw}: {keyword_snippet(text, kw)}")
                #扫描服务化部署关键词
                for kw in SERVICE_PATTERNS:
                    if kw.lower() in lower_text:
                        ev.service_hits[kw] += 1
                        add_service_evidence(ev, "service_keyword", rpath, f"{kw}: {keyword_snippet(text, kw)}")
                #扫描管线型关键词
                for kw in PIPELINE_PATTERNS:
                    if kw.lower() in lower_text:
                        ev.pipeline_hits[kw] += 1
                        add_pipeline_evidence(ev, "pipeline_keyword", rpath, f"{kw}: {keyword_snippet(text, kw)}")
                #扫描普通云端关键词
                for kw in CLOUD_PATTERNS:
                    if kw.lower() in lower_text:
                        ev.cloud_hits[kw] += 1
                #扫描强云端关键词
                for kw in CLOUD_STRONG_PATTERNS:
                    if kw.lower() in lower_text:
                        ev.cloud_strong_hits[kw] += 1
                        add_cloud_evidence(ev, "cloud_keyword", rpath, f"{kw}: {keyword_snippet(text, kw)}")
                #识别疑似AI远程URL
                for m in URL_RE.finditer(text):
                    url_value = m.group(0).rstrip(".,;:!?")
                    if CLOUD_AI_ENDPOINT_RE.match(url_value) and is_remote_url(url_value):
                        add_if_limited(ev.cloud_urls, url_value, limit=30)
                        ev.cloud_strong_hits["ai_endpoint_url"] += 1
                        add_cloud_evidence(ev, "ai_endpoint_url", rpath, match_snippet(text, m))
        #读取二进制文件
        elif (
            suffix in {".bin", ".uf2", ".elf", ".so", ".a", ".ko", ".tflite", ".onnx", ".pb"}
            or suffix in STANDARD_MODEL_EXTS
            or suffix in PRIVATE_MODEL_EXTS
            or suffix in OPTIMIZED_MODEL_EXTS
        ):
            binary_bytes_scanned = 0
            binary_recorded_keywords: Set[str] = set()
            binary_recorded_cloud_keywords: Set[str] = set()
            binary_recorded_urls: Set[str] = set()
            first_binary_chunk = True
            for data, raw_len in iter_binary_chunks(path):
                binary_bytes_scanned += raw_len
                if not data:
                    continue
                if first_binary_chunk:
                    add_binary_format_evidence(ev, path, rpath, suffix, data, binary_recorded_keywords)
                    first_binary_chunk = False
                ascii_items = extract_ascii_strings(data, min_len=4)
                if not ascii_items:
                    continue
                strings = "\n".join(ascii_items)
                lower_strings = strings.lower()
                #扫描二进制强AI证据关键词
                for kw in BINARY_STRONG_AI_KEYWORDS:
                    key = kw.lower()
                    if key in lower_strings and key not in binary_recorded_keywords:
                        add_binary_ai_keyword(ev, kw, rpath, "binary_ai_string_strong", keyword_snippet(strings, kw))
                        binary_recorded_keywords.add(key)
                #扫描二进制弱AI证据关键词，短词必须结合文件名/路径或附近上下文
                for kw in BINARY_WEAK_AI_KEYWORDS:
                    key = kw.lower()
                    if key in lower_strings and key not in binary_recorded_keywords and binary_keyword_has_context(strings, kw, rpath):
                        add_binary_ai_keyword(ev, kw, rpath, "binary_ai_string_weak_context", keyword_snippet(strings, kw))
                        binary_recorded_keywords.add(key)
                #扫描强云端关键词
                for kw in CLOUD_STRONG_PATTERNS:
                    key = kw.lower()
                    if key in lower_strings and key not in binary_recorded_cloud_keywords:
                        ev.cloud_hits[kw] += 1
                        ev.cloud_strong_hits[kw] += 1
                        add_cloud_evidence(ev, "binary_cloud_string", rpath, f"{kw}: {keyword_snippet(strings, kw)}")
                        binary_recorded_cloud_keywords.add(key)
                #识别疑似AI远程URL
                for m in URL_RE.finditer(strings):
                    url_value = m.group(0).rstrip(".,;:!?")
                    if url_value in binary_recorded_urls:
                        continue
                    if CLOUD_AI_ENDPOINT_RE.match(url_value) and is_remote_url(url_value):
                        add_if_limited(ev.cloud_urls, url_value, limit=30)
                        ev.cloud_hits["http(s)_ai_endpoint"] += 1
                        ev.cloud_strong_hits["ai_endpoint_url"] += 1
                        add_cloud_evidence(ev, "binary_ai_endpoint_url", rpath, match_snippet(strings, m))
                        binary_recorded_urls.add(url_value)
            ev.bytes_scanned += binary_bytes_scanned
    return ev

#判断开源/闭源
def classify_source_visibility(ev: Evidence, url: str) -> str:
    host = urllib.parse.urlparse(url).netloc.lower()
    if "github.com" in host or "gitlab" in host or "gitee" in host and ev.license_files >=0:
        return "开源"
    if ev.license_files > 0 and ev.source_code_files >= 3:
        return "开源"
    if ev.source_code_files >= 5 and ev.source_code_files >= ev.config_doc_files:
        return "开源"
    if ev.source_code_files >= 10:
        return "开源"
    return "闭源"

#判断端侧/云端/混合
def classify_deployment(ev: Evidence) -> str:
    l_score = local_score(ev)
    cloud_score = sum(ev.cloud_hits.values())
    s_cloud = strong_cloud_score(ev)
    if l_score > 0 and s_cloud > 0:
        return "混合"
    if l_score > 0:
        return "端侧"
    if s_cloud > 0 or (cloud_score >= 10 and l_score == 0):
        return "云端"
    return "未知"

#判断模型存储方式
def classify_model_storage(ev: Evidence) -> str:
    cats: List[str] = []
    no_independent_or_binary_model = not ev.standard_models and not ev.private_models and not ev.optimized_models
    if static_source_hit_score(ev) > 0 or (no_independent_or_binary_model and static_integration_score(ev) >= 2):
        cats.append("源码/静态集成")
    if ev.standard_tflite_models:
        cats.append("独立模型文件.tflite")
    if ev.standard_onnx_models:
        cats.append("独立模型文件.onnx")
    if ev.standard_other_models:
        cats.append("其他独立模型文件")
    if ev.private_models:
        cats.append("芯片厂商私有格式")
    if ev.optimized_models:
        cats.append("编译优化二进制")
    if not cats:
        return "未发现明显模型"

    order = [
        "源码/静态集成",
        "独立模型文件.tflite",
        "独立模型文件.onnx",
        "其他独立模型文件",
        "芯片厂商私有格式",
        "编译优化二进制",
    ]
    cats = [c for c in order if c in cats]
    return "+".join(cats)

#判断模型使用方式
def classify_usage(ev: Evidence, storage: str) -> str:
    sdk_score = sum(ev.sdk_hits.values())
    direct_score = sum(ev.direct_api_hits.values())
    service_score = sum(ev.service_hits.values())
    pipeline_score = sum(ev.pipeline_hits.values())

    labels = []
    if sdk_score > 0:
        labels.append("SDK调用")
    if direct_score > 0 and sdk_score == 0:
        labels.append("直接API调用")
    elif direct_score > 0 and sdk_score > 0 and direct_score > sdk_score * 2:
        labels.append("直接API调用")
    if service_score >= 3:
        labels.append("独立服务代理")
    if pipeline_score >= 2:
        labels.append("数据流/管线型")
    if not labels and "源码/静态集成" in storage:
        labels.append("静态嵌入")
    if not labels:
        labels.append("未知")
    if len(labels) == 1:
        return labels[0]
    return "+".join(dict.fromkeys(labels))


def top_counter(counter: Counter, n: int = 10) -> str:
    return "; ".join([f"{k}:{v}" for k, v in counter.most_common(n)])

#分析单个固件样本
def analyze_one(row: Dict[str, str], download_dir: Path, extract_dir: Path, redownload: bool, reextract: bool, use_binwalk: bool = False) -> Tuple[Dict[str, str], Dict[str, str]]:
    model = row.get("Model", "").strip()
    version = row.get("Version", "").strip()
    url = row.get("DownloadLink", "").strip()
    if not model or not version or not url:
        raise ValueError(f"missing Model/Version/DownloadLink: {row}")

    ext = infer_file_ext(url)
    key = f"{safe_name(model)}__{safe_name(version)}__{sha1_short(url)}"
    archive_path = download_dir / f"{key}{ext}"
    extracted_path = extract_dir / key
    download(url, archive_path, redownload=redownload)
    extract_archive(archive_path, extracted_path, reextract=reextract, use_binwalk=use_binwalk)
    ev = scan_tree(extracted_path, url=url)

    source_visibility = classify_source_visibility(ev, url)
    deployment = classify_deployment(ev)
    model_storage = classify_model_storage(ev)
    usage = classify_usage(ev, model_storage)

    summary = {
        "source_visibility": source_visibility,
        "deployment": deployment,
        "model_storage": model_storage,
        "usage": usage,
        "Model": model,
        "Version": version,
    }

    details = {
        **summary,
        "DownloadLink": url,
        "local_path": str(extracted_path),
        "files_scanned": str(ev.files_scanned),
        "source_files": str(ev.source_files),
        "standard_model_files": "; ".join(ev.standard_models),
        "standard_tflite_model_files": "; ".join(ev.standard_tflite_models),
        "standard_onnx_model_files": "; ".join(ev.standard_onnx_models),
        "standard_other_model_files": "; ".join(ev.standard_other_models),
        "private_model_files": "; ".join(ev.private_models),
        "optimized_model_files": "; ".join(ev.optimized_models),
        "deployment_evidence_summary": build_deployment_evidence_summary(ev, deployment),
        "local_deployment_evidence": "; ".join(ev.local_evidence),
        "static_evidence_files": "; ".join(ev.static_hits),
        "sdk_keywords": top_counter(ev.sdk_hits),
        "direct_api_keywords": top_counter(ev.direct_api_hits),
        "service_keywords": top_counter(ev.service_hits),
        "service_evidence": "; ".join(ev.service_evidence),
        "pipeline_keywords": top_counter(ev.pipeline_hits),
        "pipeline_evidence": "; ".join(ev.pipeline_evidence),
        "cloud_keywords": top_counter(ev.cloud_hits),
        "cloud_strong_keywords": top_counter(ev.cloud_strong_hits),
        "cloud_evidence_files": "; ".join(ev.cloud_evidence_files),
        "cloud_deployment_evidence": "; ".join(ev.cloud_evidence),
        "cloud_ai_endpoint_urls": "; ".join(ev.cloud_urls),
        "binary_files": "; ".join(ev.binary_hits[:30]),
    }
    return summary, details


#===批量调度、结果处理、统计输出类工具函数===

def read_targets(path: Path) -> List[Dict[str, str]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"Model", "Version", "DownloadLink"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"input CSV missing columns: {sorted(missing)}")
        return list(reader)


def write_csv(path: Path, rows: List[Dict[str, str]], fieldnames: List[str]) -> None:
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

#每分析完一个样本，清理下载和解压文件
def cleanup_artifacts(row: Dict[str, str], download_dir: Path, extract_dir: Path) -> None:
    model = row.get("Model", "").strip()
    version = row.get("Version", "").strip()
    url = row.get("DownloadLink", "").strip()
    if not model or not version or not url:
        return
    key = f"{safe_name(model)}__{safe_name(version)}__{sha1_short(url)}"
    for path in download_dir.glob(f"{key}*"):
        try:
            if path.is_file() or path.is_symlink():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)
        except Exception:
            pass
    extracted_path = extract_dir / key
    try:
        if extracted_path.exists():
            shutil.rmtree(extracted_path)
    except Exception:
        pass

#读取已经完成的样本，用于断点续跑
def load_done_keys(path: Path) -> Set[Tuple[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return set()
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            return {(r.get("Model", ""), r.get("Version", "")) for r in reader if r.get("Model") and r.get("Version")}
    except Exception:
        return set()

def append_csv_row(path: Path, row: Dict[str, str], fieldnames: List[str], write_header: bool = False) -> None:
    ensure_dir(path.parent if str(path.parent) != "." else Path(".."))
    mode = "a"
    with open(path, mode, encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        writer.writerow(row)
        f.flush()

def split_multi_label(value: str) -> List[str]:
    value = (value or "").strip()
    if not value:
        return ["空"]
    parts = [p.strip() for p in value.split("+") if p.strip()]
    return parts or [value]

def normalize_stat_label(value: str, default: str = "未知") -> str:
    value = (value or "").strip()
    return value or default

def parse_date_key(value: str) -> Optional[Tuple[int, int, int]]:
    value = (value or "").strip()
    if not value:
        return None
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%Y%m%d"):
        try:
            d = datetime.strptime(value[:10] if fmt != "%Y%m%d" else value[:8], fmt)
            return (d.year, d.month, d.day)
        except Exception:
            pass
    m = re.search(r"(20\d{2}|19\d{2})[-_/\.](\d{1,2})[-_/\.](\d{1,2})", value)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def parse_version_key(value: str) -> Optional[Tuple[Tuple[int, Any], ...]]:
    value = (value or "").strip().lower()
    if not value:
        return None
    if re.fullmatch(r"[0-9a-f]{7,40}", value):
        return None
    tokens = re.findall(r"\d+|[a-z]+", value)
    if not any(t.isdigit() for t in tokens):
        return None
    key = []
    for tok in tokens:
        if tok.isdigit():
            key.append((1, int(tok)))
        else:
            key.append((0, tok))
    return tuple(key)


def latest_row_key(row: Dict[str, str], index: int) -> Tuple[int, Any, int, Any, int]:
    date_key = parse_date_key(row.get("Date", ""))
    version_key = parse_version_key(row.get("Version", ""))
    return (1 if date_key is not None else 0, date_key or (0, 0, 0),
            1 if version_key is not None else 0, version_key or tuple(), -index)


def select_latest_rows_by_model(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    latest: Dict[str, Tuple[Tuple[int, Any, int, Any, int], Dict[str, str]]] = {}
    for idx, row in enumerate(rows):
        model = (row.get("Model", "") or "").strip()
        if not model:
            model = f"__missing_model__{idx}"
        key = latest_row_key(row, idx)
        if model not in latest or key > latest[model][0]:
            latest[model] = (key, row)
    return [item[1] for item in latest.values()]

def compute_stats_from_rows(rows: List[Dict[str, str]]) -> Dict[str, Counter]:
    stats = {
        "source_visibility": Counter(),
        "deployment": Counter(),
        "model_storage": Counter(),
        "usage": Counter(),
    }
    for row in rows:
        for key in ("source_visibility", "deployment", "model_storage", "usage"):
            default = "未发现明显模型" if key == "model_storage" else "未知"
            value = normalize_stat_label(row.get(key, ""), default=default)
            stats[key][value] += 1
    return stats

def read_result_rows(path: Path) -> List[Dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def compute_analysis_stats(path: Path, dedupe_versions: bool = False) -> Dict[str, Counter]:
    rows = read_result_rows(path)
    if dedupe_versions:
        rows = select_latest_rows_by_model(rows)
    return compute_stats_from_rows(rows)

def write_stats_csv(path: Path, stats: Dict[str, Counter]) -> None:
    ensure_dir(path.parent if str(path.parent) != "." else Path(".."))
    rows = []
    name_map = {
        "source_visibility": "开源/闭源",
        "deployment": "端侧/云端/混合",
        "model_storage": "模型存储方式",
        "usage": "使用方式",
    }
    for category in ("source_visibility", "deployment", "model_storage", "usage"):
        for label, count in stats[category].most_common():
            rows.append({"category": name_map[category], "label": label, "count": count})
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["category", "label", "count"])
        writer.writeheader()
        writer.writerows(rows)

def print_analysis_stats(stats: Dict[str, Counter], title_suffix: str = "") -> None:
    title_map = {
        "source_visibility": "开源/闭源统计",
        "deployment": "端侧/云端/混合统计",
        "model_storage": "模型存储方式统计",
        "usage": "使用方式统计",
    }
    suffix = f"（{title_suffix}）" if title_suffix else ""
    print(f"\n========== 分析结果统计{suffix} ==========")
    for category in ("source_visibility", "deployment", "model_storage", "usage"):
        print(f"\n[{title_map[category]}]")
        if not stats[category]:
            print("无结果：0")
            continue
        for label, count in stats[category].most_common():
            print(f"{label}：{count}")
    print("=================================\n")

def main() -> int:
    parser = argparse.ArgumentParser(description="Static AI firmware component analyzer, incremental and disk-friendly")
    parser.add_argument("-i", "--input", default=INPUT_CSV, help="Input CSV with Model,Version,Region,Date,DownloadLink")
    parser.add_argument("-o", "--output", default=OUTPUT_CSV, help="Output summary CSV")
    parser.add_argument("--details", default=DETAIL_CSV, help="Output detailed evidence CSV")
    parser.add_argument("--download-dir", default=DOWNLOAD_DIR)
    parser.add_argument("--extract-dir", default=EXTRACT_DIR)
    parser.add_argument("--redownload", action="store_true")
    parser.add_argument("--reextract", action="store_true")
    parser.add_argument("--binwalk", action="store_true", help="Use binwalk/7z/unsquashfs/unzip/tar to extract non-archive firmware images when available")
    parser.add_argument("--keep-files", action="store_true", help="Keep downloaded archives and extracted directories. Default is to delete each sample after analysis.")
    parser.add_argument("--resume", action="store_true", help="Skip Model+Version rows that already exist in output CSV")
    parser.add_argument("--stats", default="", help="Output statistics CSV path. Default: <output>_stats.csv")
    parser.add_argument("--no-stats", action="store_true", help="Do not print/write category statistics after analysis")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    detail_path = Path(args.details)
    error_path = output_path.with_suffix(".errors.txt")
    download_dir = Path(args.download_dir)
    extract_dir = Path(args.extract_dir)
    ensure_dir(download_dir)
    ensure_dir(extract_dir)

    targets = read_targets(input_path)
    summary_fields = ["source_visibility", "deployment", "model_storage", "usage", "Model", "Version"]
    detail_fields = [
        "source_visibility", "deployment", "model_storage", "usage", "Model", "Version", "DownloadLink", "local_path",
        "files_scanned", "source_files", "standard_model_files",
        "standard_tflite_model_files", "standard_onnx_model_files", "standard_other_model_files",
        "private_model_files", "optimized_model_files",
        "deployment_evidence_summary", "local_deployment_evidence", "static_evidence_files",
        "sdk_keywords", "direct_api_keywords", "service_keywords", "service_evidence",
        "pipeline_keywords", "pipeline_evidence",
        "cloud_keywords", "cloud_strong_keywords", "cloud_evidence_files", "cloud_deployment_evidence",
        "cloud_ai_endpoint_urls", "binary_files"
    ]

    if not args.resume:
        with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
            csv.DictWriter(f, fieldnames=summary_fields).writeheader()
        with open(detail_path, "w", encoding="utf-8-sig", newline="") as f:
            csv.DictWriter(f, fieldnames=detail_fields).writeheader()
        if error_path.exists():
            error_path.unlink()

    done = load_done_keys(output_path) if args.resume else set()
    success = 0
    errors = 0
    skipped = 0

    for idx, row in enumerate(targets, start=1):
        model = row.get("Model", "")
        version = row.get("Version", "")
        key = (model, version)
        if args.resume and key in done:
            skipped += 1
            print(f"[{idx}/{len(targets)}] skip existing {model} {version}", flush=True)
            continue
        print(f"[{idx}/{len(targets)}] {model} {version}", flush=True)
        try:
            summary, detail = analyze_one(row, download_dir, extract_dir, args.redownload, args.reextract, use_binwalk=args.binwalk)
            append_csv_row(output_path, summary, summary_fields, write_header=False)
            append_csv_row(detail_path, detail, detail_fields, write_header=False)
            success += 1
        except Exception as e:
            err = f"{model},{version}: {e}"
            print(f"[error] {err}", file=sys.stderr, flush=True)
            with open(error_path, "a", encoding="utf-8") as f:
                f.write(err + "\n")
            errors += 1
        finally:
            if not args.keep_files:
                cleanup_artifacts(row, download_dir, extract_dir)

    print(f"[done] success={success}, errors={errors}, skipped={skipped}", flush=True)
    print(f"[done] summary: {output_path}", flush=True)
    print(f"[done] details: {detail_path}", flush=True)

    if not args.no_stats:
        stats = compute_analysis_stats(output_path, dedupe_versions=False)
        stats_no_version = compute_analysis_stats(output_path, dedupe_versions=True)
        stats_path = Path(args.stats) if args.stats else output_path.with_name(output_path.stem + "_stats.csv")
        stats_no_version_path = stats_path.with_name(stats_path.stem + "_no_version" + stats_path.suffix)
        write_stats_csv(stats_path, stats)
        write_stats_csv(stats_no_version_path, stats_no_version)
        print_analysis_stats(stats, title_suffix="带版本")
        print_analysis_stats(stats_no_version, title_suffix="无版本")
        print(f"[done] stats: {stats_path}", flush=True)
        print(f"[done] stats_no_version: {stats_no_version_path}", flush=True)

    if errors:
        print(f"[warn] errors: {error_path}", flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())