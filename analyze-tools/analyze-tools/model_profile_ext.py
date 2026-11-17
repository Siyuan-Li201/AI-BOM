#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
model_profile_ext.py

Extended static model profilers for 01_ai_firmware_extract_profile.py.

"""

from __future__ import annotations

import json
import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional


def empty_profile(status: str) -> Dict[str, str]:
    return {
        "input_shapes": "",
        "output_shapes": "",
        "input_output_dtypes": "",
        "tensor_count": "",
        "quantization": "",
        "operators_top": "",
        "arch_guess": "",
        "profile_status": status,
    }


def json_short(obj: Any, max_len: int = 20000) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False)[:max_len]
    except Exception:
        return ""


def read_text(path: Path, max_bytes: int = 30_000_000) -> str:
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def is_git_lfs_pointer(path: Path) -> bool:
    try:
        if path.stat().st_size > 4096:
            return False
        text = path.read_text(encoding="utf-8", errors="ignore")
        return text.startswith("version https://git-lfs.github.com/spec/v1") and "oid sha256:" in text
    except Exception:
        return False


def onnx_profile(path: Path) -> Dict[str, str]:
    out = empty_profile("onnx_profile_skipped")
    try:
        import onnx  # type: ignore
        from onnx import TensorProto  # type: ignore

        model = onnx.load(str(path), load_external_data=False)
        try:
            model = onnx.shape_inference.infer_shapes(model)
        except Exception:
            pass

        ops = Counter(n.op_type for n in model.graph.node)
        initializer_names = {x.name for x in model.graph.initializer}

        def _vi_dims(v):
            dims = []
            try:
                for d in v.type.tensor_type.shape.dim:
                    if d.HasField("dim_value"):
                        dims.append(int(d.dim_value))
                    elif d.HasField("dim_param"):
                        dims.append(str(d.dim_param))
                    else:
                        dims.append("?")
            except Exception:
                pass
            return dims

        def _looks_like_weight_or_param_input(v) -> bool:
            name = (v.name or "").strip()
            lname = name.lower()
            dims = _vi_dims(v)

            if name in initializer_names:
                return True

            # 很多导出的 ONNX 会把权重/BN 参数错误暴露在 graph.input 中，
            # 名字常常是纯数字，例如 1、2、9、10。
            if re.fullmatch(r"\d+", name):
                return True

            # 常见权重/参数命名
            if any(x in lname for x in [
                "weight", "bias", "running_mean", "running_var",
                "gamma", "beta", "kernel", "bn", "batchnorm"
            ]):
                return True

            # 典型权重形状，且名字不像业务输入
            if len(dims) in {0, 1, 2, 4} and not any(x in lname for x in [
                "input", "image", "pillar", "points", "mask", "feature", "vox", "scan"
            ]):
                if re.search(r"(conv|bn|gemm|matmul|linear|batchnorm|onnx::)", lname):
                    return True

            return False

        real_inputs = [v for v in model.graph.input if not _looks_like_weight_or_param_input(v)]
        if not real_inputs:
            real_inputs = list(model.graph.input)

        def dtype_name(elem_type: int) -> str:
            try:
                return TensorProto.DataType.Name(elem_type)
            except Exception:
                return str(elem_type)

        def vi_summary(vs):
            arr = []
            for v in vs:
                dims = []
                dtype = ""
                try:
                    tt = v.type.tensor_type
                    dtype = dtype_name(tt.elem_type)
                    for d in tt.shape.dim:
                        if d.HasField("dim_value"):
                            dims.append(int(d.dim_value))
                        elif d.HasField("dim_param"):
                            dims.append(str(d.dim_param))
                        else:
                            dims.append("?")
                except Exception:
                    pass
                arr.append({"name": v.name, "shape": dims, "dtype": dtype})
            return json_short(arr)

        dtypes = []
        for v in list(real_inputs) + list(model.graph.output):
            try:
                dtypes.append(dtype_name(v.type.tensor_type.elem_type))
            except Exception:
                pass

        out.update({
            "input_shapes": vi_summary(real_inputs),
            "output_shapes": vi_summary(model.graph.output),
            "input_output_dtypes": ";".join(sorted(set(dtypes))),
            "tensor_count": str(len(model.graph.initializer)),
            "operators_top": ";".join(f"{k}:{v}" for k, v in ops.most_common(60)),
            "profile_status": "ok",
        })
        keys = set(ops)
        if {"LSTM", "GRU", "RNN"} & keys:
            out["arch_guess"] = "RNN/LSTM-like"
        elif {"Attention", "MultiHeadAttention"} & keys or ({"MatMul", "Softmax"} <= keys and ops.get("MatMul", 0) >= 4):
            out["arch_guess"] = "Transformer/Attention-like（弱推测）"
        elif "Conv" in keys or "ConvTranspose" in keys:
            out["arch_guess"] = "CNN-like"
        elif "Gemm" in keys or "MatMul" in keys:
            out["arch_guess"] = "MLP/DNN-like"
        else:
            out["arch_guess"] = "未知"
    except Exception as e:
        out["profile_status"] = f"onnx_profile_skipped_or_failed:{e}"
    return out


def tensorflow_pb_profile(path: Path) -> Dict[str, str]:
    out = empty_profile("tensorflow_pb_skipped")
    try:
        import tensorflow as tf  # type: ignore

        gd = tf.compat.v1.GraphDef()
        gd.ParseFromString(path.read_bytes())

        ops = Counter(n.op for n in gd.node)
        consumers = set()
        for n in gd.node:
            for inp in n.input:
                base = inp.split(":")[0].lstrip("^")
                if base:
                    consumers.add(base)

        inputs, outputs, dtypes = [], [], []
        for n in gd.node:
            if n.op in {"Placeholder", "PlaceholderV2", "PlaceholderWithDefault"}:
                shape = []
                try:
                    for d in n.attr["shape"].shape.dim:
                        shape.append(int(d.size) if int(d.size) >= 0 else -1)
                except Exception:
                    pass
                dtype = ""
                try:
                    dtype = tf.dtypes.as_dtype(n.attr["dtype"].type).name
                    dtypes.append(dtype)
                except Exception:
                    pass
                inputs.append({"name": n.name, "shape": shape, "dtype": dtype})

        skip_out_ops = {
            "Const", "Assign", "NoOp", "Identity", "Placeholder", "PlaceholderV2",
            "PlaceholderWithDefault", "ReadVariableOp"
        }
        for n in gd.node:
            if n.name not in consumers and n.op not in skip_out_ops:
                shape = []
                try:
                    shp = n.attr["_output_shapes"].list.shape[0]
                    shape = [int(d.size) if int(d.size) >= 0 else -1 for d in shp.dim]
                except Exception:
                    pass
                outputs.append({"name": n.name, "op": n.op, "shape": shape})
                if len(outputs) >= 50:
                    break

        out.update({
            "input_shapes": json_short(inputs),
            "output_shapes": json_short(outputs),
            "input_output_dtypes": ";".join(sorted(set(dtypes))),
            "tensor_count": str(len(gd.node)),
            "operators_top": ";".join(f"{k}:{v}" for k, v in ops.most_common(60)),
            "profile_status": "ok" if gd.node else "tensorflow_pb_empty_graph",
        })

        keys = set(ops)
        if {"LSTMBlockCell", "BlockLSTM", "CudnnRNN"} & keys:
            out["arch_guess"] = "RNN/LSTM-like"
        elif "Conv2D" in keys or "DepthwiseConv2dNative" in keys:
            out["arch_guess"] = "CNN-like"
        elif "MatMul" in keys or "BatchMatMul" in keys:
            out["arch_guess"] = "MLP/DNN/Transformer-like"
        else:
            out["arch_guess"] = "未知"
    except Exception as e:
        out["profile_status"] = f"tensorflow_pb_profile_failed_or_tensorflow_missing:{e}"
    return out


def tensorflow_pbtxt_profile(path: Path) -> Dict[str, str]:
    text = read_text(path, max_bytes=30_000_000)
    out = empty_profile("tensorflow_pbtxt_basic")
    if not text:
        out["profile_status"] = "tensorflow_pbtxt_empty_or_too_large"
        return out

    ops = Counter(re.findall(r'\bop:\s*"([^"]+)"', text))
    inputs = []
    for block in re.findall(r'node\s*\{(.*?)\n\}', text, flags=re.S):
        if re.search(r'\bop:\s*"(Placeholder|PlaceholderV2|PlaceholderWithDefault)"', block):
            name_m = re.search(r'\bname:\s*"([^"]+)"', block)
            dims = []
            for dm in re.finditer(r'\bsize:\s*(-?\d+)', block):
                try:
                    dims.append(int(dm.group(1)))
                except Exception:
                    pass
            inputs.append({"name": name_m.group(1) if name_m else "", "shape": dims})
            if len(inputs) >= 50:
                break

    out["input_shapes"] = json_short(inputs)
    out["operators_top"] = ";".join(f"{k}:{v}" for k, v in ops.most_common(60))
    out["tensor_count"] = str(sum(ops.values()))
    keys = set(ops)
    if "Conv2D" in keys or "DepthwiseConv2dNative" in keys:
        out["arch_guess"] = "CNN-like"
    elif "MatMul" in keys or "BatchMatMul" in keys:
        out["arch_guess"] = "MLP/DNN/Transformer-like"
    elif keys:
        out["arch_guess"] = "未知"
    out["profile_status"] = "ok" if ops or inputs else "tensorflow_pbtxt_no_graph_pattern_found"
    return out


def _walk_tensor_like(obj: Any, max_items: int = 3000) -> List[Tuple[str, List[int], str]]:
    items: List[Tuple[str, List[int], str]] = []

    def rec(x: Any, prefix: str = "", depth: int = 0) -> None:
        if len(items) >= max_items or depth > 8:
            return
        if hasattr(x, "shape") and hasattr(x, "dtype"):
            try:
                items.append((prefix or "tensor", [int(i) for i in list(x.shape)], str(x.dtype)))
            except Exception:
                pass
            return
        if isinstance(x, dict):
            preferred = []
            for k in ["state_dict", "model_state_dict", "net", "model", "module", "weights"]:
                if k in x:
                    preferred.append((k, x[k]))
            rest = list(x.items())[:200]
            seen_keys = set()
            for k, v in preferred + rest:
                if id(v) in seen_keys:
                    continue
                seen_keys.add(id(v))
                rec(v, f"{prefix}.{k}" if prefix else str(k), depth + 1)
                if len(items) >= max_items:
                    break
        elif isinstance(x, (list, tuple)):
            for i, v in enumerate(list(x)[:200]):
                rec(v, f"{prefix}.{i}" if prefix else str(i), depth + 1)
                if len(items) >= max_items:
                    break

    rec(obj)
    return items


def _profile_from_weight_shapes(tensors: List[Tuple[str, List[int], str]], status: str) -> Dict[str, str]:
    out = empty_profile(status)
    if not tensors:
        out["profile_status"] = status + "_no_tensor_shapes_found"
        return out

    ranks = Counter(len(s) for _, s, _ in tensors)
    dtypes = sorted({dt for _, _, dt in tensors if dt})
    ops = Counter()

    for name, shape, dtype in tensors:
        lname = name.lower()
        if len(shape) == 4:
            ops["Conv/4D_weight"] += 1
        elif len(shape) == 3:
            ops["TemporalConv_or_Embedding/3D_weight"] += 1
        elif len(shape) == 2:
            ops["Linear/Gemm/2D_weight"] += 1
        elif len(shape) == 1:
            ops["Bias/Norm/1D_parameter"] += 1
        if any(x in lname for x in ["bn", "batchnorm", "running_mean", "running_var"]):
            ops["BatchNorm_parameter"] += 1
        if any(x in lname for x in ["lstm", "gru", "rnn"]):
            ops["RNN_parameter"] += 1
        if any(x in lname for x in ["attn", "attention", "q_proj", "k_proj", "v_proj", "query", "key", "value"]):
            ops["Attention_parameter"] += 1

    tensor_summary = [{"name": n, "shape": s, "dtype": dt} for n, s, dt in tensors[:120]]
    input_hints, output_hints = [], []

    convs = [(n, s) for n, s, _ in tensors if len(s) == 4]
    linears = [(n, s) for n, s, _ in tensors if len(s) == 2]

    if convs:
        n, s = convs[0]
        input_hints.append({
            "source": "weak_from_first_conv_weight",
            "name": n,
            "shape_hint": ["N", int(s[1]), "H", "W"],
            "kernel": [int(s[2]), int(s[3])]
        })
    elif linears:
        n, s = linears[0]
        input_hints.append({
            "source": "weak_from_first_linear_weight",
            "name": n,
            "shape_hint": ["N", int(s[1])]
        })

    if linears:
        n, s = linears[-1]
        output_hints.append({
            "source": "weak_from_last_linear_weight",
            "name": n,
            "shape_hint": ["N", int(s[0])]
        })
    elif convs:
        n, s = convs[-1]
        output_hints.append({
            "source": "weak_from_last_conv_weight",
            "name": n,
            "channels": int(s[0])
        })

    out.update({
        "input_shapes": json_short(input_hints),
        "output_shapes": json_short(output_hints),
        "input_output_dtypes": ";".join(dtypes),
        "tensor_count": str(len(tensors)),
        "operators_top": ";".join(f"rank{k}:{v}" for k, v in ranks.most_common()) + (";" if ranks else "") + ";".join(f"{k}:{v}" for k, v in ops.most_common(60)),
        "quantization": "quantized_or_int_weights" if any(("int8" in d or "qint" in d or "uint8" in d) for d in dtypes) else "not_obvious",
        "profile_status": status,
    })

    keys = set(ops)
    if "Attention_parameter" in keys:
        out["arch_guess"] = "Transformer/Attention-like（基于权重名弱推测）"
    elif "RNN_parameter" in keys:
        out["arch_guess"] = "RNN/LSTM-like（基于权重名弱推测）"
    elif "Conv/4D_weight" in keys:
        out["arch_guess"] = "CNN-like（基于权重形状弱推测）"
    elif "Linear/Gemm/2D_weight" in keys:
        out["arch_guess"] = "MLP/DNN-like（基于权重形状弱推测）"
    else:
        out["arch_guess"] = "未知"

    if len(out["operators_top"]) < 500:
        out["operators_top"] += ";tensor_examples=" + json_short(tensor_summary, 3000)
    return out


def torch_profile(path: Path) -> Dict[str, str]:
    try:
        import torch  # type: ignore
    except Exception as e:
        out = empty_profile("torch_profile_skipped_no_torch")
        out["profile_status"] = f"torch_profile_skipped_no_torch:{e}"
        return out

    if path.suffix.lower() in {".pt", ".ptl", ".torchscript"}:
        try:
            m = torch.jit.load(str(path), map_location="cpu")
            graph_text = str(getattr(m, "inlined_graph", getattr(m, "graph", "")))
            found = re.findall(r"\b(?:aten|prim|quantized|torchvision)::([A-Za-z0-9_]+)", graph_text)
            ops = Counter(found)
            out = empty_profile("torchscript_basic_graph")
            out["operators_top"] = ";".join(f"{k}:{v}" for k, v in ops.most_common(60))
            out["profile_status"] = "ok_torchscript_graph"
            keys = set(ops)
            if "conv2d" in keys or "convolution" in keys:
                out["arch_guess"] = "CNN-like"
            elif "linear" in keys or "matmul" in keys:
                out["arch_guess"] = "MLP/DNN/Transformer-like"
            if out["operators_top"]:
                return out
        except Exception:
            pass

    try:
        try:
            obj = torch.load(str(path), map_location="cpu", weights_only=True)
        except TypeError:
            out = empty_profile("torch_profile_skipped_old_torch_no_weights_only")
            out["profile_status"] = "torch_profile_skipped_old_torch_no_weights_only"
            return out
        tensors = _walk_tensor_like(obj)
        return _profile_from_weight_shapes(tensors, "ok_pytorch_weights_only")
    except Exception as e:
        out = empty_profile("torch_profile_failed")
        out["profile_status"] = f"torch_profile_failed:{e}"
        return out


def npz_profile(path: Path) -> Dict[str, str]:
    out = empty_profile("npz_profile_skipped")
    try:
        import numpy as np  # type: ignore

        tensors: List[Tuple[str, List[int], str]] = []
        extras = []
        with np.load(str(path), allow_pickle=False) as data:
            for k in data.files:
                arr = data[k]
                tensors.append((k, [int(i) for i in arr.shape], str(arr.dtype)))
                if arr.size <= 64 and any(x in k.lower() for x in ["input", "output", "shape", "dim"]):
                    try:
                        extras.append({"name": k, "value": arr.tolist()})
                    except Exception:
                        pass

        prof = _profile_from_weight_shapes(tensors, "ok_npz_arrays")
        if extras:
            prof["input_shapes"] = json_short(extras)
        return prof
    except Exception as e:
        out["profile_status"] = f"npz_profile_failed:{e}"
        return out


def keras_h5_profile(path: Path) -> Dict[str, str]:
    out = empty_profile("keras_h5_profile_skipped")
    try:
        import h5py  # type: ignore

        layer_types = Counter()
        input_shapes, output_shapes, tensors = [], [], []

        with h5py.File(str(path), "r") as h:
            cfg_raw = h.attrs.get("model_config")
            if cfg_raw is not None:
                if isinstance(cfg_raw, bytes):
                    cfg_raw = cfg_raw.decode("utf-8", errors="ignore")
                try:
                    cfg = json.loads(cfg_raw)

                    def walk_layers(x):
                        if isinstance(x, dict):
                            if "class_name" in x:
                                layer_types[str(x.get("class_name"))] += 1
                            conf = x.get("config") or {}
                            if isinstance(conf, dict):
                                for key in ["batch_input_shape", "batch_shape", "input_shape"]:
                                    if key in conf:
                                        input_shapes.append({"layer": conf.get("name", ""), "shape": conf.get(key)})
                                if "output_shape" in conf:
                                    output_shapes.append({"layer": conf.get("name", ""), "shape": conf.get("output_shape")})
                            for v in x.values():
                                walk_layers(v)
                        elif isinstance(x, list):
                            for v in x:
                                walk_layers(v)

                    walk_layers(cfg)
                except Exception:
                    pass

            def visitor(name, obj):
                try:
                    if hasattr(obj, "shape") and hasattr(obj, "dtype"):
                        tensors.append((name, [int(i) for i in obj.shape], str(obj.dtype)))
                except Exception:
                    pass

            h.visititems(visitor)

        prof = _profile_from_weight_shapes(tensors, "ok_keras_h5")
        if layer_types:
            prof["operators_top"] = ";".join(f"{k}:{v}" for k, v in layer_types.most_common(60)) + ";" + prof.get("operators_top", "")
        if input_shapes:
            prof["input_shapes"] = json_short(input_shapes)
        if output_shapes:
            prof["output_shapes"] = json_short(output_shapes)
        return prof
    except Exception as e:
        out["profile_status"] = f"keras_h5_profile_failed:{e}"
        return out


def keras_zip_profile(path: Path) -> Dict[str, str]:
    out = empty_profile("keras_zip_profile_skipped")
    try:
        layer_types = Counter()
        input_shapes, output_shapes = [], []
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            cfg_name = "config.json" if "config.json" in names else next((n for n in names if n.endswith("/config.json")), "")
            if cfg_name:
                cfg = json.loads(z.read(cfg_name).decode("utf-8", errors="ignore"))

                def walk(x):
                    if isinstance(x, dict):
                        if "class_name" in x:
                            layer_types[str(x.get("class_name"))] += 1
                        conf = x.get("config") or {}
                        if isinstance(conf, dict):
                            for key in ["batch_input_shape", "batch_shape", "input_shape"]:
                                if key in conf:
                                    input_shapes.append({"layer": conf.get("name", ""), "shape": conf.get(key)})
                            if "output_shape" in conf:
                                output_shapes.append({"layer": conf.get("name", ""), "shape": conf.get("output_shape")})
                        for v in x.values():
                            walk(v)
                    elif isinstance(x, list):
                        for v in x:
                            walk(v)

                walk(cfg)

        out["input_shapes"] = json_short(input_shapes)
        out["output_shapes"] = json_short(output_shapes)
        out["operators_top"] = ";".join(f"{k}:{v}" for k, v in layer_types.most_common(60))
        out["profile_status"] = "ok_keras_zip_config" if layer_types or input_shapes else "keras_zip_no_config_shapes_found"
        if any(k in layer_types for k in ["Conv2D", "DepthwiseConv2D", "SeparableConv2D"]):
            out["arch_guess"] = "CNN-like"
        elif any(k in layer_types for k in ["LSTM", "GRU", "SimpleRNN"]):
            out["arch_guess"] = "RNN/LSTM-like"
        elif any(k in layer_types for k in ["Dense"]):
            out["arch_guess"] = "MLP/DNN-like"
        return out
    except Exception as e:
        out["profile_status"] = f"keras_zip_profile_failed:{e}"
        return out


def safetensors_profile(path: Path) -> Dict[str, str]:
    out = empty_profile("safetensors_profile_skipped")
    try:
        from safetensors import safe_open  # type: ignore

        tensors: List[Tuple[str, List[int], str]] = []
        with safe_open(str(path), framework="pt", device="cpu") as f:
            for k in f.keys():
                sl = f.get_slice(k)
                tensors.append((k, [int(i) for i in sl.get_shape()], str(sl.get_dtype())))
        return _profile_from_weight_shapes(tensors, "ok_safetensors")
    except Exception as e:
        out["profile_status"] = f"safetensors_profile_failed:{e}"
        return out


def coreml_profile(path: Path) -> Dict[str, str]:
    out = empty_profile("coreml_profile_skipped")
    try:
        import coremltools as ct  # type: ignore

        spec = ct.utils.load_spec(str(path))

        def ft_shape(f):
            try:
                if f.type.HasField("multiArrayType"):
                    return list(f.type.multiArrayType.shape)
                if f.type.HasField("imageType"):
                    return [f.type.imageType.colorSpace, f.type.imageType.height, f.type.imageType.width]
            except Exception:
                pass
            return []

        inputs = [{"name": x.name, "shape": ft_shape(x)} for x in spec.description.input]
        outputs = [{"name": x.name, "shape": ft_shape(x)} for x in spec.description.output]
        out["input_shapes"] = json_short(inputs)
        out["output_shapes"] = json_short(outputs)
        out["profile_status"] = "ok_coreml_spec"
        out["arch_guess"] = "CoreML model"
    except Exception as e:
        out["profile_status"] = f"coreml_profile_failed_or_coremltools_missing:{e}"
    return out


def openvino_xml_profile(path: Path) -> Dict[str, str]:
    out = empty_profile("openvino_xml_profile_skipped")
    try:
        import xml.etree.ElementTree as ET

        tree = ET.parse(str(path))
        root = tree.getroot()
        ops = Counter()
        inputs, outputs = [], []

        for layer in root.findall(".//layer"):
            typ = layer.attrib.get("type", "")
            name = layer.attrib.get("name", "")
            if typ:
                ops[typ] += 1
            if typ.lower() in {"input", "parameter"}:
                dims = []
                for d in layer.findall(".//output/port/dim"):
                    try:
                        dims.append(int((d.text or "").strip()))
                    except Exception:
                        dims.append((d.text or "").strip())
                inputs.append({"name": name, "shape": dims})
            if typ.lower() in {"result", "output"}:
                dims = []
                for d in layer.findall(".//input/port/dim"):
                    try:
                        dims.append(int((d.text or "").strip()))
                    except Exception:
                        dims.append((d.text or "").strip())
                outputs.append({"name": name, "shape": dims})

        out["input_shapes"] = json_short(inputs)
        out["output_shapes"] = json_short(outputs)
        out["tensor_count"] = str(sum(ops.values()))
        out["operators_top"] = ";".join(f"{k}:{v}" for k, v in ops.most_common(60))
        out["profile_status"] = "ok_openvino_xml" if ops or inputs else "openvino_xml_no_layers_found"

        keys = set(ops)
        if "Convolution" in keys:
            out["arch_guess"] = "CNN-like"
        elif "MatMul" in keys or "FullyConnected" in keys:
            out["arch_guess"] = "MLP/DNN/Transformer-like"
    except Exception as e:
        out["profile_status"] = f"openvino_xml_profile_failed:{e}"
    return out


def enhanced_profile(path_like: Any, fmt: str = "") -> Optional[Dict[str, str]]:
    path = Path(path_like)
    if is_git_lfs_pointer(path):
        return empty_profile("git_lfs_pointer_not_real_model")

    ext = path.suffix.lower()

    if ext == ".onnx":
        return onnx_profile(path)
    if ext == ".pb":
        return tensorflow_pb_profile(path)
    if ext == ".pbtxt":
        return tensorflow_pbtxt_profile(path)
    if ext in {".pt", ".pth", ".ptl", ".torchscript", ".ckpt"}:
        return torch_profile(path)
    if ext == ".npz":
        return npz_profile(path)
    if ext == ".h5":
        return keras_h5_profile(path)
    if ext == ".keras":
        return keras_zip_profile(path)
    if ext == ".safetensors":
        return safetensors_profile(path)
    if ext == ".mlmodel":
        return coreml_profile(path)
    if ext == ".xml":
        return openvino_xml_profile(path)

    # 这些格式通常只是权重容器或专用二进制，缺少通用静态 shape 描述；
    # 保留状态，避免误认为“解析失败”。
    if ext in {".weights", ".pkl", ".joblib", ".mnn", ".gguf", ".ggml", ".mar"}:
        out = empty_profile(f"standard_container_or_weights_shape_unknown:{fmt}")
        out["profile_status"] = f"standard_container_or_weights_shape_unknown:{fmt}"
        return out

    return None
