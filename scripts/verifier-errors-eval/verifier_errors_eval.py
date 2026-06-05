#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# API harness for the BPF verifier error repair evaluation.

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


SCRIPT_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = SCRIPT_DIR / "public"
PRIV_DIR = SCRIPT_DIR / "privileged"
DEFAULT_RESULTS_ROOT = SCRIPT_DIR / "results"

SYSTEM_PROMPT = """\
You are solving a BPF verifier selftest repair task.

You only have the source and verifier log in the user prompt. Do not use tools,
do not assume internet access, do not assume access to the verifier, and do not
assume access to hidden files or answers.

Explain the verifier failure and propose the smallest source-level fix likely
to make the program pass verification. If a patch is clear, provide it.
"""

class ApiError(Exception):
    def __init__(self, status: int | None, body: str):
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}: {body[:300]}")


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def read_json(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")


def append_jsonl(path: Path, obj: object, lock: threading.Lock) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(obj, sort_keys=True)
    with lock:
        with path.open("a") as f:
            f.write(line + "\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def load_key_labels(path: Path) -> dict[str, str]:
    labels: dict[str, str] = {}
    if not path.exists():
        return labels
    for line in path.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        value = value.strip()
        if value:
            labels[key.strip().lower()] = value
    return labels


def load_api_key(provider: dict, key_labels: dict[str, str]) -> str:
    for name in provider.get("env_candidates", []):
        if os.environ.get(name):
            return os.environ[name]
    for label in provider.get("secret_label_candidates", []):
        value = key_labels.get(label.lower())
        if value:
            return value
    return ""


def http_json(method: str, url: str, headers: dict[str, str],
              payload: dict | None = None, timeout: int = 180) -> dict:
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers = dict(headers)
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode()
            if not body:
                return {}
            return json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise ApiError(e.code, body)
    except urllib.error.URLError as e:
        raise ApiError(None, str(e))
    except (TimeoutError, socket.timeout) as e:
        raise ApiError(None, f"timed out: {e}")


def extract_openai_text(resp: dict) -> str:
    if isinstance(resp.get("output_text"), str):
        return resp["output_text"]
    parts: list[str] = []
    for item in resp.get("output", []) or []:
        for content in item.get("content", []) or []:
            if content.get("type") in ("output_text", "text"):
                parts.append(content.get("text", ""))
    return "\n".join(p for p in parts if p)


def extract_chat_text(resp: dict) -> tuple[str, str]:
    choices = resp.get("choices") or []
    if not choices:
        return "", ""
    msg = choices[0].get("message") or {}
    text = msg.get("content") or ""
    reasoning = msg.get("reasoning") or msg.get("reasoning_content") or ""
    return text, reasoning


def extract_anthropic_text(resp: dict) -> tuple[str, str]:
    text_parts: list[str] = []
    thinking_parts: list[str] = []
    for block in resp.get("content", []) or []:
        typ = block.get("type")
        if typ == "text":
            text_parts.append(block.get("text", ""))
        elif typ in ("thinking", "redacted_thinking"):
            thinking_parts.append(block.get("thinking") or block.get("data") or "")
    return "\n".join(text_parts), "\n".join(thinking_parts)


def normalize_usage(provider: str, raw_usage: dict | None,
                    reasoning_text: str = "") -> dict:
    usage = raw_usage or {}
    out = {
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "cache_write_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_tokens": 0,
        "total_tokens": 0,
        "reasoning_content_chars": len(reasoning_text or ""),
        "raw_usage": usage,
    }
    if provider == "openai":
        out["input_tokens"] = usage.get("input_tokens", 0) or 0
        out["output_tokens"] = usage.get("output_tokens", 0) or 0
        out["total_tokens"] = usage.get("total_tokens", 0) or (
            out["input_tokens"] + out["output_tokens"])
        details = usage.get("input_tokens_details") or {}
        out["cached_input_tokens"] = details.get("cached_tokens", 0) or 0
        odetails = usage.get("output_tokens_details") or {}
        out["reasoning_tokens"] = odetails.get("reasoning_tokens", 0) or 0
        return out
    if provider == "anthropic":
        out["input_tokens"] = usage.get("input_tokens", 0) or 0
        out["output_tokens"] = usage.get("output_tokens", 0) or 0
        out["cache_write_input_tokens"] = (
            usage.get("cache_creation_input_tokens", 0) or 0)
        out["cached_input_tokens"] = usage.get("cache_read_input_tokens", 0) or 0
        out["total_tokens"] = out["input_tokens"] + out["output_tokens"]
        return out

    out["input_tokens"] = usage.get("prompt_tokens", 0) or usage.get(
        "input_tokens", 0) or 0
    out["output_tokens"] = usage.get("completion_tokens", 0) or usage.get(
        "output_tokens", 0) or 0
    out["total_tokens"] = usage.get("total_tokens", 0) or (
        out["input_tokens"] + out["output_tokens"])
    details = usage.get("completion_tokens_details") or {}
    out["reasoning_tokens"] = details.get("reasoning_tokens", 0) or usage.get(
        "reasoning_tokens", 0) or 0
    return out


def compute_cost(model: dict, usage: dict) -> dict:
    prices = model.get("prices_per_1m_tokens", {})
    input_price = prices.get("input", 0.0) or 0.0
    output_price = prices.get("output", 0.0) or 0.0
    cached_price = prices.get("cached_input", prices.get("cache_read", 0.0)) or 0.0
    cache_write_price = prices.get("cache_write_5m", input_price) or input_price

    input_tokens = usage.get("input_tokens", 0) or 0
    cached_tokens = usage.get("cached_input_tokens", 0) or 0
    cache_write_tokens = usage.get("cache_write_input_tokens", 0) or 0
    output_tokens = usage.get("output_tokens", 0) or 0

    billable_input = max(input_tokens - cached_tokens - cache_write_tokens, 0)
    input_cost = billable_input * input_price / 1_000_000
    cached_cost = cached_tokens * cached_price / 1_000_000
    cache_write_cost = cache_write_tokens * cache_write_price / 1_000_000
    output_cost = output_tokens * output_price / 1_000_000

    total = input_cost + cached_cost + cache_write_cost + output_cost
    return {
        "input_cost_usd": input_cost,
        "cached_input_cost_usd": cached_cost,
        "cache_write_cost_usd": cache_write_cost,
        "output_cost_usd": output_cost,
        "total_cost_usd": total,
    }


def call_openai(provider: dict, model: dict, api_key: str, prompt: str,
                timeout: int) -> tuple[dict, str, str]:
    profile = model.get("reasoning_profile", {})
    payload = {
        "model": model["model"],
        "input": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "max_output_tokens": model.get("max_output_tokens", 32768),
    }
    if profile.get("parameter") == "reasoning.effort":
        payload["reasoning"] = {"effort": profile.get("value")}
    resp = http_json("POST", provider["base_url"] + "/responses", {
        "Authorization": f"Bearer {api_key}",
    }, payload, timeout=timeout)
    return resp, extract_openai_text(resp), ""


def call_anthropic(provider: dict, model: dict, api_key: str,
                   prompt: str, timeout: int) -> tuple[dict, str, str]:
    profile = model.get("reasoning_profile", {})
    payload = {
        "model": model["model"],
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": model.get("max_output_tokens", 32768),
    }
    if profile.get("parameter") == "output_config.effort":
        payload["output_config"] = {"effort": profile.get("value")}
    thinking = profile.get("thinking")
    if thinking:
        payload["thinking"] = thinking
    resp = http_json("POST", provider["base_url"] + "/v1/messages", {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }, payload, timeout=timeout)
    text, thinking_text = extract_anthropic_text(resp)
    return resp, text, thinking_text


def call_openai_compatible(provider_name: str, provider: dict, model: dict,
                           api_key: str, prompt: str,
                           timeout: int) -> tuple[dict, str, str]:
    profile = model.get("reasoning_profile", {})
    payload = {
        "model": model["model"],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": model.get("max_output_tokens", 32768),
    }
    if provider_name == "kimi":
        payload["temperature"] = model.get("temperature", 0.6)
        if profile.get("parameter") == "thinking.type":
            payload["thinking"] = {"type": profile.get("value")}
    else:
        payload["temperature"] = 0
    if provider_name == "openrouter":
        payload["usage"] = {"include": True}
        if profile.get("include_reasoning"):
            payload["include_reasoning"] = True
        if profile.get("parameter") == "reasoning.effort":
            payload["reasoning"] = {"effort": profile.get("value")}
    resp = http_json("POST", provider["base_url"] + "/chat/completions", {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "https://github.com/torvalds/linux",
        "X-Title": "BPF verifier diagnostics evaluation",
    }, payload, timeout=timeout)
    text, reasoning = extract_chat_text(resp)
    if provider_name == "openrouter" and resp.get("id"):
        stats = fetch_openrouter_generation(provider, api_key, resp["id"],
                                            min(timeout, 60))
        if stats:
            resp["_openrouter_generation"] = stats
    return resp, text, reasoning


def fetch_openrouter_generation(provider: dict, api_key: str, gen_id: str,
                                timeout: int) -> dict | None:
    query = urllib.parse.urlencode({"id": gen_id})
    url = provider["base_url"] + "/generation?" + query
    try:
        return http_json("GET", url, {"Authorization": f"Bearer {api_key}"}, None,
                         timeout=timeout)
    except ApiError:
        return None


def run_one(model: dict, providers: dict, key_labels: dict[str, str],
            case: dict, variant: str, out_dir: Path,
            solver_max_output_tokens: int | None = None,
            timeout_seconds: int = 300) -> dict:
    if solver_max_output_tokens:
        model = dict(model)
        model["max_output_tokens"] = min(model.get("max_output_tokens", 4096),
                                         solver_max_output_tokens)
    profile_id = model["profile_id"]
    provider_name = model["provider"]
    provider = providers[provider_name]
    api_key = load_api_key(provider, key_labels)
    run_id = str(uuid.uuid4())
    prompt_path = PUBLIC_DIR / case["variants"][variant]["prompt"]
    prompt = prompt_path.read_text()
    started = now_utc()
    t0 = time.monotonic()
    rel = Path("responses") / profile_id / f"{case['id']}-{variant}.json"
    response_path = out_dir / rel
    answer_rel = Path("answers") / profile_id / f"{case['id']}-{variant}.txt"
    answer_path = out_dir / answer_rel

    meta = {
        "run_id": run_id,
        "case_id": case["id"],
        "variant": variant,
        "provider": provider_name,
        "model": model["model"],
        "profile": profile_id,
        "reasoning_profile": model.get("reasoning_profile", {}),
        "prompt_path": str(prompt_path.relative_to(SCRIPT_DIR)),
        "prompt_sha256": sha256_text(prompt),
        "prompt_bytes": len(prompt.encode()),
        "started_at": started,
        "timeout_seconds": timeout_seconds,
        "raw_response_path": str(rel),
        "answer_text_path": str(answer_rel),
    }

    if not api_key:
        row = {
            **meta,
            "finished_at": now_utc(),
            "wall_time_ms": int((time.monotonic() - t0) * 1000),
            "status": "missing_api_key",
            "error": f"no API key for provider {provider_name}",
        }
        write_json(response_path, {"meta": meta, "error": row["error"]})
        return row

    try:
        if provider_name == "openai":
            resp, answer, reasoning = call_openai(provider, model, api_key,
                                                 prompt, timeout_seconds)
        elif provider_name == "anthropic":
            resp, answer, reasoning = call_anthropic(provider, model, api_key,
                                                    prompt, timeout_seconds)
        elif provider_name in ("kimi", "openrouter"):
            resp, answer, reasoning = call_openai_compatible(
                provider_name, provider, model, api_key, prompt,
                timeout_seconds)
        else:
            raise ApiError(None, f"unsupported provider {provider_name}")
        finished = now_utc()
        raw_usage = resp.get("usage") or {}
        if provider_name == "openrouter" and resp.get("_openrouter_generation"):
            raw_usage = dict(raw_usage)
            raw_usage["_openrouter_generation"] = resp["_openrouter_generation"]
        usage = normalize_usage(provider_name, raw_usage, reasoning)
        cost = compute_cost(model, usage)
        row = {
            **meta,
            "finished_at": finished,
            "wall_time_ms": int((time.monotonic() - t0) * 1000),
            "status": "ok" if answer.strip() else "invalid_response",
            "stop_reason": extract_stop_reason(provider_name, resp),
            **usage,
            **cost,
            "answer_chars": len(answer),
        }
        write_text(answer_path, answer)
        write_json(response_path, {
            "meta": meta,
            "normalized_usage": usage,
            "normalized_cost": cost,
            "reasoning_content": reasoning,
            "answer_text": answer,
            "raw_response": resp,
        })
        return row
    except ApiError as e:
        status = "api_error"
        if e.status == 429:
            status = "rate_limited"
        elif e.status is None and "timed out" in e.body.lower():
            status = "timeout"
        row = {
            **meta,
            "finished_at": now_utc(),
            "wall_time_ms": int((time.monotonic() - t0) * 1000),
            "status": status,
            "http_status": e.status,
            "error": e.body[:4000],
        }
        write_json(response_path, {"meta": meta, "error": row["error"],
                                   "http_status": e.status})
        return row
    except Exception as e:  # Keep long paid runs resumable.
        row = {
            **meta,
            "finished_at": now_utc(),
            "wall_time_ms": int((time.monotonic() - t0) * 1000),
            "status": "client_error",
            "error": repr(e),
        }
        write_json(response_path, {"meta": meta, "error": row["error"]})
        return row


def extract_stop_reason(provider: str, resp: dict) -> str:
    if provider == "openai":
        for item in resp.get("output", []) or []:
            if item.get("status"):
                return item.get("status")
        return resp.get("status", "")
    if provider == "anthropic":
        return resp.get("stop_reason", "")
    choices = resp.get("choices") or []
    if choices:
        return choices[0].get("finish_reason", "")
    return ""


def load_manifest() -> dict:
    return read_json(PUBLIC_DIR / "manifest.json")


def load_matrix() -> dict:
    return read_json(PRIV_DIR / "api_model_matrix.json")


def select_profiles(matrix: dict, args: argparse.Namespace) -> list[dict]:
    models = {m["profile_id"]: m for m in matrix["models"]}
    if args.profiles:
        ids = split_csv(args.profiles)
    else:
        ids = matrix.get("run_sets", {}).get(args.run_set, [])
    missing = [profile for profile in ids if profile not in models]
    if missing:
        raise SystemExit(f"unknown profiles: {', '.join(missing)}")
    return [models[profile] for profile in ids]


def select_cases(manifest: dict, args: argparse.Namespace) -> list[dict]:
    cases = {c["id"]: c for c in manifest["cases"]}
    if args.cases:
        ids = split_csv(args.cases)
    else:
        ids = [c["id"] for c in manifest["cases"]]
    missing = [case_id for case_id in ids if case_id not in cases]
    if missing:
        raise SystemExit(f"unknown cases: {', '.join(missing)}")
    return [cases[case_id] for case_id in ids]


def split_csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def cmd_list_models(args: argparse.Namespace) -> int:
    matrix = load_matrix()
    models = select_profiles(matrix, args)
    for model in models:
        profile = model.get("reasoning_profile", {})
        value = profile.get("value", "default")
        print(f"{model['profile_id']}: {model['provider']} {model['model']} "
              f"({profile.get('parameter', 'default')}={value})")
    return 0


def cmd_estimate(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    matrix = load_matrix()
    cases = select_cases(manifest, args)
    models = select_profiles(matrix, args)
    variants = split_csv(args.variants)
    approx_input = 0
    for case in cases:
        for variant in variants:
            prompt = (PUBLIC_DIR / case["variants"][variant]["prompt"]).read_text()
            approx_input += max(len(prompt) // 4, 1)
    print(f"cases={len(cases)} variants={len(variants)} profiles={len(models)}")
    print(f"calls={len(cases) * len(variants) * len(models)}")
    print("rough input-token cost floor, excluding output/reasoning:")
    for model in models:
        price = model.get("prices_per_1m_tokens", {}).get("input", 0.0)
        cost = approx_input * price / 1_000_000
        print(f"  {model['profile_id']}: ~{approx_input:,} input tokens, "
              f"${cost:.4f} per complete profile pass")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    matrix = load_matrix()
    cases = select_cases(manifest, args)
    models = select_profiles(matrix, args)
    variants = split_csv(args.variants)
    providers = matrix["providers"]
    key_labels = load_key_labels(Path(args.keys))

    out_dir = Path(args.out_dir) if args.out_dir else Path(args.results_root) / timestamp()
    out_dir.mkdir(parents=True, exist_ok=True)
    latest_rows = {}
    if args.only_failed:
        for row in read_jsonl(out_dir / "rows.jsonl"):
            latest_rows[(row.get("profile"), row.get("case_id"), row.get("variant"))] = row
    run_manifest = {
        "created_at": now_utc(),
        "cases": [c["id"] for c in cases],
        "variants": variants,
        "profiles": [m["profile_id"] for m in models],
        "matrix_path": str((PRIV_DIR / "api_model_matrix.json").relative_to(SCRIPT_DIR)),
        "public_manifest_path": str((PUBLIC_DIR / "manifest.json").relative_to(SCRIPT_DIR)),
    }
    if (out_dir / "run_manifest.json").exists():
        write_json(out_dir / "attempts" / f"{timestamp()}.json", run_manifest)
    else:
        write_json(out_dir / "run_manifest.json", run_manifest)

    tasks = []
    for model in models:
        for case in cases:
            for variant in variants:
                key = (model["profile_id"], case["id"], variant)
                if args.only_failed and latest_rows.get(key, {}).get("status") == "ok":
                    continue
                response_path = out_dir / "responses" / model["profile_id"] / (
                    f"{case['id']}-{variant}.json")
                if args.resume and response_path.exists():
                    continue
                tasks.append((model, case, variant))

    print(f"result_dir={out_dir}")
    print(f"scheduled={len(tasks)} profiles={len(models)} cases={len(cases)} "
          f"variants={len(variants)} workers={args.workers}")
    rows_path = out_dir / "rows.jsonl"
    lock = threading.Lock()

    def worker(item: tuple[dict, dict, str]) -> dict:
        model, case, variant = item
        row = run_one(model, providers, key_labels, case, variant, out_dir,
                      args.solver_max_output_tokens, args.timeout_seconds)
        append_jsonl(rows_path, row, lock)
        print(f"{row['status']:>16} {row['profile']} {row['case_id']} "
              f"{row['variant']} ${row.get('total_cost_usd', 0):.5f}",
              flush=True)
        return row

    if args.workers == 1:
        for item in tasks:
            worker(item)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = [ex.submit(worker, item) for item in tasks]
            for fut in concurrent.futures.as_completed(futs):
                fut.result()
    return 0


def grade_packet(case_key: dict, answer: str, meta: dict) -> dict:
    payload = {
        "meta": meta,
        "case_id": case_key["id"],
        "category": case_key.get("category"),
        "difficulty": case_key.get("difficulty"),
        "expected_explanation": case_key.get("expected_explanation"),
        "canonical_fix": case_key.get("canonical_fix"),
        "acceptable_fixes": case_key.get("acceptable_fixes", []),
        "must_mention": case_key.get("must_mention", []),
        "wrong_if": case_key.get("wrong_if", []),
        "scoring": {
            "0": "Unrelated or does not identify the verifier failure.",
            "1": "Broad area only, no actionable source-level fix.",
            "2": "Likely cause, but incomplete/unsafe/verifier-insufficient fix.",
            "3": "Source-level fix likely to satisfy verifier, but imprecise.",
            "4": "Minimal intended fix or equivalent patch with correct reasoning.",
        },
        "success_threshold": 3,
        "model_answer": answer,
        "required_json_schema": {
            "score": "integer 0..4",
            "success": "boolean",
            "verdict": "short string",
            "strengths": ["short strings"],
            "problems": ["short strings"],
            "missing": ["short strings"],
            "repair_summary": "short string",
        },
    }
    return payload


LOCAL_GRADE_RULES = {
    "case-001": {
        "cause": [r"scalar|integer", r"cast"],
        "fix": [r"bpf_cpumask_create|verifier-known|valid .*memory|stack|map"],
        "detail": [r"bpf_cpumask_release|release", r"first argument|r1|destination"],
        "wrong": [r"null check.*0x123456|check.*invalid"],
    },
    "case-002": {
        "cause": [r"leak|unreleased|reference", r"cpumask"],
        "fix": [r"bpf_cpumask_release|release"],
        "detail": [r"all paths|every path|before return|non-null|null path"],
    },
    "case-003": {
        "cause": [r"spill|spilled|slot|fp-8", r"partial|byte|overwrit|corrupt|overlap|mixed|unknown"],
        "fix": [r"separate stack|different stack|do not overwrite|remove .*store|preserve|move .*slot|fp-16|fp-9|non-overlap|does not overlap"],
        "detail": [r"reload|dereference|scalar|pointer|ctx"],
    },
    "case-004": {
        "cause": [r"null|nullable", r"dereference|->x|s->"],
        "fix": [r"if\s*\(!?s\)|null check|check .*null|guard"],
        "detail": [r"helper_a|callee|global function|before"],
    },
    "case-005": {
        "cause": [r"sleep|sleepable", r"preempt"],
        "fix": [r"move .*outside|enable preempt|bpf_preempt_enable|before .*copy"],
        "detail": [r"bpf_copy_from_user|critical section|disabled"],
    },
    "case-006": {
        "cause": [r"not allowed|not permitted|forbidden|unsupported|cannot use", r"program type|prog type|kprobe"],
        "fix": [r"allowed helper|different helper|bpf_ktime_get_ns|change .*program type|attach"],
        "detail": [r"policy|compatib"],
    },
    "case-007": {
        "cause": [r"variable|unbounded|not bounded", r"length|len", r"buffer|fallback|stack"],
        "fix": [r"bound|check|clamp|constant|sizeof"],
        "detail": [r"<=|less than|no larger|upper"],
    },
    "case-008": {
        "cause": [r"9", r"8", r"buffer|length|size"],
        "fix": [r"buffer\\[9\\]|increase .*buffer|reduce .*9|sizeof\\(buffer\\)|8"],
        "detail": [r"fallback|dynptr_slice|memory/length"],
    },
    "case-009": {
        "cause": [r"null|nullable|may be null", r"trusted|untrusted|rcu|kptr|map"],
        "fix": [r"null check|check .*task|rcu_read_lock|trusted|acquire .*after"],
        "detail": [r"bpf_task_acquire|value->task|first argument|r1"],
    },
    "case-010": {
        "cause": [r"modified .*ctx|ctx pointer|context pointer|context pointers?", r"skb\\s*\\+\\s*1|\\+\\s*1|pointer arithmetic"],
        "fix": [r"pass .*skb\\b|original .*skb|unmodified|preserve .*ctx"],
        "detail": [r"helper_c|callee|dereference"],
    },
    "case-011": {
        "cause": [r"ringbuf|dynptr", r"leak|release|reserved"],
        "fix": [r"submit|discard|bpf_ringbuf_(submit|discard)_dynptr|release"],
        "detail": [r"second|all paths|every path|before return"],
    },
    "case-012": {
        "cause": [r"sleep|sleepable", r"irq"],
        "fix": [r"restore .*irq|enable .*irq|outside .*irq|before .*helper|move .*helper|static .*helper|make .*static|static .*__noinline"],
        "detail": [r"global|subprog|subprogram|disabled|bpf_copy_from_user"],
    },
    "case-013": {
        "cause": [r"stack", r"depth|limit"],
        "fix": [r"reduce|shrink|smaller|stack usage|call chain|buffer"],
        "detail": [r"512|combined|nested|global"],
    },
    "case-014": {
        "cause": [r"variable|offset", r"upper|max|unbounded", r"map"],
        "fix": [r"upper bound|check|if .*offset|clamp|prove"],
        "detail": [r"offset.*size|access size|map value|within"],
    },
    "case-015": {
        "cause": [r"invalidat|changed", r"packet|data_end|data"],
        "fix": [r"reload|recompute|revalidate|check .*data_end"],
        "detail": [r"after .*call|global function|helper"],
    },
    "case-016": {
        "cause": [r"reference|ref", r"leak|unreleased", r"branch|path"],
        "fix": [r"release|bpf_sk_release|free", r"all paths|every path|before return|before exit|before exiting|early exit|exit path"],
        "detail": [r"mark|subbranch|non-null|null"],
    },
    "case-017": {
        "cause": [r"irq", r"out of order|order|mismatch"],
        "fix": [r"reverse order|lifo|matching .*flags|restore .*order"],
        "detail": [r"save|restore|nested"],
    },
    "case-018": {
        "cause": [r"spin", r"lock", r"out of order|order"],
        "fix": [r"unlock .*lock2.*lock1|lock2 .*before .*lock1|reverse order|lifo"],
        "detail": [r"resource|nested"],
    },
    "case-019": {
        "cause": [r"recursion|recursive|cycle", r"call graph|bpf2bpf"],
        "fix": [r"remove .*recursion|acyclic|bounded loop|ordinary .*loop|rewrite .*loop|replace .*call|backward branch|break .*cycle"],
        "detail": [r"verifier|subprog|function"],
    },
    "case-020": {
        "cause": [r"liveness|complexity", r"limit|10001|exponential"],
        "fix": [r"reduce|simplify|fewer calls|call sites|flatten|shorten"],
        "detail": [r"call pattern|call chain|helper|recomputation|state"],
    },
}


def has_all(text: str, patterns: list[str]) -> bool:
    return all(re.search(pattern, text, re.I | re.S) for pattern in patterns)


def has_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, re.I | re.S) for pattern in patterns)


def local_grade(case_id: str, answer: str) -> dict:
    text = answer.lower()
    rules = LOCAL_GRADE_RULES[case_id]
    cause = has_all(text, rules["cause"])
    fix = has_all(text, rules["fix"])
    detail = has_any(text, rules.get("detail", []))
    wrong = has_any(text, rules.get("wrong", []))

    if wrong and not fix:
        score = 1 if cause else 0
        verdict = "Mentions the area but suggests a wrong or insufficient fix."
    elif cause and fix and detail:
        score = 4
        verdict = "Identifies the verifier cause and gives an actionable fix."
    elif fix and (cause or detail):
        score = 3
        verdict = "Gives a likely source-level fix but with limited explanation."
    elif cause or fix:
        score = 2
        verdict = "Identifies part of the issue but lacks a complete verifier fix."
    elif has_any(text, [r"verifier|bpf|pointer|memory|reference|lock|helper"]):
        score = 1
        verdict = "Only gives a broad verifier-area answer."
    else:
        score = 0
        verdict = "Does not identify the intended verifier failure."

    return {
        "score": score,
        "success": score >= 3,
        "verdict": verdict,
        "signals": {
            "cause": cause,
            "fix": fix,
            "detail": detail,
            "wrong": wrong,
        },
        "graded_by": "local-rule-grader",
        "graded_at": now_utc(),
    }


def cmd_grade(args: argparse.Namespace) -> int:
    result_dir = Path(args.result_dir)
    if not result_dir.exists():
        raise SystemExit(f"missing result dir: {result_dir}")

    answer_key = {c["id"]: c for c in read_json(PRIV_DIR / "answer_key.json")["cases"]}
    response_files = sorted((result_dir / "responses").glob("*/*.json"))
    packets = []
    for path in response_files:
        raw = read_json(path)
        meta = raw.get("meta", {})
        if not raw.get("answer_text"):
            continue
        case_key = answer_key[meta["case_id"]]
        packet = grade_packet(case_key, raw["answer_text"], meta)
        out = result_dir / "grade_packets" / meta["profile"] / (
            f"{meta['case_id']}-{meta['variant']}.json")
        write_json(out, packet)
        packets.append(out)
    print(f"wrote {len(packets)} local grading packets under "
          f"{result_dir / 'grade_packets'}")
    print("Use the packet files to grade locally, then record each grade with:")
    print("  verifier_errors_eval.py record-grade RESULT_DIR --profile PROFILE "
          "--case CASE --variant VARIANT --score N --verdict TEXT")
    return 0


def cmd_record_grade(args: argparse.Namespace) -> int:
    result_dir = Path(args.result_dir)
    packet_path = result_dir / "grade_packets" / args.profile / (
        f"{args.case}-{args.variant}.json")
    if not packet_path.exists():
        raise SystemExit(f"missing grade packet: {packet_path}")
    packet = read_json(packet_path)
    meta = packet["meta"]
    grade = {
        "score": args.score,
        "success": args.score >= 3,
        "verdict": args.verdict,
        "strengths": split_csv(args.strengths) if args.strengths else [],
        "problems": split_csv(args.problems) if args.problems else [],
        "missing": split_csv(args.missing) if args.missing else [],
        "repair_summary": args.repair_summary or "",
        "graded_by": "local-codex",
        "graded_at": now_utc(),
    }
    grade_path = result_dir / "grades" / args.profile / (
        f"{args.case}-{args.variant}.json")
    write_json(grade_path, {"meta": meta, "grade": grade})

    row = {
        "case_id": args.case,
        "variant": args.variant,
        "profile": args.profile,
        "provider": meta.get("provider"),
        "model": meta.get("model"),
        "status": "ok",
        "grader": "local-codex",
        "score": args.score,
        "success": args.score >= 3,
        "verdict": args.verdict,
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "cache_write_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_tokens": 0,
        "total_tokens": 0,
        "reasoning_content_chars": 0,
        "total_cost_usd": 0.0,
        "wall_time_ms": 0,
    }
    append_jsonl(result_dir / "grade_rows.jsonl", row, threading.Lock())
    print(f"recorded grade={args.score} {args.profile} {args.case} {args.variant}")
    return 0


def cmd_auto_grade(args: argparse.Namespace) -> int:
    result_dir = Path(args.result_dir)
    answer_key = {c["id"]: c for c in read_json(PRIV_DIR / "answer_key.json")["cases"]}
    response_files = sorted((result_dir / "responses").glob("*/*.json"))
    if args.replace:
        for path in (result_dir / "grades").glob("*/*.json"):
            path.unlink()
        if (result_dir / "grade_rows.jsonl").exists():
            (result_dir / "grade_rows.jsonl").unlink()
    count = 0
    lock = threading.Lock()
    for path in response_files:
        raw = read_json(path)
        meta = raw.get("meta", {})
        answer = raw.get("answer_text", "")
        if not answer or meta.get("case_id") not in answer_key:
            continue
        grade = local_grade(meta["case_id"], answer)
        case_key = answer_key[meta["case_id"]]
        grade_path = result_dir / "grades" / meta["profile"] / (
            f"{meta['case_id']}-{meta['variant']}.json")
        write_json(grade_path, {
            "meta": meta,
            "grade": grade,
            "case": {
                "category": case_key["category"],
                "difficulty": case_key["difficulty"],
            },
        })
        row = {
            "case_id": meta["case_id"],
            "variant": meta["variant"],
            "profile": meta["profile"],
            "provider": meta.get("provider"),
            "model": meta.get("model"),
            "status": "ok",
            "grader": "local-rule-grader",
            "score": grade["score"],
            "success": grade["success"],
            "verdict": grade["verdict"],
            "input_tokens": 0,
            "cached_input_tokens": 0,
            "cache_write_input_tokens": 0,
            "output_tokens": 0,
            "reasoning_tokens": 0,
            "total_tokens": 0,
            "reasoning_content_chars": 0,
            "total_cost_usd": 0.0,
            "wall_time_ms": 0,
        }
        append_jsonl(result_dir / "grade_rows.jsonl", row, lock)
        count += 1
    print(f"auto-graded {count} answers in {result_dir}")
    return 0


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def dedupe_rows(rows: list[dict]) -> list[dict]:
    latest = {}
    for row in rows:
        key = (row.get("profile"), row.get("case_id"), row.get("variant"))
        latest[key] = row
    return list(latest.values())


def dedupe_row_map(rows: list[dict]) -> dict[tuple, dict]:
    latest = {}
    for row in rows:
        key = (row.get("profile"), row.get("case_id"), row.get("variant"))
        latest[key] = row
    return latest


def grouped(rows: list[dict], keys: tuple[str, ...]) -> dict[tuple, list[dict]]:
    out: dict[tuple, list[dict]] = {}
    for row in rows:
        key = tuple(row.get(k) for k in keys)
        out.setdefault(key, []).append(row)
    return out


def mean(values: list[float]) -> float:
    return statistics.mean(values) if values else 0.0


def median(values: list[float]) -> float:
    return statistics.median(values) if values else 0.0


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * pct
    lo = int(rank)
    hi = min(lo + 1, len(ordered) - 1)
    frac = rank - lo
    return ordered[lo] * (1 - frac) + ordered[hi] * frac


def summarize_group(rows: list[dict]) -> dict:
    ok = [r for r in rows if r.get("status") == "ok"]
    scores = [r.get("score", 0) for r in ok if "score" in r]
    successes = [r for r in ok if r.get("success")]
    costs = [r.get("total_cost_usd", 0.0) for r in ok]
    wall = [r.get("wall_time_ms", 0) for r in ok]
    input_tokens = [r.get("input_tokens", 0) for r in ok]
    output_tokens = [r.get("output_tokens", 0) for r in ok]
    reasoning_tokens = [r.get("reasoning_tokens", 0) for r in ok]
    reasoning_chars = [r.get("reasoning_content_chars", 0) for r in ok]
    answer_chars = [r.get("answer_chars", 0) for r in ok]
    return {
        "runs": len(rows),
        "status_counts": dict(collections.Counter(r.get("status", "unknown") for r in rows)),
        "ok": len(ok),
        "successes": len(successes),
        "success_rate": len(successes) / len(ok) if ok else 0.0,
        "mean_score": mean(scores),
        "median_score": median(scores),
        "total_cost_usd": sum(costs),
        "mean_cost_usd": mean(costs),
        "median_cost_usd": median(costs),
        "p90_cost_usd": percentile(costs, 0.90),
        "p95_cost_usd": percentile(costs, 0.95),
        "input_tokens": sum(input_tokens),
        "mean_input_tokens": mean(input_tokens),
        "median_input_tokens": median(input_tokens),
        "output_tokens": sum(output_tokens),
        "mean_output_tokens": mean(output_tokens),
        "median_output_tokens": median(output_tokens),
        "p90_output_tokens": percentile(output_tokens, 0.90),
        "p95_output_tokens": percentile(output_tokens, 0.95),
        "reasoning_tokens": sum(reasoning_tokens),
        "mean_reasoning_tokens": mean(reasoning_tokens),
        "median_reasoning_tokens": median(reasoning_tokens),
        "p90_reasoning_tokens": percentile(reasoning_tokens, 0.90),
        "p95_reasoning_tokens": percentile(reasoning_tokens, 0.95),
        "reasoning_content_chars": sum(reasoning_chars),
        "mean_reasoning_content_chars": mean(reasoning_chars),
        "median_reasoning_content_chars": median(reasoning_chars),
        "answer_chars": sum(answer_chars),
        "mean_answer_chars": mean(answer_chars),
        "median_answer_chars": median(answer_chars),
        "mean_wall_time_ms": mean(wall),
        "median_wall_time_ms": median(wall),
        "p90_wall_time_ms": percentile(wall, 0.90),
        "p95_wall_time_ms": percentile(wall, 0.95),
    }


def cmd_summarize(args: argparse.Namespace) -> int:
    result_dir = Path(args.result_dir)
    manifest = load_manifest()
    matrix = load_matrix()
    cases = select_cases(manifest, args)
    models = select_profiles(matrix, args)
    variants = split_csv(args.variants)
    expected = {
        (model["profile_id"], case["id"], variant)
        for model in models
        for case in cases
        for variant in variants
    }
    row_map = dedupe_row_map(read_jsonl(result_dir / "rows.jsonl"))
    rows = []
    model_by_profile = {model["profile_id"]: model for model in models}
    for key in sorted(expected):
        row = row_map.get(key)
        if row:
            rows.append(row)
        else:
            profile, case_id, variant = key
            model = model_by_profile[profile]
            rows.append({
                "profile": profile,
                "case_id": case_id,
                "variant": variant,
                "provider": model.get("provider"),
                "model": model.get("model"),
                "status": "missing",
            })
    grade_map = dedupe_row_map(read_jsonl(result_dir / "grade_rows.jsonl"))
    grade_rows = [grade_map[key] for key in sorted(expected) if key in grade_map]
    answer_key = {c["id"]: c for c in read_json(PRIV_DIR / "answer_key.json")["cases"]}
    meta_by_case = {cid: {"category": c["category"], "difficulty": c["difficulty"]}
                    for cid, c in answer_key.items()}

    for row in rows:
        row.update(meta_by_case.get(row.get("case_id"), {}))
    for row in grade_rows:
        row.update(meta_by_case.get(row.get("case_id"), {}))

    reports_dir = result_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    write_csv(reports_dir / "runs.csv", rows)
    write_csv(reports_dir / "grades.csv", grade_rows)

    summary = {
        "result_dir": str(result_dir),
        "generated_at": now_utc(),
        "expected_solver_calls": len(expected),
        "profiles": [m["profile_id"] for m in models],
        "cases": [c["id"] for c in cases],
        "variants": variants,
        "solver": {
            "overall": summarize_group(rows),
            "by_profile_variant": {
                "|".join(k): summarize_group(v)
                for k, v in grouped(rows, ("profile", "variant")).items()
            },
            "by_provider": {
                "|".join(k): summarize_group(v)
                for k, v in grouped(rows, ("provider",)).items()
            },
            "by_variant": {
                "|".join(k): summarize_group(v)
                for k, v in grouped(rows, ("variant",)).items()
            },
        },
        "grades": {
            "overall": summarize_group(grade_rows),
            "by_variant": {
                "|".join(k): summarize_group(v)
                for k, v in grouped(grade_rows, ("variant",)).items()
            },
            "by_profile_variant": {
                "|".join(k): summarize_group(v)
                for k, v in grouped(grade_rows, ("profile", "variant")).items()
            },
            "by_category_variant": {
                "|".join(k): summarize_group(v)
                for k, v in grouped(grade_rows, ("category", "variant")).items()
            },
            "by_difficulty_variant": {
                "|".join(k): summarize_group(v)
                for k, v in grouped(grade_rows, ("difficulty", "variant")).items()
            },
        },
    }
    write_json(result_dir / "summary.json", summary)
    write_summary_md(result_dir, summary, rows, grade_rows)
    print(result_dir / "summary.md")
    return 0


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        write_text(path, "")
        return
    keys: list[str] = []
    for row in rows:
        for key in row:
            if key not in keys and key != "raw_usage":
                keys.append(key)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_summary_md(result_dir: Path, summary: dict, rows: list[dict],
                     grade_rows: list[dict]) -> None:
    lines = [
        "# BPF Verifier AI Repair Evaluation Results",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Solver Calls",
        "",
    ]
    solver = summary["solver"]["overall"]
    lines += [
        f"- Runs: {solver['runs']}",
        f"- Successful API responses: {solver['ok']}",
        f"- Status counts: {format_status_counts(solver['status_counts'])}",
        f"- Solver API cost: ${solver['total_cost_usd']:.4f}",
        f"- Mean solver cost per response: ${solver['mean_cost_usd']:.5f}",
        f"- Median solver cost per response: ${solver['median_cost_usd']:.5f}",
        f"- P95 solver cost per response: ${solver['p95_cost_usd']:.5f}",
        f"- Input tokens: {solver['input_tokens']:,}",
        f"- Output tokens: {solver['output_tokens']:,}",
        f"- Reasoning tokens: {solver['reasoning_tokens']:,}",
        f"- Median wall time: {solver['median_wall_time_ms']:.0f} ms",
        f"- P95 wall time: {solver['p95_wall_time_ms']:.0f} ms",
        "",
        "## Graded Repair Quality",
        "",
    ]
    grades = summary["grades"]["overall"]
    lines += [
        f"- Graded answers: {grades['ok']}",
        f"- Successes: {grades['successes']}",
        f"- Success rate: {grades['success_rate']:.1%}",
        f"- Mean score: {grades['mean_score']:.2f} / 4",
        f"- Median score: {grades['median_score']:.2f} / 4",
        "- Grader cost: $0.0000 (local rule-based Codex grading)",
        "",
        "## Legacy Vs Diagnostic",
        "",
        "| Variant | Responses | Solver cost | Output tokens | Reasoning tokens | Median wall ms | Graded answers | Success rate | Mean score |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    grade_by_variant = summary["grades"]["by_variant"]
    for key, item in sorted(summary["solver"]["by_variant"].items()):
        variant = key
        grade_item = grade_by_variant.get(key, {})
        lines.append(f"| {variant} | {item['ok']} | "
                     f"${item['total_cost_usd']:.4f} | "
                     f"{item['output_tokens']:,} | "
                     f"{item['reasoning_tokens']:,} | "
                     f"{item['median_wall_time_ms']:.0f} | "
                     f"{grade_item.get('ok', 0)} | "
                     f"{grade_item.get('success_rate', 0):.1%} | "
                     f"{grade_item.get('mean_score', 0):.2f} |")
    lines += [
        "",
        "## Cost And Effort By Model Profile",
        "",
        "| Profile | Variant | Responses | Cost | Median cost | Output tokens | Reasoning tokens | Median wall ms |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for key, item in sorted(summary["solver"]["by_profile_variant"].items()):
        profile, variant = key.split("|", 1)
        lines.append(f"| `{profile}` | {variant} | {item['ok']} | "
                     f"${item['total_cost_usd']:.4f} | "
                     f"${item['median_cost_usd']:.5f} | "
                     f"{item['output_tokens']:,} | "
                     f"{item['reasoning_tokens']:,} | "
                     f"{item['median_wall_time_ms']:.0f} |")
    lines += [
        "",
        "## By Category And Prompt Variant",
        "",
        "| Category | Variant | Answers | Success rate | Mean score |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for key, item in sorted(summary["grades"]["by_category_variant"].items()):
        category, variant = key.split("|", 1)
        lines.append(f"| {category} | {variant} | {item['ok']} | "
                     f"{item['success_rate']:.1%} | {item['mean_score']:.2f} |")
    lines += [
        "",
        "## By Difficulty And Prompt Variant",
        "",
        "| Difficulty | Variant | Answers | Success rate | Mean score |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for key, item in sorted(summary["grades"]["by_difficulty_variant"].items()):
        difficulty, variant = key.split("|", 1)
        lines.append(f"| {difficulty} | {variant} | {item['ok']} | "
                     f"{item['success_rate']:.1%} | {item['mean_score']:.2f} |")
    lines += [
        "",
        "## By Model Profile And Prompt Variant",
        "",
        "| Profile | Variant | Answers | Success rate | Mean score | Solver cost |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    solver_by_pv = summary["solver"]["by_profile_variant"]
    for key, item in sorted(summary["grades"]["by_profile_variant"].items()):
        profile, variant = key.split("|", 1)
        solver_item = solver_by_pv.get(key, {})
        lines.append(f"| `{profile}` | {variant} | {item['ok']} | "
                     f"{item['success_rate']:.1%} | {item['mean_score']:.2f} | "
                     f"${solver_item.get('total_cost_usd', 0):.4f} |")
    lines += [
        "",
        "Detailed CSV exports are in `reports/runs.csv` and `reports/grades.csv`.",
        "",
    ]
    write_text(result_dir / "summary.md", "\n".join(lines))


def format_status_counts(counts: dict) -> str:
    return ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keys", default="API_KEYS.md",
                        help="local provider key file, never written to outputs")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_selection(p: argparse.ArgumentParser) -> None:
        p.add_argument("--run-set", default="full", choices=("smoke", "full"))
        p.add_argument("--profiles", help="comma-separated profile IDs")
        p.add_argument("--cases", help="comma-separated public case IDs")
        p.add_argument("--variants", default="legacy,diagnostic",
                       help="comma-separated prompt variants")

    p = sub.add_parser("list-models")
    add_selection(p)
    p.set_defaults(func=cmd_list_models)

    p = sub.add_parser("estimate")
    add_selection(p)
    p.set_defaults(func=cmd_estimate)

    p = sub.add_parser("run")
    add_selection(p)
    p.add_argument("--results-root", default=str(DEFAULT_RESULTS_ROOT))
    p.add_argument("--out-dir")
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--only-failed", action="store_true",
                   help="with --out-dir, rerun only latest non-ok or missing rows")
    p.add_argument("--solver-max-output-tokens", type=int,
                   help="optional cap for smoke/debug runs; full eval should omit it")
    p.add_argument("--timeout-seconds", type=int, default=300)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("grade")
    p.add_argument("result_dir")
    p.set_defaults(func=cmd_grade)

    p = sub.add_parser("record-grade")
    p.add_argument("result_dir")
    p.add_argument("--profile", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--variant", required=True, choices=("legacy", "diagnostic"))
    p.add_argument("--score", required=True, type=int, choices=range(0, 5))
    p.add_argument("--verdict", required=True)
    p.add_argument("--strengths", default="")
    p.add_argument("--problems", default="")
    p.add_argument("--missing", default="")
    p.add_argument("--repair-summary", default="")
    p.set_defaults(func=cmd_record_grade)

    p = sub.add_parser("auto-grade")
    p.add_argument("result_dir")
    p.add_argument("--replace", action="store_true")
    p.set_defaults(func=cmd_auto_grade)

    p = sub.add_parser("summarize")
    p.add_argument("result_dir")
    add_selection(p)
    p.set_defaults(func=cmd_summarize)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
