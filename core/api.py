import requests
import time
import json
from .config import (
    ATTACKER_API_URL, ATTACKER_API_KEY, ATTACKER_MODEL_NAME,
    ANALYST_API_URL, ANALYST_API_KEY, ANALYST_MODEL_NAME,
    TARGET_API_URL, TARGET_API_KEY, TARGET_MODEL_NAME,
    LLAMA_GUARD3_URL, LLAMA_GUARD3_MODEL
)
from .rate_limit import RateLimiter
from .retry import AdaptiveRetry
from .datatypes import ScoreResult
import threading

print_lock = threading.Lock()

global_rate_limiter = RateLimiter(max_calls_per_second=1.5)
adaptive_retry = AdaptiveRetry()

def call_model_with_retry(messages, max_retries=3, retry_delay=2):
    api_name = "target_model"
    max_retries, base_delay = adaptive_retry.get_retry_params(api_name)
    payload = {
        "model": TARGET_MODEL_NAME,
        "messages": messages,
        "temperature": 0
    }
    headers = {
        "Authorization": f"Bearer {TARGET_API_KEY}",
        "Content-Type": "application/json"
    }
    for attempt in range(max_retries):
        global_rate_limiter.wait()
        try:
            response = requests.post(TARGET_API_URL, headers=headers, json=payload, timeout=60)
            if response.status_code == 429:
                delay = base_delay * (attempt + 2)
                with print_lock:
                    print(f"⚠️ API Rate Limit (429) hit, cooling down for {delay:.1f}s...")
                time.sleep(delay)
                continue
            response.raise_for_status()
            result = response.json()
            if "choices" in result and len(result["choices"]) > 0:
                adaptive_retry.record_success(api_name)
                return result["choices"][0]["message"]["content"]
            else:
                raise ValueError("Invalid response format")
        except Exception as e:
            if attempt < max_retries - 1:
                delay = base_delay * (attempt + 1)
                with print_lock:
                    print(f"API call failed (attempt {attempt+1}/{max_retries}): {e}, retrying in {delay:.1f} seconds")
                time.sleep(delay)
                continue
            else:
                adaptive_retry.record_failure(api_name)
                with print_lock:
                    print(f"API call failed, reached maximum retry attempts")
                return None
    return None

def call_analyst_model_with_retry(messages, max_retries=3, retry_delay=2):
    api_name = "analyst_model"
    max_retries, base_delay = adaptive_retry.get_retry_params(api_name)
    payload = {
        "model": ANALYST_MODEL_NAME,
        "messages": messages,
        "temperature": 0
    }
    headers = {
        "Authorization": f"Bearer {ANALYST_API_KEY}",
        "Content-Type": "application/json"
    }
    for attempt in range(max_retries):
        global_rate_limiter.wait()
        try:
            response = requests.post(ANALYST_API_URL, headers=headers, json=payload, timeout=60)
            if response.status_code == 429:
                delay = base_delay * (attempt + 2)
                with print_lock:
                    print(f"⚠️ Analyst API Rate Limit (429), cooling down...")
                time.sleep(delay)
                continue
            response.raise_for_status()
            result = response.json()
            if "choices" in result and len(result["choices"]) > 0:
                adaptive_retry.record_success(api_name)
                return result["choices"][0]["message"]["content"]
            else:
                raise ValueError("Invalid response format")
        except Exception as e:
            if attempt < max_retries - 1:
                delay = base_delay * (attempt + 1)
                time.sleep(delay)
                continue
            else:
                adaptive_retry.record_failure(api_name)
                return None
    return None

def call_attacker_model_with_retry(messages, max_retries=3, retry_delay=2):
    api_name = "attacker_model"
    max_retries, base_delay = adaptive_retry.get_retry_params(api_name)
    payload = {
        "model": ATTACKER_MODEL_NAME,
        "messages": messages,
        "temperature": 0
    }
    headers = {
        "Authorization": f"Bearer {ATTACKER_API_KEY}",
        "Content-Type": "application/json"
    }
    for attempt in range(max_retries):
        global_rate_limiter.wait()
        try:
            response = requests.post(ATTACKER_API_URL, headers=headers, json=payload, timeout=60)
            if response.status_code == 429:
                delay = base_delay * (attempt + 2)
                with print_lock:
                    print(f"⚠️ Attacker API Rate Limit (429), cooling down...")
                time.sleep(delay)
                continue
            response.raise_for_status()
            result = response.json()
            if "choices" in result and len(result["choices"]) > 0:
                adaptive_retry.record_success(api_name)
                return result["choices"][0]["message"]["content"]
            else:
                raise ValueError("Invalid response format")
        except Exception as e:
            if attempt < max_retries - 1:
                delay = base_delay * (attempt + 1)
                time.sleep(delay)
                continue
            else:
                adaptive_retry.record_failure(api_name)
                return None
    return None

def llama_guard3_check_with_retry(text, max_retries=3, retry_delay=2):
    payload = {
        "model": LLAMA_GUARD3_MODEL,
        "prompt": text,
        "stream": False
    }
    for attempt in range(max_retries):
        try:
            resp = requests.post(LLAMA_GUARD3_URL, json=payload, timeout=30)
            resp.raise_for_status()
            result = resp.json()
            label = result.get("response", "").strip().lower()
            with print_lock:
                print(f"LlamaGuard3 label: {label}")
            return label
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (attempt + 1))
                continue
            else:
                with print_lock:
                    print(f"LlamaGuard3 request failed: {e}")
                return None
    return None
