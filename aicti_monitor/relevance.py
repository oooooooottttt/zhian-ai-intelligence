"""Explainable, offline AI relevance rules for normalized monitoring records.

The score describes relevance to AI, not severity or exploitability. Upstream
text is treated only as data; no instructions in it are interpreted or executed.
"""

from __future__ import annotations

import re
from typing import Any

from .models import Record


def _term(expression: str) -> re.Pattern[str]:
    # ASCII boundaries also recognize English terms next to Chinese characters.
    return re.compile(r"(?<![a-z0-9_])(?:" + expression + r")(?![a-z0-9_])", re.I)


_COMPONENTS = {
    "PyTorch": _term(r"pytorch|torch(?:vision|audio|serve)?"),
    "TensorFlow": _term(r"tensorflow|tf[-_]keras|keras"),
    "Transformers": _term(r"(?:hugging[ -]?face(?:/transformers)?|transformers)"),
    "LangChain": _term(r"langchain(?:[-_]community|[-_]core)?|langgraph"),
    "LlamaIndex": _term(r"llama[-_]?index"),
    "vLLM": _term(r"vllm"),
    "Ollama": _term(r"ollama"),
    "ONNX": _term(r"onnx(?:runtime)?"),
    "scikit-learn": _term(r"scikit[-_]learn|sklearn"),
    "MLflow": _term(r"mlflow"),
    "Ray AI": _term(r"ray[ ._-](?:serve|train|tune|rllib)"),
    "Triton inference": _term(r"(?:nvidia[ -])?triton[ -](?:inference|server)"),
    "BentoML": _term(r"bentoml"),
    "Stable Diffusion": _term(r"stable[ -]diffusion|diffusers|comfyui"),
    "OpenAI SDK": _term(r"openai|chatgpt"),
    "LiteLLM": _term(r"litellm"),
    "Gradio": _term(r"gradio"),
    "XGBoost": _term(r"xgboost|lightgbm"),
    "PaddlePaddle": _term(r"paddlepaddle"),
}

_CONCEPTS = {
    "large language model": _term(r"llms?|large[ -]language[ -]models?"),
    "artificial intelligence": _term(r"artificial[ -]intelligence|generative[ -]ai"),
    "machine learning": _term(r"machine[ -]learning|deep[ -]learning"),
    "neural network": _term(r"neural[ -]networks?"),
    "retrieval augmented generation": _term(r"retrieval[ -]augmented[ -]generation"),
    "AI agent": _term(r"(?:ai|llm)[ -]agents?|agentic[ -]ai"),
    "model training": _term(r"model[ -](?:training|inference|weights)"),
}

_CHINESE_CONCEPTS = {
    "人工智能": "人工智能",
    "大语言模型": "大语言模型",
    "大模型": "大模型",
    "机器学习": "机器学习",
    "深度学习": "深度学习",
    "神经网络": "神经网络",
    "生成式AI": "生成式AI",
    "模型训练": "模型训练",
    "模型推理": "模型推理",
}

_BEHAVIORS = {
    "prompt injection": re.compile(r"prompt[ -]injection|提示(?:词)?注入", re.I),
    "model jailbreak": re.compile(r"(?:llm|model|chatbot)[ -]jailbreak|jailbreak(?:ing)?[ -](?:llm|model|chatbot)|模型越狱|大模型越狱", re.I),
    "training data poisoning": re.compile(r"(?:training[ -]data|model|dataset)[ -]poisoning|训练数据投毒|模型投毒", re.I),
    "model extraction": re.compile(r"model[ -](?:extraction|stealing)|模型(?:提取|窃取)", re.I),
    "model inversion": re.compile(r"model[ -]inversion|membership[ -]inference|模型反演|成员推断", re.I),
    "adversarial examples": re.compile(r"adversarial[ -](?:examples?|perturbations?)|对抗样本", re.I),
    "model supply chain": re.compile(r"model[ -]supply[ -]chain|模型供应链", re.I),
}

_RISKS = {
    "prompt_injection": _BEHAVIORS["prompt injection"],
    "jailbreak": _BEHAVIORS["model jailbreak"],
    "data_poisoning": _BEHAVIORS["training data poisoning"],
    "model_theft": _BEHAVIORS["model extraction"],
    "privacy_leakage": re.compile(r"model[ -]inversion|membership[ -]inference|(?:data|information|secret)[ -](?:leak(?:age)?|exfiltration|disclosure)|模型反演|成员推断|数据泄露|信息泄露", re.I),
    "adversarial_attack": _BEHAVIORS["adversarial examples"],
    "code_execution": re.compile(r"(?:remote|arbitrary)[ -]code[ -]execution|\bRCE\b|(?:unsafe|insecure)[ -]deseriali[sz]ation|代码执行|不安全反序列化", re.I),
    "denial_of_service": re.compile(r"denial[ -]of[ -]service|\bDoS\b|拒绝服务", re.I),
    "supply_chain": re.compile(r"supply[ -]chain|dependency[ -]confusion|供应链|依赖混淆", re.I),
    "access_control": re.compile(r"authentication[ -]bypass|authorization[ -]bypass|(?:privilege[ -]escalation)|认证绕过|权限提升|未授权访问", re.I),
}

_AI_WORD = _term(r"ai")
_AI_CONTEXT = _term(r"model|models|training|inference|chatbot|agents?|security|safety|systems?|governance|policy|standard")


def classify(record: Record) -> dict[str, Any]:
    """Return deterministic relevance, supporting reasons, and risk labels.

    Only title, summary, and component names are evidence. URLs, aliases, and
    arbitrary metadata cannot promote a record merely because they contain AI.
    A standalone AI abbreviation needs context; a bare ML, RAG, or Ray does not
    suffice. Risks are returned only for records with positive AI evidence.
    """
    text = "\n".join([record.title, record.summary, *record.components])
    reasons: list[str] = []
    weights: list[float] = []
    for name, pattern in _COMPONENTS.items():
        if pattern.search(text):
            # Transformers is also an electrical term. Require an explicit
            # package name or ML context when it is the only generic word.
            if name == "Transformers" and not (
                any(_term(r"transformers").search(c) for c in record.components)
                or re.search(r"hugging[ -]?face", text, re.I)
                or re.search(r"(?:language|neural|attention|model|nlp|机器学习|模型)", text, re.I)
            ):
                continue
            reasons.append(f"Known AI component: {name}")
            weights.append(0.95)
    for name, pattern in _CONCEPTS.items():
        if pattern.search(text):
            reasons.append(f"AI concept: {name}")
            weights.append(0.85)
    for name, phrase in _CHINESE_CONCEPTS.items():
        if phrase.casefold() in text.casefold():
            reasons.append(f"AI concept: {name}")
            weights.append(0.85)
    for name, pattern in _BEHAVIORS.items():
        if pattern.search(text):
            reasons.append(f"AI security behavior: {name}")
            weights.append(0.90)
    if _AI_WORD.search(text) and (
        _AI_CONTEXT.search(text)
        or re.search(r"模型|训练|推理|安全|治理|政策|标准|智能体", text)
    ):
        reasons.append("AI abbreviation with model, system, or security context")
        weights.append(0.70)
    related = bool(weights)
    return {
        "is_ai_related": related,
        "score": round(min(1.0, max(weights, default=0.0) + 0.01 * max(0, len(weights) - 1)), 2),
        "reasons": reasons or ["No explicit AI component, concept, or security behavior found"],
        "risk_categories": [name for name, pattern in _RISKS.items() if related and pattern.search(text)],
    }
