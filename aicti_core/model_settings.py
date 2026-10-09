"""Host-owned model construction and public status; credentials stay in memory."""
from __future__ import annotations

import re

PROVIDERS = frozenset({"facts", "ollama", "deepseek", "mock"})
EFFORTS = frozenset({"none", "low", "high", "max"})
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9._-]+)?\Z")
_SECRET_MODEL = re.compile(r"(?:^|[/:-])(?:sk[-_]|bearer|api[-_]?key|password|access[-_]?token)",re.I)


def make_gateway(provider, *, model=None, api_key=None, reasoning_effort="none", existing=None):
    if type(provider) is not str or provider not in PROVIDERS:
        raise ValueError("Unsupported model provider")
    if type(reasoning_effort) is not str or reasoning_effort not in EFFORTS:
        raise ValueError("Unsupported reasoning effort")
    if model is not None and (type(model) is not str or len(model)>128 or not _MODEL.fullmatch(model) or _SECRET_MODEL.search(model)):
        raise ValueError("Invalid model name")
    if api_key is not None and (type(api_key) is not str or len(api_key)>512 or any(not 33<=ord(c)<=126 for c in api_key)):
        raise ValueError("Invalid model credential")
    if provider!="deepseek" and api_key is not None:
        raise ValueError("Credential is only accepted for DeepSeek")
    if provider=="facts":
        if model is not None or reasoning_effort!="none":
            raise ValueError("Facts mode has no model settings")
        return None
    if provider=="mock":
        if model not in (None,"mock-deepseek-v4-pro") or reasoning_effort!="none":
            raise ValueError("Mock configuration is fixed")
        from .mock_gateway import MockGateway
        return MockGateway()
    if provider=="deepseek":
        if model not in (None,"deepseek-v4-pro"):
            raise ValueError("Only the official requested model is supported")
        from .cloud_gateway import DeepSeekGateway
        # UI omission retains only this provider's explicit in-memory key.
        # A new UI configuration cannot accidentally discover an environment key.
        if api_key is None:
            api_key = getattr(existing,"_api_key","") if getattr(existing,"provider",None)=="deepseek" else ""
        return DeepSeekGateway(api_key,model="deepseek-v4-pro",timeout=20,reasoning_effort=reasoning_effort)
    if reasoning_effort!="none" or not model:
        raise ValueError("A local model name is required")
    from .gateway import ModelGateway
    return ModelGateway(model=model,timeout=8)


def public_model(gateway, *, generation=0, last_test=None):
    enabled = bool(gateway and getattr(gateway,"enabled",False))
    provider = getattr(gateway,"provider",None) if gateway else "facts"
    if provider not in PROVIDERS:
        provider = "ollama" if enabled else "facts"
    model = getattr(gateway,"model",None)
    if type(model) is not str or not _MODEL.fullmatch(model) or len(model)>128 or _SECRET_MODEL.search(model):
        model = None
    configured = bool(gateway and getattr(gateway,"configured",enabled))
    embedding = bool(gateway and getattr(gateway,"embedding_enabled",False))
    semantic = "mock_plan" if provider=="mock" else "llm_semantic" if provider=="deepseek" and enabled else "local_embedding" if embedding else "facts"
    endpoint = "https://api.deepseek.com/chat/completions" if provider=="deepseek" else "http://127.0.0.1:11434" if provider=="ollama" else None
    return {"provider":provider,"enabled":enabled,"configured":configured,
        "credential_configured":bool(provider=="deepseek" and configured),"model":model,
        "reasoning_effort":getattr(gateway,"reasoning_effort","none"),"semantic_mode":semantic,
        "embedding_enabled":embedding,"embedding_model":getattr(gateway,"embedding_model",None),
        "endpoint":endpoint,"generation":generation,"last_test":dict(last_test) if last_test else None,
        "mock":provider=="mock"}
