"""Bounded host guards and plain-text display for evidence-linked model advice.

Claims must first be independently matched to the current host card catalog by
the caller. This module does not decide freshness, authorization or truth. Its
shape, citation, numeric and recognizable-identity guards do not prove semantic
entailment: a model can misinterpret a source without introducing a new token.
Accepted prose therefore remains explicitly labeled model inference/advice.

Malformed sections are dropped individually. Oversized top-level inputs fail
closed as a whole; no partial model output is silently advertised as complete.
Model prose never supplies links: host-owned citation objects supply URLs.
"""
from __future__ import annotations

import json
import math
import re
import unicodedata

MAX_SECTIONS = 8
MAX_SECTION_CHARS = 1200
MAX_TOTAL_CHARS = 6000
MAX_CLAIMS = 64
MAX_CLAIM_REFS = 16
MAX_EVIDENCE_REFS = 128
_CLAIM_KEYS = frozenset({"id", "text", "evidence_ids", "entity_id", "predicate", "value"})
_SECTION_KEYS = frozenset({"kind", "text", "claim_ids", "evidence_ids"})
_KINDS = frozenset({"analysis", "recommendation", "uncertainty"})
_CLAIM_ID = re.compile(r"(?:event:[1-9]\d*:(?:fact|asset):(?:0|[1-9]\d*)|asset:counts)\Z")
_EVIDENCE_ID = re.compile(r"obs:[1-9]\d*:r:[1-9]\d*\Z")
_NUMBER = re.compile(r"(?<![A-Za-z\d])\d+(?:\.\d+)*(?![A-Za-z\d])")
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:[./:@+-][A-Za-z0-9_]+)*")
_IDENTIFIER = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}|"
    r"CWE-\d+|CAPEC-\d+|obs:\d+:r:\d+|event:\d+:(?:fact|asset):\d+|"
    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\b", re.I)
_LINK = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*://|\bwww\.|\b(?:mailto|javascript|data|file):|"
                   r"\[[^\]\n]{0,200}\]\s*\(|\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?:com|org|net|cn|io|dev|edu|gov|local|internal)\b)", re.I)
_MARKUP = re.compile(r"<\s*(?:/?[A-Za-z]|!|\?)|&(?:#\d+|#x[0-9a-f]+|[A-Za-z]+);", re.I)
_SECRET = re.compile(r"(?:\bsk[-_][A-Za-z0-9_-]{8,}|\b(?:api[_ -]?key|access[_ -]?token|authorization|password)\s*[:=]|\bBearer\s+\S+)", re.I)
_DIRECTIVE = re.compile(r"(?:忽略|忽视|绕过|覆盖).{0,24}(?:指令|规则|提示词|安全限制)|"
                        r"(?:输出|打印|泄露|发送).{0,24}(?:API\s*密钥|API\s*Key|系统提示词|全部原始清单)|"
                        r"(?:ignore|override|bypass).{0,32}(?:instructions|system\s+prompt|safety\s+rules)", re.I)
_LABEL_SPOOF = re.compile(r"(?:【|\[|#)\s*(?:已核验|已验证|verified|系统消息|system|assistant|developer)", re.I)
_METADATA_OVERCLAIM = re.compile(
    r"(?:已经?|已|确认|确定)?(?:阅读|读过|读完|审阅|核验)(?:过|了)?(?:其|该(?:资料|论文))?全文|"
    r"(?:完全|已经?|已|确认|确定)?(?:符合|满足)(?:现行|当前|全部|所有|适用)?(?:法律|法规|合规要求)|"
    r"(?:已经?|已|确认|确定)[^，。；！？\n]{0,8}(?:合规|合法)", re.I)
_SCORE = re.compile(r"(?:评分|分数|风险分|风险值|score)\s*(?:为|是|达到|[:：=])?\s*(\d+(?:\.\d+)?)|"
                    r"(\d+(?:\.\d+)?)\s*(?:/\s*10|分\b|(?:的)?\s*(?:CVSS\s*)?(?:评分|分数))", re.I)
_VERSION_AFTER_LABEL = re.compile(r"(?:版本|升级(?:到|至)|回退(?:到|至)|降级(?:到|至)|version|upgrade\s+to)\s*[:：为是]?\s*[vV]?(\d+(?:\.\d+)*(?:[-+][A-Za-z0-9.]+)?)", re.I)
_VERSION_BEFORE_LABEL = re.compile(r"(?<![\d.])[vV]?(\d+(?:\.\d+)*(?:[-+][A-Za-z0-9.]+)?)\s*(?:的)?(?:修复|补丁|软件|组件)?版本")
_CHINESE_NUMERIC = re.compile(r"(?:评分|分数|风险值|版本|升级到|升级至)\s*(?:为|是|[:：])?\s*[零〇一二三四五六七八九十百千万两]+(?:点[零〇一二三四五六七八九十]+)+")
_EXPLOIT_ASSERTION = re.compile(
    r"(?:已经?|已|确认|确定|证实|成功)(?:遭(?:到|受)?|被|发生|完成|受到)?(?:实际)?(?:利用|入侵|攻破|攻击|失陷)|"
    r"(?:确认|确定|证实)(?:存在|形成|具有)?(?:可利用(?:的)?攻击链|可利用性)|"
    r"(?:was|is|has\s+been|have\s+been|successfully|confirmed)\s+(?:already\s+)?(?:exploited|compromised|hacked)|"
    r"confirmed\s+exploitation|"
    r"(?:已经?|已|确认|确定|证实|成功)[^，。；！？\n]{0,12}(?:被(?:实际|在野)?利用|入侵|攻破|失陷|利用成功)|"
    r"存在[^，。；！？\n]{0,8}可利用(?:的)?攻击链|可以直接(?:利用|攻破)", re.I)
_NEGATIVE_PREFIX = re.compile(
    r"(?:不能|无法|未能|尚未|未|不|没有|无|缺少|缺乏|不足以|尚不)(?:据此)?"
    r"(?:证明|确认|认定|判断|判定|证实|说明|代表|表示|意味着|等于|支持|证据)(?:[^，。；！？\n]{0,16})$|"
    r"(?:no\s+evidence(?:\s+that)?|cannot\s+confirm|not\s+confirmed|does\s+not\s+(?:prove|mean)|"
    r"cannot\s+conclude)(?:[^.;!?\n]{0,40})$|"
    r"(?:不能|无法|尚未|未|不|没有|不足以)(?:据此)?$", re.I)
# Ordinary security vocabulary can describe conditional actions without naming
# a new product/asset. Arbitrary ASCII names and IDs require a cited host text.
_VOCABULARY = frozenset("ai llm rag api http https tls dns sbom json cvss poc cve cwe ip "
                        "cpu gpu cors csp waf acl sso mfa rbac abac iam soc csrf ssrf xss sql "
                        "ci cd id tcp udp rpc url audit log logs read write tool tools prompt "
                        "injection risk fix patch mitigation unknown version score evidence "
                        "if then should may might can cannot no not and or the a an of to in "
                        "for with from this that is are be been was were has have it its "
                        "confirm confirmed exploited exploitation compromised successfully "
                        "does prove mean conclude".split())
_LABELS = {
    "analysis": "模型分析（推断）",
    "recommendation": "模型修复建议（需核实适用条件）",
    "uncertainty": "模型不确定性说明",
}
_EMPTY = "当前快照没有能支持本题的有效事实。资料缺失、正在更新或判断未知均不能据此认定安全。"


def _normalized(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def _plain(text: str) -> bool:
    return not any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} and char not in "\n\t" for char in text)


def _bounded_value(value) -> bool:
    """Validate JSON without calling arbitrary objects or recursing unboundedly."""
    if type(value) is not dict:
        return False
    stack, nodes, characters = [(value, 0)], 0, 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > 4096 or depth > 12:
            return False
        if type(item) is dict:
            if len(item) > 256 or any(type(key) is not str for key in item):
                return False
            characters += sum(len(key) for key in item)
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            if len(item) > 256:
                return False
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            characters += len(item)
        elif type(item) in {int, float}:
            if type(item) is float and not math.isfinite(item):
                return False
            if type(item) is int and item.bit_length() > 256:
                return False
        elif item is not None and type(item) is not bool:
            return False
        if characters > 16384:
            return False
    return True


def _refs(values, pattern, cap) -> bool:
    return (type(values) is list and 0 < len(values) <= cap
            and all(type(item) is str and len(item) <= 128 and pattern.fullmatch(item) for item in values)
            and len(set(values)) == len(values))


def _catalog(claims) -> dict[str, dict]:
    if type(claims) is not list or len(claims) > MAX_CLAIMS:
        return {}
    result, ambiguous = {}, set()
    for claim in claims:
        if type(claim) is not dict or set(claim) != _CLAIM_KEYS:
            continue
        identifier = claim.get("id")
        if type(identifier) is not str or len(identifier) > 128 or not _CLAIM_ID.fullmatch(identifier):
            continue
        if identifier in result or identifier in ambiguous:
            result.pop(identifier, None)
            ambiguous.add(identifier)
            continue
        text, predicate = claim.get("text"), claim.get("predicate")
        if (type(text) is not str or not text.strip() or len(text) > 16384 or not _plain(text)
                or type(predicate) is not str or not 0 < len(predicate) <= 64
                or type(claim.get("entity_id")) is not int or claim["entity_id"] <= 0 or claim["entity_id"].bit_length() > 128
                or not _refs(claim.get("evidence_ids"), _EVIDENCE_ID, MAX_EVIDENCE_REFS)
                or not _bounded_value(claim.get("value"))):
            continue
        # No references to caller-owned containers survive this JSON copy.
        result[identifier] = json.loads(json.dumps(claim, ensure_ascii=False, allow_nan=False))
    return result


def _guard_text(text: str, cited: list[dict]) -> bool:
    body = _normalized(text)
    if (not _plain(body) or _LINK.search(body) or _MARKUP.search(body) or _SECRET.search(body)
            or _DIRECTIVE.search(body) or _LABEL_SPOOF.search(body)):
        return False
    # Only visible cited facts contribute prose tokens. Internal metadata,
    # implementation versions, locators and citation IDs are not fact prose.
    sources = [_normalized(claim["text"]) for claim in cited]
    source = "\n".join(sources)
    numbers = set(_NUMBER.findall(_IDENTIFIER.sub("", source)))
    if not set(_NUMBER.findall(_IDENTIFIER.sub("", body))) <= numbers:
        return False
    words = {word.casefold() for word in _WORD.findall(source)}
    if any(word.casefold() not in words and word.casefold() not in _VOCABULARY for word in _WORD.findall(body)):
        return False
    identities = {identifier.casefold() for identifier in _IDENTIFIER.findall(source)}
    if not {identifier.casefold() for identifier in _IDENTIFIER.findall(body)} <= identities:
        return False
    scores = set()
    versions = set()
    for claim, visible in zip(cited, sources):
        value = claim["value"]
        if claim["predicate"] == "cvss" and type(value.get("score")) in {int, float}:
            score = value["score"]
            if math.isfinite(score) and 0 <= score <= 10:
                scores.add(f"{score:g}")
        # Only explicit visible package/installed versions qualify as versions;
        # specification versions, dates and implementation metadata do not.
        fields = {"fix": ("patched_versions",), "affected_range": ("ranges", "range", "vulnerable_version_range", "exact_versions")}.get(claim["predicate"], ())
        for field in fields:
            raw = value.get(field)
            entries = [raw] if type(raw) is str else raw if type(raw) is list else []
            for entry in entries:
                if type(entry) is str and _normalized(entry) in visible:
                    versions.update(_NUMBER.findall(_normalized(entry)))
                    versions.add(_normalized(entry))
        if claim["predicate"] == "asset_assessment":
            for match in re.finditer(r"清单版本[:：]\s*([vV]?\d+[A-Za-z0-9.+_-]*)", visible):
                versions.add(match.group(1).removeprefix("v").removeprefix("V"))
    for match in _SCORE.finditer(body):
        if next(group for group in match.groups() if group is not None) not in scores:
            return False
    for pattern in (_VERSION_AFTER_LABEL, _VERSION_BEFORE_LABEL):
        for match in pattern.finditer(body):
            if match.group(1) not in versions:
                return False
    if any(match.group(0) not in source for match in _CHINESE_NUMERIC.finditer(body)):
        return False
    for match in _EXPLOIT_ASSERTION.finditer(body):
        prefix = body[max(0, match.start() - 80):match.start()]
        if not _NEGATIVE_PREFIX.search(prefix):
            # Model sections do not assert confirmed exploitation, even when a
            # source description might discuss it. The original host card stays.
            return False
    if any(claim["predicate"] == "source_metadata" for claim in cited):
        for match in _METADATA_OVERCLAIM.finditer(body):
            if not _NEGATIVE_PREFIX.search(body[max(0, match.start() - 80):match.start()]):
                return False
    return True


def validate_analysis_sections(sections, claims) -> list[dict]:
    """Return detached supported sections, dropping malformed/unsafe entries.

    Every section has exactly four fields. Its unique current claim references
    require the exact union of evidence references, without omissions/extras.
    The result provides citation/token guards, not a semantic correctness proof.
    Caller-owned verified claims are never changed or returned by reference.
    """
    if type(sections) is not list or len(sections) > MAX_SECTIONS:
        return []
    if sum(len(item.get("text", "")) for item in sections
           if type(item) is dict and type(item.get("text")) is str) > MAX_TOTAL_CHARS:
        return []
    catalog = _catalog(claims)
    if not catalog:
        return []
    result, seen = [], set()
    for section in sections:
        if type(section) is not dict or set(section) != _SECTION_KEYS:
            continue
        kind, text = section.get("kind"), section.get("text")
        if (type(kind) is not str or kind not in _KINDS or type(text) is not str
                or not text.strip() or len(text) > MAX_SECTION_CHARS):
            continue
        ids, refs = section.get("claim_ids"), section.get("evidence_ids")
        if (not _refs(ids, _CLAIM_ID, MAX_CLAIM_REFS) or not _refs(refs, _EVIDENCE_ID, MAX_EVIDENCE_REFS)
                or any(identifier not in catalog for identifier in ids)):
            continue
        cited = [catalog[identifier] for identifier in ids]
        expected = sorted({ref for claim in cited for ref in claim["evidence_ids"]})
        if set(refs) != set(expected) or not _guard_text(text, cited):
            continue
        text = text.strip()
        identity = (kind, text, tuple(ids), tuple(expected))
        if identity in seen:
            continue
        seen.add(identity)
        result.append({"kind": kind, "text": text, "claim_ids": list(ids), "evidence_ids": expected})
    return result


def compose_answer(claims, sections, *, empty_answer=None) -> str:
    """Deterministically display host facts separately from model suggestions.

    Return plain text; the UI must render it as text, not interpret Markdown or
    HTML. ``empty_answer`` is an optional host-owned absence message, never model
    prose. Analysis is revalidated here so unsupported sections cannot be saved
    by using this display function directly.
    """
    catalog = _catalog(claims)
    current = list(catalog.values())
    valid = validate_analysis_sections(sections, current)
    empty = empty_answer if type(empty_answer) is str and 0 < len(empty_answer) <= 8192 and _plain(empty_answer) else _EMPTY
    blocks = ["【已核验事实】\n" + ("\n".join(claim["text"] for claim in current) if current else empty)]
    for section in valid:
        blocks.append("【" + _LABELS[section["kind"]] + "】\n" + section["text"]
                      + "\n依据事实：" + "、".join(section["claim_ids"])
                      + "；证据：" + "、".join(section["evidence_ids"]))
    return "\n\n".join(blocks)
