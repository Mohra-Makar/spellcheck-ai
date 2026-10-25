"""SpellCheck AI detection engine v1.

Pipeline: normalize -> match weighted regex rules on several text variants
-> sum weights -> block when score >= BLOCK_THRESHOLD.

Variants scanned: normalized text, leetspeak-decoded text, letter-squashed text
(catches "r e v e a l" style spacing) and decoded base64 blobs.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

from sensitive import find_sensitive

BLOCK_THRESHOLD = 5
MAX_SCAN_CHARS = 20_000

CAT_INJECTION = "injection"
CAT_LEAKING = "leaking"
CAT_JAILBREAK = "jailbreak"
CAT_ROLEPLAY = "roleplay"
CAT_SENSITIVE = "sensitive"

REASONS = {
    CAT_SENSITIVE: "OWASP LLM02: Sensitive Information in Prompt (secret or card number)",
    CAT_INJECTION: "OWASP LLM01: Direct Prompt Injection Detected",
    CAT_LEAKING: "OWASP LLM07: System Prompt Leaking Attempt",
    CAT_JAILBREAK: "OWASP LLM01: Jailbreak / Persona Override Detected",
    CAT_ROLEPLAY: "OWASP LLM01: Adversarial Roleplay Attempt Detected",
}

LLM01_URL = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
LLM07_URL = "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/"
LLM02_URL = "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"

# Shown to the user when a prompt is blocked: why it is dangerous + where to read more.
EXPLANATIONS = {
    CAT_INJECTION: (
        "This prompt tries to override the model's original instructions. Attackers use this to make "
        "the model ignore its safety rules or the developer's intent.", LLM01_URL),
    CAT_LEAKING: (
        "This prompt tries to make the model reveal its hidden system prompt, which can expose internal "
        "rules, secrets or business logic.", LLM07_URL),
    CAT_JAILBREAK: (
        "This prompt tries to switch the model into an unrestricted persona (such as DAN or developer "
        "mode) so it bypasses its safeguards.", LLM01_URL),
    CAT_ROLEPLAY: (
        "This prompt uses an adversarial persona to push the model into producing content it would "
        "normally refuse.", LLM01_URL),
    CAT_SENSITIVE: (
        "This prompt contains what looks like a secret (an API key, token, private key or card number). "
        "Sending it to an LLM can leak it into logs, provider storage or model replies. Remove it, and "
        "rotate it if it is real.", LLM02_URL),
}

# ---------------------------------------------------------------- normalization
_ZERO_WIDTH = dict.fromkeys(
    map(ord, "​‌‍‎‏⁠⁡⁢⁣⁤﻿­᠎"), None
)
# Cyrillic / Greek look-alikes that NFKC does not fold to Latin.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ɡ": "g",
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ρ": "p", "τ": "t", "υ": "u",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
# Arabic: drop diacritics (harakat, shadda, dagger alef) and tatweel; fold letter variants
# (alef forms -> alef, alef maqsura -> yeh, teh marbuta -> heh). Arabic rules below are
# written in this folded form.
_AR_STRIP = dict.fromkeys([*range(0x064B, 0x0660), 0x0670, 0x0640], None)
_AR_FOLD = str.maketrans({
    "أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا",
    "ى": "ي", "ة": "ه",
})


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_ZERO_WIDTH).translate(_HOMOGLYPHS)
    text = text.translate(_AR_STRIP).translate(_AR_FOLD)
    text = text.casefold()
    return re.sub(r"\s+", " ", text).strip()


def _squash(text: str) -> str:
    return re.sub(r"[\W_]+", "", text)


_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _base64_payloads(text: str) -> list[str]:
    out = []
    for token in _B64_RE.findall(text)[:10]:
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded and sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) > 0.95:
            out.append(normalize(decoded))
    return out


# ------------------------------------------------------------------------ rules
@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    weight: int
    pattern: re.Pattern


def _r(name, category, weight, pattern):
    return Rule(name, category, weight, re.compile(pattern, re.I))


_INSTR = r"(?:instructions?|rules?|commands?|directives?|guidelines?|prompts?|programming)"

RULES = [
    # ---- injection (LLM01)
    _r("inj_ignore_previous", CAT_INJECTION, 10,
       r"\b(?:ignore|disregard|forget|override|bypass|discard)\b\s+(?:\w+\s+){0,3}?"
       r"(?:previous|prior|above|earlier|preceding|original|all|every|your|system)\s+(?:\w+\s+){0,2}?" + _INSTR + r"\b"),
    _r("inj_forget_everything", CAT_INJECTION, 10,
       r"\b(?:forget|ignore|disregard)\s+(?:everything|anything|all)\s+(?:you\s+(?:were|have\s+been|had\s+been)\s+(?:told|given|instructed)|before|above)\b"),
    _r("inj_instructions_void", CAT_INJECTION, 10,
       r"\b(?:instructions?|rules?|directives?)\b[^.\n]{0,30}\b(?:are|is|were)\s+(?:now\s+)?(?:void|invalid|cancell?ed|obsolete|revoked)\b"
       r"|\bno\s+longer\s+apply\b"),
    _r("inj_new_instructions", CAT_INJECTION, 3, r"\b(?:new|updated)\s+(?:instructions?|rules?)\s*:"),
    # ---- system prompt leaking (LLM07)
    _r("leak_reveal_system_prompt", CAT_LEAKING, 10,
       r"\b(?:reveal|show|print|output|display|repeat|echo|leak|dump|tell|give|share|expose|recite|disclose)\b\s+(?:\w+\s+){0,3}?"
       r"(?:your|its|the|ur)\s+(?:\w+\s+){0,2}?(?:system|initial|original|hidden|secret|internal|developer)\s+"
       r"(?:prompt|message|instructions?|rules?|configuration|config)\b"),
    _r("leak_print_above", CAT_LEAKING, 10,
       r"\b(?:print|repeat|output|show|echo|copy|recite)\s+(?:\w+\s+){0,3}?"
       r"(?:everything|all|text|content|words|prompt|message)\s+(?:above|before)\b"),
    _r("leak_words_given", CAT_LEAKING, 10,
       r"\bwhat\s+(?:were|was|are)\s+(?:the\s+)?(?:exact\s+)?(?:words|instructions|rules|text)\s+you\s+(?:were|have\s+been)\s+given\b"),
    _r("leak_what_are_instructions", CAT_LEAKING, 3, r"\bwhat\s+are\s+your\s+(?:instructions|rules|guidelines)\b"),
    # ---- jailbreak / persona override (LLM01)
    _r("jb_developer_mode", CAT_JAILBREAK, 10,
       r"\byou\s+(?:are|will\s+be)\s+(?:\w+\s+){0,2}?(?:in\s+)?(?:developer|jailbreak|god|unrestricted)\s+mode\b"),
    _r("jb_enter_mode", CAT_JAILBREAK, 4,
       r"\b(?:switch\s+to|enter|enable|activate|turn\s+on)\s+(?:developer|jailbreak|god|unrestricted|dan)\s+mode\b"),
    _r("jb_dan", CAT_JAILBREAK, 10,
       r"\bdo\s+anything\s+now\b|\bdan\s+mode\b|\byou\s+are\s+dan\b|\bact\s+as\s+dan\b|\bdan\s+can\s+do\s+anything\b"),
    _r("jb_unfiltered", CAT_JAILBREAK, 10,
       r"\b(?:act|behave|respond|answer)\s+(?:as|like)\s+(?:an?\s+)?(?:\w+\s+){0,2}?(?:unfiltered|uncensored|unrestricted|unethical|jailbroken)\b"
       r"|\bai\s+(?:with|having)\s+no\s+(?:restrictions|rules|limits|filters|ethical\s+guidelines)"),
    _r("jb_no_rules", CAT_JAILBREAK, 10,
       r"\bpretend\s+(?:that\s+)?you\s+(?:have|had)\s+no\s+(?:rules|restrictions|limits|guidelines|filters)\b"),
    _r("jb_disable_safety", CAT_JAILBREAK, 4,
       r"\b(?:disable|turn\s+off|remove|bypass|circumvent|evade|get\s+around)\s+(?:\w+\s+){0,2}?(?:your|the|all)\s+(?:\w+\s+){0,2}?"
       r"(?:content\s+policy|safety|safeguards?|filters?|restrictions?|guardrails?|moderation)\b"),
    # ---- adversarial roleplay (LLM01)
    _r("rp_persona", CAT_ROLEPLAY, 5,
       r"\b(?:you\s+are|you're|act\s+as|pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as|imagine\s+you\s+are|play\s+the\s+role\s+of|behave\s+as)\s+"
       r"(?:\w+\s+){0,2}?(?:an?\s+)?(?:\w+\s+){0,2}?(?:hacker|attacker|adversary|malicious\s+actor|threat\s+actor|black[- ]hat)\b"),
    _r("rp_simulate_attack", CAT_ROLEPLAY, 3, r"\bsimulate\s+(?:an?\s+)?(?:cyber\s*)?attack\b"),

    # ================= Arabic (patterns are in the folded form produced by normalize) =================
    # ---- injection
    _r("ar_inj_ignore", CAT_INJECTION, 10,
       r"\b(?:تجاهل|تجاهلي|اهمل|انس|انسي|تخطي|الغ|الغي|تجاوز)\s+(?:\S+\s+){0,3}?"
       r"(?:التعليمات|القواعد|الاوامر|الارشادات|التوجيهات|القوانين)(?!\w)"),
    _r("ar_inj_forget_everything", CAT_INJECTION, 10,
       r"\b(?:انس|انسي|تجاهل|تجاهلي)\s+(?:كل|جميع)\s+ما\s+(?:قيل|طلب|اعطي|اخبر|كتب|سبق)\w*"),
    # ---- system prompt leaking
    _r("ar_leak_system", CAT_LEAKING, 10,
       r"\b(?:اكشف|اظهر|اعرض|اطبع|اخبرني|قل|اعطني|شارك|كرر|انسخ|سرب|ترجم)\s+(?:\S+\s+){0,3}?"
       r"(?:موجه|رساله|رسائل|تعليمات|قواعد|اعدادات|توجيهات|برومبت|تهيئه)\s+(?:ال)?نظام"),
    _r("ar_leak_own_instructions", CAT_LEAKING, 10,
       r"\b(?:اكشف|اظهر|اعرض|اطبع|اخبرني|قل|اعطني|شارك|كرر|انسخ)\s+(?:\S+\s+){0,2}?"
       r"(?:تعليماتك|قواعدك|اوامرك|توجيهاتك)\s*(?:ال)?(?:اوليه|مخفيه|سريه|داخليه|اساسيه|اصليه)"),
    _r("ar_leak_print_above", CAT_LEAKING, 10,
       r"\b(?:اطبع|اعرض|كرر|انسخ)\s+(?:\S+\s+){0,3}?(?:النص|الكلام|المحتوي)\s+(?:الذي\s+)?(?:فوق|اعلاه|قبل)"),
    _r("ar_leak_what_are_instructions", CAT_LEAKING, 3,
       r"\bما\s+(?:هي\s+)?(?:تعليماتك|قواعدك|توجيهاتك)"),
    # ---- jailbreak / persona override
    _r("ar_jb_developer_mode", CAT_JAILBREAK, 10,
       r"\bانت\s+(?:الان\s+)?(?:في\s+)?وضع\s+(?:المطور|المطورين|جيلبريك|غير\s+مقيد)"),
    _r("ar_jb_enter_mode", CAT_JAILBREAK, 4,
       r"\bو?(?:فعل|شغل|ادخل\s+في|انتقل\s+الي)\s+وضع\s+(?:المطور|المطورين|جيلبريك|dan)"),
    _r("ar_jb_dan", CAT_JAILBREAK, 10,
       r"\bانت\s+(?:الان\s+)?dan\b|\bو?(?:افعل|فعل)\s+اي\s+شيء\s+الان|وضع\s+dan\b"),
    _r("ar_jb_unrestricted", CAT_JAILBREAK, 10,
       r"\b(?:تصرف|اجب|رد|اعمل)\s+(?:ك\S*|مثل\s+\S+)\s+(?:\S+\s+){0,3}?(?:بلا|بدون|غير)\s+"
       r"(?:قيود|قواعد|فلاتر|مقيد|اخلاقيات)"),
    _r("ar_jb_no_rules", CAT_JAILBREAK, 10,
       r"\bتظاهر\s+(?:بان\S*|ان\S*)\s+(?:ليس\s+لديك|لا\s+تملك|ليس\s+عندك)\s+(?:اي\s+)?"
       r"(?:قواعد|قيود|قوانين|تعليمات)"),
    _r("ar_jb_disable_safety", CAT_JAILBREAK, 4,
       r"\bو?(?:اوقف|عطل|الغ|الغي|تجاوز|تخطي|اطفئ|ازل)\s+(?:\S+\s+){0,2}?"
       r"(?:سياسه\s+المحتوي|الحمايه|الفلاتر|الضوابط|الامان|قيود\S*|مرشحات)"),
    # ---- adversarial roleplay
    _r("ar_rp_persona", CAT_ROLEPLAY, 5,
       r"\b(?:انت|تخيل\s+انك|تظاهر\s+بانك|العب\s+دور|تصرف\s+(?:ك|كانك|مثل))\s*(?:\S+\s+){0,2}?"
       r"(?:هاكر|مخترق|مهاجم|قرصان)"),
]

# Long phrases matched on the letter-squashed text ("r e v e a l y o u r ...").
_SQUASHED = {
    "ignorepreviousinstructions": CAT_INJECTION, "ignoreallpreviousinstructions": CAT_INJECTION,
    "ignorepriorinstructions": CAT_INJECTION, "disregardpriorrules": CAT_INJECTION,
    "disregardpreviousinstructions": CAT_INJECTION, "overridesysteminstructions": CAT_INJECTION,
    "ignoreallpreviouscommands": CAT_INJECTION,
    "revealyoursystemprompt": CAT_LEAKING, "showmeyourinitialprompt": CAT_LEAKING,
    "outputyourfullsystemmessage": CAT_LEAKING, "printthepromptabove": CAT_LEAKING,
    "younowindevelopermode": CAT_JAILBREAK, "youareinnowdevelopermode": CAT_JAILBREAK,
    "actasanunfilteredai": CAT_JAILBREAK, "pretendyouhavenorules": CAT_JAILBREAK,
}

# Third-person / educational framing. It only lowers the score by a little, so a
# strong rule on its own still blocks (otherwise "explain: ignore previous
# instructions" would be a trivial bypass).
_MENTION_CONTEXT = re.compile(
    r"\b(?:defend|defen[cs]e|protect|prevent|detect|mitigat\w*|training|awareness|tabletop|regex|"
    r"explain|what\s+is|what\s+does|how\s+(?:does|do)|example\s+of|owasp|"
    r"(?:people|users|attackers?|hackers?)\s+(?:who\s+)?(?:try|tries|trying|attempt)\w*)\b",
    re.I,
)
_MENTION_CONTEXT_AR = re.compile(r"(?:حمايه|احمي|دفاع|تدريب|توعيه|اشرح|تعبير\s+منتظم|regex|مثال\s+علي)")
_MENTION_DISCOUNT = 3


@dataclass
class Detection:
    blocked: bool
    score: int
    category: str | None
    reason: str
    threat_level: str
    matches: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    explanation: str = ""
    learn_more: str = ""


def _variants(text: str):
    norm = normalize(text)
    leet = norm.translate(_LEET)
    yield "normalized", norm
    if leet != norm:
        yield "leet", leet
    for i, decoded in enumerate(_base64_payloads(text)):
        yield "base64", decoded
        leet_dec = decoded.translate(_LEET)
        if leet_dec != decoded:
            yield "base64", leet_dec


def _analyze_rules(text: str) -> Detection:
    text = text[:MAX_SCAN_CHARS]
    hits: dict[str, Rule] = {}
    techniques: set[str] = set()

    for technique, variant in _variants(text):
        for rule in RULES:
            if rule.name not in hits and rule.pattern.search(variant):
                hits[rule.name] = rule
                if technique != "normalized":
                    techniques.add(technique)

    # letter-spaced / punctuation-split phrases
    norm = normalize(text)
    for squashed in {_squash(norm), _squash(norm.translate(_LEET))}:
        for phrase, cat in _SQUASHED.items():
            key = f"squashed:{phrase}"
            if phrase in squashed and key not in hits and not any(
                r.category == cat and r.weight >= 10 for r in hits.values()
            ):
                hits[key] = Rule(key, cat, 10, re.compile(phrase))
                techniques.add("squashed")

    score = sum(r.weight for r in hits.values())
    if score and (_MENTION_CONTEXT.search(norm) or _MENTION_CONTEXT_AR.search(norm)):
        score -= _MENTION_DISCOUNT

    if score < BLOCK_THRESHOLD:
        return Detection(False, max(score, 0), None, "Clean Prompt", "LOW", sorted(hits), sorted(techniques))

    by_cat: dict[str, int] = {}
    for r in hits.values():
        by_cat[r.category] = by_cat.get(r.category, 0) + r.weight
    category = max(by_cat, key=by_cat.get)
    reason = REASONS[category] + (" (obfuscated)" if techniques else "")
    if category == CAT_LEAKING and score >= 10:
        level = "CRITICAL"
    elif score >= 10:
        level = "HIGH"
    else:
        level = "MEDIUM"
    explanation, learn_more = EXPLANATIONS[category]
    return Detection(True, score, category, reason, level, sorted(hits), sorted(techniques),
                     explanation, learn_more)


def analyze(text: str) -> Detection:
    """Run the prompt rules, then the secret / card scan (LLM02) on the original text."""
    result = _analyze_rules(text)
    kinds = sorted({kind for kind, _, _ in find_sensitive(text[:MAX_SCAN_CHARS])})
    if not kinds:
        return result
    matches = sorted(set(result.matches) | {f"sensitive:{k}" for k in kinds})
    if result.blocked:  # already blocked for an injection-type reason: keep it, note the secret too
        result.matches = matches
        return result
    explanation, learn_more = EXPLANATIONS[CAT_SENSITIVE]
    return Detection(True, 10, CAT_SENSITIVE, REASONS[CAT_SENSITIVE], "HIGH",
                     matches, result.techniques, explanation, learn_more)


def analyze_prompt_security(prompt: str):
    """Backwards-compatible tuple API used by the original main.py."""
    d = analyze(prompt)
    return d.blocked, d.reason, d.threat_level
