"""Pattern checks for risky code in JavaScript/TypeScript, HTML and PHP.

These are leads for a human, not verdicts. The checks that produce the most
noise in plain-JS apps are HTML sinks (``innerHTML = `...${x}...` ``), so for
those the value written is parsed and each interpolated expression is judged:
anything passed through an escaping helper, numbers, string literals and calls
to HTML-producing helpers are not reported. What remains is the raw data
written as HTML, which is where cross-site scripting comes from.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import CodeFinding, downgrade
from .walker import CODE_EXT, is_test_path, iter_files, looks_generated

JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html", ".htm"}

# ── expression reading ─────────────────────────────────────────────────────
_OPEN = {"(": ")", "[": "]", "{": "}"}
_CLOSE = {")", "]", "}"}
_CONTINUES = set("+-*/%=&|?:,.([{<>!")


def _skip_string(text: str, i: int) -> int:
    """``text[i]`` is a quote; return the index after the closing quote."""
    q = text[i]
    i += 1
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if q == "`" and c == "$" and text.startswith("${", i):
            i = _skip_braces(text, i + 1)
            continue
        if c == q:
            return i + 1
        if c == "\n" and q != "`":
            return i
        i += 1
    return i


def _skip_braces(text: str, i: int) -> int:
    """``text[i]`` is ``{``; return the index after its matching ``}``."""
    depth = 0
    while i < len(text):
        c = text[i]
        if c in "'\"`":
            i = _skip_string(text, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return i


def read_expr(text: str, start: int, limit: int = 8000) -> str:
    """Read one JS expression starting at ``start``: up to ``;``, an unbalanced
    closing bracket, a top-level comma, or a line break that ends the statement."""
    i, depth, end = start, 0, min(len(text), start + limit)
    last = ""
    while i < end:
        c = text[i]
        if c in "'\"`":
            i = _skip_string(text, i)
            last = c
            continue
        if c in _OPEN:
            depth += 1
        elif c in _CLOSE:
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and c in ";,":
            break
        elif depth == 0 and c == "\n" and last and last not in _CONTINUES:
            nxt = text[i + 1:i + 200].lstrip()
            if not nxt or nxt[0] not in "+-*/%&|?:.":
                break
        if not c.isspace():
            last = c
        i += 1
    return text[start:i].strip()


def template_parts(expr: str) -> tuple[list[str], list[str]]:
    """Split an expression into (leaf interpolations, leaves that start a URL attribute).

    Interpolations that themselves contain template literals (``items.map(i =>
    `<li>${esc(i)}</li>`).join('')``) are descended into, so the leaves are the
    expressions whose value is actually written."""
    leaves: list[str] = []
    urls: list[str] = []
    i = 0
    while i < len(expr):
        c = expr[i]
        if c == "`":
            j = i + 1
            buf: list[str] = []
            while j < len(expr) and expr[j] != "`":
                if expr[j] == "\\":
                    buf.append(expr[j:j + 2])
                    j += 2
                    continue
                if expr.startswith("${", j):
                    k = _skip_braces(expr, j + 1)
                    inner = expr[j + 2:k - 1]
                    if "`" in inner and not _CALLS_KNOWN.match(inner):
                        sub_leaves, sub_urls = template_parts(inner)
                        leaves += sub_leaves
                        urls += sub_urls
                    else:
                        leaves.append(inner.strip())
                        if _URL_ATTR.search("".join(buf)[-60:]) and not _SAFE_URL.search(inner):
                            urls.append(inner.strip())
                    buf.append("\x00")
                    j = k
                    continue
                buf.append(expr[j])
                j += 1
            i = j + 1
            continue
        if c in "'\"":
            i = _skip_string(expr, i)
            continue
        i += 1
    return leaves, urls


def _calls_known(s: str) -> bool:
    return bool(_ESCAPED.match(s) or _HTML_HELPER.match(s) or _NUM_FORMAT.match(s))


class _Known:
    match = staticmethod(_calls_known)


_CALLS_KNOWN = _Known()
_URL_ATTR = re.compile(r"""(?:href|src|action|formaction|xlink:href)\s*=\s*["']?$""", re.I)
_SAFE_URL = re.compile(r"(?i)(safe|sanitiz|clean|valid|allow|trusted)\w*(url|href|link|uri)|"
                       r"encodeURIComponent|URL\.createObjectURL|blob|dataUrl|objectUrl")


_ESCAPED = re.compile(
    r"""^\s*(?:await\s+)?(?:[\w$]+\.)*(?:esc\w*|escape\w*|\w*Escape\w*|sanitiz\w*|\w*Sanitiz\w*|purify\w*|"""
    r"""encode\w*|h|e|attr|safe\w*|DOMPurify\.sanitize|textContent)\s*\(""", re.I)
_NUMERIC = re.compile(
    r"""^\s*(?:[\d\s.+\-*/%()]+|[\w$.?!\[\]]*\.(?:length|size|count|toFixed\(\d*\)|toLocaleString\([^)]*\))|"""
    r"""(?:Math|Number|parseInt|parseFloat)\b.*|\w*(?:Count|count|Total|total|Index|index|idx|Width|width|"""
    r"""Height|height|Pct|pct|Percent|percent|Px|px|Size|size|Num|num|Ms|ms)|[ijn])\s*$""")
_LITERAL_ONLY = re.compile(r"""^\s*(?:(['"])[^'"]*\1|null|undefined|true|false|''|"")\s*$""")
_LIT = r"""(?:(['"`])[^'"`$]*\{n}|-?\d+(?:\.\d+)?|null|''|"")"""
_TERNARY_LITERALS = re.compile(
    r"""^[^?]+\?\s*""" + _LIT.format(n=1) + r"""\s*:\s*""" + _LIT.format(n=2) + r"""\s*$""")
_BOOLEAN = re.compile(r"""^[^?'"`]*(?:===|!==|==|!=|>=|<=|\s[<>]\s|^!)[^?'"`]*$""")
_ARITH = re.compile(r"""^[\w$.\[\]]+\s*[-+*/%]\s*\d+(?:\.\d+)?$""")
_NUM_FORMAT = re.compile(
    r"""^\s*(?:[\w$]+\.)*(?:num|fmt\w*|format\w*|pct|percent\w*|px|round\w*|clamp|toFixed|"""
    r"""money|currency|bytes|humanSize|duration|relTime|timeAgo|date\w*)\s*\(""", re.I)
_HTML_VAR = re.compile(
    r"""^(?:[\w$]+\.)*(?:\w*(?:html|Html|HTML|markup|Markup|tpl|Tpl|svg|Svg|SVG|icon|Icon)\w*|"""
    r"""(?:icons?|ICONS?|Icons?)(?:\.\w+|\[[^\]]+\])|rows|cells|items|options|opts|out|parts|chunks)$""")
_HTML_HELPER = re.compile(
    r"""^\s*(?:await\s+)?(?:[\w$]+\.)*(?:icon|svg|render|html|template|tpl|markup|view|partial|badge|"""
    r"""avatar|button|btn|row|item|card|chip|pill|tag|cell|list|section|field|input|option|options|"""
    r"""spinner|empty)\w*\s*\(|^\s*(?:[\w$]+\.)*(?:t|tr|i18n|__|\w*(?:Html|HTML|Svg|SVG|Markup))\s*\(""",
    re.I)
_JOINED = re.compile(r"""\.join\(\s*(?:['"`]{2})?\s*\)\s*$""")  # pre-built HTML fragments
_DATA_HINT = re.compile(
    r"""(?i)\.(name|title|subject|body|text|content|message|msg|description|desc|label|value|comment|"""
    r"""note|notes|email|html|summary|bio|address|filename|file_?name|query|search|reply|caption)\b|"""
    r"""\b(query|search|params|location|hash|input|user\w*|customer\w*|requester\w*|data)\b""")


def judge(leaf: str) -> str:
    """'safe', 'helper' or 'raw' for one written expression."""
    s = leaf.strip()
    if not s:
        return "safe"
    if (_ESCAPED.match(s) or _LITERAL_ONLY.match(s) or _NUMERIC.match(s)
            or _TERNARY_LITERALS.match(s) or _BOOLEAN.match(s) or _ARITH.match(s)
            or _NUM_FORMAT.match(s)):
        return "safe"
    if _HTML_HELPER.match(s) or _JOINED.search(s) or _HTML_VAR.match(s):
        return "helper"
    return "raw"


# ── rules ──────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    cwe: str
    pattern: re.Pattern[str]
    langs: str = "js"     # js | php
    sink: bool = False    # value after the match is HTML: analyse its interpolations
    message: str = ""


def _r(p: str) -> re.Pattern[str]:
    return re.compile(p)


RULES: list[Rule] = [
    Rule("js.html-sink.innerhtml", "Unescaped data written as HTML", "medium", "CWE-79",
         _r(r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*"), sink=True),
    Rule("js.html-sink.insertadjacent", "Unescaped data written as HTML", "medium", "CWE-79",
         _r(r"\.insertAdjacentHTML\s*\(\s*[^,()]+,\s*"), sink=True),
    Rule("js.html-sink.document-write", "Unescaped data written as HTML", "medium", "CWE-79",
         _r(r"\bdocument\.write(?:ln)?\s*\(\s*"), sink=True),
    Rule("js.html-sink.dangerously", "Unescaped data written as HTML", "medium", "CWE-79",
         _r(r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*"), sink=True),
    Rule("js.html-sink.srcdoc", "Unescaped data written into an iframe document", "medium", "CWE-79",
         _r(r"\.srcdoc\s*=(?!=)\s*"), sink=True),
    Rule("js.html-sink.contextual-fragment", "Unescaped data parsed as HTML", "medium", "CWE-79",
         _r(r"\.createContextualFragment\s*\(\s*"), sink=True),
    Rule("js.eval", "Dynamic code execution (eval)", "high", "CWE-95",
         _r(r"(?<![\w.$])(?<!async )(?<!\* )eval\s*\((?![^()\n]*\)\s*[:{])")),
    Rule("js.new-function", "Dynamic code execution (new Function)", "medium", "CWE-95",
         _r(r"\bnew\s+Function\s*\(")),
    Rule("js.string-timer", "String passed to setTimeout/setInterval", "medium", "CWE-95",
         _r(r"\bset(?:Timeout|Interval)\s*\(\s*['\"`]")),
    Rule("js.postmessage-wildcard", "postMessage to any origin", "low", "CWE-201",
         _r(r"\.postMessage\s*\([^;]*,\s*['\"]\*['\"]\s*\)"),
         message="Data sent with target origin '*' can be read by whatever page embeds or opened "
                 "this one. Name the expected origin if the message carries anything private."),
    Rule("js.weak-random", "Math.random() used for a security value", "medium", "CWE-338",
         _r(r"(?i)\b(?:token|secret|nonce|passw\w*|salt|session\w*|invite\w*|otp|apikey|api_key|"
            r"linkkey|link_key|accesskey|access_key)\b[^\n]{0,80}Math\.random\(\)|"
            r"Math\.random\(\)[^\n]{0,80}\b(?:token|secret|nonce|passw\w*|salt|session|invite|otp)\b"),
         message="Math.random() is predictable. Use crypto.getRandomValues() or "
                 "crypto.randomUUID() for anything an attacker must not guess."),
    Rule("js.cors-wildcard", "CORS allows any origin", "low", "CWE-942",
         _r(r"""(?i)['"]?access-control-allow-origin['"]?\s*[:,]\s*['"]\*['"]"""),
         message="Any website can read these responses from a visitor's browser. Fine for public "
                 "data; a problem if responses depend on the visitor's cookies or tokens."),
    # PHP / Laravel
    Rule("php.blade-unescaped", "Unescaped Blade output {!! !!}", "medium", "CWE-79",
         _r(r"\{!!\s*(?!\s*(?:csrf_field|method_field|\$slot\b|__\(|trans\(|json_encode|"
            r"\$attributes|config\(|asset\(|route\(|url\(|vite|\$__))[^!]+!!\}"), langs="php"),
    Rule("php.raw-sql-interpolation", "SQL built from a PHP variable", "high", "CWE-89",
         _r(r"""(?:DB::(?:raw|select|statement|unprepared|insert|update|delete)|"""
            r"""->(?:whereRaw|orWhereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw|fromRaw))\s*\(\s*"""
            r"""(?:"[^"]*\$\w|'[^']*'\s*\.\s*\$)"""), langs="php",
         message="Variables inside raw SQL can be used to change the query. Use bindings "
                 "(whereRaw('col = ?', [$value]))."),
    Rule("php.command-exec", "Command or code execution with a variable", "high", "CWE-78",
         _r(r"(?<![\w>$:])(?:eval|exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*[\"']?[^)]*\$"),
         langs="php"),
    Rule("php.unserialize-input", "unserialize() on request data", "high", "CWE-502",
         _r(r"unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)|unserialize\s*\(\s*\$request->"),
         langs="php"),
    Rule("php.echo-request", "Request data echoed without escaping", "high", "CWE-79",
         _r(r"(?:echo|print)\s+\$_(?:GET|POST|REQUEST|COOKIE)\["), langs="php"),
]

_MESSAGE_LISTENER = re.compile(
    r"""(?<![\w.])(?:window\.)?addEventListener\s*\(\s*['"]message['"]|\bwindow\.onmessage\s*=""")


def _in_comment(text: str, pos: int) -> bool:
    """Cheap check: the match sits after // or on a /* … */ continuation line."""
    line_start = text.rfind("\n", 0, pos) + 1
    prefix = text[line_start:pos].lstrip()
    return prefix.startswith(("*", "/*", "//", "#")) or "//" in prefix.split("'")[0].split('"')[0]


def _lang(path: Path) -> str | None:
    ext = path.suffix.lower()
    if ext == ".php":
        return "php"
    if ext in JS_EXT:
        return "js"
    return None


def _line_starts(text: str) -> list[int]:
    return [0] + [m.end() for m in re.finditer("\n", text)]


def _short(s: str, n: int = 80) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def scan_text(text: str, rel: str, lang: str) -> list[CodeFinding]:
    if looks_generated(text):
        return []
    starts = _line_starts(text)
    lines = text.splitlines()
    test = is_test_path(rel)
    out: list[CodeFinding] = []

    def add(rule_id: str, title: str, severity: str, cwe: str, pos: int, message: str,
            confidence: str = "medium", data: dict[str, Any] | None = None) -> None:
        line = bisect.bisect_right(starts, pos)
        snippet = lines[line - 1].strip()[:200] if line - 1 < len(lines) else ""
        out.append(CodeFinding(
            check="sast", rule_id=rule_id, title=title,
            severity=downgrade(severity, 2) if test else severity, file=rel, line=line,
            snippet=snippet, cwe=cwe, confidence=confidence,
            message=message + (" (test code)" if test else ""), data={**(data or {}), "in_tests": test},
        ))

    for rule in RULES:
        if rule.langs != lang:
            continue
        for m in rule.pattern.finditer(text):
            if rule.sink:
                expr = read_expr(text, m.end())
                if not expr.startswith(("`", "'", '"')) and _calls_known(expr):
                    continue
                leaves, urls = template_parts(expr)
                if not leaves and "`" not in expr:
                    # Not a template: a literal, a concatenation or a variable.
                    if _LITERAL_ONLY.match(expr) or not expr:
                        continue
                    parts = [p for p in re.split(r"\s\+\s", expr) if not _LITERAL_ONLY.match(p)]
                    leaves = parts or [expr]
                raw = [lf for lf in leaves if judge(lf) == "raw"]
                if raw:
                    hinted = [lf for lf in raw if _DATA_HINT.search(lf)]
                    add(rule.id, rule.title, rule.severity, rule.cwe, m.start(),
                        "Written as HTML without an escaping helper: "
                        + ", ".join(_short(lf, 60) for lf in raw[:3])
                        + (f" (+{len(raw) - 3} more)" if len(raw) > 3 else "")
                        + ". If any of it can come from another user, this is cross-site scripting.",
                        confidence="medium" if hinted else "low",
                        data={"unescaped": [_short(lf, 120) for lf in raw[:10]]})
                for u in urls:
                    add("js.html-sink.url-scheme", "URL attribute built from data", "low", "CWE-79",
                        m.start(),
                        f"href/src starts with {_short(u, 60)}. HTML escaping does not stop a "
                        "'javascript:' URL; check the scheme is http(s) before writing it.",
                        confidence="low", data={"value": _short(u, 120)})
                continue
            if _in_comment(text, m.start()):
                continue
            add(rule.id, rule.title, rule.severity, rule.cwe, m.start(),
                rule.message or rule.title + ".", confidence="medium")

    if lang == "js":
        for m in _MESSAGE_LISTENER.finditer(text):
            body = text[m.end():m.end() + 1500]
            ref = re.match(r"\s*,\s*(?:this\.)?([A-Za-z_$][\w$]*)\s*[,)]", body)
            if ref:  # handler passed by name: check its definition instead
                d = re.search(rf"(?:function\s+{re.escape(ref.group(1))}\b|\b{re.escape(ref.group(1))}\s*[=:(])", text)
                if d:
                    body = text[d.end():d.end() + 1500]
            if not re.search(r"\.origin\b|\.source\b|\borigin\s*[!=]==?", body):
                add("js.message-no-origin-check", "Message handler does not check the sender",
                    "medium", "CWE-346", m.start(),
                    "A window 'message' handler that never reads event.origin accepts messages "
                    "from any site that can open or frame this page.")
        # CORS with credentials turns a wildcard into a real problem.
        if re.search(r"(?i)access-control-allow-credentials['\"]?\s*[:,]\s*['\"]?true", text):
            for f in out:
                if f.rule_id == "js.cors-wildcard":
                    f.severity = "high"
    return out


def scan(root: Path, include_tests: bool = True) -> list[CodeFinding]:
    root = root.resolve()
    base = root if root.is_dir() else root.parent
    findings: list[CodeFinding] = []
    for path, text in iter_files(root, CODE_EXT, skip_tests=not include_tests):
        lang = _lang(path)
        if lang:
            findings += scan_text(text, str(path.relative_to(base)), lang)
    return findings
