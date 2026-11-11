"""Report generation: text, JSON and standalone HTML."""

from __future__ import annotations

import html
import json
from collections import Counter, OrderedDict
from datetime import datetime, timezone

from . import __version__
from .rules import RULES_BY_ID, SEVERITY_ORDER
from .scanner import ScanResult
from .theme import AMBIENT_HTML, CSS_CORE, CSS_REPORT, HEAD_JS, JS_3D, JS_UI, font_css

DISCLAIMER = (
    "QuantumShield is a pattern-based scanner. It can miss real issues and "
    "can flag harmless code. A clean result does not prove that code is safe. "
    "Use it as a starting point for a cryptographic inventory, not as a "
    "substitute for a security review."
)

SEVERITY_LABEL = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO",
}

CATEGORY_LABEL = {
    "quantum": "Quantum-vulnerable",
    "classical": "Classically weak / hygiene",
    "pqc": "Post-quantum references",
}

ANSI = {
    "critical": "\033[1;95m", "high": "\033[1;91m", "medium": "\033[93m",
    "low": "\033[96m", "info": "\033[92m", "dim": "\033[2m",
    "bold": "\033[1m", "reset": "\033[0m",
}


def summarize(result: ScanResult) -> dict:
    by_sev = Counter(f.severity for f in result.findings)
    by_cat = Counter(f.category for f in result.findings)
    actionable = [f for f in result.findings if f.severity != "info"]
    if any(f.severity in ("critical", "high") for f in actionable):
        verdict = "Action needed"
    elif actionable:
        verdict = "Review recommended"
    else:
        verdict = "No findings from this rule set"
    return {
        "total": len(result.findings),
        "by_severity": {s: by_sev.get(s, 0) for s in SEVERITY_ORDER if s in by_sev or s != "info"},
        "by_category": dict(by_cat),
        "verdict": verdict,
    }


# ---------------------------------------------------------------- text

def text_report(result: ScanResult, color: bool = False) -> str:
    def c(key: str, text: str) -> str:
        return f"{ANSI[key]}{text}{ANSI['reset']}" if color else text

    summary = summarize(result)
    out = []
    out.append(c("bold", f"QuantumShield {__version__}"))
    out.append(f"Scanned: {result.root}")
    out.append(f"Files scanned: {result.files_scanned}   Skipped: {result.files_skipped}")
    out.append("")
    out.append(c("bold", f"Verdict: {summary['verdict']}"))
    sev = summary["by_severity"]
    out.append(
        "  " + "   ".join(f"{SEVERITY_LABEL[s]}: {sev.get(s, 0)}" for s in ("critical", "high", "medium", "low"))
        + f"   INFO: {sum(1 for f in result.findings if f.severity == 'info')}"
    )
    out.append("")

    if not result.findings:
        out.append("No findings.")
    for f in result.findings:
        label = c(f.severity, f"[{SEVERITY_LABEL[f.severity]}]")
        out.append(f"{label} {f.rule_id} {f.title}")
        out.append(f"    {f.file}:{f.line}")
        out.append(c("dim", f"    {f.snippet}"))

    seen = OrderedDict()
    for f in result.findings:
        seen.setdefault(f.rule_id, f)
    if seen:
        out.append("")
        out.append(c("bold", "Recommended actions"))
        for rule_id, f in seen.items():
            if f.severity == "info":
                continue
            out.append(f"  {rule_id} {f.title}")
            out.append(f"      Why: {f.why}")
            out.append(f"      Fix: {f.fix}")
    out.append("")
    out.append(c("dim", DISCLAIMER))
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- json

def json_report(result: ScanResult) -> str:
    payload = {
        "tool": "quantumshield",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summarize(result),
        "disclaimer": DISCLAIMER,
        **result.to_dict(),
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------- html

SEV_VAR = {
    "critical": "var(--critical)", "high": "var(--high)", "medium": "var(--medium)",
    "low": "var(--low)", "info": "var(--info)",
}


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _italic_last_word(text: str) -> str:
    head, _, last = text.rpartition(" ")
    if not head:
        return f"<em>{_esc(text)}</em>"
    return f"{_esc(head)} <em>{_esc(last)}</em>"


def html_report(result: ScanResult) -> str:
    from .report3d import html_report_3d
    return html_report_3d(result, summarize(result), DISCLAIMER)


def _html_report_legacy(result: ScanResult) -> str:
    summary = summarize(result)
    sev = summary["by_severity"]
    info_count = sum(1 for f in result.findings if f.severity == "info")
    verdict_color = {
        "Action needed": "var(--high)",
        "Review recommended": "var(--medium)",
    }.get(summary["verdict"], "var(--info)")
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    p = []
    p.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    p.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    p.append(HEAD_JS)
    p.append("<title>QuantumShield Report</title>")
    p.append(f"<style>{font_css()}{CSS_CORE}{CSS_REPORT}</style></head><body>")
    p.append(AMBIENT_HTML)
    p.append("<div class='wrap'>")

    # hero
    p.append("<section class='hero'><div>")
    p.append("<div class='eyebrow'>Cryptographic exposure report</div>")
    p.append("<h1 class='display' data-split>Quantum<em>Shield</em></h1>")
    p.append(
        f"<p class='lead'>{result.files_scanned} files scanned, {summary['total']} findings. "
        "Results are pattern-based, so review each one before acting.</p>"
    )
    p.append(
        f"<div class='meta mono'>{_esc(result.root)}<br>v{_esc(__version__)} &middot; {_esc(stamp)}</div>"
    )
    p.append(
        "</div><div class='stage'><canvas id='qs3d' aria-hidden='true'></canvas>"
        "<i class='corner tl'></i><i class='corner tr'></i><i class='corner bl'></i><i class='corner br'></i>"
        "<span class='tag'>Illustration</span></div></section>"
    )

    # verdict + tiles
    p.append(
        f"<div class='verdict glass rv' style='--vc:{verdict_color}'>"
        f"<div><div class='vt'>{_italic_last_word(summary['verdict'])}</div>"
        f"<div class='muted' style='margin-top:6px'>{result.files_skipped} files skipped</div></div></div>"
    )
    p.append("<div class='tiles'>")
    delay = 0.0
    for s in ("critical", "high", "medium", "low"):
        p.append(
            f"<div class='tile glass tilt rv' style='--c:{SEV_VAR[s]};--d:{delay:.2f}s'>"
            f"<div class='n' data-to='{sev.get(s, 0)}'>{sev.get(s, 0)}</div>"
            f"<div class='l'>{SEVERITY_LABEL[s]}</div></div>"
        )
        delay += 0.07
    p.append(
        f"<div class='tile glass tilt rv' style='--c:{SEV_VAR['info']};--d:{delay:.2f}s'>"
        f"<div class='n' data-to='{info_count}'>{info_count}</div><div class='l'>PQC refs</div></div></div>"
    )

    # toolbar
    p.append("<div class='toolbar glass'>")
    p.append("<input id='q' type='search' placeholder='Search findings  ( / )' aria-label='Search findings'>")
    p.append("<div class='fb'><button class='on' data-filter='all'>All</button>")
    for s in ("critical", "high", "medium", "low", "info"):
        p.append(f"<button data-filter='{s}'>{SEVERITY_LABEL[s]}</button>")
    p.append(f"</div><div class='cnt'><b id='cnt'>{summary['total']}</b> shown</div></div>")

    # findings
    grouped = OrderedDict()
    for f in result.findings:
        grouped.setdefault(f.category, []).append(f)
    if not result.findings:
        p.append("<div class='empty glass'>No findings from this rule set.</div>")
    for cat in ("quantum", "classical", "pqc"):
        items = grouped.get(cat)
        if not items:
            continue
        p.append(
            f"<h2 class='cat' data-cat='{cat}'><span>{len(items):02d}</span>{_esc(CATEGORY_LABEL[cat])}</h2>"
        )
        for f in items:
            loc = f"{f.file}:{f.line}"
            p.append(
                f"<article class='f glass rv' data-sev='{f.severity}' data-catof='{cat}' "
                f"style='--c:{SEV_VAR[f.severity]}'>"
                f"<div class='top'><span class='chip'>{SEVERITY_LABEL[f.severity]}</span>"
                f"<span class='rid mono'>{_esc(f.rule_id)}</span></div>"
                f"<h3>{_esc(f.title)}</h3>"
                f"<div class='loc mono'><span>{_esc(loc)}</span>"
                f"<button class='copy' type='button' data-copy='{_esc(loc)}'>Copy</button></div>"
                f"<pre>{_esc(f.snippet)}</pre>"
                f"<details><summary>Why it matters and how to fix</summary>"
                f"<p><i>Why</i>{_esc(f.why)}</p><p><i>Fix</i>{_esc(f.fix)}</p></details></article>"
            )
    p.append("<div id='empty' class='empty glass hide'>No findings match your search or filter.</div>")

    p.append(f"<div class='disc'>{_esc(DISCLAIMER)}</div>")
    p.append("<div class='foot'>QUANTUMSHIELD &middot; OPEN SOURCE &middot; MIT</div>")
    p.append(f"</div><script>{JS_3D}{JS_UI}</script></body></html>")
    return "".join(p)
