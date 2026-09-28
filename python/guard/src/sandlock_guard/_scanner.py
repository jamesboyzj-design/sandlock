# SPDX-License-Identifier: Apache-2.0
# Selected patterns adapted from InjectionGuard; modified scope and severity.
"""Dependency-free text inspection and a bounded stream worker.

Findings are heuristic indicators, not proof that text is malicious or safe.
The stream worker forwards original bytes only after a complete successful scan.
"""
from __future__ import annotations

import base64
import binascii
import html
import json
import math
import os
import re
import signal
import sys
import unicodedata
from dataclasses import dataclass, field
from collections import deque
from html.parser import HTMLParser
from typing import Optional, Tuple
from urllib.parse import unquote

if __package__:
    from ._classifier import Model
else:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _classifier import Model

_LEVELS = ('low', 'medium', 'high', 'critical')
_RULESET = '4'
_RULES = tuple((name, severity, re.compile(pattern, re.I), message)
    for name, severity, pattern, message in (
        ('instruction-override', 'high',
         r'\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:(?:your|the)\s+)?'
         r'(?:previous|prior|earlier|above|system|current)\s+(?:instructions?|rules?|prompts?|guidelines?|training)\b',
         'Instruction override request'),
        ('authority-command', 'high',
         r'\b(?:system|administrator|developer)\s+(?:directive|override|message)\b'
         r'[\s\S]{0,240}\b(?:must|execute|run|add|send|ignore)\b',
         'Claimed authority followed by a command'),
        ('code-insertion', 'high',
         r'\b(?:add|insert|place)\s+(?:the\s+)?following\s+code\b'
         r'[\s\S]{0,120}\b(?:script|program|top)\b',
         'Request to insert supplied code'),
        ('prompt-extraction', 'high',
         r'\b(?:show|reveal|display|output|print|repeat|dump|tell\s+me)\s+(?:me\s+)?'
         r'(?:your\s+(?:system\s+)?|the\s+system\s+)(?:prompt|instructions?|rules?|guidelines?)\b',
         'System prompt disclosure request'),
        ('role-delimiter', 'high',
         r'<\|(?:im_start|system|start_header_id)\|>|\[/?INST\]|<</?SYS>>',
         'Model instruction delimiter'),
        ('safety-override', 'high',
         r'\b(?:disable|remove|ignore|bypass|override)\s+'
         r'(?:(?:(?:your|the|all)\s+)?(?:safety(?:\s+(?:checks|filters|rules))?|'
         r'guardrails?|content\s+policy)|(?:your|all)\s+restrictions?)\b',
         'Request to disable safety controls'),
        ('concealed-action', 'medium',
         r'\bdo\s+not\s+(?:mention|disclose|reveal)\s+(?:it|this|the\s+action)\b',
         'Request to conceal an action'),
    ))
_RULES += tuple((name, level, re.compile(pattern, re.I), message)
    for name, level, pattern, message in (
        ('training-override', 'high', r'\bforget\s+(?:all\s+)?your\s+(?:training|rules)\b',
         'Request to discard governing constraints'),
        ('indirect-override', 'high', r'\b(?:set aside|do not follow|stop following)\s+(?:the\s+)?(?:earlier|previous|prior|system)\s+(?:directions|instructions|rules)\b',
         'Request to disregard earlier directions'),
        ('instruction-precedence', 'high', r'\b(?:supersedes?|replaces?|takes precedence over)\s+(?:all\s+)?(?:previous|system|prior)\s+(?:instructions|rules|prompts)\b',
         'Claim to supersede governing instructions'),
        ('unrestricted-persona', 'high', r'\b(?:you are now|act as|pretend|behave as|imagine you)\b.{0,100}\b(?:unrestricted|unfiltered|no restrictions|no safety rules)\b',
         'Unrestricted persona instruction'),
        ('privileged-mode', 'high', r'\b(?:switch|change|enter|enable)\s+(?:to\s+)?(?:developer|admin|unrestricted|jailbreak)\s+mode\b',
         'Privileged mode instruction'),
        ('system-replacement', 'high', r'\bnew\s+system\s+(?:instructions|prompt)\s*:',
         'Replacement system instructions'),
        ('instruction-extraction', 'high', r'\bwhat\s+(?:are|were)\s+your\s+(?:original\s+)?(?:instructions?|rules?|guidelines?|prompt)\b',
         'Request for governing instructions'),
        ('prompt-copy', 'high', r'\b(?:copy|paste|echo|dump)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions)\b',
         'Request to copy prompt content'),
        ('conversation-transfer', 'critical', r'\b(?:send|transmit|post|forward)\s+(?:all|the|this|my)\s+(?:\w+\s+){0,3}(?:conversation|messages|data)\s+to\b',
         'Request to transfer conversation or data'),
        ('secret-transfer', 'critical', r'\b(?:upload|send|post|transmit|forward|exfiltrate)\b.{0,100}\b(?:credentials|secrets?|api keys?|passwords?|tokens?)\b.{0,100}(?:https?://|\bto\b)',
         'Request to transfer sensitive data'),
        ('sensitive-tool', 'high', r'\b(?:call|invoke|execute|run)\s+(?:the\s+)?(?:tool|function|api|endpoint)\b.{0,140}(?:/secrets/|\.ssh/|\.env\b|password|credential)',
         'Tool instruction targeting sensitive data'),
        ('jailbreak-mode', 'high', r'\b(?:dan|jailbreak)\s+(?:mode|prompt)\b',
         'Jailbreak persona marker'),
        ('dan-persona', 'high', r'\b(?:you\s+are\s+now|act\s+as|behave\s+as)\s+(?:(?:a|an|the)\s+)?dan\b',
         'DAN persona instruction'),
        ('unrestricted-action', 'high', r'\b(?:do\s+anything\s+now|no\s+restrictions?\s+mode)\b',
         'Unrestricted action instruction'),
        ('response-hijack', 'medium', r'\b(?:continue|complete)\s+(?:the|this)\s+(?:response|output|text)\s+(?:with|by|as)\b',
         'Response continuation instruction'),
        ('conceal-from-user', 'high', r"\b(?:do not|don't|never)\s+(?:tell|inform|notify|show)\s+(?:the\s+)?(?:user|human|owner)\b",
         'Instruction to conceal activity from the user'),
        ('forged-authorization', 'high', r'\b(?:user|administrator|owner)\s+has\s+(?:authorized|approved)\b.{0,160}\b(?:credentials|secrets|upload|delete|execute)\b',
         'Claim of authorization for a sensitive action'),
        ('persistent-instruction', 'high', r'\b(?:remember|save|store)\s+(?:this|the)\s+(?:rule|instruction)\b.{0,100}\b(?:future|subsequent|every)\s+(?:conversations?|sessions?|requests?)\b',
         'Request to persist instructions across sessions'),
        ('forged-conversation', 'high', r'\b(?:assistant|system|developer)\s*:.{0,140}\b(?:permission|ignore|reveal|execute|override)\b',
         'Conversation role spoofing with an instruction'),
        ('model-boundary', 'high', r'<\|(?:user|assistant|im_end|endoftext|begin_of_text|end_header_id|eot_id)\|>',
         'Model message boundary marker'),
        ('xml-role', 'high', r'<\s{0,32}/?\s{0,32}(?:system|assistant|developer)\s{0,32}>',
         'Role tag in untrusted content'),
        ('section-boundary', 'high', r'(?:={3,32}|[-]{3,32})\s{0,32}(?:system|new|end)\s{0,32}(?:={3,32}|[-]{3,32})',
         'Forged instruction section boundary'),
        ('padding', 'low', r'\n{10,}|(.)\1{999,}',
         'Repetitive context padding'),
        ('invisible-unicode', 'low', r'[\u200b-\u200f\u2060\ufeff\u00ad\u202a-\u202c]',
         'Invisible Unicode formatting character'),
        ('unicode-direction-override', 'medium', r'[\u202d\u202e]',
         'Unicode direction override'),
    ))
_ENCODED = re.compile(r'[A-Za-z0-9+/_-]{24,}={0,2}|(?:\\x[0-9a-fA-F]{2}){4,}')
_ESCAPES = re.compile(r'\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})')
_CONFUSABLES = str.maketrans('аесорхуіјѕ', 'aecopxyijs')
_WORDS = ('ignore', 'previous', 'current', 'instructions', 'disregard', 'override', 'system', 'reveal')
_COLLAPSED_WORDS = {re.sub(r'(.)\1+', r'\1', word): word for word in _WORDS}
_SPACED = tuple((re.compile(r'\b' + r'[ ._-]+'.join(word) + r'\b'), word)
                for word in _WORDS)


class _MarkupText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)

    def handle_comment(self, data):
        self.parts.append(data)


def _canonical(text):
    text = unicodedata.normalize('NFKC', text).casefold().translate(_CONFUSABLES)
    text = ''.join(c for c in text if unicodedata.category(c) != 'Cf')
    for pattern, word in _SPACED:
        text = pattern.sub(word, text)

    def repair(match):
        word = match.group()
        if any(c.isdigit() for c in word):
            word = word.translate(str.maketrans('013457', 'oieast'))
        word = _COLLAPSED_WORDS.get(word, word)
        for target in _WORDS:
            if (len(word) == len(target) and word[0] == target[0]
                    and word[-1] == target[-1]
                    and sorted(word[1:-1]) == sorted(target[1:-1])):
                return target
        return word

    return re.sub(r'[a-z0-9]+', repair, text)


class ScanError(Exception):
    """Inspection could not complete; code is safe to log."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: str
    severity: str
    message: str
    _compiled: re.Pattern = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if not isinstance(self.id, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}', self.id):
            raise ValueError('Invalid rule ID')
        if self.severity not in _LEVELS:
            raise ValueError('Invalid rule severity')
        if not isinstance(self.message, str) or not self.message.strip():
            raise ValueError('Rule message must be a nonempty string')
        if not isinstance(self.pattern, str) or not self.pattern:
            raise ValueError('Rule pattern must be a nonempty string')
        try:
            compiled = re.compile(self.pattern, re.I)
        except re.error:
            raise ValueError('Invalid rule pattern') from None
        object.__setattr__(self, '_compiled', compiled)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str


@dataclass(frozen=True)
class ScanReport:
    flagged: bool
    findings: Tuple[Finding, ...]
    input_bytes: int
    ruleset_version: str = _RULESET
    model_score: Optional[float] = None
    model_digest: Optional[str] = None


@dataclass(frozen=True)
class PromptGuard:
    """Reusable text scanner configuration.

    scan() runs synchronously in the calling process without a wall-clock limit.
    scan_timeout is used only by the buffered stream worker after EOF.
    """

    threshold: str = 'medium'
    max_bytes: int = 1_048_576
    scan_timeout: float = 2.0
    rules: Tuple[Rule, ...] = ()
    model: Optional[str] = None
    _model: Optional[Model] = field(init=False, repr=False, compare=False, default=None)

    def __post_init__(self):
        if self.threshold not in _LEVELS:
            raise ValueError('Invalid threshold')
        if type(self.max_bytes) is not int or self.max_bytes <= 0:
            raise ValueError('max_bytes must be a positive integer')
        if (isinstance(self.scan_timeout, bool)
                or not isinstance(self.scan_timeout, (int, float))
                or not math.isfinite(self.scan_timeout) or self.scan_timeout <= 0):
            raise ValueError('scan_timeout must be positive and finite')
        rules = tuple(self.rules)
        ids = {name for name, _, _, _ in _RULES} | {'statistical-injection'}
        for rule in rules:
            if not isinstance(rule, Rule):
                raise TypeError('rules must contain Rule objects')
            if rule.id in ids:
                raise ValueError('Duplicate rule ID: ' + rule.id)
            ids.add(rule.id)
        object.__setattr__(self, 'rules', rules)
        if self.model is not None:
            path = os.path.realpath(os.fspath(self.model))
            object.__setattr__(self, 'model', path)
            object.__setattr__(self, '_model', Model.load(path))

    def scan(self, text: str) -> ScanReport:
        """Inspect text without changing it; raise ScanError on incomplete scans."""
        if not isinstance(text, str):
            raise TypeError('scan requires a Unicode string')
        if len(text) > self.max_bytes:
            raise ScanError('input_too_large')
        try:
            size = len(text.encode('utf-8'))
        except UnicodeError:
            raise ScanError('invalid_utf8') from None
        if size > self.max_bytes:
            raise ScanError('input_too_large')
        try:
            found = {}
            score = None
            rules = _RULES + tuple((r.id, r.severity, r._compiled, r.message) for r in self.rules)
            for view in self._views(text):
                for name, level, pattern, message in rules:
                    if pattern.search(view):
                        found[name] = Finding(name, level, message)
                if self._model is not None:
                    value = self._model.score(view)
                    score = value if score is None else max(score, value)
            if self._model is not None and score >= self._model.threshold:
                found['statistical-injection'] = Finding(
                    'statistical-injection', 'high', 'Statistical classifier threshold exceeded')
            findings = tuple(found.values())
            flagged = any(_LEVELS.index(f.severity) >= _LEVELS.index(self.threshold)
                          for f in findings)
            return ScanReport(flagged, findings, size, model_score=score,
                              model_digest=self._model.digest if self._model else None)
        except ScanError:
            raise
        except Exception:
            raise ScanError('scanner_failed') from None

    def _views(self, text):
        queue = deque([(text, 0)])
        seen = {text}
        candidates = set()
        used = len(text.encode('utf-8'))
        while queue:
            view, depth = queue.popleft()
            yield view
            derived = [_canonical(view), html.unescape(view), unquote(view)]
            if _ESCAPES.search(view):
                decoded = _ESCAPES.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), view)
                try:
                    decoded.encode('utf-8')
                except UnicodeError:
                    raise ScanError('invalid_encoding') from None
                derived.append(decoded)
            if '<' in view and '>' in view:
                parser = _MarkupText()
                parser.feed(view)
                parser.close()
                derived.extend((''.join(parser.parts), ' '.join(' '.join(parser.parts).split())))
            for match in _ENCODED.finditer(view):
                candidate = match.group()
                if candidate in candidates:
                    continue
                candidates.add(candidate)
                if len(candidates) > 64:
                    raise ScanError('processing_limit')
                try:
                    if candidate.startswith('\\x'):
                        decoded = bytes.fromhex(candidate.replace('\\x', '')).decode('utf-8')
                    else:
                        decoded = base64.b64decode(candidate + '=' * (-len(candidate) % 4),
                                                   altchars=b'-_', validate=True).decode('utf-8')
                except (ValueError, UnicodeError, binascii.Error):
                    continue
                derived.append(decoded)
            for value in derived:
                if value in seen:
                    continue
                used += len(value.encode('utf-8'))
                if depth >= 4 or len(seen) >= 32 or used > self.max_bytes * 8:
                    raise ScanError('processing_limit')
                seen.add(value)
                queue.append((value, depth + 1))


def _deadline(signum, frame):
    raise ScanError('scan_timeout')


def _main():
    try:
        rules = tuple(Rule(**r) for r in json.loads(sys.argv[4])) if len(sys.argv) > 4 else ()
        model = sys.argv[5] if len(sys.argv) > 5 else None
        guard = PromptGuard(sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), rules, model)
        if model is not None and guard._model.digest != sys.argv[6]:
            raise ScanError('model_changed')
        data = sys.stdin.buffer.read(guard.max_bytes + 1)
        if len(data) > guard.max_bytes:
            raise ScanError('input_too_large')
        try:
            text = data.decode('utf-8')
        except UnicodeError:
            raise ScanError('invalid_utf8') from None
        signal.signal(signal.SIGALRM, _deadline)
        signal.setitimer(signal.ITIMER_REAL, guard.scan_timeout)
        try:
            report = guard.scan(text)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        if report.flagged:
            print('sandlock guard: rejected (' + ', '.join(
                f.rule_id for f in report.findings) + ')', file=sys.stderr)
            return 1
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return 0
    except ScanError as exc:
        print('sandlock guard: ' + exc.code, file=sys.stderr)
        return 2
    except Exception:
        print('sandlock guard: worker_failed', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(_main())
