# SPDX-License-Identifier: Apache-2.0
"""Inference for exported binary character n-gram logistic regression models."""
import hashlib
import json
import math
import unicodedata
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

FORMAT = 'sandlock-char-logistic-v1'
WINDOW = 512
STRIDE = 256
MAX_FEATURES = 20000
MAX_MODEL_BYTES = 2 * 1024 * 1024


def normalize(text):
    return ' '.join(unicodedata.normalize('NFKC', text).casefold().split())


def features(text):
    return {text[i:i + n] for n in (3, 4, 5) for i in range(len(text) - n + 1)}


def windows(text):
    text = normalize(text)
    for start in range(0, max(1, len(text) - WINDOW + STRIDE), STRIDE):
        yield text[start:start + WINDOW]


def _number(value):
    return type(value) in (int, float) and abs(value) <= 1000 and math.isfinite(value)


@dataclass(frozen=True)
class Model:
    intercept: float
    threshold: float
    weights: Mapping[str, float]
    digest: str

    @classmethod
    def load(cls, path):
        with open(path, 'rb') as source:
            raw = source.read(MAX_MODEL_BYTES + 1)
        if len(raw) > MAX_MODEL_BYTES:
            raise ValueError('Model exceeds size limit')
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get('format') != FORMAT:
            raise ValueError('Unsupported model format')
        intercept, threshold, weights = (data.get(k) for k in ('intercept', 'threshold', 'weights'))
        if not _number(intercept) or not _number(threshold) or not 0 < threshold < 1:
            raise ValueError('Invalid model intercept or threshold')
        if not isinstance(weights, dict) or not 0 < len(weights) <= MAX_FEATURES:
            raise ValueError('Invalid model vocabulary size')
        if any(not 3 <= len(k) <= 5 or not _number(v) for k, v in weights.items()):
            raise ValueError('Invalid model feature or weight')
        return cls(intercept, threshold, MappingProxyType(weights), hashlib.sha256(raw).hexdigest())

    def score(self, text):
        highest = -math.inf
        for window in windows(text):
            logit = self.intercept + math.fsum(self.weights.get(f, 0.0) for f in features(window))
            highest = max(highest, logit)
        if highest >= 0:
            return 1 / (1 + math.exp(-highest))
        exp = math.exp(highest)
        return exp / (1 + exp)
