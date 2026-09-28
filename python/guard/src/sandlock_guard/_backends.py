# SPDX-License-Identifier: Apache-2.0
"""Serializable classifier configurations for direct and sandboxed scans."""
import hashlib
import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import ClassVar, Optional, Tuple

if __package__:
    from ._classifier import Model
else:
    from _classifier import Model


def _threshold(value):
    if type(value) not in (int, float) or not 0 < value < 1:
        raise ValueError('Classifier threshold must be between 0 and 1')


@dataclass(frozen=True)
class StatisticalClassifier:
    """Character n-gram classifier loaded from an existing guard-model.json."""
    path: str
    threshold: Optional[float] = None
    _model: Model = field(init=False, repr=False, compare=False)
    rule_id: ClassVar[str] = 'statistical-injection'
    message: ClassVar[str] = 'Statistical classifier threshold exceeded'
    memory: ClassVar[str] = '256M'

    def __post_init__(self):
        if self.threshold is not None:
            _threshold(self.threshold)
        object.__setattr__(self, 'path', os.path.realpath(os.fspath(self.path)))
        object.__setattr__(self, '_model', Model.load(self.path))
        if self.threshold is None:
            object.__setattr__(self, 'threshold', self._model.threshold)

    @property
    def digest(self):
        return self._model.digest

    def score(self, text):
        return self._model.score(text)

    def _config(self):
        return dict(kind='statistical', path=self.path, threshold=self.threshold, digest=self.digest)


def _model_digest(path):
    root = Path(path)
    required = ('config.json', 'model.safetensors', 'tokenizer.json')
    optional = ('tokenizer_config.json', 'special_tokens_map.json', 'added_tokens.json')
    names = sorted(required + tuple(name for name in optional if (root / name).exists()))
    digest = hashlib.sha256()
    total = 0
    for name in names:
        source = root / name
        if source.is_symlink() or not source.is_file():
            raise ValueError('Transformer model files must be regular local files: ' + name)
        size = source.stat().st_size
        total += size
        if total > 2 * 1024 ** 3:
            raise ValueError('Transformer model exceeds 2 GiB limit')
        digest.update((name + '\0' + str(size) + '\0').encode())
        with source.open('rb') as stream:
            remaining = size
            while remaining:
                chunk = stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError('Transformer model changed while reading')
                digest.update(chunk)
                remaining -= len(chunk)
            if stream.read(1):
                raise ValueError('Transformer model changed while reading')
    return digest.hexdigest()


@dataclass(frozen=True)
class TransformersClassifier:
    """Offline CPU inference for local, mutually exclusive text classifiers."""
    path: str
    positive_labels: Tuple[str, ...]
    threshold: float = 0.5
    max_length: int = 512
    stride: int = 256
    digest: str = field(init=False)
    _runtime: object = field(init=False, default=None, repr=False, compare=False)
    _lock: object = field(init=False, default_factory=Lock, repr=False, compare=False)
    rule_id: ClassVar[str] = 'transformers-injection'
    message: ClassVar[str] = 'Transformers classifier threshold exceeded'
    memory: ClassVar[str] = '2G'

    def __post_init__(self):
        _threshold(self.threshold)
        if isinstance(self.positive_labels, str):
            raise ValueError('positive_labels must be a sequence of label names')
        labels = tuple(self.positive_labels)
        if (not labels or any(not isinstance(label, str) or not label for label in labels)
                or len(set(labels)) != len(labels)):
            raise ValueError('positive_labels must contain unique nonempty label names')
        if (type(self.max_length) is not int or not 4 <= self.max_length <= 8192
                or type(self.stride) is not int or not 0 <= self.stride < self.max_length):
            raise ValueError('Invalid classifier window length or stride')
        object.__setattr__(self, 'positive_labels', labels)
        object.__setattr__(self, 'path', os.path.realpath(os.fspath(self.path)))
        object.__setattr__(self, 'digest', _model_digest(self.path))

    def _config(self):
        return dict(kind='transformers', path=self.path, threshold=self.threshold, digest=self.digest,
                    positive_labels=self.positive_labels, max_length=self.max_length, stride=self.stride)

    def _load(self):
        with self._lock:
            if self._runtime is not None:
                return self._runtime
            if _model_digest(self.path) != self.digest:
                raise ValueError('Transformer model changed before loading')
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            tokenizer = AutoTokenizer.from_pretrained(
                self.path, local_files_only=True, trust_remote_code=False, use_fast=True)
            model = AutoModelForSequenceClassification.from_pretrained(
                self.path, local_files_only=True, trust_remote_code=False, use_safetensors=True)
            labels = model.config.id2label
            if (model.config.num_labels < 2
                    or set(labels) != set(range(model.config.num_labels))
                    or len(set(labels.values())) != model.config.num_labels
                    or not set(self.positive_labels) < set(labels.values())
                    or model.config.problem_type not in (None, 'single_label_classification')):
                raise ValueError('Expected a mutually exclusive classifier with configured positive labels')
            if not tokenizer.is_fast or self.stride >= self.max_length - tokenizer.num_special_tokens_to_add():
                raise ValueError('Tokenizer cannot support the configured overlapping windows')
            limit = getattr(model.config, 'max_position_embeddings', None)
            if isinstance(limit, int) and self.max_length > limit:
                raise ValueError('Window length exceeds model position limit')
            model.to('cpu').eval()
            if _model_digest(self.path) != self.digest:
                raise ValueError('Transformer model changed while loading')
            object.__setattr__(self, '_runtime', (tokenizer, model))
            return self._runtime

    def score(self, text):
        import torch

        tokenizer, model = self._load()
        positive = [key for key, value in model.config.id2label.items() if value in self.positive_labels]
        encoded = tokenizer(text, truncation=True, max_length=self.max_length, stride=self.stride,
                            return_overflowing_tokens=True, padding=True, return_tensors='pt')
        encoded.pop('overflow_to_sample_mapping', None)
        highest = 0.0
        with torch.inference_mode():
            for start in range(0, len(encoded['input_ids']), 4):
                batch = {name: values[start:start + 4] for name, values in encoded.items()}
                scores = model(**batch).logits.softmax(dim=-1)[:, positive].sum(dim=-1)
                if not torch.isfinite(scores).all().item():
                    raise ValueError('Nonfinite classifier output')
                highest = max(highest, scores.max().item())
        if not math.isfinite(highest):
            raise ValueError('Nonfinite classifier output')
        return highest


def from_config(config):
    kinds = {'statistical': StatisticalClassifier, 'transformers': TransformersClassifier}
    options = dict(path=config['path'], threshold=config['threshold'])
    if config['kind'] == 'transformers':
        options.update({key: config[key] for key in ('positive_labels', 'max_length', 'stride')})
    return kinds[config['kind']](**options)
