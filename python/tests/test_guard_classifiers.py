# SPDX-License-Identifier: Apache-2.0
import json
import subprocess
import sys

import pytest

from sandlock_guard import PromptGuard, ScanError


@pytest.fixture
def json_model(tmp_path):
    path = tmp_path / 'guard-model.json'
    path.write_text(json.dumps({'format': 'sandlock-char-logistic-v1',
                               'intercept': -4, 'threshold': 0.9, 'weights': {'xyz': 8}}))
    return path


def test_existing_model_supports_both_apis(json_model):
    from sandlock_guard import StatisticalClassifier
    old = PromptGuard(model=json_model)
    new = PromptGuard(classifier=StatisticalClassifier(json_model))
    assert new.scan('xyz') == old.scan('xyz')
    assert new.scan('weather report') == old.scan('weather report')
    assert not PromptGuard(classifier=StatisticalClassifier(json_model, threshold=0.99)).scan('xyz').flagged


def test_ambiguous_or_unknown_classifier_rejected(json_model):
    from sandlock_guard import StatisticalClassifier
    with pytest.raises(ValueError, match='model.*classifier'):
        PromptGuard(model=json_model, classifier=StatisticalClassifier(json_model))
    with pytest.raises(TypeError, match='classifier'):
        PromptGuard(classifier=object())


@pytest.mark.parametrize('threshold', [0, 1, float('nan'), True, '0.5'])
def test_invalid_classifier_threshold(json_model, threshold):
    from sandlock_guard import StatisticalClassifier, TransformersClassifier
    with pytest.raises(ValueError):
        StatisticalClassifier(json_model, threshold=threshold)
    with pytest.raises(ValueError):
        TransformersClassifier(json_model.parent, positive_labels=('MALICIOUS',), threshold=threshold)


def test_new_statistical_config_reaches_worker(json_model):
    from sandlock.guard import PromptGuard, StatisticalClassifier
    for threshold, code in [(0.9, 1), (0.99, 0)]:
        guard = PromptGuard(classifier=StatisticalClassifier(json_model, threshold=threshold))
        result = subprocess.run(guard.stage().args, input=b'xyz', capture_output=True, timeout=5)
        assert result.returncode == code, result.stderr
        assert result.stdout == (b'' if code else b'xyz')


@pytest.fixture
def neural_model(tmp_path):
    torch = pytest.importorskip('torch')
    transformers = pytest.importorskip('transformers')
    from tokenizers import Tokenizer, models, pre_tokenizers, processors
    torch.set_num_threads(1)
    tokenizer = Tokenizer(models.WordLevel(
        {'[UNK]': 0, '[PAD]': 1, '[CLS]': 2, '[SEP]': 3, 'hello': 4, 'attack': 5},
        unk_token='[UNK]'))
    tokenizer.pre_tokenizer = pre_tokenizers.Whitespace()
    tokenizer.post_processor = processors.TemplateProcessing(
        single='[CLS] $A [SEP]', special_tokens=[('[CLS]', 2), ('[SEP]', 3)])
    fast = transformers.PreTrainedTokenizerFast(
        tokenizer_object=tokenizer, unk_token='[UNK]', pad_token='[PAD]',
        cls_token='[CLS]', sep_token='[SEP]', model_max_length=512)
    config = transformers.DebertaV2Config(
        vocab_size=6, hidden_size=16, num_hidden_layers=1, num_attention_heads=2,
        intermediate_size=32, max_position_embeddings=512,
        id2label={0: 'MALICIOUS', 1: 'BENIGN'}, label2id={'MALICIOUS': 0, 'BENIGN': 1})
    model = transformers.DebertaV2ForSequenceClassification(config)
    with torch.no_grad():
        model.classifier.weight.zero_()
        model.classifier.bias.copy_(torch.tensor([3.0, 0.0]))
    path = tmp_path / 'neural'
    model.save_pretrained(path, safe_serialization=True)
    fast.save_pretrained(path)
    return path


def test_transformers_uses_label_mapping_and_scans_past_first_window(neural_model):
    import torch
    from sandlock_guard import TransformersClassifier
    classifier = TransformersClassifier(neural_model, positive_labels=('MALICIOUS',))
    report = PromptGuard(classifier=classifier).scan('hello')
    assert report.flagged
    assert report.findings[0].rule_id == 'transformers-injection'
    assert report.model_score == pytest.approx(0.95257413)
    tokenizer, model = classifier._load()
    seen = []
    handle = model.register_forward_pre_hook(
        lambda module, args, kwargs: seen.extend(kwargs['input_ids'].tolist()), with_kwargs=True)
    def mark_attack(module, args, kwargs, output):
        attack = (kwargs['input_ids'] == tokenizer.convert_tokens_to_ids('attack')).any(dim=1)
        output.logits[:, 0] = torch.where(attack, 3.0, -3.0)
        return output
    scores = model.register_forward_hook(mark_attack, with_kwargs=True)
    try:
        assert not PromptGuard(classifier=classifier).scan('hello').flagged
        seen.clear()
        assert PromptGuard(classifier=classifier).scan('hello ' * 700 + 'attack').flagged
    finally:
        handle.remove()
        scores.remove()
    assert len(seen) > 1
    assert all(len(window) <= 512 for window in seen)
    assert any(tokenizer.convert_tokens_to_ids('attack') in window for window in seen[1:])


@pytest.mark.parametrize('change', [
    {'id2label': {'0': 'LABEL_0', '1': 'LABEL_1'}},
    {'problem_type': 'multi_label_classification'},
    {'problem_type': 'regression'},
])
def test_transformers_rejects_unsupported_label_schema(neural_model, change):
    from sandlock_guard import TransformersClassifier
    path = neural_model / 'config.json'
    data = json.loads(path.read_text())
    data.update(change)
    path.write_text(json.dumps(data))
    with pytest.raises(ScanError, match='scanner_failed'):
        PromptGuard(classifier=TransformersClassifier(neural_model, positive_labels=('MALICIOUS',))).scan('hello')


@pytest.mark.parametrize('options', [
    {'positive_labels': ('MALICIOUS', 'BENIGN')},
    {'max_length': 1024}, {'max_length': 4, 'stride': 3},
])
def test_incompatible_model_configuration_fails_closed(neural_model, options):
    from sandlock_guard import TransformersClassifier
    config = dict(positive_labels=('MALICIOUS',))
    config.update(options)
    with pytest.raises(ScanError, match='scanner_failed'):
        PromptGuard(classifier=TransformersClassifier(neural_model, **config)).scan('hello')


def test_transformers_worker_detects_modified_files(neural_model):
    from sandlock.guard import TransformersClassifier, PromptGuard
    stage = PromptGuard(classifier=TransformersClassifier(neural_model, positive_labels=('MALICIOUS',)), scan_timeout=30).stage()
    path = neural_model / 'tokenizer_config.json'
    path.write_text(path.read_text() + '\n')
    result = subprocess.run(stage.args, input=b'hello', capture_output=True, timeout=10)
    assert result.returncode == 2
    assert result.stdout == b''
    assert b'model_changed' in result.stderr


def test_transformers_stage_owns_private_scratch_and_memory_override(neural_model):
    from pathlib import Path
    from sandlock.guard import TransformersClassifier, PromptGuard
    stage = PromptGuard(classifier=TransformersClassifier(neural_model, positive_labels=('MALICIOUS',))).stage(max_memory='3G')
    scratch = Path(stage.sandbox.env['TMPDIR'])
    assert stage.sandbox.max_memory == '3G'
    assert scratch.is_dir()
    assert str(neural_model) not in stage.sandbox.fs_writable
    assert str(scratch) in stage.sandbox.fs_writable
    del stage
    assert not scratch.exists()


def test_nonfinite_transformers_output_fails_closed(neural_model):
    import torch
    from sandlock_guard import TransformersClassifier
    classifier = TransformersClassifier(neural_model, positive_labels=('MALICIOUS',))
    _, model = classifier._load()
    with torch.no_grad():
        model.classifier.bias.fill_(float('nan'))
    with pytest.raises(ScanError, match='scanner_failed'):
        PromptGuard(classifier=classifier).scan('hello')


@pytest.mark.parametrize('threshold,status', [(0.5, 1), (0.99, 0)])
def test_transformers_native_pipeline(neural_model, threshold, status):
    from sandlock import Sandbox
    from sandlock.guard import TransformersClassifier, PromptGuard
    producer = Sandbox(fs_readable=['/usr', '/lib', '/lib64', sys.prefix], clean_env=True)
    guard = PromptGuard(classifier=TransformersClassifier(neural_model, positive_labels=('MALICIOUS',), threshold=threshold), scan_timeout=30)
    result = (producer.cmd([sys.executable, '-c', "print('hello')"]) | guard.stage()).run(timeout=60)
    assert result.exit_code == status, result.stderr
    assert result.stdout == (b'' if status else b'hello\n')


@pytest.mark.parametrize('options', [
    {'positive_labels': ()}, {'positive_labels': 'attack'},
    {'positive_labels': ('attack', 'attack')}, {'positive_labels': (1,)},
    {'max_length': True}, {'max_length': 0}, {'stride': -1}, {'stride': 512},
])
def test_invalid_transformers_configuration(json_model, options):
    from sandlock_guard import TransformersClassifier
    config = dict(positive_labels=('attack',))
    config.update(options)
    with pytest.raises(ValueError):
        TransformersClassifier(json_model.parent, **config)


def test_other_architecture_and_multiple_positive_labels(neural_model):
    import torch
    from transformers import BertConfig, BertForSequenceClassification
    from sandlock_guard import TransformersClassifier
    config = BertConfig(vocab_size=6, hidden_size=16, num_hidden_layers=1,
                        num_attention_heads=2, intermediate_size=32, max_position_embeddings=64,
                        id2label={0: 'safe', 1: 'injection', 2: 'jailbreak'})
    model = BertForSequenceClassification(config)
    with torch.no_grad():
        model.classifier.weight.zero_()
        model.classifier.bias.copy_(torch.tensor([0.0, 1.0, 1.0]))
    model.save_pretrained(neural_model, safe_serialization=True)
    classifier = TransformersClassifier(neural_model, positive_labels=('injection', 'jailbreak'),
                                        threshold=0.8, max_length=64, stride=16)
    report = PromptGuard(classifier=classifier).scan('hello ' * 100)
    assert report.flagged
    assert report.model_score == pytest.approx(0.8446376)
    from sandlock.guard import PromptGuard as StageGuard
    stage = StageGuard(classifier=classifier, scan_timeout=30).stage()
    result = subprocess.run(stage.args, input=b'hello', capture_output=True, timeout=40,
                            env=dict(__import__('os').environ, **stage.sandbox.env))
    assert result.returncode == 1, result.stderr
    assert result.stdout == b''
