# SPDX-License-Identifier: Apache-2.0
"""Train and evaluate an optional guard model from three disjoint JSONL datasets."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import warnings

from sandlock_guard import PromptGuard
from sandlock_guard._classifier import FORMAT, MAX_FEATURES, Model, WINDOW, features, normalize, windows


def read_rows(path):
    rows = [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines() if line.strip()]
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get('text'), str)
                or not normalize(row['text']) or type(row.get('label')) is not int
                or row['label'] not in (0, 1) or not isinstance(row.get('group'), str)
                or not row['group'].strip()):
            raise ValueError('Each row needs nonempty text, integer label 0/1, and group')
    if {row['label'] for row in rows} != {0, 1}:
        raise ValueError('Each dataset must contain both classes')
    return rows


def check_splits(*splits):
    groups, texts = set(), set()
    for rows in splits:
        new_groups = {r['group'] for r in rows}
        new_texts = {normalize(r['text']) for r in rows}
        if groups & new_groups or texts & new_texts:
            raise ValueError('Dataset splits overlap in groups or normalized text')
        groups.update(new_groups)
        texts.update(new_texts)


def fit(rows):
    from sklearn.exceptions import ConvergenceWarning
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.linear_model import LogisticRegression

    texts, labels = [], []
    for row in rows:
        if row['label'] and len(normalize(row['text'])) > WINDOW:
            raise ValueError('Positive training excerpts must fit in 512 normalized characters')
        for window in windows(row['text']):
            texts.append(window)
            labels.append(row['label'])
    vectorizer = CountVectorizer(analyzer=features, binary=True, max_features=MAX_FEATURES)
    matrix = vectorizer.fit_transform(texts)
    classifier = LogisticRegression(solver='liblinear', random_state=0, max_iter=1000)
    with warnings.catch_warnings():
        warnings.simplefilter('error', ConvergenceWarning)
        classifier.fit(matrix, labels)
    data = {
        'format': FORMAT, 'intercept': float(classifier.intercept_[0]), 'threshold': 0.5,
        'weights': dict(zip(vectorizer.get_feature_names_out(), map(float, classifier.coef_[0]))),
    }
    return data, vectorizer, classifier


def choose_threshold(scores, labels, max_fpr):
    if not math.isfinite(max_fpr) or not 0 <= max_fpr < 1:
        raise ValueError('False positive rate must be in [0, 1)')
    negatives = sorted(s for s, label in zip(scores, labels) if label == 0)
    bound = negatives[len(negatives) - math.floor(max_fpr * len(negatives)) - 1]
    threshold = bound + (1 - bound) * 1e-12
    if not 0 < threshold < 1:
        raise ValueError('No usable threshold satisfies the validation false positive budget')
    return threshold


def measure(rows, model):
    guard = PromptGuard()
    scores, rules = [], []
    for row in rows:
        scores.append(max(model.score(view) for view in guard._views(row['text'])))
        rules.append(guard.scan(row['text']).flagged)
    return scores, rules


def metrics(labels, predicted):
    tp = sum(label == 1 and flag for label, flag in zip(labels, predicted))
    fp = sum(label == 0 and flag for label, flag in zip(labels, predicted))
    positives = sum(labels)
    negatives = len(labels) - positives
    return dict(true_positive=tp, false_positive=fp, false_negative=positives - tp,
                true_negative=negatives - fp, recall=tp / positives,
                false_positive_rate=fp / negatives)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('train', 'validation', 'test', 'output'):
        parser.add_argument(name, type=Path)
    parser.add_argument('--max-fpr', type=float, default=0.01,
                        help='Maximum classifier false positive rate on validation data (default: 0.01)')
    args = parser.parse_args()
    train, validation, test = [read_rows(p) for p in (args.train, args.validation, args.test)]
    check_splits(train, validation, test)
    data, _, _ = fit(train)
    model = Model(data['intercept'], data['threshold'], data['weights'], '')
    scores, _ = measure(validation, model)
    data['threshold'] = choose_threshold(scores, [r['label'] for r in validation], args.max_fpr)
    scores, rules = measure(test, model)
    predicted = [s >= data['threshold'] for s in scores]
    labels = [r['label'] for r in test]
    import sklearn
    data['training'] = {
        'sklearn_version': sklearn.__version__,
        'sha256': {name: hashlib.sha256(path.read_bytes()).hexdigest()
                   for name, path in [('train', args.train), ('validation', args.validation), ('test', args.test)]},
    }
    raw = json.dumps(data, ensure_ascii=True, sort_keys=True, allow_nan=False) + '\n'
    with args.output.open('x', encoding='utf-8') as output:
        output.write(raw)
    Model.load(args.output)
    print(json.dumps({
        'examples': {'train': len(train), 'validation': len(validation), 'test': len(test)},
        'features': len(data['weights']), 'model_bytes': len(raw.encode()),
        'threshold': data['threshold'],
        'rules': metrics(labels, rules), 'classifier': metrics(labels, predicted),
        'combined': metrics(labels, [a or b for a, b in zip(rules, predicted)]),
    }, indent=2))


if __name__ == '__main__':
    main()
