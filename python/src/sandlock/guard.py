# SPDX-License-Identifier: Apache-2.0
"""Optional Sandlock pipeline adapter for the standalone text detector."""
import os
import sys
import json
import site
import tempfile

from sandlock_guard import Finding, Rule, ScanError, ScanReport, TransformersClassifier, StatisticalClassifier
from sandlock_guard import PromptGuard as TextGuard
from sandlock_guard import _scanner

__all__ = ['PromptGuard', 'Rule', 'Finding', 'ScanError', 'ScanReport',
           'StatisticalClassifier', 'TransformersClassifier']


class PromptGuard(TextGuard):
    """The standalone scanner with an additional sandboxed stage factory."""

    def stage(self, *, max_memory=None):
        """Return a sandboxed Stage reading stdin and forwarding approved bytes.

        Rejection exits 1; scan failures exit 2. Existing pipelines report their
        last command's status, so consumers should handle empty input explicitly.
        """
        from .sandbox import Sandbox

        runtime_paths = ['/usr', '/lib', '/lib64', sys.prefix, sys.base_prefix,
                         os.path.realpath(sys.executable),
                         os.path.dirname(os.path.realpath(_scanner.__file__))]
        if self.classifier is not None:
            runtime_paths.append(self.classifier.path)
        python_paths = []
        writable_paths = []
        scratch = None
        env = {}
        if isinstance(self.classifier, TransformersClassifier):
            runtime_paths.append('/dev/urandom')
            writable_paths.append('/dev/null')
            scratch = tempfile.TemporaryDirectory(prefix='sandlock-guard-')
            writable_paths.append(scratch.name)
            env = {'TMPDIR': scratch.name, 'HF_HOME': scratch.name,
                   'HF_HUB_OFFLINE': '1', 'TRANSFORMERS_OFFLINE': '1',
                   'TOKENIZERS_PARALLELISM': 'false', 'OMP_NUM_THREADS': '1',
                   'MKL_NUM_THREADS': '1', 'OPENBLAS_NUM_THREADS': '1'}
            roots = set(site.getsitepackages() + [site.getusersitepackages()])
            python_paths = [p for p in sys.path if p in roots and os.path.isdir(p)]
            runtime_paths.extend(python_paths)
        memory = self.classifier.memory if self.classifier else '256M'
        sandbox = Sandbox(
            fs_readable=list(dict.fromkeys(p for p in runtime_paths if os.path.exists(p))),
            fs_writable=writable_paths,
            net_allow=[], clean_env=True, max_memory=memory if max_memory is None else max_memory,
            env=env,
        )
        rules = json.dumps([dict(id=r.id, pattern=r.pattern, severity=r.severity,
                                 message=r.message) for r in self.rules])
        args = [sys.executable, '-I', os.path.realpath(_scanner.__file__),
                self.threshold, str(self.max_bytes), str(self.scan_timeout), rules]
        if self.classifier is not None:
            config = self.classifier._config()
            config['python_paths'] = python_paths
            args.append(json.dumps(config))
        stage = sandbox.cmd(args)
        stage._guard_scratch = scratch
        return stage
