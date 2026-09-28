# SPDX-License-Identifier: Apache-2.0
"""Optional Sandlock pipeline adapter for the standalone text detector."""
import os
import sys
import json

from sandlock_guard import Finding, Rule, ScanError, ScanReport
from sandlock_guard import PromptGuard as TextGuard
from sandlock_guard import _scanner

__all__ = ['PromptGuard', 'Rule', 'Finding', 'ScanError', 'ScanReport']


class PromptGuard(TextGuard):
    """The standalone scanner with an additional sandboxed stage factory."""

    def stage(self):
        """Return a sandboxed Stage reading stdin and forwarding approved bytes.

        Rejection exits 1; scan failures exit 2. Existing pipelines report their
        last command's status, so consumers should handle empty input explicitly.
        """
        from .sandbox import Sandbox

        runtime_paths = ['/usr', '/lib', '/lib64', sys.prefix, sys.base_prefix,
                         os.path.realpath(sys.executable),
                         os.path.dirname(os.path.realpath(_scanner.__file__))]
        if self.model is not None:
            runtime_paths.append(self.model)
        sandbox = Sandbox(
            fs_readable=list(dict.fromkeys(p for p in runtime_paths if os.path.exists(p))),
            net_allow=[], clean_env=True, max_memory='256M',
        )
        rules = json.dumps([dict(id=r.id, pattern=r.pattern, severity=r.severity,
                                 message=r.message) for r in self.rules])
        args = [sys.executable, '-I', os.path.realpath(_scanner.__file__),
                self.threshold, str(self.max_bytes), str(self.scan_timeout), rules]
        if self.model is not None:
            args.extend((self.model, self._model.digest))
        return sandbox.cmd(args)
