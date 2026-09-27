#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Scan text from stdin before passing it to a pipeline consumer.

Install python/guard first, then run with PYTHONPATH=python/src
python3 python/examples/text_guard.py.
The consumer rejects empty input, including EOF following a guard rejection.
"""
import sys

from sandlock import Sandbox
from sandlock.guard import PromptGuard


def main():
    runtime = Sandbox(
        fs_readable=['/usr', '/lib', '/lib64', '/bin', sys.prefix],
        net_allow=[], clean_env=True,
    )
    producer = runtime.cmd(['/bin/cat'])
    consumer = runtime.cmd([sys.executable, '-c',
        'import sys; data = sys.stdin.buffer.read(); '
        'sys.stdout.buffer.write(data); sys.exit(0 if data else 3)'])
    result = (producer | PromptGuard().stage() | consumer).run(timeout=30)
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    return 0 if result.success else 1


if __name__ == '__main__':
    sys.exit(main())
