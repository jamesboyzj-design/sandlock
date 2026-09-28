# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
from shutil import copyfile

from setuptools import setup


project = Path(__file__).resolve().parent
license_file = project / 'LICENSE'
generated = not license_file.exists()
if generated:
    copyfile(project.parents[1] / 'LICENSE', license_file)
try:
    setup()
finally:
    if generated:
        license_file.unlink()
