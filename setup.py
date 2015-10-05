#!/usr/bin/env python3
#
# ssh-import-id - Authorize SSH public keys from trusted online identities.
# Copyright (c) 2013 Casey Marshall <casey.marshall@gmail.com>
#
# ssh-import-id is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# ssh-import-id is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ssh-import-id.  If not, see <http://www.gnu.org/licenses/>.

import os
from setuptools import setup

try:
	readme = open(os.path.join(os.path.dirname(__file__), "README.md")).read()
except:
	readme = "See: http://pypi.python.org/pypi?name=ssh-import-id&:action=display_pkginfo"
setup(
		name='ssh-import-id',
		description='Authorize SSH public keys from trusted online identities',
		long_description=readme,
		version='4.5',
		author='Casey Marshall, Dustin Kirkland',
		author_email='casey.marshall@gmail.com, dustin.kirkland@gmail.com',
		license="GPLv3",
		keywords="ssh public key",
		url='https://launchpad.net/ssh-import-id',
		platforms=['any'],
		scripts=['bin/ssh-import-id', 'bin/ssh-import-id-gh', 'bin/ssh-import-id-lp'],
		install_requires=["Requests>=1.1.0"],
)
