#!/usr/bin/env python
# ssh-auth-id - Authorize SSH public keys from trusted online identities.
# Copyright (c) 2013 Casey Marshall <casey.marshall@gmail.com>
#
# ssh-auth-id is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# ssh-auth-id is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ssh-auth-id.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup

setup(name='ssh-auth-id',
	version='1.0.1',
	description='Authorize SSH public keys from trusted online identities',
	author='Casey Marshall',
	author_email='casey.marshall@gmail.com',
	url='http://github.com/cmars/ssh-auth-id',
	scripts=['bin/ssh-auth-id', 'bin/ssh-auth-id-gh', 'bin/ssh-auth-id-lp'],
	install_requires=["argparse", "Requests>=1.1.0"],
)
