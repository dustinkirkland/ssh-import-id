#!/usr/bin/python
#
#    ssh-import-id - authorize a user by fetching their key
#                    from a public SSH keyserver; Launchpad.net
#                    by default
#
#    Copyright (C) 2013 Dustin Kirkland
#
#    Authors: Dustin Kirkland <dustin.kirkland@gmail.com>
#
#    Original authors of the shell implementation:
#             Dustin Kirkland <dustin.kirkland@gmail.com>
#             Scott Moser <smoser@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, version 3 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import getopt
import io
import os
import pycurl
import string
import subprocess
import sys
import tempfile
try:
	# Python2
	from urllib import quote_plus
	from StringIO import StringIO
except:
	# Python3
	from urllib.parse import quote_plus
	from io import StringIO


def error(msg, tmpfile=False):
	"""Print error message on stderr and exit non-zero immediately"""
	sys.stderr.write("ERROR: %s\n" % msg)
	if tmpfile and os.path.exists(tmpfile):
		os.unlink(tmpfile)
	sys.exit(1)


def warn(msg):
	"""Print warning message on stderr but do not exit"""
	sys.stderr.write("WARNING: %s\n" % msg)


def info(msg):
	"""Print info message on stderr but do not exit"""
	sys.stderr.write("INFO: %s\n" % msg)


def validate(keys):
	"""Validate one or more public ssh keys in a file"""
	f, tmp = tempfile.mkstemp()
	os.close(f)
	rc = True
	# Split the retrieved public keys into one-line-per-file
	for k in open(keys, "r").readlines():
		# Skip blank lines
		if k.strip():
			f = open(tmp, "w")
			f.write(k)
			f.close()
			# Validate that ssh can calculate the fingerprint of each key
			p = subprocess.Popen(["ssh-keygen", "-l", "-f", tmp], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			stdout, stderr = p.communicate()
			# Show fingerprints on stderr (not stdout)
			sys.stderr.write(stdout.decode('utf-8'))
			sys.stderr.write(stderr.decode('utf-8'))
			if p.returncode != 0:
				# Return false if any one fails to compute
				rc = False
	os.unlink(tmp)
	return rc


def get_authkeypath():
	"""Validate and return the user's authorized keys file"""
	# Only support writing to this user's authorized_keys file
	# Use the $HOME environment variable, if possible
	home = os.getenv("HOME", None)
	if home is None:
		try:
			# If $HOME wasn't set, check pwent
			home = pwd.getpwuid(os.getuid())[5]
		except:
			error("Cannot get passwd entry")
	# Ensure that the .ssh directory exists, create if necessary
	if os.direxists("%s/.ssh" % home) == False:
		os.makedirs("%s/.ssh" % home, 0o700)
	# Ensure that the authorized keys file exists, create if necessary
	if os.path.exists("%s/.ssh/authorized_keys" % home) == False:
		f = os.open("%s/.ssh/authorized_keys", os.O_WRONLY | os.O_CREAT, 0o600, "w")
		os.close(f)
	return "%s/.ssh/authorized_keys" % home


def get_url():
	# Default to the Launchpad URL, for legacy operation
	default_url = "https://launchpad.net/~%s/+sshkeys"
	# Allow for an override using the $URL environment variable
	url = os.getenv("URL", None)
	if url == None:
		# Source the configuration file if it exists
		if os.path.exists("/etc/ssh/ssh_import_id"):
			try:
				# UGLY: source the legacy configuration file, which was a shell variable definition
				gconf = {}
				lconf = {}
				with open("/etc/ssh/ssh_import_id") as f:
					code = compile(f.read(), "/etc/ssh/ssh_import_id", 'exec')
					exec(code, gconf, lconf)
				if "URL" in gconf:
					url = gconf["URL"]
				else:
					url = default_url
			except:
				error("Could not source /etc/ssh/ssh_import_id")
		else:
			url = default_url
	else:
		url = default_url
	return url


def get_args():
	"""Handle argument parsing"""
	parser = argparse.ArgumentParser()
	parser.add_argument("-o", "--output", help="write output to FILE; default ~/.ssh/authorized_keys, use '-' for STDOUT", default=None, metavar="FILE")
	parser.add_argument("user_id", help="USER_ID [USER_ID_2] ... [USER_ID_n]", nargs="+")
	return parser.parse_args()


def get_output(args):
	"""Determine output destination"""
	if args.output is None:
		output = get_authkeypath()
	else:
		output = args.output
	return output


def configure_curl():
	"""Create and configure a curl handler"""
	curl = pycurl.Curl()
	curl.setopt(pycurl.SSL_VERIFYPEER, 1)
	curl.setopt(pycurl.SSL_VERIFYHOST, 2)
	curl.setopt(pycurl.CAINFO, "/etc/ssl/certs/ca-certificates.crt")
	return curl


def main():
	"""Main function of ssh-import-id"""
	# Define main variables
	rc = 0
	args = get_args()
	output = get_output(args)
	url = get_url()
	curl = configure_curl()
	f, tmp = tempfile.mkstemp()
	os.close(f)
	# Loop over user id positional arguments
	for i in args.user_id:
		# Ensure the user id is url safe (quoted)
		u = url % quote_plus(i)
		try:
			# Attempt to do the curl fetch
			curl.setopt(pycurl.URL, u)
			resp = StringIO()
			curl.setopt(pycurl.WRITEFUNCTION, resp.write)
			curl.perform()
		except:
			error("Unable to retrieve url [%s]" % u, tmp)
		try:
			# Write the output to a temporary file for validation
			f = open(tmp, "w")
			f.write("\n%s\n" % resp.getvalue())
			f.close()
			# Validate that each non-blank line in the tempfile are good ssh keys
			if validate(tmp) == False:
				warn("Invalid keys at [%s]" % u)
				rc += 1
				continue
		except:
			error("Unable to validate keys from [%s]" % u, tmp)
		try:
			# Handle output
			if args.output == "-":
				# Print output to stdout
				sys.stdout.write(resp.getvalue())
			else:
				# Print output to a file
				try:
					f = open(output, "a")
					f.write("\n%s\n" % resp.getvalue())
					f.close()
				except:
					error("Could not write to [%s]" % output, tmp)
			# This user's key(s) look good!
			info("Successfully authorized [%s]" % i)
		except:
			warn("Failed to retrieve key for [%s] from [%s]" % (i, u))
			rc += 1
	if os.path.exists(tmp):
		os.unlink(tmp)
	sys.exit(rc)


if __name__ == '__main__':
	main()
