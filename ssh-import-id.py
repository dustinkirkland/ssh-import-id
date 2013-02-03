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
import json
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
except (ImportError,):
	# Python3
	from urllib.parse import quote_plus
	from io import StringIO


def error(msg):
	"""Print error message on stderr and exit non-zero immediately"""
	sys.stderr.write("ERROR: %s\n" % msg)
	sys.exit(1)


def warn(msg):
	"""Print warning message on stderr but do not exit"""
	sys.stderr.write("WARNING: %s\n" % msg)


def info(msg):
	"""Print info message on stderr but do not exit"""
	sys.stderr.write("INFO: %s\n" % msg)


def valid(public_key_file, output):
	"""Validate a public key in a file"""
	# Validate that ssh can calculate the fingerprint of each key
	p = subprocess.Popen(["ssh-keygen", "-l", "-f", public_key_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, stderr = p.communicate()
	# Show fingerprints on stderr (not stdout)
	sys.stderr.write(stdout.decode('utf-8'))
	sys.stderr.write(stderr.decode('utf-8'))
	if p.returncode == 0:
		# Handle output
		f = open(public_key_file, "r")
		pubkey = f.read()
		f.close()
		if output == "-":
			# Print public key to stdout
			sys.stdout.write(pubkey)
			sys.stdout.write("\n")
		else:
			# Print public key to a file
			try:
				f = open(output, "a")
				f.write("\n%s\n" % pubkey)
				f.close()
			except:
				error("Could not write to [%s]" % output)
		return True
	return False


def validate(keys, results_type, output):
	"""Use the appropriate driver for key processing"""
	if results_type == "raw":
		return validate_raw(keys, output)
	elif results_type == "json":
		return validate_json(keys, output)
	else:
		return False


def validate_raw(keys, output):
	"""Validate one or more public ssh keys in a raw file"""
	f, tmp = tempfile.mkstemp()
	os.close(f)
	rc = True
	# Split the retrieved public keys into one-line-per-file
	for k in keys.split("\n"):
		# Skip blank lines
		if k.strip():
			f = open(tmp, "w")
			f.write(k)
			f.close()
			if not valid(tmp, output):
				rc = False
	os.unlink(tmp)
	return rc


def validate_json(keys, output):
	"""Validate one or more public ssh keys in a json structure"""
	f, tmp = tempfile.mkstemp()
	os.close(f)
	rc = True
	data = json.loads(keys)
	for i in data:
		if "key" in i:
			f = open(tmp, "w")
			f.write(i["key"])
			f.close()
			if not valid(tmp, output):
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


def get_default_url():
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
	default_url = get_default_url()
	curl = configure_curl()
	# Loop over user id positional arguments
	for i in args.user_id:
		# Ensure the user id is url safe (quoted)
		if i.startswith("gh:"):
			u = "https://api.github.com/users/%s/keys" % quote_plus(i.split("gh:")[1])
			results_type = "json"
		elif i.startswith("lp:"):
			u = "https://launchpad.net/~%s/+sshkeys" % quote_plus(i.split("lp:")[1])
			results_type = "raw"
		else:
			u = default_url % quote_plus(i)
			results_type = "raw"
		try:
			# Attempt to do the curl fetch
			curl.setopt(pycurl.URL, u)
			resp = StringIO()
			curl.setopt(pycurl.WRITEFUNCTION, resp.write)
			curl.perform()
		except:
			error("Unable to retrieve url [%s]" % u)
		try:
			# Validate that each non-blank line in the tempfile are good ssh keys
			if validate(resp.getvalue(), results_type, output) == False:
				warn("Invalid keys at [%s]" % u)
				rc += 1
				continue
		except:
			error("Unable to validate keys from [%s]" % u)
		# This user's key(s) look valid!
		info("Successfully authorized [%s]" % i)
	sys.exit(rc)


if __name__ == '__main__':
	main()
