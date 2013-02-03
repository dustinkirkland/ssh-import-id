#!/usr/bin/python
#
#    ssh-import-id - authorize a user by fetching their key
#                    from a public SSH keyserver; Launchpad.net
#                    by default
#
#    Copyright (C) 2013 Dustin Kirkland
#
#    Authors: Dustin Kirkland <dustin.kirkland@gmail.com>
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
import os
import pycurl
import string
import StringIO
import subprocess
import sys
import tempfile
import urllib


def error(msg):
	sys.stderr.write("ERROR: %s\n" % msg)
	sys.exit(1)


def warn(msg):
	sys.stderr.write("WARNING: %s\n" % msg)


def info(msg):
	sys.stderr.write("INFO: %s\n" % msg)


def validate(keys):
	# Split the retrieved public keys into one-line-per-file
	# Validate that ssh can calculate the fingerprint of each key
	# Show fingerprints on stderr (not stdout)
	# Return non-zero of any one fails to compute
	# Remove blank lines
	f, tmp = tempfile.mkstemp()
	os.close(f)
	rc = True
	for k in open(keys, "r").readlines():
		if k.strip():
			f = open(tmp, "w")
			f.write(k)
			f.close()
			p = subprocess.Popen(["ssh-keygen", "-l", "-f", tmp], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			stdout, stderr = p.communicate()
			sys.stderr.write(stdout)
			sys.stderr.write(stderr)
			if p.returncode != 0:
				rc = False
	os.unlink(tmp)
	return rc


def get_authkeypath():
	# Only support writing to this user's authorized_keys file
	home = os.getenv("HOME", None)
	if home is None:
		try:
			home = pwd.getpwuid(os.getuid())[5]
		except:
			error("Cannot get passwd entry")
	if os.direxists("%s/.ssh" % home) == False:
		os.makedirs("%s/.ssh" % home, 0700)
	if os.path.exists("%s/.ssh/authorized_keys" % home) == False:
		f = os.open("%s/.ssh/authorized_keys", os.O_WRONLY | os.O_CREAT, 0600, "w")
		os.close(f)
	return "%s/.ssh/authorized_keys" % home


def get_url():
	default_url = "https://launchpad.net/~%s/+sshkeys"
	url = os.getenv("URL", None)
	if url == None:
		if os.path.exists("/etc/ssh/ssh_import_id"):
			try:
				conf = {}
				execfile("/etc/ssh/ssh_import_id", conf)
				if "URL" in conf:
					url = conf["URL"]
				else:
					url = default_url
			except:
				error("Could not source /etc/ssh/ssh_import_id")
		else:
			url = default_url
	else:
		url = default_url
	return url


# Main
parser = argparse.ArgumentParser()
parser.add_argument("-o", "--output", help="write output to FILE; default ~/.ssh/authorized_keys, use '-' for STDOUT", default=None, metavar="FILE")
parser.add_argument("user_id", help="USER_ID [USER_ID_2] ... [USER_ID_n]", nargs="+")
args = parser.parse_args()
if args.output == None:
	output = get_authkeypath()
else:
	output = args.output
url = get_url()
rc = 0
f, tmp = tempfile.mkstemp()
os.close(f)
curl = pycurl.Curl()
curl.setopt(pycurl.SSL_VERIFYPEER, 1)
curl.setopt(pycurl.SSL_VERIFYHOST, 2)
curl.setopt(pycurl.CAINFO, "/etc/ssl/certs/ca-certificates.crt")
for i in args.user_id:
	u = url % urllib.quote_plus(i)
	try:
		curl.setopt(pycurl.URL, u)
		resp = StringIO.StringIO()
		curl.setopt(pycurl.WRITEFUNCTION, resp.write)
		curl.perform()
		f = open(tmp, "w")
		f.write("\n%s\n" % resp.getvalue())
		f.close()
		if validate(tmp) == False:
			warn("Invalid keys at [%s]" % u)
			rc += 1
			continue
		if args.output == "-":
			sys.stdout.write(resp.getvalue())
		else:
			try:
				f = open(output, "a")
				f.write("\n%s\n" % resp.getvalue())
				f.close()
			except:
				error("Could not write to [%s]" % output)
	except pycurl.error, e:
		warn("Failed to retrieve key for [%s] from [%s]" % (i, u))
		rc += 1
	info("Successfully authorized [%s]" % i)
os.unlink(f)
sys.exit(rc)
