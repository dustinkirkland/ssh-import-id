#!/usr/bin/env python3
#
# ssh-import-id - Authorize SSH public keys from trusted online identities
#
# Copyright (c) 2013 Casey Marshall <casey.marshall@gmail.com>
# Copyright (c) 2013 Dustin Kirkland <dustin.kirkland@gmail.com>
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

import argparse
import getpass
import json
try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError
import logging
import os
import subprocess
import sys
import tempfile
import urllib.error
from urllib.parse import quote_plus
from urllib.request import Request, urlopen

import distro

from .version import VERSION


DEFAULT_TIMEOUT = 15.0


DEFAULT_PROTO = "lp"
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
                    level=logging.INFO)
parser = argparse.ArgumentParser(
    description='Authorize SSH public keys from trusted online identities.',
    prog="ssh-import-id")
parser.add_argument(
    '-o', '--output', metavar='FILE',
    help='Write output to file (default ~/.ssh/authorized_keys)')
parser.add_argument(
    '-r', '--remove', action="store_true", default=False,
    help='Remove a key from authorized keys file')
parser.add_argument(
    '-u', '--useragent', metavar='USERAGENT', default="",
    help='Append to the http user agent string')
parser.add_argument(
    'userids', nargs='+', metavar="USERID",
    help='User IDs to import')
parser.options = None
TEMPFILES = []


def cleanup():
    """
    Cleanup tempfiles
    """
    for f in TEMPFILES:
        if os.path.exists(f):
            os.unlink(f)


def die(msg):
    """
    The only thing in Perl worth keeping
    """
    logging.error(msg)
    cleanup()
    sys.exit(1)


def key_fingerprint(fields):
    """
    Get the fingerprint for an SSH public key
    Returns None if not valid key material
    """
    if not fields:
        return None
    if len(fields) < 3:
        return None
    tempfd, tempname = tempfile.mkstemp(
        prefix='ssh-auth-key-check', suffix='.pub')
    TEMPFILES.append(tempname)
    with os.fdopen(tempfd, "w") as tempf:
        tempf.write(" ".join(fields))
        tempf.write("\n")
    keygen_proc = subprocess.Popen(
        ['ssh-keygen', '-l', '-f', tempname], stdout=subprocess.PIPE)
    keygen_out, _ = keygen_proc.communicate(None)
    if keygen_proc.returncode:
        # Non-zero RC: probably not a public key
        return None
    os.unlink(tempname)
    keygen_fields = keygen_out.split()
    if not keygen_fields or len(keygen_fields) < 2:
        # Empty output?
        return None
    out = []
    for k in keygen_out.split():
        out.append(str(k.decode('utf-8').strip()))
    return out


def open_output(name, mode='a+'):
    """
    Open output for writing, supporting either stdout or a filename
    """
    if name == '-':
        return False
    return open(name, mode)


def assert_parent_dir(keyfile):
    """
    Ensure that the keyfile parent directory exists
    """
    # Standard out: nothing to do
    if keyfile == "-":
        return True
    # Get output file parent directory
    if os.path.dirname(keyfile):
        parent_dir = os.path.dirname(keyfile)
    else:
        parent_dir = "."
    # Ensure parent directory exists
    if not os.path.exists(parent_dir):
        umask = os.umask(0o077)
        os.makedirs(parent_dir, 0o700)
        os.umask(umask)
    if os.path.isdir(parent_dir):
        return True
    die("Parent directory not found for output [%s]" % (keyfile))


def read_keyfile():
    """
    Locate key file, read the current state, return lines in a list
    """
    keyfile = get_keyfile(parser.options.output)
    if keyfile == "-" or not os.path.exists(keyfile):
        lines = []
    else:
        try:
            with open(keyfile, "r") as fp:
                lines = fp.readlines()
        except OSError:
            die("Could not read authorized key file [%s]" % (keyfile))

    return lines


def write_keyfile(keyfile_lines, mode):
    """
    Locate key file, write lines to it
    """
    output_file = get_keyfile(parser.options.output)
    if output_file == "-":
        for line in keyfile_lines:
            if line:
                sys.stdout.write(line)
                sys.stdout.write("\n\n")
        sys.stdout.flush()
    elif assert_parent_dir(output_file):
        with open(output_file, mode) as f:
            for line in keyfile_lines:
                if line.strip():
                    f.write(line)
                    f.write("\n\n")


def get_keyfile(path=None):
    """Return 'path' if true, else a path to current user's authorized_keys."""
    if not path:
        if os.environ.get("HOME"):
            home = os.environ["HOME"]
        else:
            home = os.path.expanduser("~" + getpass.getuser())

        path = os.path.join(home, ".ssh", "authorized_keys")
    return path


def fp_tuple(fp):
    """
    Build a string that uniquely identifies a key
    """
    # An SSH public key is uniquely identified by the tuple
    # [length, hash, type].  fp should be a list of results of
    # the `ssh-keygen -l -f` command
    return ' '.join([fp[0], fp[1], fp[-1]])


def key_list(keyfile_lines):
    """
    Return a list of uniquely identified keys
    """
    # Map out which keys we already have
    keys = []
    for line in keyfile_lines:
        ssh_fp = key_fingerprint(line.split())
        if ssh_fp:
            keys.append(fp_tuple(ssh_fp))
    logging.debug("Already have SSH public keys: [%s]", ' '.join(keys))
    return keys


def fetch_keys(proto, username, useragent):
    """
    Call out to a subcommand to handle the specified protocol and username
    """
    if proto == "lp":
        return fetch_keys_lp(username, useragent)
    if proto == "gh":
        return fetch_keys_gh(username, useragent)

    die("ssh-import-id protocol handler %s: not found or cannot execute" %
        (proto))


def import_keys(proto, username, useragent):
    """
    Import keys from service at 'proto' for 'username', appending to output
    file
    """
    # Map out which keys we already have, so we don't append duplicates.
    local_keys = key_list(read_keyfile())
    # Protocol handler should output SSH keys, one per line
    result = []
    keyfile_lines = []
    comment_string = "# ssh-import-id %s:%s" % (proto, username)
    for line in fetch_keys(proto, username, useragent).split('\n'):
        # Validate/clean-up key text
        line = line.strip()
        fields = line.split()
        fields.append(comment_string)
        ssh_fp = key_fingerprint(fields)
        if ssh_fp:
            if fp_tuple(ssh_fp) in local_keys:
                logging.info(
                    "Already authorized %s", ssh_fp[:3] + ssh_fp[-1:])
                result.append(fields)
            else:
                keyfile_lines.append(" ".join(fields))
                result.append(fields)
                logging.info("Authorized key %s", ssh_fp[:3] + ssh_fp[-1:])
    write_keyfile(keyfile_lines, "a+")
    return result


def remove_keys(proto, username):
    """
    Remove keys from the output file, if they were inserted by this tool
    """
    # Only remove keys labeled with our comment string
    comment_string = "# ssh-import-id %s:%s\n" % (proto, username)
    update_lines = []
    removed = []
    for line in read_keyfile():
        if line.endswith(comment_string):
            ssh_fp = key_fingerprint(line.split())
            logging.info("Removed labeled key %s", ssh_fp[:3] + ssh_fp[-1:])
            removed.append(line)
        else:
            update_lines.append(line)
    write_keyfile(update_lines, "w")
    return removed


def user_agent(extra=""):
    """"
    Construct a useful user agent string
    """
    ssh_import_id = "ssh-import-id/%s" % VERSION
    python = "python/%d.%d.%d" % (
        sys.version_info.major, sys.version_info.minor, sys.version_info.micro)
    linux_dist = "/".join(distro.linux_distribution())
    uname = "%s/%s/%s" % (os.uname()[0], os.uname()[2], os.uname()[4])
    return "%s %s %s %s %s" % (ssh_import_id, python, linux_dist, uname, extra)


def fetch_keys_lp(lpid, useragent):
    conf_file = "/etc/ssh/ssh_import_id"
    try:
        url = os.getenv("URL", None)
        if url is None and os.path.exists(conf_file):
            try:
                contents = open(conf_file).read()
            except OSError:
                raise Exception("Failed to read %s" % conf_file)

            try:
                conf = json.loads(contents)
            except JSONDecodeError:
                raise Exception(
                    "File %s did not have valid JSON." % conf_file)
            url = conf.get("URL", None) % (quote_plus(lpid))
        elif url is not None:
            url = url % (quote_plus(lpid))
        # Finally, fall back to Launchpad
        if url is None:
            url = "https://launchpad.net/~%s/+sshkeys" % (quote_plus(lpid))
        headers = {'User-Agent': user_agent(useragent)}

        try:
            with urlopen(Request(url, headers=headers),
                         timeout=DEFAULT_TIMEOUT) as response:
                keys = response.read().decode('utf-8')
        except urllib.error.HTTPError as e:
            msg = 'Requesting Launchpad keys failed.'
            if e.code == 404:
                msg = 'Launchpad user not found.'
            die(msg + " status_code=%d user=%s" % (e.code, lpid))

    # pylint: disable=broad-except
    except Exception as e:
        die(str(e))
    return keys


def fetch_keys_gh(ghid, useragent):
    x_ratelimit_remaining = 'x-ratelimit-remaining'
    help_url = 'https://developer.github.com/v3/#rate-limiting'
    keys = ""
    try:
        url = "https://api.github.com/users/%s/keys" % (quote_plus(ghid))
        headers = {'User-Agent': user_agent(useragent)}
        try:
            with urlopen(Request(url, headers=headers),
                         timeout=DEFAULT_TIMEOUT) as resp:
                data = json.load(resp)
        except urllib.error.HTTPError as e:
            msg = 'Requesting GitHub keys failed.'
            if e.code == 404:
                msg = 'Username "%s" not found at GitHub API.' % ghid
            elif e.hdrs.get(x_ratelimit_remaining) == "0":
                msg = ('GitHub REST API rate-limited this IP address. See %s .'
                       % help_url)
            die(msg + " status_code=%d user=%s" % (e.code, ghid))
        for keyobj in data:
            keys += "%s %s@github/%s\n" % (keyobj['key'], ghid, keyobj['id'])
    # pylint: disable=broad-except
    except Exception as e:
        die(str(e))
    return keys


def main():
    errors = []
    try:
        os.umask(0o177)
        parser.options = parser.parse_args()
        keys = []
        for userid in parser.options.userids:
            user_pieces = userid.split(':')
            if len(user_pieces) == 2:
                proto, username = user_pieces
            elif len(user_pieces) == 1:
                proto, username = DEFAULT_PROTO, userid
            else:
                die("Invalid user ID: [%s]" % (userid))
            if parser.options.remove:
                changes = remove_keys(proto, username)
                keys.extend(changes)
                action = "Removed"
            else:
                changes = import_keys(
                    proto, username, parser.options.useragent)
                keys.extend(changes)
                action = "Authorized"
            if not changes:
                errors.append(userid)
        logging.info("[%d] SSH keys [%s]", len(keys), action)
    # pylint: disable=broad-except
    except Exception as e:
        die(str(e))
    cleanup()
    if errors:
        die("No matching keys found for [%s]" % ','.join(errors))
    sys.exit(0)
