
ssh-import-id
===========

You're logged onto a cloud instance working on a problem with your fellow devs, and you want to invite them to log in and take a look at these crazy log messages. What do?

Oh. You have to ask them to cat their public SSH key, paste it into IRC (wait, no, it's id\_rsa.pub, not id\_rsa silly!) then you copy it and cat it to the end of authorized\_hosts.

That's where ssh-import-id comes in. With ssh-import-id, you can add the public SSH keys from a known, trusted online identity to grant SSH access.

Currently supported identities include Github and Launchpad.

Usage
-----

ssh-import-id uses short prefix to indicate the location of the online identity. For now, these are:

    'gh:' for Github
    'lp:' for Launchpad

Command line help:

    usage: ssh-import-id [-h] [-o FILE] USERID [USERID ...]

    Authorize SSH public keys from trusted online identities.

    positional arguments:
      USERID                User IDs to import

    optional arguments:
      -h, --help            show this help message and exit
      -o FILE, --output FILE
                            Write output to file (default ~/.ssh/authorized_keys)

Example
-------

If you wanted me to be able to ssh into your server, as the desired user on that machine you would use:

    $ ssh-import-id gh:cmars

You can also import multiple users on the same line, even from different key services, like so:

    $ ssh-import-id gh:cmars lp:kirkland

Used with care, it's a great collaboration tool!

Installing
----------

ssh-import-id can be installed on Python >= 2.6 with a recent version of pip:

    $ pip install ssh-import-id

ssh-import-id requires a recent version of Requests (>=1.1.0) for verified SSL/TLS connections.

Extending
---------

You can add support for your own SSH public key providers by creating a script named ssh-import-id-*prefix*. Make the script executable and place it in the same bin directory as ssh-import-id.

The script should accept the identity username for the service it connects to, and output lines in the same format as an ~/.ssh/authorized\_keys file.

If you do develop such a handler, I recommend that you connect to the service with SSL/TLS, and require a valid certificate and matching hostname. Use Requests.get(url, verify=True), for example.

Credits
-------

This project is authored and maintained by Dustin Kirkland, Scott Moser, and Casey Marshall.

