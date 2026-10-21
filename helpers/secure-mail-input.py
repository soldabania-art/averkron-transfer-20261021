#!/usr/bin/python3
"""Generic systemd SMTP input utility: no connection, send or service action."""
import argparse
import getpass
import os
import stat
import sys
import warnings


def quote(value):
    value.encode("utf-8", "strict")
    if any(c in "\0\r\n" or ord(c) == 0xFEFF or
           0xFDD0 <= ord(c) <= 0xFDEF or ord(c) & 0xFFFF in (0xFFFE, 0xFFFF)
           for c in value):
        raise ValueError
    return '"' + ''.join('\\' + c if c in ('\\', '"', '$', '`') else c
                         for c in value) + '"'


def password():
    with open(os.ctermid(), "w", encoding="utf-8") as tty:
        if not tty.isatty():
            raise OSError
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            first = getpass.getpass("Mailbox password: ", stream=tty)
            second = getpass.getpass("Repeat password: ", stream=tty)
    if not first or first != second or len(first.encode("utf-16-le")) > 8192:
        raise ValueError
    return first


def create_mail(directory, smtp_host, mailbox, prompt=password):
    if os.geteuid() != 0:
        raise PermissionError
    if not os.path.isabs(directory) or os.path.realpath(directory) != directory:
        raise ValueError
    if not smtp_host or not mailbox:
        raise ValueError
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(dfd)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError
        try:
            os.stat("mail.env", dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError
        values = {"SMTP_HOST": smtp_host, "SMTP_PORT": "465",
                  "SMTP_SECURE": "true", "SMTP_USER": mailbox, "SMTP_PASS": prompt()}
        data = ''.join(k + '=' + quote(v) + '\n' for k, v in values.items()).encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open("mail.env", flags, 0o600, dir_fd=dfd)
        created = os.fstat(fd)
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.fsync(dfd)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            current = os.stat("mail.env", dir_fd=dfd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                os.unlink("mail.env", dir_fd=dfd)
            raise
    finally:
        os.close(dfd)
    print("Created mail.env: root:root 0600. No service action performed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    parser.add_argument("smtp_host")
    parser.add_argument("mailbox")
    args = parser.parse_args()
    try:
        create_mail(args.directory, args.smtp_host, args.mailbox)
    except FileExistsError:
        sys.exit("mail.env already exists; unchanged. No values displayed.")
    except (KeyboardInterrupt, EOFError, OSError, ValueError, getpass.GetPassWarning):
        sys.exit("Secure input/save failed; no values displayed. Service unchanged.")
