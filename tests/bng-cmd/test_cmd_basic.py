import pytest
from common import process


def test_bng_cmd_version(bng_cmd):
    (exit, out, err) = process.run([bng_cmd, "--version"])

    # test that bng-cmd --version exits with code 0, prints
    # nothing to stdout and prints to stdout
    assert exit == 0 and err == "" and "bng-cmd " in out and len(out.split(" ")) == 2


def test_bng_cmd_non_existent_host(bng_cmd):
    (exit, out, err) = process.run([bng_cmd, "-Hnon-existent-host", "--verbose"])

    # test that bng-cmd (tried to connecto to non-existent host) exits with code != 0,
    # prints nothing to stdout and prints an error to stderr
    assert exit != 0 and out == "" and err != ""


def test_bng_cmd_mcast_host(bng_cmd):
    (exit, out, err) = process.run([bng_cmd, "-H225.0.0.1"])

    # test that bng-cmd (tried to connecto to mcast host) exits with code != 0,
    # prints nothing to stdout and prints an error to stderr
    assert exit != 0 and out == "" and err != ""
