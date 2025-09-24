import pytest
from common import process


def test_micro_bngd_version(micro_bngd):
    (exit, out, err) = process.run([micro_bngd, "--version"])

    # test that micro-bngd --version exits with code 0, prints
    # nothing to stdout and prints to stdout
    assert exit == 0 and err == "" and "micro-bng " in out and len(out.split(" ")) == 2


@pytest.fixture()
def micro_bngd_config():
    return """
    [modules]
    log_file
    log_syslog
    log_tcp
    #log_pgsql

    pptp
    l2tp
    sstp
    pppoe
    ipoe

    auth_mschap_v2
    auth_mschap_v1
    auth_chap_md5
    auth_pap

    radius
    chap-secrets

    ippool

    pppd_compat
    shaper
    #net-snmp
    logwtmp
    connlimit

    ipv6_nd
    ipv6_dhcp
    ipv6pool

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [cli]
    tcp=127.0.0.1:2001

    [pppoe]

    [client-ip-range]
    10.0.0.0/8

    [radius]
    """


# load all modules and check that micro-bngd replies to 'show stat' command
def test_load_all_modules(micro_bngd_instance, bng_cmd):

    # test that micro-bngd started successfully
    assert micro_bngd_instance

    (exit_sh_stat, out_sh_stat, err_sh_stat) = process.run([bng_cmd, "show stat"])

    # test that 'show stat' has no errors and contains 'uptime'
    assert (
        exit_sh_stat == 0
        and len(out_sh_stat) > 1
        and err_sh_stat == ""
        and "uptime" in out_sh_stat
    )
