import pytest
from common import process


@pytest.fixture()
def micro_bngd_config():
    return """
    [modules]

    [log]
    log-debug=/dev/stdout
    level=5

    [cli]
    tcp=127.0.0.1:2001
    """


# test bng-cmd command with started micro-bngd
def test_bng_cmd_commands(micro_bngd_instance, bng_cmd):

    # test that micro-bngd started successfully
    assert micro_bngd_instance

    (exit_sh_stat, out_sh_stat, err_sh_stat) = process.run([bng_cmd, "show stat"])

    # test that 'show stat' has no errors and contains 'uptime'
    assert (
        exit_sh_stat == 0
        and len(out_sh_stat) > 0
        and err_sh_stat == ""
        and "uptime" in out_sh_stat
    )

    (exit_sh_ses, out_sh_ses, err_sh_ses) = process.run(
        [bng_cmd, "show sessions sid,uptime"]
    )
    # test that 'show sessions' has no errors and contains 'sid'
    assert (
        exit_sh_ses == 0
        and len(out_sh_ses) > 0
        and err_sh_ses == ""
        and "sid" in out_sh_ses
    )

    (exit_help, out_help, err_help) = process.run([bng_cmd, "help"])
    # test that 'help' has no errors and contains 'show stat'
    assert (
        exit_help == 0
        and len(out_help) > 0
        and err_help == ""
        and "show stat" in out_help
    )
