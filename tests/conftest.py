import pytest
from common import micro_bngd_process, config, veth


def pytest_addoption(parser):
    parser.addoption("--bng_cmd", action="store", default="bng-cmd")
    parser.addoption("--micro_bngd", action="store", default="micro-bngd")
    parser.addoption("--pppd", action="store", default="pppd")  # pppd client
    parser.addoption(
        "--dhclient", action="store", default="dhclient"
    )  # isc-dhcp-client
    parser.addoption(
        "--micro_bngd_max_wait_time", action="store", default=5.0
    )  # start timeout
    parser.addoption(
        "--micro_bngd_max_finish_time", action="store", default=10.0
    )  # fininsh timeout (before kill)


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "ipoe_driver: marks tests as related to ipoe kernel module (deselect with '-m \"not ipoe_driver\"')",
    )
    config.addinivalue_line(
        "markers",
        "vlan_mon_driver: marks tests as related to ipoe kernel module (deselect with '-m \"not vlan_mon_driver\"')",
    )


# micro-bngd executable file name
@pytest.fixture()
def micro_bngd(pytestconfig):
    return pytestconfig.getoption("micro_bngd")


# bng-cmd executable file name
@pytest.fixture()
def bng_cmd(pytestconfig):
    return pytestconfig.getoption("bng_cmd")


# micro-bngd configuration as string (should be redefined by specific test)
@pytest.fixture()
def micro_bngd_config():
    return ""


# micro-bngd configuration file name
@pytest.fixture()
def micro_bngd_config_file(micro_bngd_config):
    # test setup:
    filename = config.make_tmp(micro_bngd_config)

    # test execution
    yield filename

    # test teardown:
    config.delete_tmp(filename)


# setup and teardown for tests that required running micro-bngd
@pytest.fixture()
def micro_bngd_instance(micro_bngd, micro_bngd_config_file, bng_cmd, pytestconfig):
    # test setup:
    is_started, micro_bngd_thread, micro_bngd_control = micro_bngd_process.start(
        micro_bngd,
        ["-c" + micro_bngd_config_file],
        bng_cmd,
        pytestconfig.getoption("micro_bngd_max_wait_time"),
    )

    # test execution:
    yield is_started

    # test teardown:
    micro_bngd_process.end(
        micro_bngd_thread,
        micro_bngd_control,
        bng_cmd,
        pytestconfig.getoption("micro_bngd_max_finish_time"),
    )

# defines vlans that will be created over veth pair (might be redefined by specific test)
@pytest.fixture()
def veth_pair_vlans_config():
    return {"vlans_a": [], "vlans_b": []}

# setup and teardown for netns and veth pair
@pytest.fixture()
def veth_pair_netns(veth_pair_vlans_config):
    # test setup:
    veth_pair_netns_instance = veth.create_veth_pair_netns(veth_pair_vlans_config)

    # test execution:
    yield veth_pair_netns_instance

    # test teardown:
    veth.delete_veth_pair_netns(veth_pair_netns_instance)
