import pathlib

import pytest
import tftest

REGION = "eu-west-1"
DOMAIN = "vandelay-industries.com"


@pytest.fixture(scope="session")
def terraform_dir():
    return str(pathlib.Path(__file__).resolve().parent.parent / "terraform")


@pytest.fixture()
def plan(terraform_dir: str):
    tf = tftest.TerraformTest(".", terraform_dir)
    tf.init()
    return tf.plan(tf_vars={"region": REGION, "domain": DOMAIN}, output=True)


def test_output(plan):
    outputs = plan.outputs

    assert outputs["Region"] == REGION
    assert outputs["Domain"] == DOMAIN

    # Test whether keys exist. The values are None since values are only
    # avaiable after applying changes.
    assert outputs["AccessKeyId"] is None
    assert outputs["SecretAccessKey"] is None
    assert outputs["DkimTokens"] is None
