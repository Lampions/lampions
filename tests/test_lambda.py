import pathlib

import pytest
import sure  # noqa

import lampions.lambda_function

REGION = "eu-west-1"
DOMAIN = "vandelay-industries.com"


@pytest.fixture()
def create_ses_sns_event(s3_bucket, create_test_email):
    bucket = s3_bucket(DOMAIN)

    email = create_test_email(DOMAIN)
    message_id = "42"
    bucket.put_object(Body=email, Key=str(pathlib.Path("inbox") / message_id))

    return {"Records": [{"ses": {"mail": {"messageId": message_id}}}]}, None


@pytest.fixture()
def _create_routes(s3_bucket, create_test_routes):
    bucket = s3_bucket(DOMAIN)
    routes = create_test_routes(
        [
            ("yankees", "kel@varnsen.biz", True),
            ("art", "kel@varnsen.biz", True),
        ]
    )
    bucket.put_object(Body=routes, Key="routes.json")


@pytest.mark.usefixtures("_create_routes")
def test_handler(monkeypatch, create_ses_sns_event, ses_client):
    monkeypatch.setenv("LAMPIONS_REGION", REGION)
    monkeypatch.setenv("LAMPIONS_DOMAIN", DOMAIN)

    ses_client.verify_domain_identity(Domain=DOMAIN)

    event, context = create_ses_sns_event
    lampions.lambda_function.handler(event, context)
    int(ses_client.get_send_quota()["SentLast24Hours"]).should.equal(2)
