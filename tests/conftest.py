import json
import os

import boto3
import pytest
from moto import mock_s3, mock_ses

REGION = "eu-west-1"


@pytest.fixture
def aws_credentials():
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"


@pytest.fixture
def s3_client(aws_credentials):
    with mock_s3():
        yield boto3.client("s3", region_name=REGION)


@pytest.fixture
def s3_bucket(s3_client):
    def create_bucket(domain: str):
        bucket_name = f"lampions.{domain}"
        try:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": REGION},
            )
        except (
            s3_client.exceptions.BucketAlreadyExists,
            s3_client.exceptions.BucketAlreadyOwnedByYou,
        ):
            pass
        return boto3.resource("s3").Bucket(bucket_name)

    yield create_bucket


@pytest.fixture
def ses_client():
    with mock_ses():
        yield boto3.client("ses", region_name=REGION)


@pytest.fixture
def create_test_email():
    # TODO: Don't use raw strings for this.
    def test_email(domain: str):
        return f"""
Received: from mailout.mobile.de
Received-SPF: pass
Authentication-Results: amazonses.com;
Received: from localhost (localhost [127.0.0.1])
DKIM-Signature: v=1;
Subject: Shark Tank
Content-Type: text/html;charset=UTF-8
Date: Tue, 31 Aug 2021 10:55:28 +0200 (CEST)
Mime-Version: 1.0
Content-Transfer-Encoding: quoted-printable
Message-ID: <42@{domain}>
From: H.E. Pennypacker <he@pennypacker.biz>
To: art@{domain}

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4=2E01 Transitional//EN" "http://ww=
w=2Ew3=2Eorg/TR/html4/loose=2Edtd">
<html>
<body>Hello</body>
</html>
""".strip()

    return test_email


@pytest.fixture
def create_test_routes():
    def test_routes(routes) -> str:
        return json.dumps(
            {
                "routes": [
                    {
                        "id": i,
                        "active": state,
                        "alias": alias,
                        "forward": forward_address,
                        "createdAt": "Sat, 11 Feb 2023 19:47:17 GMT",
                        "meta": None,
                    }
                    for i, (alias, forward_address, state) in enumerate(routes)
                ],
            }
        )

    return test_routes
