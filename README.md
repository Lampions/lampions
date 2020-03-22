# Lampions

Lampions is a small project to configure email aliases and handle email
relaying/forwarding leveraging the AWS infrastructure.
The goal is to insulate a user's primary email address(es) from services they
have signed up for by creating dedicated aliases and associated routes used to
forward emails to private inboxes.
The advantage is that instead of having to manually opt-out of marketing
emails, Lampions lets users deactivate a route and silently drop such emails.
Moreover, if an alias suddenly starts receiving spam, it is easy to pinpoint
the service which leaked the address in the first place.

The core functionality of Lampions is built on top of AWS Simple Email Service
(SES), S3 and AWS Lambda.
The service is complemented by a small [browser extension] to quickly define
new email aliases, change forward addresses or enable/disable individual email
routes.
This repository describes the underlying architecture, and provides a
command-line utility to define and configure the necessary AWS infrastructure.

## Architecture Overview

The general architecture of Lampions is based on the [AWS email forwarding
guide].
The event sequence when an incoming email arrives on a domain is as follows:
1. All arriving emails on a domain are first accepted by SES and simply written
   to an S3 bucket.
1. A Lambda function is triggered to process the email.
   The function checks the recipient address against a set of routes to decide
   what to do with the email.
1. If an address found in the `To` header of an email matches a known (active)
   alias, the email header is updated, and the mail is sent to the
   corresponding forward address.
1. If no known alias is found or a route is inactive, the email is simply
   ignored.

## Caveats

Due to limitations in SES, there are a few caveats to keep in mind when using
Lampions.
1. Without moving the associated AWS account out of the [SES sandbox], it is
   only possible to forward emails to verified addresses.
   Since the set of forward addresses in the general use case is expected to be
   rather limited, this limitation does not pose any significant issues.
   For convenience, the `lampions` command-line utility provides the
   `verify-email-addresses` subcommand to initiate the verification process.
1. Addresses in `From` and `Return-Path` headers must be verified in SES.
   This means that we cannot preserve the original `From` header of incoming
   emails.
   Instead, we always forward emails using the special `lampions@<domain>`
   address.
   To reflect the original sender in the forwarded email, we update the headers
   such that
   ```raw
   From: Art Vandelay <art@vandelay-industries.com>
   ```
   becomes
   ```raw
   From: Art Vandelay (via) art@vandelay-industries.com <lampions@<domain>
   ```
   The `Reply-To` header is left untouched if it was present in the original
   email.

## Setup

For ease of use, `lampions` provides a series of subcommands to configure the
necessary AWS infrastructure.
To that end, we assume that the [AWS CLI] has been configured following [AWS
best practices].
In particular, we assume that the access key found in the `~/.aws/credentials`
file belongs to a user with admin privileges for S3, SES, IAM and AWS Lambda.
Alternatively, since `lampions` uses the `boto3` python package to interface
with the AWS API, the usual environment variable overrides `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, etc. can be used instead.

To get started, first run `lampions init --region <region> --domain <domain>`
to initialize the Lampions config with the region in which all AWS resources
will be created.

After that, the `lampions configure` command can be used to perform all
necessary configuration steps in sequence.
Alternatively, one may perform the individual steps manually:
1. Call `lampions configure create-bucket` to create an S3 bucket in which the
   routes table and incoming emails will be stored.
1. Use `lampions configure create-route-user` to create a new user in IAM with
   read/write access to the routes table.
   The user credentials, which are also needed to define routes via the
   [browser extension], will be stored in the config file.
   To view the config and retrieve the user credentials, run `lampions
   show-config`.
1. In order to configure a domain for sending and receiving, use `lampions
   configure verify-domain` to add a domain to SES.
   When a domain is successfully added, the subcommand writes a set of DKIM
   tokens to the config file.
   These tokens then need to be used to add a set of CNAME records to the DNS
   settings of the domain in order to enable email sending via the domain.
1. Finally, create a receipt rule set to write incoming emails to an S3 bucket,
   and trigger the Lambda function, which forwards emails according to the
   information found in the routes table.
   To that end, run `lampions configure create-receipt-rule`.

## Defining Routes

In order to forward incoming emails when the AWS account is still in the [SES
sandbox], forward addresses first need to be verified by SES.
To that end, use `lampions add-forward-address` to add an address to the SES
identity list, and send a verification mail to the address.

In order to manipulate routes, the following commands are provided:
* To list defined routes, use `lampions list-routes`.
* To add, update or remove a route, use `lampions {add,update,remove}-route`.

Refer to the help pages of the respective commands for more information.

[browser extension]: https://github.com/lampions/lampions-browser-extension
[AWS email forwarding guide]: https://aws.amazon.com/blogs/messaging-and-targeting/forward-incoming-email-to-an-external-destination/
[AWS CLI]: https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html#cli-quick-configuration
[AWS best practices]: https://docs.aws.amazon.com/IAM/latest/UserGuide/getting-started_create-admin-group.html
[SES sandbox]: https://docs.aws.amazon.com/ses/latest/DeveloperGuide/request-production-access.html
