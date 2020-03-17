# Lampions

Lampions is a project to configure email aliases and handle email
relaying/forwarding with opaque sender information.
The aim is to insulate a user's primary email address(es) from services they
have signed up for by creating dedicated aliases and associated routes for each
unique combination of sender and receiver.
The core functionality is built on top of AWS Simple Email Service (SES), S3
and AWS Lambda.
The service is complemented by a small [browser extension] to quickly define
new email aliases, change forward addresses or enable/disable individual email
routes.
This repository provides a command-line utility to ease setting up the required
AWS infrastructure.

[browser extension]: https://github.com/lampions/lampions-webext
