# AWS Sigature Proxy

## Motivation

The AWS API requires a [non-standard signing process invented by
Amazon](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html),
which makes it incompatible with many standard tools, as you can see from the
need for projects like [awscurl](https://github.com/okigan/awscurl), also known
as "curl but it works with AWS".

This project aims to fix that by hiding the non-standard signing process behind
a proxy, so that standard clients like curl (example below) and
[OpenAPI](https://github.com/APIs-guru/openapi-directory/tree/master/APIs/amazonaws.com)
can interact with the AWS API by sending all requests through it.

That will hopefully allow us to take advantage of powerful open source tools
that would otherwise be difficult to use with this API. If you are bored and
want to know why the proxy seemed like a good idea over other alternatives, feel
free to read [this
post](https://shaunverch.com/butter/open-source/2019/09/27/butter-days-6.html).

## Usage

First, make sure you have your AWS credentials set up, and then run:

```shell
cargo run 8080
```

Then, in another terminal, run:

```shell
https_proxy=localhost:8080 curl --insecure --silent \
    "https://ec2.amazonaws.com?Action=DescribeInstances&Version=2013-10-15"
```

## Self Signed Certificates

By default, the proxy generates a standalone self signed certificate for each
endpoint on demand, which means you will have to ignore certificate validation
errors to use it.

To use your own certificates that you have presumably trusted, you can set
`MONIE_CERT_FILE` and `MONIE_KEY_FILE` to custom certificates.

The `gencerts.sh` helper script uses the wonderful
[mkcert](https://github.com/FiloSottile/mkcert) tool to help you easily generate
some self signed certificates that can pose as the AWS endpoints.  The mkcert
tool also automatically tells your system to trust the CA, so after you run this
the certs should "just work":

```
$ ./gencerts.sh ./certs us-east-1 us-west-2
+ mkdir certs
Generating certificates for endpoints in "us-east-1 us-west-2"
+ go run github.com/FiloSottile/mkcert -install -cert-file certs/cert.pem -key-file certs/private.pem *.amazonaws.com *.us-east-1.amazonaws.com *.us-west-2.amazonaws.com
Using the local CA at "/home/sverch/.local/share/mkcert" ✨

Created a new certificate valid for the following names 📜
 - "*.amazonaws.com"
 - "*.us-east-1.amazonaws.com"
 - "*.us-west-2.amazonaws.com"

Reminder: X.509 wildcards only go one level deep, so this won't match a.b.amazonaws.com ℹ️

The certificate is at "certs/cert.pem" and the key at "certs/private.pem" ✅

Converting private key to RSA private key
+ openssl rsa -in certs/private.pem -out certs/private.key
writing RSA key
Certificates generated!  Set the following environment variables:
export MONIE_CERT_FILE=certs/cert.pem
export MONIE_KEY_FILE=certs/private.key
```

After setting `MONIE_CERT_FILE` and `MONIE_KEY_FILE` to what the script tells
you to set them to, you should be able to run `curl` without the `--insecure`
option.  You should also be able to run other clients without any errors.

## The AWS Signing Process

If you want to understand the signing process, there are many AWS docs on this.
For the purposes of this project, the logic here was taken from
[awscurl](https://github.com/okigan/awscurl), which in turn was likely heavily
copied from [these python examples in the AWS
docs](https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html).

## Caveats

- Only `GET` requests are supported.

## Thanks

- This project wouldn't be possible without the great work on
  https://github.com/okigan/awscurl.  The signing logic is heavily ported from
  that.
- It also wouldn't be possible without
  https://github.com/terry90/rs-simple-proxy which the first version was based
  on or https://github.com/nlevitt/monie which was necessary for man in the
  middle https support.
