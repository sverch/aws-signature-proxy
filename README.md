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

## The AWS Signing Process

If you want to understand the signing process, there are many AWS docs on this.
For the purposes of this project, the logic here was taken from
[awscurl](https://github.com/okigan/awscurl), which in turn was likely heavily
copied from [these python examples in the AWS
docs](https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html).

## Caveats

- Only `GET` requests are supported.
- Region is hardcoded to `us-east-1`.  Could auto detect from the URL by
  following https://docs.aws.amazon.com/general/latest/gr/rande.html.  Also,
  there is a relevant [rusoto
  issue](https://github.com/rusoto/rusoto/issues/1120) about getting the default
  region from the current profile.
- No attempt has been made to address the invalid certificate errors a client
  will experience when working with this proxy.

## Thanks

- This project wouldn't be possible without the great work on
  https://github.com/okigan/awscurl.  The signing logic is heavily ported from
  that.
- It also wouldn't be possible without
  https://github.com/terry90/rs-simple-proxy which the first version was based
  on or https://github.com/nlevitt/monie which was necessary for man in the
  middle https support.
