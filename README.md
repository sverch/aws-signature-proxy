# AWS Sigature Proxy

## Motivation

The AWS API requires a non-standard signing process invented by Amazon, which
makes it incompatible with many standard tools, as you can see from the need for
projects like [awscurl](https://github.com/okigan/awscurl), also known as "curl
but it works with AWS".

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
cargo run 8080 us-east-1
```

Then, in another terminal, run:

```shell
http_proxy=localhost:8080 curl -s \
    "http://ec2.amazonaws.com?Action=DescribeInstances&Version=2013-10-15"
```

## Caveats

- Only `GET` requests are supported.
- Region handling is weird, could auto detect from the URL by following
  https://docs.aws.amazon.com/general/latest/gr/rande.html.  Also, there is a
  relevant [rusoto issue](https://github.com/rusoto/rusoto/issues/1120) about
  getting the default region from the current profile.
- Only http is supported because the proxy can't change the headers for https
  requests.  Changing the proxy library to a man in the middle proxy should
  allow for https support.  See
  [here](https://github.com/nlevitt/monie/blob/master/examples/add-via.rs) for
  an example.

## Thanks

This project wouldn't be possible without the great work on
https://github.com/okigan/awscurl.  The signing logic is heavily ported from
that.
