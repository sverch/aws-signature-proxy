# AWS Sigature Proxy

A proxy whose entire job is to sign requests destined for the AWS API.

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
