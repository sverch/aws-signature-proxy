extern crate simple_proxy;

mod aws_signature_builder;

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Cli {
    port: u16,
}

use rusoto_credential::{ProvideAwsCredentials, DefaultCredentialsProvider};
use futures::future::Future;

use hyper::{Body, Chunk, Request, Response, Server};

use http::uri::Uri;

use monie::{Mitm, MitmProxyService};

#[derive(Debug)]
struct AddsAWSSignatureHeaders;

fn add_signature_headers(req: Request<Body>) -> Request<Body> {
    let mut request = Request::from(req);
    let aws_utc_datestrings = aws_signature_builder::AwsUTCDateStrings::new();
    let provider = DefaultCredentialsProvider::new().unwrap();
    let credentials = provider.credentials().wait().unwrap();
    let new_headers = aws_signature_builder::generate_aws_signature_headers(
        aws_utc_datestrings,
        credentials,
        &mut request);
    aws_signature_builder::add_aws_signature_headers(&mut request, new_headers);
    request
}

impl Mitm for AddsAWSSignatureHeaders {
    fn new(uri: Uri) -> AddsAWSSignatureHeaders {
        println!("proxying request for {}", uri);
        AddsAWSSignatureHeaders { }
    }

    fn request_headers(&self, req: Request<Body>) -> Request<Body> {
        add_signature_headers(req)
    }

    fn response_headers(&self, res: Response<Body>) -> Response<Body> {
        res
    }

    fn request_body_chunk(&self, chunk: Chunk) -> Chunk {
        chunk
    }

    fn response_body_chunk(&self, chunk: Chunk) -> Chunk {
        chunk
    }
}

fn main() {
    let args = Cli::from_args();
    let addr = ([127, 0, 0, 1], args.port).into();
    let svc = MitmProxyService::<AddsAWSSignatureHeaders>::new();
    let server = Server::bind(&addr)
        .serve(svc)
        .map_err(|e| eprintln!("server error: {}", e));
    println!("add-via mitm proxy listening on http://{}", addr);
    hyper::rt::run(server);
}
