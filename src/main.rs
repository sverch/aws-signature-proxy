extern crate simple_proxy;

mod aws_signature_builder;

use simple_proxy::{SimpleProxy, Environment};

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Cli {
    port: u16,
}

use rusoto_credential::{ProvideAwsCredentials, DefaultCredentialsProvider};
use futures::future::Future;

use hyper::{Body, Request};

use simple_proxy::proxy::error::MiddlewareError;
use simple_proxy::proxy::middleware::MiddlewareResult::Next;
use simple_proxy::proxy::middleware::{Middleware, MiddlewareResult};
use simple_proxy::proxy::service::{ServiceContext, State};

pub struct AwsSignatureHeaders { }

impl AwsSignatureHeaders {
    pub fn new() -> Self {
        AwsSignatureHeaders{ }
    }
}

impl Middleware for AwsSignatureHeaders {
    fn name() -> String {
        String::from("AwsSignatureHeaders")
    }

    fn before_request(
        &mut self,
        req: &mut Request<Body>,
        _context: &ServiceContext,
        _state: &State,
    ) -> Result<MiddlewareResult, MiddlewareError> {
        let aws_utc_datestrings = aws_signature_builder::AwsUTCDateStrings::new();
        let provider = DefaultCredentialsProvider::new().unwrap();
        let credentials = provider.credentials().wait().unwrap();
        let new_headers = aws_signature_builder::generate_aws_signature_headers(
            aws_utc_datestrings,
            credentials,
            req);
        aws_signature_builder::add_aws_signature_headers(req, new_headers);
        Ok(Next)
    }
}

fn main() {
    let args = Cli::from_args();

    // Simple proxy setup
    let mut proxy = SimpleProxy::new(args.port, Environment::Development);

    // Adding signature middleware
    let add_aws_signature_headers = AwsSignatureHeaders::new();
    proxy.add_middleware(Box::new(add_aws_signature_headers));

    // Start proxy
    proxy.run();
}
