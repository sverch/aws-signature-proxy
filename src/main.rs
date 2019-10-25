extern crate simple_proxy;

mod aws_signature_builder;

use simple_proxy::{SimpleProxy, Environment};

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Cli {
    port: u16,
    region: String,
}

use rusoto_credential::{ProvideAwsCredentials, DefaultCredentialsProvider};
use futures::future::Future;

use hyper::header::HeaderValue;
use hyper::{Body, Request};

use hyper::header::AUTHORIZATION;

const XAMZCONTENTSHA256: &str = "x-amz-content-sha256";
const XAMZSECURITYTOKEN: &str = "x-amz-security-token";
const XAMZDATE: &str = "x-amz-date";

use simple_proxy::proxy::error::MiddlewareError;
use simple_proxy::proxy::middleware::MiddlewareResult::Next;
use simple_proxy::proxy::middleware::{Middleware, MiddlewareResult};
use simple_proxy::proxy::service::{ServiceContext, State};

pub struct AwsSignatureHeaders {
    region: String
}

impl AwsSignatureHeaders {
    pub fn new(region: String) -> Self {
        AwsSignatureHeaders{
            region: region
        }
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
        let mut headers = ::std::collections::HashMap::new();
        for (key, value) in req.headers().iter() {
            headers.insert(String::from(key.as_str()), String::from(value.to_str().unwrap()));
        }
        let port = match req.uri().port_part() {
            Some(x) => Some(x.as_u16()),
            None => None,
        };
        let host: String = req.uri().host().unwrap().to_string();
        let host_parts: Vec<&str> = host.split(".").collect();
        let provider = DefaultCredentialsProvider::new().unwrap();
        let credentials = provider.credentials().wait().unwrap();
        let new_headers = aws_signature_builder::generate_aws_signature_headers(
            aws_utc_datestrings,
            credentials,
            req.uri().query().unwrap().to_string(),
            headers,
            port,
            req.uri().host().unwrap().to_string(),
            req.method().to_string(),
            Vec::new(),
            false,
            host_parts[0].to_string(),
            self.region.clone(),
            req.uri().path().to_string());
        if new_headers.contains_key(XAMZCONTENTSHA256) {
            req.headers_mut().insert(XAMZCONTENTSHA256,
                HeaderValue::from_str(&new_headers[XAMZCONTENTSHA256]).unwrap());
        }
        if new_headers.contains_key(XAMZSECURITYTOKEN) {
            req.headers_mut().insert(XAMZSECURITYTOKEN,
                HeaderValue::from_str(&new_headers[XAMZSECURITYTOKEN]).unwrap());
        }
        if new_headers.contains_key(XAMZDATE) {
            req.headers_mut().insert(XAMZDATE,
                HeaderValue::from_str(&new_headers[XAMZDATE]).unwrap());
        }
        if new_headers.contains_key("Authorization") {
            req.headers_mut().insert(AUTHORIZATION,
                HeaderValue::from_str(&new_headers["Authorization"]).unwrap());
        }
        Ok(Next)
    }
}

fn main() {
    let args = Cli::from_args();

    // Simple proxy setup
    let mut proxy = SimpleProxy::new(args.port, Environment::Development);

    // Adding signature middleware
    let add_aws_signature_headers = AwsSignatureHeaders::new(args.region);
    proxy.add_middleware(Box::new(add_aws_signature_headers));

    // Start proxy
    proxy.run();
}
