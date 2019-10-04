extern crate querystring;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use hmac_sha256::HMAC;

use hex;
use chrono;

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

use std::collections::HashMap;

/// https://url.spec.whatwg.org/#fragment-percent-encode-set
const FRAGMENT: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'<').add(b'>').add(b'`');

/// https://url.spec.whatwg.org/#path-percent-encode-set
const PATH: &AsciiSet = &FRAGMENT.add(b'#').add(b'?').add(b'{').add(b'}');

fn normalize_query_string(query: String) -> String {
    let mut query_pairs = querystring::querify(&query);
    query_pairs.sort_by(|a, b| a.0.cmp(&b.0));
    return String::from(querystring::stringify(query_pairs).trim_end_matches("&"));
}

pub fn get_utc_aws_signature_datestrings() -> (String, String) {
    let now = chrono::Utc::now();
    let amzdate = now.format("%Y%m%dT%H%M%SZ").to_string();
    let datestamp = now.format("%Y%m%d").to_string();
    return (amzdate, datestamp)
}

pub fn generate_aws_signature_headers(
    query: String,
    headers: HashMap<String, String>,
    port: Option<u16>,
    host: String,
    amzdate: String,
    method: String,
    data: Vec<u8>,
    security_token: Option<String>,
    data_binary: bool,
    datestamp: String,
    service: String,
    region: String,
    access_key: String,
    secret_key: String,
    canonical_uri: String) -> HashMap<String, String> {
    let (canonical_request,
         payload_hash,
         signed_headers) = task_1_create_a_canonical_request(
         query, headers, port, host, amzdate.clone(), method, data, security_token.clone(),
         data_binary, canonical_uri);
    let (string_to_sign,
         algorithm,
         credential_scope) = task_2_create_the_string_to_sign(
         amzdate.clone(), datestamp.clone(), canonical_request, service.clone(), region.clone());
    let signature = task_3_calculate_the_signature(
        datestamp, string_to_sign, service, region, secret_key);
    let new_headers = task_4_build_auth_headers_for_the_request(
        amzdate, payload_hash, algorithm, credential_scope, signed_headers, signature, access_key,
        security_token);
    return new_headers;
}

/// ************* TASK 1: CREATE A CANONICAL REQUEST *************
/// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
///
/// Step 1 is to define the verb (GET, POST, etc.)--already done.
///
/// Step 2: Create canonical URI--the part of the URI from domain to query string (use '/' if no
/// path)
fn task_1_create_a_canonical_request(
    query: String,
    headers: HashMap<String, String>,
    port: Option<u16>,
    host: String,
    amzdate: String,
    method: String,
    data: Vec<u8>,
    security_token: Option<String>,
    data_binary: bool,
    canonical_uri: String) -> (String, String, String) {

    // Step 3: Create the canonical query string. In this example (a GET request), request
    // parameters are in the query string. Query string values must be URL-encoded (space=%20). The
    // parameters must be sorted by name.  For this example, the query string is pre-formatted in
    // the request_parameters variable.
    let canonical_querystring = normalize_query_string(query);

    // If the host was specified in the HTTP header, ensure that the canonical headers are set
    // accordingly
    let fullhost = if headers.contains_key("host") {
        headers["host"].clone()
    } else {
        let fullhost = match port {
            Some(p) => format!("{}:{}", host, p.to_string()),
            None => host,
        };
        fullhost
    };

    // Step 4: Create the canonical headers and signed headers. Header names and value must be
    // trimmed and lowercase, and sorted in ASCII order.  Note that there is a trailing \n.
    let mut canonical_headers = format!("host:{}\nx-amz-date:{}\n", fullhost, amzdate);
    match &security_token {
        Some(t) => canonical_headers.push_str(&format!("x-amz-security-token:{}\n", t)),
        None => (),
    };

    // Step 5: Create the list of signed headers. This lists the headers in the canonical_headers
    // list, delimited with ";" and in alpha order.  Note: The request can include any headers;
    // canonical_headers and signed_headers lists those that you want to be included in the hash of
    // the request. "Host" and "x-amz-date" are always required.
    let mut signed_headers = String::from("host;x-amz-date");
    match &security_token {
        Some(_) => signed_headers.push_str(";x-amz-security-token"),
        None => (),
    };

    // Step 6: Create payload hash (hash of the request body content). For GET requests, the
    // payload is an empty string ("").
    let mut hasher = Sha256::new();
    let payload_hash = if data_binary {
        hasher.input(&data);
        hasher.result_str()
    } else {
        let s = match std::str::from_utf8(&data) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };
        hasher.input_str(s);
        hasher.result_str()
    };

    // Step 7: Combine elements to create create canonical request
    let canonical_request = format!("{}\n{}\n{}\n{}\n{}\n{}",
        method, utf8_percent_encode(&canonical_uri, PATH).to_string(), canonical_querystring,
        canonical_headers, signed_headers, payload_hash);

    return (canonical_request, payload_hash, signed_headers)
}

/// ************* TASK 2: CREATE THE STRING TO SIGN*************
/// Match the algorithm to the hashing algorithm you use, either SHA-1 or SHA-256 (recommended)
fn task_2_create_the_string_to_sign(
    amzdate: String,
    datestamp: String,
    canonical_request: String,
    service: String,
    region: String) -> (String, String, String) {
    let algorithm = String::from("AWS4-HMAC-SHA256");
    let credential_scope = format!("{}/{}/{}/aws4_request", datestamp, region, service);
    let mut hasher = Sha256::new();
    hasher.input_str(&canonical_request);
    let canonical_request_hash = hasher.result_str();
    let string_to_sign = format!("{}\n{}\n{}\n{}", algorithm, amzdate, credential_scope,
        canonical_request_hash);

    return (string_to_sign, algorithm, credential_scope)
}

/// ************* TASK 3: CALCULATE THE SIGNATURE *************
fn task_3_calculate_the_signature(
    datestamp: String,
    string_to_sign: String,
    service: String,
    region: String,
    secret_key: String) -> String {

    // See: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
    //
    // In AWS Signature Version 4, instead of using your AWS access keys to sign a request, you
    // first create a signing key that is scoped to a specific region and service.  For more
    // information about signing keys, see Introduction to Signing Requests.
    //
    // Key derivation functions.
    // See: http://docs.aws.amazon.com
    // /general/latest/gr/signature-v4-examples.html
    // #signature-v4-examples-python
    let k_date = HMAC::mac(datestamp.as_bytes(), format!("AWS4{}", secret_key).as_bytes());
    let k_region = HMAC::mac(region.as_bytes(), &k_date);
    let k_service = HMAC::mac(service.as_bytes(), &k_region);
    let k_signing = HMAC::mac(b"aws4_request", &k_service);

    // Sign the string_to_sign using the signing key
    let signature = HMAC::mac(string_to_sign.as_bytes(), &k_signing);

    return hex::encode(signature.to_vec())
}

/// ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST ***********
/// The signing information can be either in a query string value or in a header named
/// Authorization. This function shows how to use the header.  It returns a headers dict with all
/// the necessary signing headers.
fn task_4_build_auth_headers_for_the_request(
    amzdate: String,
    payload_hash: String,
    algorithm: String,
    credential_scope: String,
    signed_headers: String,
    signature: String,
    access_key: String,
    security_token: Option<String>) -> HashMap<String, String> {

    // Create authorization header and add to request headers
    let authorization_header = format!("{} Credential={}/{}, SignedHeaders={}, Signature={}",
        algorithm, access_key, credential_scope, signed_headers, signature);

    // The request can include any headers, but MUST include "host", "x-amz-date", and (for this
    // scenario) "Authorization". "host" and "x-amz-date" must be included in the canonical_headers
    // and signed_headers, as noted earlier. Order here is not significant.
    let mut headers = ::std::collections::HashMap::new();
    headers.insert(
        String::from("Authorization"),
        String::from(authorization_header));
    headers.insert(
        String::from("x-amz-date"),
        String::from(amzdate));
    match &security_token {
        Some(t) => headers.insert(
            String::from("x-amz-security-token"),
            String::from(t)),
        None => None,
    };
    headers.insert(
        String::from("x-amz-content-sha256"),
        String::from(payload_hash));
    return headers;
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_normalize_query_string() {
        let canonical_querystring_1 = super::normalize_query_string(
            String::from("Version=2013-10-15&Action=DescribeInstances"));
        assert_eq!(canonical_querystring_1,
            String::from("Action=DescribeInstances&Version=2013-10-15"));
        let canonical_querystring_2 = super::normalize_query_string(
            String::from("Version=2013-10-15&Action=DescribeInstances"));
        assert_eq!(canonical_querystring_2,
            String::from("Action=DescribeInstances&Version=2013-10-15"));
    }

    #[test]
    fn test_task_1_create_a_canonical_request() {
        let mut headers = ::std::collections::HashMap::new();
        headers.insert(
            String::from("Content-Type"),
            String::from("application/json"));
        headers.insert(
            String::from("Accept"),
            String::from("application/xml"));
        let (canonical_request,
             payload_hash,
             signed_headers) = super::task_1_create_a_canonical_request(
            String::from("Action=DescribeInstances&Version=2013-10-15"),
            headers,
            None,
            String::from("ec2.amazonaws.com"),
            String::from("20190921T022008Z"),
            String::from("GET"),
            Vec::new(),
            None,
            false,
            String::from("/"));
        assert_eq!(canonical_request, "GET\n\
                         /\n\
                         Action=DescribeInstances&Version=2013-10-15\n\
                         host:ec2.amazonaws.com\n\
                         x-amz-date:20190921T022008Z\n\
                         \n\
                         host;x-amz-date\n\
                         e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(payload_hash,
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(signed_headers, "host;x-amz-date");
    }


    #[test]
    fn test_task_2_create_the_string_to_sign() {
        let (string_to_sign,
             algorithm,
             credential_scope) = super::task_2_create_the_string_to_sign(
            String::from("20190921T022008Z"),
            String::from("20190921"),
            String::from("GET\n\
            /\n\
            Action=DescribeInstances&Version=2013-10-15\n\
            host:ec2.amazonaws.com\n\
            x-amz-date:20190921T022008Z\n\
            \n\
            host;x-amz-date\n\
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            String::from("ec2"),
            String::from("us-east-1"));
        assert_eq!(string_to_sign, "AWS4-HMAC-SHA256\n\
                         20190921T022008Z\n\
                         20190921/us-east-1/ec2/aws4_request\n\
                         4a3b77321aca7e671d4945f0b3b826112e5ca3f2a10c4357e54f518798e7c8ff");
        assert_eq!(algorithm, "AWS4-HMAC-SHA256");
        assert_eq!(credential_scope, "20190921/us-east-1/ec2/aws4_request");
    }


    #[test]
    fn test_task_3_calculate_the_signature() {
        let signature = super::task_3_calculate_the_signature(
            String::from("20190921"),
            String::from("AWS4-HMAC-SHA256\n\
                20190921T022008Z\n\
                20190921/us-east-1/ec2/aws4_request\n\
                4a3b77321aca7e671d4945f0b3b826112e5ca3f2a10c4357e54f518798e7c8ff"),
            String::from("ec2"),
            String::from("us-east-1"),
            String::from("dummytestsecretkey"));
        assert_eq!(signature,
                         "9164aea23e266890838ff6e51eea552e2ee39c63896ac61d91990f200bb16362");
    }


    #[test]
    fn test_task_4_build_auth_headers_for_the_request() {
        let new_headers = super::task_4_build_auth_headers_for_the_request(
            String::from("20190921T022008Z"),
            String::from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            String::from("AWS4-HMAC-SHA256"),
            String::from("20190921/us-east-1/ec2/aws4_request"),
            String::from("host;x-amz-date"),
            String::from("9164aea23e266890838ff6e51eea552e2ee39c63896ac61d91990f200bb16362"),
            String::from("AKIAIJLPLDILMJV53HCQ"),
            None);
        assert_eq!(
            new_headers["x-amz-content-sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert!(!new_headers.contains_key("x-amz-security-token"));
        assert_eq!(
            new_headers["x-amz-date"],
            "20190921T022008Z");
        assert_eq!(
            new_headers["Authorization"],
            "AWS4-HMAC-SHA256 \
            Credential=AKIAIJLPLDILMJV53HCQ/20190921/us-east-1/ec2/aws4_request, \
            SignedHeaders=host;x-amz-date, \
            Signature=9164aea23e266890838ff6e51eea552e2ee39c63896ac61d91990f200bb16362");
    }

    #[test]
    fn test_generate_aws_signature_headers() {
        let mut headers = ::std::collections::HashMap::new();
        headers.insert(
            String::from("Content-Type"),
            String::from("application/json"));
        headers.insert(
            String::from("Accept"),
            String::from("application/xml"));
        let new_headers = super::generate_aws_signature_headers(
            String::from("Action=DescribeInstances&Version=2013-10-15"),
            headers,
            None,
            String::from("ec2.amazonaws.com"),
            String::from("20190921T022008Z"),
            String::from("GET"),
            Vec::new(),
            None,
            false,
            String::from("20190921"),
            String::from("ec2"),
            String::from("us-east-1"),
            String::from("AKIAIJLPLDILMJV53HCQ"),
            String::from("dummytestsecretkey"),
            String::from("/"));
        assert_eq!(
            new_headers["x-amz-content-sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert!(!new_headers.contains_key("x-amz-security-token"));
        assert_eq!(
            new_headers["x-amz-date"],
            "20190921T022008Z");
        assert_eq!(
            new_headers["Authorization"],
            "AWS4-HMAC-SHA256 \
            Credential=AKIAIJLPLDILMJV53HCQ/20190921/us-east-1/ec2/aws4_request, \
            SignedHeaders=host;x-amz-date, \
            Signature=9164aea23e266890838ff6e51eea552e2ee39c63896ac61d91990f200bb16362");
    }
}
