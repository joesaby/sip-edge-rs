// benches/parser_benchmarks.rs - Performance benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use sip_parser::*;
use std::collections::HashMap;

fn create_simple_request() -> Vec<u8> {
    b"OPTIONS sip:server.com SIP/2.0\r\n\
      Via: SIP/2.0/UDP client.com;branch=z9hG4bK776asdhds\r\n\
      From: <sip:client@client.com>;tag=1928301774\r\n\
      To: <sip:server@server.com>\r\n\
      Call-ID: a84b4c76e66710@client.com\r\n\
      CSeq: 63104 OPTIONS\r\n\
      Max-Forwards: 70\r\n\
      Content-Length: 0\r\n\
      \r\n".to_vec()
}

fn create_complex_request() -> Vec<u8> {
    b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
      Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
      Via: SIP/2.0/UDP bigbox3.site3.atlanta.com\r\n\
      Max-Forwards: 70\r\n\
      From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
      To: Bob <sip:bob@biloxi.com>\r\n\
      Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
      CSeq: 314159 INVITE\r\n\
      Contact: <sip:alice@pc33.atlanta.com>\r\n\
      Authorization: Digest username=\"alice\", realm=\"atlanta.com\",\r\n\
        nonce=\"84a4cc6f3082121f32b42a2187831a9e\",\r\n\
        response=\"7587245234b3434cc3412213e5f113a5432\"\r\n\
      Content-Type: application/sdp\r\n\
      Content-Length: 142\r\n\
      \r\n\
      v=0\r\n\
      o=alice 2890844526 2890844526 IN IP4 pc33.atlanta.com\r\n\
      s=Session Description\r\n\
      c=IN IP4 pc33.atlanta.com\r\n\
      t=0 0\r\n\
      m=audio 49170 RTP/AVP 0\r\n\
      a=rtpmap:0 PCMU/8000\r\n".to_vec()
}

fn create_response() -> Vec<u8> {
    b"SIP/2.0 200 OK\r\n\
      Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds;received=192.0.2.1\r\n\
      From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
      To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
      Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
      CSeq: 314159 INVITE\r\n\
      Contact: <sip:bob@192.0.2.4>\r\n\
      Content-Type: application/sdp\r\n\
      Content-Length: 131\r\n\
      \r\n\
      v=0\r\n\
      o=bob 2890844527 2890844527 IN IP4 biloxi.com\r\n\
      s=Session Description\r\n\
      c=IN IP4 biloxi.com\r\n\
      t=0 0\r\n\
      m=audio 3456 RTP/AVP 0\r\n\
      a=rtpmap:0 PCMU/8000\r\n".to_vec()
}

fn benchmark_parse_simple_request(c: &mut Criterion) {
    let request = create_simple_request();
    let mut group = c.benchmark_group("parse_simple_request");
    group.throughput(Throughput::Bytes(request.len() as u64));
    
    group.bench_function("parse", |b| {
        b.iter(|| {
            let result = parse_sip_message(black_box(&request));
            assert!(result.is_ok());
        })
    });
    
    group.finish();
}

fn benchmark_parse_complex_request(c: &mut Criterion) {
    let request = create_complex_request();
    let mut group = c.benchmark_group("parse_complex_request");
    group.throughput(Throughput::Bytes(request.len() as u64));
    
    group.bench_function("parse", |b| {
        b.iter(|| {
            let result = parse_sip_message(black_box(&request));
            assert!(result.is_ok());
        })
    });
    
    group.finish();
}

fn benchmark_parse_response(c: &mut Criterion) {
    let response = create_response();
    let mut group = c.benchmark_group("parse_response");
    group.throughput(Throughput::Bytes(response.len() as u64));
    
    group.bench_function("parse", |b| {
        b.iter(|| {
            let result = parse_sip_message(black_box(&response));
            assert!(result.is_ok());
        })
    });
    
    group.finish();
}

fn benchmark_security_validation(c: &mut Criterion) {
    let request_bytes = create_complex_request();
    let message = parse_sip_message(&request_bytes).unwrap();
    let security_config = security::SecurityConfig::default();
    let validator = security::SecurityValidator::new(security_config);
    
    c.bench_function("security_validation", |b| {
        b.iter(|| {
            let result = validator.validate_message(black_box(&message), "127.0.0.1");
            assert!(result.is_ok());
        })
    });
}

fn benchmark_codec_encode(c: &mut Criterion) {
    use bytes::BytesMut;
    use tokio_util::codec::Encoder;
    
    let mut headers = HashMap::new();
    headers.insert("via".to_string(), vec!["SIP/2.0/UDP pc33.atlanta.com".to_string()]);
    headers.insert("from".to_string(), vec!["<sip:alice@atlanta.com>;tag=123".to_string()]);
    headers.insert("to".to_string(), vec!["<sip:bob@biloxi.com>".to_string()]);
    headers.insert("call-id".to_string(), vec!["test123@atlanta.com".to_string()]);
    headers.insert("cseq".to_string(), vec!["1 INVITE".to_string()]);
    headers.insert("content-length".to_string(), vec!["0".to_string()]);
    
    let request = SipRequest {
        method: SipMethod::Invite,
        uri: SipUri::new("sip", "bob@biloxi.com"),
        version: "SIP/2.0".to_string(),
        headers,
        body: None,
    };
    
    let message = SipMessage::Request(request);
    let mut codec = codec::SipCodec::new();
    
    c.bench_function("codec_encode", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(1024);
            codec.encode(black_box(message.clone()), &mut buf).unwrap();
        })
    });
}

fn benchmark_codec_decode(c: &mut Criterion) {
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;
    
    let request = create_complex_request();
    let mut codec = codec::SipCodec::new();
    
    c.bench_function("codec_decode", |b| {
        b.iter(|| {
            let mut buf = BytesMut::from(&request[..]);
            let result = codec.decode(&mut buf);
            assert!(result.unwrap().is_some());
        })
    });
}

fn benchmark_uri_parsing(c: &mut Criterion) {
    let uris = vec![
        "sip:alice@atlanta.com",
        "sips:bob@biloxi.com:5061",
        "sip:carol@chicago.com:5060;transport=tcp",
        "sip:dave@denver.com;user=phone",
        "sip:+13125551212@gateway.com;user=phone",
    ];
    
    c.bench_function("uri_parsing", |b| {
        b.iter(|| {
            for uri in &uris {
                let parsed = SipUri::new("sip", black_box(uri));
                parsed.validate().unwrap();
            }
        })
    });
}

fn benchmark_header_operations(c: &mut Criterion) {
    let request_bytes = create_complex_request();
    let mut message = parse_sip_message(&request_bytes).unwrap();
    
    let mut group = c.benchmark_group("header_operations");
    
    group.bench_function("get_header", |b| {
        b.iter(|| {
            let _ = utils::get_header(black_box(&message), "from");
            let _ = utils::get_header(black_box(&message), "to");
            let _ = utils::get_header(black_box(&message), "call-id");
        })
    });
    
    group.bench_function("add_header", |b| {
        b.iter(|| {
            utils::add_header(black_box(&mut message), "x-custom", "value".to_string());
        })
    });
    
    group.bench_function("extract_branch", |b| {
        let via = "SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds";
        b.iter(|| {
            let _ = utils::extract_branch(black_box(via));
        })
    });
    
    group.finish();
}

fn benchmark_transaction_id(c: &mut Criterion) {
    let request_bytes = create_complex_request();
    let message = parse_sip_message(&request_bytes).unwrap();
    
    c.bench_function("get_transaction_id", |b| {
        b.iter(|| {
            let _ = utils::get_transaction_id(black_box(&message));
        })
    });
}

fn benchmark_rate_limiter(c: &mut Criterion) {
    use std::time::Duration;
    
    let mut security_config = security::SecurityConfig::default();
    security_config.max_requests_per_window = 1000;
    security_config.rate_limit_window = Duration::from_secs(60);
    
    let rate_limiter = security::RateLimiter::new(security_config);
    
    c.bench_function("rate_limiter_check", |b| {
        let mut counter = 0;
        b.iter(|| {
            let client_id = format!("client_{}", counter % 100);
            let _ = rate_limiter.check_rate_limit(black_box(&client_id));
            counter += 1;
        })
    });
}

fn benchmark_parallel_parsing(c: &mut Criterion) {
    use std::sync::Arc;
    use std::thread;
    
    let requests: Vec<Arc<Vec<u8>>> = vec![
        Arc::new(create_simple_request()),
        Arc::new(create_complex_request()),
        Arc::new(create_response()),
    ];
    
    c.bench_function("parallel_parsing_4_threads", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|i| {
                    let request = requests[i % requests.len()].clone();
                    thread::spawn(move || {
                        for _ in 0..100 {
                            let _ = parse_sip_message(black_box(&request));
                        }
                    })
                })
                .collect();
            
            for handle in handles {
                handle.join().unwrap();
            }
        })
    });
}

criterion_group!(
    benches,
    benchmark_parse_simple_request,
    benchmark_parse_complex_request,
    benchmark_parse_response,
    benchmark_security_validation,
    benchmark_codec_encode,
    benchmark_codec_decode,
    benchmark_uri_parsing,
    benchmark_header_operations,
    benchmark_transaction_id,
    benchmark_rate_limiter,
    benchmark_parallel_parsing
);

criterion_main!(benches);