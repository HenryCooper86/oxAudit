use super::*;

struct HttpFixture {
    url: String,
    requests: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl HttpFixture {
    async fn json(responses: Vec<Value>) -> Self {
        Self::raw(
            responses
                .into_iter()
                .map(|value| {
                    let body = value.to_string();
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                })
                .collect(),
        )
        .await
    }
    async fn raw(responses: Vec<String>) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let received = requests.clone();
        let server = tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(stream.read_u8().await.unwrap());
                }
                let header = String::from_utf8(header).unwrap();
                let length: usize = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                received.lock().unwrap().push(if body.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&body).unwrap()
                });
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        Self {
            url,
            requests,
            server,
        }
    }
    fn client(&self) -> OsvClient {
        OsvClient::new(
            reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(2))
                .build()
                .unwrap(),
        )
    }
}
fn dependency(name: &str) -> Dependency {
    Dependency {
        ecosystem: "npm".into(),
        name: name.into(),
        version: "1.0.0".into(),
        lockfile: "fixture.lock".into(),
        license: None,
        occurrence: Default::default(),
    }
}

#[tokio::test]
async fn package_queries_follow_empty_pages_and_deduplicate_advisories() {
    // Both version-specific queries and package searches use this path.
    for version in [None, Some("1.0.0")] {
        let fixture = HttpFixture::json(vec![
            serde_json::json!({"next_page_token":"two"}),
            serde_json::json!({"vulns":[{"id":"GHSA-a"}],"next_page_token":"three"}),
            serde_json::json!({"vulns":[{"id":"GHSA-a"},{"id":"GHSA-b"}]}),
        ])
        .await;
        let mut body = serde_json::json!({"package":{"ecosystem":"npm","name":"example"}});
        if let Some(version) = version {
            body["version"] = serde_json::json!(version);
        }
        let records = fixture
            .client()
            .query_records_at(&fixture.url, body)
            .await
            .unwrap();
        assert_eq!(
            records
                .iter()
                .map(|record| record["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["GHSA-a", "GHSA-b"]
        );
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].get("page_token").is_none());
        assert_eq!(requests[1]["page_token"], "two");
        assert_eq!(requests[2]["page_token"], "three");
        for request in requests.iter() {
            assert_eq!(
                request["package"],
                serde_json::json!({"ecosystem":"npm","name":"example"})
            );
            assert_eq!(request.get("version").and_then(Value::as_str), version);
        }
    }
}

#[tokio::test]
async fn batch_pagination_requeries_only_pending_packages_and_preserves_mapping() {
    let fixture = HttpFixture::json(vec![
        serde_json::json!({"results":[
            {"vulns":[{"id":"GHSA-a"}],"next_page_token":"a-two"},
            {},
            {"vulns":[{"id":"GHSA-c"}],"next_page_token":"c-two"},
            {"vulns":[{"id":"GHSA-d"}],"next_page_token":"d-two"}
        ]}),
        serde_json::json!({"results":[
            {"vulns":[{"id":"GHSA-a"},{"id":"GHSA-e"}]},
            {"next_page_token":"c-three"},
            {}
        ]}),
        serde_json::json!({"results":[{"vulns":[{"id":"GHSA-f"}]}]}),
    ])
    .await;
    let deps = [
        dependency("a"),
        dependency("b"),
        dependency("c"),
        dependency("d"),
    ];
    let results = fixture
        .client()
        .query_batch_at(&deps, &fixture.url)
        .await
        .unwrap();
    assert_eq!(
        results["npm\u{0}a\u{0}1.0.0"]
            .iter()
            .map(|v| v.id.as_str())
            .collect::<Vec<_>>(),
        ["GHSA-a", "GHSA-e"]
    );
    assert!(!results.contains_key("npm\u{0}b\u{0}1.0.0"));
    assert_eq!(
        results["npm\u{0}c\u{0}1.0.0"]
            .iter()
            .map(|v| v.id.as_str())
            .collect::<Vec<_>>(),
        ["GHSA-c", "GHSA-f"]
    );
    assert_eq!(results["npm\u{0}d\u{0}1.0.0"][0].id, "GHSA-d");
    let requests = fixture.requests.lock().unwrap();
    let pending = |index: usize| {
        requests[index]["queries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|q| {
                (
                    q["package"]["name"].as_str().unwrap().to_owned(),
                    q.get("page_token")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        pending(0),
        vec![
            ("a".into(), None),
            ("b".into(), None),
            ("c".into(), None),
            ("d".into(), None)
        ]
    );
    assert_eq!(
        pending(1),
        vec![
            ("a".into(), Some("a-two".into())),
            ("c".into(), Some("c-two".into())),
            ("d".into(), Some("d-two".into()))
        ]
    );
    assert_eq!(pending(2), vec![("c".into(), Some("c-three".into()))]);
    assert_eq!(requests.len(), 3);
    for request in requests.iter() {
        for query in request["queries"].as_array().unwrap() {
            assert_eq!(query["version"], "1.0.0");
            assert_eq!(query["package"]["ecosystem"], "npm");
        }
    }
}

#[tokio::test]
async fn package_queries_reject_malformed_advisory_pages() {
    for page in [
        serde_json::json!(null),
        serde_json::json!([]),
        serde_json::json!({"vulns":null}),
        serde_json::json!({"vulns":{}}),
        serde_json::json!({"vulns":[{}]}),
        serde_json::json!({"vulns":[{"id":" "}]}),
        serde_json::json!({"next_page_token":5}),
    ] {
        let fixture = HttpFixture::json(vec![page.clone()]).await;
        assert!(
            fixture
                .client()
                .query_records_at(
                    &fixture.url,
                    serde_json::json!({"package":{"ecosystem":"npm","name":"example"}})
                )
                .await
                .is_err(),
            "accepted {page}"
        );
    }
}

#[tokio::test]
async fn advisory_pagination_refuses_oversized_tokens() {
    let token = "x".repeat(4097);
    let fixture = HttpFixture::json(vec![serde_json::json!({"next_page_token":token})]).await;
    let result = fixture
        .client()
        .query_records_at(
            &fixture.url,
            serde_json::json!({"package":{"ecosystem":"npm","name":"example"}}),
        )
        .await;
    assert!(matches!(result, Err(error) if error.contains("resource limit")));
    let fixture = HttpFixture::json(vec![
        serde_json::json!({"results":[{"next_page_token":token}]}),
    ])
    .await;
    let error = fixture
        .client()
        .query_batch_at(&[dependency("example")], &fixture.url)
        .await
        .unwrap_err();
    assert!(error.contains("resource limit"), "{error}");
}

#[tokio::test]
async fn cyclic_pagination_tokens_fail_instead_of_partial_results() {
    let fixture = HttpFixture::json(vec![
        serde_json::json!({"next_page_token":"two"}),
        serde_json::json!({"next_page_token":"three"}),
        serde_json::json!({"next_page_token":"two"}),
    ])
    .await;
    let error = fixture
        .client()
        .query_records_at(
            &fixture.url,
            serde_json::json!({"package":{"ecosystem":"npm","name":"example"}}),
        )
        .await
        .unwrap_err();
    assert!(error.contains("repeated pagination token"), "{error}");
    let fixture = HttpFixture::json(vec![
        serde_json::json!({"results":[{"next_page_token":"two"}]}),
        serde_json::json!({"results":[{"next_page_token":"three"}]}),
        serde_json::json!({"results":[{"next_page_token":"two"}]}),
    ])
    .await;
    let error = fixture
        .client()
        .query_batch_at(&[dependency("example")], &fixture.url)
        .await
        .unwrap_err();
    assert!(error.contains("repeated pagination token"), "{error}");
}

#[tokio::test]
async fn batch_pagination_rejects_a_short_later_page() {
    let fixture = HttpFixture::json(vec![
        serde_json::json!({"results":[{"next_page_token":"two"},{"next_page_token":"two"}]}),
        serde_json::json!({"results":[{}]}),
    ])
    .await;
    let error = fixture
        .client()
        .query_batch_at(&[dependency("a"), dependency("b")], &fixture.url)
        .await
        .unwrap_err();
    assert!(error.contains("1 results for 2 queries"), "{error}");
}

#[tokio::test]
async fn advisory_queries_bound_declared_and_streamed_response_bytes() {
    let padding = "x".repeat(32 * 1024 * 1024);
    for response in [
        "HTTP/1.1 200 OK\r\nContent-Length: 33554433\r\nConnection: close\r\n\r\n".to_string(),
        format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{{\"vulns\":[],\"padding\":\"{padding}\"}}"),
    ] {
        let fixture = HttpFixture::raw(vec![response]).await;
        let error = fixture.client().query_records_at(&fixture.url, serde_json::json!({"package":{"ecosystem":"npm","name":"example"}})).await.unwrap_err();
        assert!(error.contains("resource limit"), "{error}");
    }
}

#[tokio::test]
async fn advisory_queries_refuse_unbounded_pages_and_record_counts() {
    let pages = (0..65)
        .map(|page| serde_json::json!({"next_page_token":format!("page-{page}")}))
        .collect();
    let fixture = HttpFixture::json(pages).await;
    let error = fixture
        .client()
        .query_records_at(
            &fixture.url,
            serde_json::json!({"package":{"ecosystem":"npm","name":"example"}}),
        )
        .await
        .unwrap_err();
    assert!(error.contains("resource limit"), "{error}");
    let pages = (0..65)
        .map(|page| serde_json::json!({"results":[{"next_page_token":format!("page-{page}")}]}))
        .collect();
    let fixture = HttpFixture::json(pages).await;
    let error = fixture
        .client()
        .query_batch_at(&[dependency("example")], &fixture.url)
        .await
        .unwrap_err();
    assert!(error.contains("resource limit"), "{error}");

    let records: Vec<_> = (0..10_001)
        .map(|id| serde_json::json!({"id":format!("GHSA-{id}")}))
        .collect();
    let fixture = HttpFixture::json(vec![serde_json::json!({"vulns":records})]).await;
    let error = fixture
        .client()
        .query_records_at(
            &fixture.url,
            serde_json::json!({"package":{"ecosystem":"npm","name":"example"}}),
        )
        .await
        .unwrap_err();
    assert!(error.contains("resource limit"), "{error}");
    let fixture = HttpFixture::json(vec![serde_json::json!({"results":[{"vulns":records}]})]).await;
    let error = fixture
        .client()
        .query_batch_at(&[dependency("example")], &fixture.url)
        .await
        .unwrap_err();
    assert!(error.contains("resource limit"), "{error}");
}

#[tokio::test]
async fn package_query_later_http_and_body_failures_do_not_return_partial_records() {
    for later in [
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"vulns\":[",
    ] {
        let first = r#"{"vulns":[{"id":"GHSA-first"}],"next_page_token":"two"}"#;
        let fixture = HttpFixture::raw(vec![
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{first}",
                first.len()
            ),
            later.into(),
        ])
        .await;
        assert!(fixture
            .client()
            .query_records_at(
                &fixture.url,
                serde_json::json!({"package":{"ecosystem":"npm","name":"example"}})
            )
            .await
            .is_err());
    }
}
