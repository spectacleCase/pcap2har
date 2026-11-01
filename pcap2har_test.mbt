///|
test "sample pcap becomes one validated HAR entry" {
  match @pcap2har.pcap_to_har(@pcap2har.sample_pcap()) {
    Err(@pcap2har.HarRejected(message)) => fail(message)
    Err(@pcap2har.InvalidPcap) => fail("invalid pcap")
    Ok(har) => {
      let document = @har.parse_har(har).unwrap()
      let result = @har.validate_har(document)
      assert_true(result.is_valid())
      assert_eq(document.version(), "1.2")
      assert_eq(document.creator().name(), "pcap2har")
      assert_eq(document.creator().version(), @pcap2har.version)
      assert_eq(document.entry_count(), 1)
      let entry = document.entries()[0]
      assert_eq(entry.started_datetime(), "2024-09-01T00:00:00Z")
      assert_eq(entry.time(), 0.0)
      assert_eq(entry.request().request_method(), "GET")
      assert_eq(entry.request().url(), "http://example.com/api/users?id=7")
      assert_eq(entry.request().http_version(), "HTTP/1.1")
      assert_eq(entry.request().header_values("Host"), ["example.com"])
      assert_eq(entry.request().query_values("id"), ["7"])
      assert_eq(entry.request().body_size(), 0.0)
      assert_eq(entry.response().status(), 200.0)
      assert_eq(entry.response().status_text(), "OK")
      assert_eq(entry.response().content().mime_type(), "text/plain")
      assert_eq(entry.response().content().text(), Some("hello"))
      assert_eq(entry.response().body_size(), 5.0)
    }
  }
}

///|
test "extract exchanges exposes the paired request" {
  let exchanges = @pcap2har.extract_exchanges(@pcap2har.sample_pcap()).unwrap()
  assert_eq(exchanges.length(), 1)
  assert_eq(exchanges[0].http_method(), "GET")
  assert_eq(exchanges[0].url(), "http://example.com/api/users?id=7")
  assert_eq(exchanges[0].status(), 200)
  assert_eq(exchanges[0].status_text(), "OK")
  assert_eq(exchanges[0].response_body(), "hello")
}

///|
test "bytes that are not a pcap are rejected" {
  assert_true(@pcap2har.pcap_to_har(Bytes::from_array([b'\x00'])) is Err(_))
}

///|
test "sample pcap uses the little endian classic magic" {
  let sample = @pcap2har.sample_pcap()
  assert_eq(sample[0], b'\xd4')
  assert_eq(sample[1], b'\xc3')
  assert_eq(sample[2], b'\xb2')
  assert_eq(sample[3], b'\xa1')
}
