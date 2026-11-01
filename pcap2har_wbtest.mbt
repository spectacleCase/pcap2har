///|
test "unix seconds format as UTC" {
  assert_eq(unix_utc(0), "1970-01-01T00:00:00Z")
  assert_eq(unix_utc(86400), "1970-01-02T00:00:00Z")
  assert_eq(unix_utc(1725148800), "2024-09-01T00:00:00Z")
}

///|
test "status text comes from the response line" {
  let pcap = exchange_pcap(
    "GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n", "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nmissing",
  )
  let exchanges = extract_exchanges(pcap).unwrap()
  assert_eq(exchanges.length(), 1)
  assert_eq(exchanges[0].status(), 404)
  assert_eq(exchanges[0].status_text(), "Not Found")
  assert_eq(exchanges[0].response_body(), "missing")
  assert_true(pcap_to_har(pcap) is Ok(_))
}

///|
test "empty pcap yields an empty HAR log" {
  let har = pcap_to_har(classic_pcap([], true)).unwrap()
  let document = @har.parse_har(har).unwrap()
  assert_eq(document.entry_count(), 0)
  assert_true(@har.validate_har(document).is_valid())
}

///|
test "post body size is kept and postData is not invented" {
  let pcap = exchange_pcap(
    "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\n\r\nhi",
    "HTTP/1.1 204 No Content\r\n\r\n",
  )
  let har = pcap_to_har(pcap).unwrap()
  let entry = @har.parse_har(har).unwrap().entries()[0]
  assert_eq(entry.request().request_method(), "POST")
  assert_eq(entry.request().url(), "http://example.com/login")
  assert_eq(entry.request().body_size(), 2.0)
  assert_eq(entry.request().post_data(), None)
  assert_eq(entry.response().status(), 204.0)
  assert_eq(entry.response().status_text(), "No Content")
}

///|
test "response without a matching request is dropped" {
  let pcap = classic_pcap(
    [
      {
        seconds: 1725148800,
        fraction: 0,
        payload: http_frame(
          server_ip(),
          client_ip(),
          server_mac(),
          client_mac(),
          80,
          12345,
          sample_response(),
        ),
      },
    ],
    true,
  )
  let exchanges = extract_exchanges(pcap).unwrap()
  assert_eq(exchanges.length(), 0)
}

///|
test "big endian classic pcap matches the little endian sample" {
  let little = exchange_pcap(sample_request(), sample_response())
  let big = exchange_pcap_endian(sample_request(), sample_response(), false)
  assert_eq(pcap_to_har(little).unwrap(), pcap_to_har(big).unwrap())
}
