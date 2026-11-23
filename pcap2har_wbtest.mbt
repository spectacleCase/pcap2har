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
test "post body is written as postData" {
  let pcap = exchange_pcap(
    "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\n\r\nhi",
    "HTTP/1.1 204 No Content\r\n\r\n",
  )
  let har = pcap_to_har(pcap).unwrap()
  let entry = @har.parse_har(har).unwrap().entries()[0]
  assert_eq(entry.request().request_method(), "POST")
  assert_eq(entry.request().url(), "http://example.com/login")
  assert_eq(entry.request().body_size(), 2.0)
  assert_eq(entry.request().post_data().unwrap().text(), Some("hi"))
  assert_eq(entry.request().post_data().unwrap().mime_type(), "text/plain")
  assert_eq(entry.response().status(), 204.0)
  assert_eq(entry.response().status_text(), "No Content")
}

///|
test "split and reordered tcp segments become one exchange" {
  let request = "GET /split HTTP/1.1\r\nHost: example.com\r\n\r\n"
  let cut = 16
  let head = request[:cut].to_owned()
  let tail = request[cut:].to_owned()
  let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
  let pcap = classic_pcap(
    [
      {
        seconds: 1725148800,
        fraction: 0,
        payload: http_frame_seq(
          client_ip(),
          server_ip(),
          client_mac(),
          server_mac(),
          12345,
          80,
          1 + head.length(),
          tail,
        ),
      },
      {
        seconds: 1725148800,
        fraction: 2000,
        payload: http_frame_seq(
          client_ip(),
          server_ip(),
          client_mac(),
          server_mac(),
          12345,
          80,
          1,
          head,
        ),
      },
      {
        seconds: 1725148801,
        fraction: 0,
        payload: http_frame(
          server_ip(),
          client_ip(),
          server_mac(),
          client_mac(),
          80,
          12345,
          response,
        ),
      },
    ],
    true,
  )
  let har = pcap_to_har(pcap).unwrap()
  let entry = @har.parse_har(har).unwrap().entries()[0]
  assert_eq(entry.request().url(), "http://example.com/split")
  assert_eq(entry.response().content().text(), Some("ok"))
  assert_eq(entry.timings().send(), 2.0)
  assert_eq(entry.timings().wait(), 998.0)
  assert_eq(entry.timings().receive(), 0.0)
  assert_eq(entry.time(), 1000.0)
}

///|
test "response packets split receive from wait" {
  let request = "GET /slow HTTP/1.1\r\nHost: example.com\r\n\r\n"
  let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
  let cut = 18
  let head = response[:cut].to_owned()
  let tail = response[cut:].to_owned()
  let pcap = classic_pcap(
    [
      {
        seconds: 1725148800,
        fraction: 0,
        payload: http_frame(
          client_ip(),
          server_ip(),
          client_mac(),
          server_mac(),
          12345,
          80,
          request,
        ),
      },
      {
        seconds: 1725148801,
        fraction: 0,
        payload: http_frame_seq(
          server_ip(),
          client_ip(),
          server_mac(),
          client_mac(),
          80,
          12345,
          1,
          head,
        ),
      },
      {
        seconds: 1725148801,
        fraction: 5000,
        payload: http_frame_seq(
          server_ip(),
          client_ip(),
          server_mac(),
          client_mac(),
          80,
          12345,
          1 + head.length(),
          tail,
        ),
      },
    ],
    true,
  )
  let entry = @har.parse_har(pcap_to_har(pcap).unwrap()).unwrap().entries()[0]
  assert_eq(entry.response().content().text(), Some("ok"))
  assert_eq(entry.timings().send(), 0.0)
  assert_eq(entry.timings().wait(), 1000.0)
  assert_eq(entry.timings().receive(), 5.0)
  assert_eq(entry.time(), 1005.0)
}

///|
test "empty pcapng is empty HAR and non-ethernet packets are skipped" {
  assert_eq(extract_exchanges(pcapng_packets([], true)).unwrap().length(), 0)
  let ng = pcapng_packets(
    exchange_frames(sample_request(), sample_response()),
    true,
  )
  let patched : Array[Byte] = []
  for i = 0; i < ng.length(); i = i + 1 {
    if i == 36 || i == 37 {
      patched.push(b'\x00')
    } else {
      patched.push(ng[i])
    }
  }
  assert_eq(extract_exchanges(Bytes::from_array(patched)).unwrap().length(), 0)
}

///|
test "pcapng little and big endian match the classic capture" {
  let classic = pcap_to_har(exchange_pcap(sample_request(), sample_response())).unwrap()
  let little = pcap_to_har(
    exchange_pcapng(sample_request(), sample_response(), true),
  ).unwrap()
  let big = pcap_to_har(
    exchange_pcapng(sample_request(), sample_response(), false),
  ).unwrap()
  assert_eq(little, classic)
  assert_eq(big, classic)
}

///|
test "chunked bodies are decoded" {
  let pcap = exchange_pcap(
    "POST /up HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\n\r\n",
  )
  let entry = @har.parse_har(pcap_to_har(pcap).unwrap()).unwrap().entries()[0]
  assert_eq(entry.request().post_data().unwrap().text(), Some("hi"))
  assert_eq(entry.request().body_size(), 12.0)
  assert_eq(entry.response().content().text(), Some("hello"))
  assert_eq(entry.response().content().size(), 5.0)
  assert_eq(entry.response().body_size(), 21.0)
}

///|
test "cookie headers become HAR cookies" {
  let pcap = exchange_pcap(
    "GET /home HTTP/1.1\r\nHost: example.com\r\nCookie: sid=abc; theme=dark\r\n\r\n",
    "HTTP/1.1 204 No Content\r\nSet-Cookie: sid=abc; Path=/; HttpOnly\r\n\r\n",
  )
  let entry = @har.parse_har(pcap_to_har(pcap).unwrap()).unwrap().entries()[0]
  assert_eq(entry.request().cookies().length(), 2)
  assert_eq(entry.request().cookies()[0].name(), "sid")
  assert_eq(entry.request().cookies()[0].value(), "abc")
  assert_eq(entry.request().cookies()[1].name(), "theme")
  assert_eq(entry.response().cookies().length(), 1)
  assert_eq(entry.response().cookies()[0].name(), "sid")
  assert_eq(entry.response().cookies()[0].path(), Some("/"))
  assert_eq(entry.response().cookies()[0].http_only(), Some(true))
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
