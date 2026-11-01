///|
priv struct Field {
  name : String
  value : String
}

///|
priv struct HeldRequest {
  http_method : String
  url : String
  version : String
  headers : Array[Field]
  query : Array[Field]
  headers_size : Int32
  body_size : Int32
  started_at : String
  src_ip : String
  dst_ip : String
  src_port : Int32
  dst_port : Int32
}

///|
priv struct HeldResponse {
  version : String
  status : Int32
  status_text : String
  headers : Array[Field]
  headers_size : Int32
  body_size : Int32
  mime : String
  body_text : String
  src_ip : String
  dst_ip : String
  src_port : Int32
  dst_port : Int32
}

///|
priv enum Flow {
  Request(HeldRequest)
  Response(HeldResponse)
}

///|
priv struct Captured {
  http_method : String
  url : String
  version : String
  status : Int32
  status_text : String
  started_at : String
  request_headers : Array[Field]
  query : Array[Field]
  request_headers_size : Int32
  request_body_size : Int32
  response_version : String
  response_headers : Array[Field]
  response_headers_size : Int32
  response_body_size : Int32
  mime : String
  body_text : String
}

///|
fn find_bytes(data : Bytes, pattern : Bytes) -> Int32? {
  if pattern.length() == 0 || data.length() < pattern.length() {
    return None
  }
  let last = data.length() - pattern.length()
  for i = 0; i <= last; i = i + 1 {
    let mut matched = true
    for j = 0; j < pattern.length(); j = j + 1 {
      if data[i + j] != pattern[j] {
        matched = false
        break
      }
    }
    if matched {
      return Some(i)
    }
  }
  None
}

///|
fn bytes_ascii(data : Bytes, start : Int32, end : Int32) -> String {
  let buf = StringBuilder()
  for i = start; i < end; i = i + 1 {
    buf.write_char(data[i].to_int().unsafe_to_char())
  }
  buf.to_string()
}

///|
fn owned_until(text : String, end : Int32) -> String {
  text[:end].to_owned()
}

///|
fn owned_from(text : String, start : Int32) -> String {
  text[start:].to_owned()
}

///|
fn tail_after_spaces(line : String, spaces : Int32) -> String {
  let mut seen = 0
  let mut i = 0
  while i < line.length() {
    if line[i].to_int() == 32 {
      seen = seen + 1
      if seen == spaces {
        return owned_from(line, i + 1)
      }
    }
    i = i + 1
  }
  ""
}

///|
fn parse_start_line(line : String) -> (String, String, String)? {
  match @layers.parse_http_first_line(line) {
    None => None
    Some((first, second, third)) =>
      if first.has_prefix("HTTP/") {
        Some((first, second, tail_after_spaces(line, 2)))
      } else {
        Some((first, second, third))
      }
  }
}

///|
fn parse_status(text : String) -> Int32? {
  if text.length() == 0 {
    return None
  }
  let mut n = 0
  for i = 0; i < text.length(); i = i + 1 {
    let c = text[i].to_int()
    if c < 48 || c > 57 {
      return None
    }
    n = n * 10 + (c - 48)
  }
  Some(n)
}

///|
fn header_value(headers : Array[Field], name : String) -> String? {
  let wanted = name.to_lower()
  for header in headers {
    if header.name.to_lower() == wanted {
      return Some(header.value)
    }
  }
  None
}

///|
fn split_header(line : String) -> Field? {
  match line.find(":") {
    None => None
    Some(index) => {
      let name = owned_until(line, index)
      let mut value = owned_from(line, index + 1)
      if value.has_prefix(" ") {
        value = owned_from(value, 1)
      }
      Some({ name, value, })
    }
  }
}

///|
fn parse_headers(text : String) -> Array[Field] {
  let headers : Array[Field] = []
  let mut start = 0
  let mut i = 0
  while i < text.length() {
    if text[i].to_int() == 10 {
      let mut end = i
      if end > start && text[end - 1].to_int() == 13 {
        end = end - 1
      }
      if end > start {
        match split_header(text[start:end].to_owned()) {
          Some(header) => headers.push(header)
          None => ()
        }
      }
      start = i + 1
    }
    i = i + 1
  }
  if start < text.length() {
    match split_header(owned_from(text, start)) {
      Some(header) => headers.push(header)
      None => ()
    }
  }
  headers
}

///|
fn parse_query(uri : String) -> Array[Field] {
  let query = match uri.find("?") {
    None => return []
    Some(index) => owned_from(uri, index + 1)
  }
  let fields : Array[Field] = []
  let mut start = 0
  let mut i = 0
  while i <= query.length() {
    if i == query.length() || query[i].to_int() == 38 {
      if i > start {
        let piece = query[start:i].to_owned()
        match piece.find("=") {
          Some(eq) =>
            fields.push({
              name: owned_until(piece, eq),
              value: owned_from(piece, eq + 1),
            })
          None => fields.push({ name: piece, value: "", })
        }
      }
      start = i + 1
    }
    i = i + 1
  }
  fields
}

///|
fn request_url(uri : String, headers : Array[Field]) -> String {
  if uri.has_prefix("http://") || uri.has_prefix("https://") {
    return uri
  }
  let host = match header_value(headers, "host") {
    Some(value) => value
    None => "unknown"
  }
  if uri.has_prefix("/") {
    "http://\{host}\{uri}"
  } else {
    "http://\{host}/\{uri}"
  }
}

///|
fn printable_text(data : Bytes, start : Int32) -> String? {
  let buf = StringBuilder()
  for i = start; i < data.length(); i = i + 1 {
    let c = data[i].to_int()
    if c == 9 || c == 10 || c == 13 || (c >= 32 && c <= 126) {
      buf.write_char(c.unsafe_to_char())
    } else {
      return None
    }
  }
  Some(buf.to_string())
}

///|
fn media_type(headers : Array[Field]) -> String {
  match header_value(headers, "content-type") {
    None => ""
    Some(value) =>
      match value.find(";") {
        Some(index) => owned_until(value, index)
        None => value
      }
  }
}

///|
fn ip_text(ip : Bytes) -> String {
  if ip.length() != 4 {
    return ""
  }
  "\{ip[0].to_int()}.\{ip[1].to_int()}.\{ip[2].to_int()}.\{ip[3].to_int()}"
}

///|
fn message_parts(
  payload : Bytes,
) -> (String, Array[Field], Int32, Int32, String)? {
  if @layers.parse_http(payload) is None {
    return None
  }
  let separator = Bytes::from_array(ascii("\r\n\r\n"))
  let crlf = Bytes::from_array(ascii("\r\n"))
  let split_at = match find_bytes(payload, separator) {
    Some(index) => index
    None => return None
  }
  let line_end = match find_bytes(payload, crlf) {
    Some(index) => index
    None => return None
  }
  if line_end > split_at {
    return None
  }
  let line = bytes_ascii(payload, 0, line_end)
  let header_text = if line_end + 2 < split_at {
    bytes_ascii(payload, line_end + 2, split_at)
  } else {
    ""
  }
  let headers_size = split_at + separator.length()
  let body_size = payload.length() - headers_size
  let body = match printable_text(payload, headers_size) {
    Some(text) => text
    None => ""
  }
  Some((line, parse_headers(header_text), headers_size, body_size, body))
}

///|
fn read_flow(frame : Bytes, timestamp_seconds : Int32) -> Flow? {
  let ethernet = match @layers.parse_ethernet(frame) {
    Some(header) => header
    None => return None
  }
  if ethernet.ethertype != 0x0800U {
    return None
  }
  let ip = match @layers.parse_ipv4(ethernet.payload) {
    Some(header) => header
    None => return None
  }
  if ip.protocol != b'\x06' {
    return None
  }
  let tcp = match @layers.parse_tcp(ip.payload) {
    Some(header) => header
    None => return None
  }
  if tcp.payload.length() == 0 {
    return None
  }
  let (line, headers, headers_size, body_size, body) = match
    message_parts(tcp.payload) {
    Some(parts) => parts
    None => return None
  }
  let (first, second, third) = match parse_start_line(line) {
    Some(parts) => parts
    None => return None
  }
  let src_ip = ip_text(ip.src_ip)
  let dst_ip = ip_text(ip.dst_ip)
  let src_port = tcp.src_port.reinterpret_as_int()
  let dst_port = tcp.dst_port.reinterpret_as_int()
  if first.has_prefix("HTTP/") {
    let status = match parse_status(second) {
      Some(code) => code
      None => return None
    }
    Some(
      Response({
        version: first,
        status,
        status_text: third,
        headers,
        headers_size,
        body_size,
        mime: media_type(headers),
        body_text: body,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
      }),
    )
  } else {
    Some(
      Request({
        http_method: first,
        url: request_url(second, headers),
        version: third,
        headers,
        query: parse_query(second),
        headers_size,
        body_size,
        started_at: unix_utc(timestamp_seconds),
        src_ip,
        dst_ip,
        src_port,
        dst_port,
      }),
    )
  }
}

///|
fn same_connection(request : HeldRequest, response : HeldResponse) -> Bool {
  request.src_ip == response.dst_ip &&
  request.dst_ip == response.src_ip &&
  request.src_port == response.dst_port &&
  request.dst_port == response.src_port
}

///|
fn capture_packets(packets : Array[RawPacket]) -> Array[Captured] {
  let captured : Array[Captured] = []
  let mut pending : HeldRequest? = None
  for packet in packets {
    match read_flow(packet.payload, packet.timestamp_seconds) {
      None => ()
      Some(Request(request)) => pending = Some(request)
      Some(Response(response)) =>
        match pending {
          Some(request) =>
            if same_connection(request, response) {
              captured.push({
                http_method: request.http_method,
                url: request.url,
                version: request.version,
                status: response.status,
                status_text: response.status_text,
                started_at: request.started_at,
                request_headers: request.headers,
                query: request.query,
                request_headers_size: request.headers_size,
                request_body_size: request.body_size,
                response_version: response.version,
                response_headers: response.headers,
                response_headers_size: response.headers_size,
                response_body_size: response.body_size,
                mime: response.mime,
                body_text: response.body_text,
              })
              pending = None
            }
          None => ()
        }
    }
  }
  captured
}
