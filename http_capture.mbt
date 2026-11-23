///|
priv struct Field {
  name : String
  value : String
}

///|
priv struct Cookie {
  name : String
  value : String
  path : String?
  http_only : Bool
  secure : Bool
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
  body_text : String
  cookies : Array[Cookie]
  started_at : String
  seconds : Int32
  millis : Int32
  end_seconds : Int32
  end_millis : Int32
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
  cookies : Array[Cookie]
  decoded_size : Int32
  seconds : Int32
  millis : Int32
  end_seconds : Int32
  end_millis : Int32
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
  request_body : String
  request_cookies : Array[Cookie]
  response_version : String
  response_headers : Array[Field]
  response_headers_size : Int32
  response_body_size : Int32
  response_cookies : Array[Cookie]
  mime : String
  body_text : String
  decoded_size : Int32
  send_ms : Int32
  wait_ms : Int32
  receive_ms : Int32
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
priv struct TcpPiece {
  src_ip : String
  dst_ip : String
  src_port : Int32
  dst_port : Int32
  seq : UInt32
  payload : Bytes
  seconds : Int32
  millis : Int32
}

///|
priv struct TcpDirection {
  src_ip : String
  dst_ip : String
  src_port : Int32
  dst_port : Int32
  pieces : Array[TcpPiece]
}

///|
fn trim_space(text : String) -> String {
  let mut start = 0
  let mut end = text.length()
  while start < end && text[start].to_int() == 32 {
    start = start + 1
  }
  while end > start && text[end - 1].to_int() == 32 {
    end = end - 1
  }
  text[start:end].to_owned()
}

///|
fn split_semi(text : String) -> Array[String] {
  let parts : Array[String] = []
  let mut start = 0
  let mut i = 0
  while i <= text.length() {
    if i == text.length() || text[i].to_int() == 59 {
      let piece = trim_space(text[start:i].to_owned())
      if piece.length() > 0 {
        parts.push(piece)
      }
      start = i + 1
    }
    i = i + 1
  }
  parts
}

///|
fn name_value(piece : String) -> (String, String)? {
  match piece.find("=") {
    None => None
    Some(index) =>
      Some((owned_until(piece, index), owned_from(piece, index + 1)))
  }
}

///|
fn parse_cookie_header(value : String) -> Array[Cookie] {
  let cookies : Array[Cookie] = []
  for piece in split_semi(value) {
    match name_value(piece) {
      Some((name, cookie_value)) =>
        cookies.push({
          name,
          value: cookie_value,
          path: None,
          http_only: false,
          secure: false,
        })
      None => ()
    }
  }
  cookies
}

///|
fn parse_set_cookie(value : String) -> Cookie? {
  let parts = split_semi(value)
  if parts.length() == 0 {
    return None
  }
  let (name, cookie_value) = match name_value(parts[0]) {
    Some(pair) => pair
    None => return None
  }
  let mut path : String? = None
  let mut http_only = false
  let mut secure = false
  for i = 1; i < parts.length(); i = i + 1 {
    let lower = parts[i].to_lower()
    if lower == "httponly" {
      http_only = true
    } else if lower == "secure" {
      secure = true
    } else {
      match name_value(parts[i]) {
        Some((attr, attr_value)) =>
          if attr.to_lower() == "path" {
            path = Some(attr_value)
          }
        None => ()
      }
    }
  }
  Some({ name, value: cookie_value, path, http_only, secure, })
}

///|
fn cookies_from(headers : Array[Field], set_cookie : Bool) -> Array[Cookie] {
  let cookies : Array[Cookie] = []
  let wanted = if set_cookie { "set-cookie" } else { "cookie" }
  for header in headers {
    if header.name.to_lower() == wanted {
      if set_cookie {
        match parse_set_cookie(header.value) {
          Some(cookie) => cookies.push(cookie)
          None => ()
        }
      } else {
        for cookie in parse_cookie_header(header.value) {
          cookies.push(cookie)
        }
      }
    }
  }
  cookies
}

///|
fn content_length(headers : Array[Field]) -> Int32? {
  match header_value(headers, "content-length") {
    Some(value) => parse_status(trim_space(value))
    None => None
  }
}

///|
fn method_has_body(line : String) -> Bool {
  line.has_prefix("POST ") ||
  line.has_prefix("PUT ") ||
  line.has_prefix("PATCH ")
}

///|
fn read_piece(frame : Bytes, seconds : Int32, millis : Int32) -> TcpPiece? {
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
  if tcp.payload.length() == 0 || tcp.flag_syn {
    return None
  }
  Some({
    src_ip: ip_text(ip.src_ip),
    dst_ip: ip_text(ip.dst_ip),
    src_port: tcp.src_port.reinterpret_as_int(),
    dst_port: tcp.dst_port.reinterpret_as_int(),
    seq: tcp.seq_num,
    payload: tcp.payload,
    seconds,
    millis,
  })
}

///|
fn direction_of(directions : Array[TcpDirection], piece : TcpPiece) -> Int32 {
  for i = 0; i < directions.length(); i = i + 1 {
    let direction = directions[i]
    if direction.src_ip == piece.src_ip &&
      direction.dst_ip == piece.dst_ip &&
      direction.src_port == piece.src_port &&
      direction.dst_port == piece.dst_port {
      return i
    }
  }
  directions.push({
    src_ip: piece.src_ip,
    dst_ip: piece.dst_ip,
    src_port: piece.src_port,
    dst_port: piece.dst_port,
    pieces: [],
  })
  directions.length() - 1
}

///|
fn reassemble(pieces : Array[TcpPiece]) -> Bytes {
  if pieces.length() == 0 {
    return Bytes::from_array([])
  }
  let mut min_seq = pieces[0].seq
  for piece in pieces {
    if piece.seq < min_seq {
      min_seq = piece.seq
    }
  }
  let first = pieces[0]
  let stream = @reassembly.TcpStreamReassembler::new(
    @reassembly.SessionKey::new(
      first.src_ip,
      first.src_port.reinterpret_as_uint(),
      first.dst_ip,
      first.dst_port.reinterpret_as_uint(),
    ),
  )
  stream.set_initial_seq(min_seq)
  for piece in pieces {
    stream.add_segment(piece.seq, piece.payload, 0.0)
  }
  stream.get_data()
}

///|
fn first_piece(pieces : Array[TcpPiece]) -> TcpPiece {
  let mut chosen = pieces[0]
  for piece in pieces {
    if piece.seq < chosen.seq {
      chosen = piece
    }
  }
  chosen
}

///|
priv struct ParsedHttp {
  line : String
  headers : Array[Field]
  headers_size : Int32
  wire_body : Int32
  decoded_size : Int32
  body_text : String
  byte_offset : Int32
}

///|
fn read_crlf_line(data : Bytes, at : Int32) -> (String, Int32)? {
  let mut i = at
  while i + 1 < data.length() {
    if data[i] == b'\r' && data[i + 1] == b'\n' {
      return Some((bytes_ascii(data, at, i), i + 2))
    }
    i = i + 1
  }
  None
}

///|
fn parse_chunk_size(line : String) -> Int32? {
  let mut size = 0
  let mut seen = false
  let mut i = 0
  while i < line.length() {
    let c = line[i].to_int()
    if c == 59 {
      break
    }
    if c == 32 || c == 9 {
      if seen {
        break
      }
    } else {
      let digit = if c >= 48 && c <= 57 {
        c - 48
      } else if c >= 97 && c <= 102 {
        c - 87
      } else if c >= 65 && c <= 70 {
        c - 55
      } else {
        return None
      }
      size = size * 16 + digit
      seen = true
    }
    i = i + 1
  }
  if seen {
    Some(size)
  } else {
    None
  }
}

///|
fn decode_chunks(data : Bytes) -> (Bytes, Int32)? {
  let decoded : Array[Byte] = []
  let mut at = 0
  let mut failed = false
  let mut finished = false
  while !finished && !failed {
    let (line, next) = match read_crlf_line(data, at) {
      Some(parsed) => parsed
      None => {
        failed = true
        ("", at)
      }
    }
    if !failed {
      at = next
      match parse_chunk_size(line) {
        None => failed = true
        Some(size) =>
          if size == 0 {
            let mut trailers = true
            while trailers && !failed {
              let (trailer, trailer_next) = match read_crlf_line(data, at) {
                Some(parsed) => parsed
                None => {
                  failed = true
                  ("", at)
                }
              }
              if !failed {
                at = trailer_next
                if trailer.length() == 0 {
                  trailers = false
                  finished = true
                }
              }
            }
          } else if at + size + 2 > data.length() ||
            data[at + size] != b'\r' ||
            data[at + size + 1] != b'\n' {
            failed = true
          } else {
            for i = 0; i < size; i = i + 1 {
              decoded.push(data[at + i])
            }
            at = at + size + 2
          }
      }
    }
  }
  if failed {
    None
  } else {
    Some((Bytes::from_array(decoded), at))
  }
}

///|
fn is_chunked(headers : Array[Field]) -> Bool {
  match header_value(headers, "transfer-encoding") {
    Some(value) => value.to_lower().contains("chunked")
    None => false
  }
}

///|
fn body_text_of(data : Bytes, start : Int32, len : Int32) -> String {
  let slice = copy_bytes(data, start, start + len)
  match printable_text(slice, 0) {
    Some(text) => text
    None => ""
  }
}

///|
fn messages_from(data : Bytes) -> Array[ParsedHttp] {
  let messages : Array[ParsedHttp] = []
  let mut offset = 0
  while offset < data.length() {
    let rest = copy_bytes(data, offset, data.length())
    let (line, headers, headers_size, _, _) = match message_parts(rest) {
      Some(parts) => parts
      None => break
    }
    let available = rest.length() - headers_size
    let (wire_body, decoded_size, body_text) = if is_chunked(headers) {
      let raw = copy_bytes(rest, headers_size, rest.length())
      match decode_chunks(raw) {
        Some((decoded, consumed)) =>
          (
            consumed,
            decoded.length(),
            match printable_text(decoded, 0) {
              Some(text) => text
              None => ""
            },
          )
        None => break
      }
    } else {
      let body_size = match content_length(headers) {
        Some(length) => if length > available { break } else { length }
        None =>
          if line.has_prefix("HTTP/") || method_has_body(line) {
            available
          } else {
            0
          }
      }
      (body_size, body_size, body_text_of(rest, headers_size, body_size))
    }
    messages.push({
      line,
      headers,
      headers_size,
      wire_body,
      decoded_size,
      body_text,
      byte_offset: offset,
    })
    let consumed = headers_size + wire_body
    offset = offset + consumed
    if consumed == 0 {
      break
    }
  }
  messages
}

///|
fn time_before(
  left_seconds : Int32,
  left_millis : Int32,
  right_seconds : Int32,
  right_millis : Int32,
) -> Bool {
  left_seconds < right_seconds ||
  (left_seconds == right_seconds && left_millis < right_millis)
}

///|
fn message_span(
  pieces : Array[TcpPiece],
  min_seq : UInt32,
  byte_offset : Int32,
  byte_length : Int32,
) -> (Int32, Int32, Int32, Int32) {
  let seq_start = min_seq + byte_offset.reinterpret_as_uint()
  let seq_end = seq_start + byte_length.reinterpret_as_uint()
  let mut seen = false
  let mut start_seconds = 0
  let mut start_millis = 0
  let mut end_seconds = 0
  let mut end_millis = 0
  for piece in pieces {
    let piece_end = piece.seq + piece.payload.length().reinterpret_as_uint()
    if piece.seq < seq_end && piece_end > seq_start {
      if !seen ||
        time_before(piece.seconds, piece.millis, start_seconds, start_millis) {
        start_seconds = piece.seconds
        start_millis = piece.millis
      }
      if !seen ||
        time_before(end_seconds, end_millis, piece.seconds, piece.millis) {
        end_seconds = piece.seconds
        end_millis = piece.millis
      }
      seen = true
    }
  }
  if !seen {
    let piece = first_piece(pieces)
    (piece.seconds, piece.millis, piece.seconds, piece.millis)
  } else {
    (start_seconds, start_millis, end_seconds, end_millis)
  }
}

///|
fn flows_from(direction : TcpDirection) -> Array[Flow] {
  if direction.pieces.length() == 0 {
    return []
  }
  let mut min_seq = direction.pieces[0].seq
  for piece in direction.pieces {
    if piece.seq < min_seq {
      min_seq = piece.seq
    }
  }
  let flows : Array[Flow] = []
  let payload = reassemble(direction.pieces)
  for message in messages_from(payload) {
    let byte_length = message.headers_size + message.wire_body
    let (seconds, millis, end_seconds, end_millis) = message_span(
      direction.pieces,
      min_seq,
      message.byte_offset,
      byte_length,
    )
    match parse_start_line(message.line) {
      None => ()
      Some((first, second, third)) =>
        if first.has_prefix("HTTP/") {
          match parse_status(second) {
            None => ()
            Some(status) =>
              flows.push(
                Response({
                  version: first,
                  status,
                  status_text: third,
                  headers: message.headers,
                  headers_size: message.headers_size,
                  body_size: message.wire_body,
                  mime: media_type(message.headers),
                  body_text: message.body_text,
                  cookies: cookies_from(message.headers, true),
                  decoded_size: message.decoded_size,
                  seconds,
                  millis,
                  end_seconds,
                  end_millis,
                  src_ip: direction.src_ip,
                  dst_ip: direction.dst_ip,
                  src_port: direction.src_port,
                  dst_port: direction.dst_port,
                }),
              )
          }
        } else {
          flows.push(
            Request({
              http_method: first,
              url: request_url(second, message.headers),
              version: third,
              headers: message.headers,
              query: parse_query(second),
              headers_size: message.headers_size,
              body_size: message.wire_body,
              body_text: message.body_text,
              cookies: cookies_from(message.headers, false),
              started_at: unix_utc(seconds),
              seconds,
              millis,
              end_seconds,
              end_millis,
              src_ip: direction.src_ip,
              dst_ip: direction.dst_ip,
              src_port: direction.src_port,
              dst_port: direction.dst_port,
            }),
          )
        }
    }
  }
  flows
}

///|
fn same_connection(request : HeldRequest, response : HeldResponse) -> Bool {
  request.src_ip == response.dst_ip &&
  request.dst_ip == response.src_ip &&
  request.src_port == response.dst_port &&
  request.dst_port == response.src_port
}

///|
fn elapsed_ms(
  start_seconds : Int32,
  start_millis : Int32,
  end_seconds : Int32,
  end_millis : Int32,
) -> Int32 {
  if end_seconds < start_seconds {
    return 0
  }
  let seconds = end_seconds - start_seconds
  if seconds > 2000000 {
    return 2000000000
  }
  let total = seconds * 1000 + (end_millis - start_millis)
  if total < 0 {
    0
  } else {
    total
  }
}

///|
fn capture_packets(packets : Array[RawPacket]) -> Array[Captured] {
  let directions : Array[TcpDirection] = []
  for packet in packets {
    match
      read_piece(
        packet.payload,
        packet.timestamp_seconds,
        packet.timestamp_millis,
      ) {
      None => ()
      Some(piece) => {
        let index = direction_of(directions, piece)
        directions[index].pieces.push(piece)
      }
    }
  }
  let flows : Array[Flow] = []
  for direction in directions {
    for flow in flows_from(direction) {
      flows.push(flow)
    }
  }
  let captured : Array[Captured] = []
  let pending : Array[HeldRequest] = []
  for flow in flows {
    match flow {
      Request(request) => pending.push(request)
      Response(response) => {
        let mut found = -1
        for i = 0; i < pending.length(); i = i + 1 {
          if same_connection(pending[i], response) {
            found = i
            break
          }
        }
        if found >= 0 {
          let request = pending.remove(found)
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
            request_body: request.body_text,
            request_cookies: request.cookies,
            response_version: response.version,
            response_headers: response.headers,
            response_headers_size: response.headers_size,
            response_body_size: response.body_size,
            response_cookies: response.cookies,
            mime: response.mime,
            body_text: response.body_text,
            decoded_size: response.decoded_size,
            send_ms: elapsed_ms(
              request.seconds,
              request.millis,
              request.end_seconds,
              request.end_millis,
            ),
            wait_ms: elapsed_ms(
              request.end_seconds,
              request.end_millis,
              response.seconds,
              response.millis,
            ),
            receive_ms: elapsed_ms(
              response.seconds,
              response.millis,
              response.end_seconds,
              response.end_millis,
            ),
          })
        }
      }
    }
  }
  captured
}
