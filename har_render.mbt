///|
fn hex_digit(n : Int32) -> Char {
  if n < 10 {
    (48 + n).unsafe_to_char()
  } else {
    (87 + n).unsafe_to_char()
  }
}

///|
fn json_string(text : String) -> String {
  let buf = StringBuilder()
  buf.write_char('"')
  for i = 0; i < text.length(); i = i + 1 {
    let n = text[i].to_int()
    if n == 34 || n == 92 {
      buf.write_char('\\')
      buf.write_char(n.unsafe_to_char())
    } else if n == 10 {
      buf.write_string("\\n")
    } else if n == 13 {
      buf.write_string("\\r")
    } else if n == 9 {
      buf.write_string("\\t")
    } else if n < 32 {
      buf.write_string("\\u00")
      buf.write_char(hex_digit(n / 16))
      buf.write_char(hex_digit(n % 16))
    } else {
      buf.write_char(n.unsafe_to_char())
    }
  }
  buf.write_char('"')
  buf.to_string()
}

///|
fn json_fields(fields : Array[Field]) -> String {
  let buf = StringBuilder()
  buf.write_char('[')
  for i = 0; i < fields.length(); i = i + 1 {
    if i > 0 {
      buf.write_char(',')
    }
    let field = fields[i]
    buf.write_string("{\"name\":")
    buf.write_string(json_string(field.name))
    buf.write_string(",\"value\":")
    buf.write_string(json_string(field.value))
    buf.write_char('}')
  }
  buf.write_char(']')
  buf.to_string()
}

///|
fn render_entry(entry : Captured) -> String {
  let buf = StringBuilder()
  buf.write_string("{\"startedDateTime\":")
  buf.write_string(json_string(entry.started_at))
  buf.write_string(",\"time\":0,\"request\":{\"method\":")
  buf.write_string(json_string(entry.http_method))
  buf.write_string(",\"url\":")
  buf.write_string(json_string(entry.url))
  buf.write_string(",\"httpVersion\":")
  buf.write_string(json_string(entry.version))
  buf.write_string(",\"cookies\":[],\"headers\":")
  buf.write_string(json_fields(entry.request_headers))
  buf.write_string(",\"queryString\":")
  buf.write_string(json_fields(entry.query))
  buf.write_string(",\"headersSize\":")
  buf.write_string(entry.request_headers_size.to_string())
  buf.write_string(",\"bodySize\":")
  buf.write_string(entry.request_body_size.to_string())
  buf.write_string("},\"response\":{\"status\":")
  buf.write_string(entry.status.to_string())
  buf.write_string(",\"statusText\":")
  buf.write_string(json_string(entry.status_text))
  buf.write_string(",\"httpVersion\":")
  buf.write_string(json_string(entry.response_version))
  buf.write_string(",\"cookies\":[],\"headers\":")
  buf.write_string(json_fields(entry.response_headers))
  buf.write_string(",\"content\":{\"size\":")
  buf.write_string(entry.response_body_size.to_string())
  buf.write_string(",\"mimeType\":")
  buf.write_string(json_string(entry.mime))
  buf.write_string(",\"text\":")
  buf.write_string(json_string(entry.body_text))
  buf.write_string("},\"redirectURL\":\"\",\"headersSize\":")
  buf.write_string(entry.response_headers_size.to_string())
  buf.write_string(",\"bodySize\":")
  buf.write_string(entry.response_body_size.to_string())
  buf.write_string(
    "},\"cache\":{},\"timings\":{\"send\":0,\"wait\":0,\"receive\":0}}",
  )
  buf.to_string()
}

///|
fn render_har(entries : Array[Captured]) -> String {
  let buf = StringBuilder()
  buf.write_string(
    "{\"log\":{\"version\":\"1.2\",\"creator\":{\"name\":\"pcap2har\",\"version\":",
  )
  buf.write_string(json_string(version))
  buf.write_string("},\"entries\":[")
  for i = 0; i < entries.length(); i = i + 1 {
    if i > 0 {
      buf.write_char(',')
    }
    buf.write_string(render_entry(entries[i]))
  }
  buf.write_string("]}}")
  buf.to_string()
}
