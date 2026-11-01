///|
pub enum ConvertError {
  InvalidPcap
  HarRejected(String)
} derive(Eq, Debug)

///|
pub extend ConvertError with Eq::{not_equal, equal}

///|
pub extend ConvertError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub struct HttpExchange {
  http_method : String
  url : String
  status : Int32
  status_text : String
  http_version : String
  started_at : String
  response_mime : String
  response_body : String
} derive(Eq, Debug)

///|
pub extend HttpExchange with Eq::{not_equal, equal}

///|
pub extend HttpExchange with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub fn HttpExchange::http_method(self : HttpExchange) -> String {
  self.http_method
}

///|
pub fn HttpExchange::url(self : HttpExchange) -> String {
  self.url
}

///|
pub fn HttpExchange::status(self : HttpExchange) -> Int32 {
  self.status
}

///|
pub fn HttpExchange::status_text(self : HttpExchange) -> String {
  self.status_text
}

///|
pub fn HttpExchange::http_version(self : HttpExchange) -> String {
  self.http_version
}

///|
pub fn HttpExchange::started_at(self : HttpExchange) -> String {
  self.started_at
}

///|
pub fn HttpExchange::response_mime(self : HttpExchange) -> String {
  self.response_mime
}

///|
pub fn HttpExchange::response_body(self : HttpExchange) -> String {
  self.response_body
}

///|
fn to_exchange(entry : Captured) -> HttpExchange {
  {
    http_method: entry.http_method,
    url: entry.url,
    status: entry.status,
    status_text: entry.status_text,
    http_version: entry.version,
    started_at: entry.started_at,
    response_mime: entry.mime,
    response_body: entry.body_text,
  }
}

///|
fn capture_pcap(bytes : Bytes) -> Result[Array[Captured], ConvertError] {
  let packets = match read_classic_pcap(bytes) {
    Ok(packets) => packets
    Err(error) => return Err(error)
  }
  Ok(capture_packets(packets))
}

///|
/// 从 pcap 中抽出已配对的明文 HTTP/1.1 请求和响应。
pub fn extract_exchanges(
  bytes : Bytes,
) -> Result[Array[HttpExchange], ConvertError] {
  let captured = match capture_pcap(bytes) {
    Ok(entries) => entries
    Err(error) => return Err(error)
  }
  let exchanges : Array[HttpExchange] = []
  for entry in captured {
    exchanges.push(to_exchange(entry))
  }
  Ok(exchanges)
}

///|
fn accept_har(text : String) -> Result[String, ConvertError] {
  match @har.parse_har(text) {
    Err(error) => Err(HarRejected(error.code()))
    Ok(document) => {
      let result = @har.validate_har(document)
      if result.is_valid() {
        Ok(text)
      } else {
        Err(HarRejected(@har.render_validation_text(result)))
      }
    }
  }
}

///|
/// 把经典 pcap 里的明文 HTTP/1.1 往返写成 HAR 1.2。
pub fn pcap_to_har(bytes : Bytes) -> Result[String, ConvertError] {
  let captured = match capture_pcap(bytes) {
    Ok(entries) => entries
    Err(error) => return Err(error)
  }
  accept_har(render_har(captured))
}
