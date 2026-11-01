///|
fn push_all(dst : Array[Byte], src : Array[Byte]) -> Unit {
  for b in src {
    dst.push(b)
  }
}

///|
fn ascii(text : String) -> Array[Byte] {
  let out : Array[Byte] = []
  for i = 0; i < text.length(); i = i + 1 {
    out.push(text[i].to_int().to_byte())
  }
  out
}

///|
fn u16be(n : Int32) -> Array[Byte] {
  [((n >> 8) & 255).to_byte(), (n & 255).to_byte()]
}

///|
fn u32be(n : Int32) -> Array[Byte] {
  [
    ((n >> 24) & 255).to_byte(),
    ((n >> 16) & 255).to_byte(),
    ((n >> 8) & 255).to_byte(),
    (n & 255).to_byte(),
  ]
}

///|
fn tcp_segment(
  src_port : Int32,
  dst_port : Int32,
  payload : Array[Byte],
) -> Array[Byte] {
  let seg : Array[Byte] = []
  push_all(seg, u16be(src_port))
  push_all(seg, u16be(dst_port))
  push_all(seg, u32be(1))
  push_all(seg, u32be(1))
  push_all(seg, u16be(0x5018))
  push_all(seg, u16be(65535))
  push_all(seg, u16be(0))
  push_all(seg, u16be(0))
  push_all(seg, payload)
  seg
}

///|
fn ipv4_packet(
  src : Array[Byte],
  dst : Array[Byte],
  tcp : Array[Byte],
) -> Array[Byte] {
  let total = 20 + tcp.length()
  let packet : Array[Byte] = []
  packet.push(b'\x45')
  packet.push(b'\x00')
  push_all(packet, u16be(total))
  push_all(packet, u16be(1))
  push_all(packet, u16be(0))
  packet.push(b'\x40')
  packet.push(b'\x06')
  push_all(packet, u16be(0))
  push_all(packet, src)
  push_all(packet, dst)
  push_all(packet, tcp)
  packet
}

///|
fn ethernet_frame(
  dst_mac : Array[Byte],
  src_mac : Array[Byte],
  ip : Array[Byte],
) -> Bytes {
  let frame : Array[Byte] = []
  push_all(frame, dst_mac)
  push_all(frame, src_mac)
  push_all(frame, u16be(0x0800))
  push_all(frame, ip)
  Bytes::from_array(frame)
}

///|
fn http_frame(
  src_ip : Array[Byte],
  dst_ip : Array[Byte],
  src_mac : Array[Byte],
  dst_mac : Array[Byte],
  src_port : Int32,
  dst_port : Int32,
  http : String,
) -> Bytes {
  let tcp = tcp_segment(src_port, dst_port, ascii(http))
  let ip = ipv4_packet(src_ip, dst_ip, tcp)
  ethernet_frame(dst_mac, src_mac, ip)
}

///|
fn client_ip() -> Array[Byte] {
  [b'\x0a', b'\x00', b'\x00', b'\x01']
}

///|
fn server_ip() -> Array[Byte] {
  [b'\x0a', b'\x00', b'\x00', b'\x02']
}

///|
fn client_mac() -> Array[Byte] {
  [b'\x02', b'\x00', b'\x00', b'\x00', b'\x00', b'\x01']
}

///|
fn server_mac() -> Array[Byte] {
  [b'\x02', b'\x00', b'\x00', b'\x00', b'\x00', b'\x02']
}

///|
fn exchange_pcap_endian(
  request : String,
  response : String,
  little : Bool,
) -> Bytes {
  classic_pcap(
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
        seconds: 1725148800,
        fraction: 1000,
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
    little,
  )
}

///|
fn exchange_pcap(request : String, response : String) -> Bytes {
  exchange_pcap_endian(request, response, true)
}

///|
fn sample_request() -> String {
  "GET /api/users?id=7 HTTP/1.1\r\nHost: example.com\r\nAccept: text/plain\r\n\r\n"
}

///|
fn sample_response() -> String {
  "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
}

///|
/// 一份只含一次明文 HTTP/1.1 往返的经典 pcap。
pub fn sample_pcap() -> Bytes {
  exchange_pcap(sample_request(), sample_response())
}
