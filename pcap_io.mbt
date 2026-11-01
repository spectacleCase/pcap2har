///|
priv struct RawPacket {
  timestamp_seconds : Int32
  payload : Bytes
}

///|
priv struct OutPacket {
  seconds : Int32
  fraction : Int32
  payload : Bytes
}

///|
fn push_u16(buf : Array[Byte], n : Int32, little : Bool) -> Unit {
  let lo = (n & 255).to_byte()
  let hi = ((n >> 8) & 255).to_byte()
  if little {
    buf.push(lo)
    buf.push(hi)
  } else {
    buf.push(hi)
    buf.push(lo)
  }
}

///|
fn push_u32(buf : Array[Byte], n : Int32, little : Bool) -> Unit {
  let b0 = (n & 255).to_byte()
  let b1 = ((n >> 8) & 255).to_byte()
  let b2 = ((n >> 16) & 255).to_byte()
  let b3 = ((n >> 24) & 255).to_byte()
  if little {
    buf.push(b0)
    buf.push(b1)
    buf.push(b2)
    buf.push(b3)
  } else {
    buf.push(b3)
    buf.push(b2)
    buf.push(b1)
    buf.push(b0)
  }
}

///|
fn read_u32(data : Bytes, at : Int32, little : Bool) -> Int32? {
  if at + 4 > data.length() {
    return None
  }
  let b0 = data[at].to_int()
  let b1 = data[at + 1].to_int()
  let b2 = data[at + 2].to_int()
  let b3 = data[at + 3].to_int()
  let value = if little {
    b0 + (b1 << 8) + (b2 << 16) + (b3 << 24)
  } else {
    (b0 << 24) + (b1 << 16) + (b2 << 8) + b3
  }
  if value < 0 {
    None
  } else {
    Some(value)
  }
}

///|
fn copy_bytes(data : Bytes, start : Int32, end : Int32) -> Bytes {
  let out : Array[Byte] = []
  for i = start; i < end; i = i + 1 {
    out.push(data[i])
  }
  Bytes::from_array(out)
}

///|
fn has_magic(data : Bytes, magic : Array[Byte]) -> Bool {
  if data.length() < magic.length() {
    return false
  }
  for i = 0; i < magic.length(); i = i + 1 {
    if data[i] != magic[i] {
      return false
    }
  }
  true
}

///|
fn pcap_is_little(data : Bytes) -> Bool? {
  if has_magic(data, [b'\xd4', b'\xc3', b'\xb2', b'\xa1']) ||
    has_magic(data, [b'\x4d', b'\x3c', b'\xb2', b'\xa1']) {
    Some(true)
  } else if has_magic(data, [b'\xa1', b'\xb2', b'\xc3', b'\xd4']) ||
    has_magic(data, [b'\xa1', b'\xb2', b'\x3c', b'\x4d']) {
    Some(false)
  } else {
    None
  }
}

///|
fn read_classic_pcap(data : Bytes) -> Result[Array[RawPacket], ConvertError] {
  if data.length() < 24 {
    return Err(InvalidPcap)
  }
  let little = match pcap_is_little(data) {
    Some(value) => value
    None => return Err(InvalidPcap)
  }
  match read_u32(data, 20, little) {
    Some(1) => ()
    _ => return Err(InvalidPcap)
  }
  let packets : Array[RawPacket] = []
  let mut offset = 24
  while offset + 16 <= data.length() {
    let seconds = match read_u32(data, offset, little) {
      Some(value) => value
      None => return Err(InvalidPcap)
    }
    let included = match read_u32(data, offset + 8, little) {
      Some(value) => value
      None => return Err(InvalidPcap)
    }
    let payload_at = offset + 16
    if payload_at + included > data.length() {
      return Err(InvalidPcap)
    }
    packets.push({
      timestamp_seconds: seconds,
      payload: copy_bytes(data, payload_at, payload_at + included),
    })
    offset = payload_at + included
  }
  Ok(packets)
}

///|
fn classic_pcap(packets : Array[OutPacket], little : Bool) -> Bytes {
  let buf : Array[Byte] = []
  if little {
    buf.push(b'\xd4')
    buf.push(b'\xc3')
    buf.push(b'\xb2')
    buf.push(b'\xa1')
  } else {
    buf.push(b'\xa1')
    buf.push(b'\xb2')
    buf.push(b'\xc3')
    buf.push(b'\xd4')
  }
  push_u16(buf, 2, little)
  push_u16(buf, 4, little)
  push_u32(buf, 0, little)
  push_u32(buf, 0, little)
  push_u32(buf, 65535, little)
  push_u32(buf, 1, little)
  for packet in packets {
    push_u32(buf, packet.seconds, little)
    push_u32(buf, packet.fraction, little)
    push_u32(buf, packet.payload.length(), little)
    push_u32(buf, packet.payload.length(), little)
    for i = 0; i < packet.payload.length(); i = i + 1 {
      buf.push(packet.payload[i])
    }
  }
  Bytes::from_array(buf)
}
