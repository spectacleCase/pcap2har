///|
priv struct PcapngIface {
  link_type : Int32
  decimal : Bool
  exponent : Int32
}

///|
fn read_u32_wide(data : Bytes, at : Int32, little : Bool) -> Int64? {
  if at < 0 || at + 4 > data.length() {
    return None
  }
  let b0 = data[at].to_int().to_int64()
  let b1 = data[at + 1].to_int().to_int64()
  let b2 = data[at + 2].to_int().to_int64()
  let b3 = data[at + 3].to_int().to_int64()
  if little {
    Some(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
  } else {
    Some((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
  }
}

///|
fn read_u16_wide(data : Bytes, at : Int32, little : Bool) -> Int32? {
  if at < 0 || at + 2 > data.length() {
    return None
  }
  let lo = data[at].to_int()
  let hi = data[at + 1].to_int()
  if little {
    Some(lo + (hi << 8))
  } else {
    Some((lo << 8) + hi)
  }
}

///|
fn pcapng_little(data : Bytes, at : Int32) -> Bool? {
  if at + 12 > data.length() {
    return None
  }
  if data[at + 8] == b'\x4d' &&
    data[at + 9] == b'\x3c' &&
    data[at + 10] == b'\x2b' &&
    data[at + 11] == b'\x1a' {
    Some(true)
  } else if data[at + 8] == b'\x1a' &&
    data[at + 9] == b'\x2b' &&
    data[at + 10] == b'\x3c' &&
    data[at + 11] == b'\x4d' {
    Some(false)
  } else {
    None
  }
}

///|
fn pow10_i64(exponent : Int32) -> Int64 {
  let mut value = 1L
  for i = 0; i < exponent; i = i + 1 {
    value = value * 10L
  }
  value
}

///|
fn clamp_millis(millis : Int64) -> Int32 {
  if millis <= 0L {
    0
  } else if millis >= 999L {
    999
  } else {
    millis.to_int()
  }
}

///|
fn stamp_from_ticks(
  ticks : Int64,
  decimal : Bool,
  exponent : Int32,
) -> (Int32, Int32) {
  if ticks <= 0L || exponent < 0 {
    return (0, 0)
  }
  if decimal && exponent <= 18 {
    let scale = pow10_i64(exponent)
    let seconds = ticks / scale
    let millis = ticks % scale * 1000L / scale
    if seconds > 2147483647L {
      (2147483647, 999)
    } else {
      (seconds.to_int(), clamp_millis(millis))
    }
  } else if !decimal && exponent <= 53 {
    let seconds = ticks >> exponent
    let rem = ticks & ((1L << exponent) - 1L)
    let millis = (rem * 1000L) >> exponent
    if seconds > 2147483647L {
      (2147483647, 999)
    } else {
      (seconds.to_int(), clamp_millis(millis))
    }
  } else {
    (0, 0)
  }
}

///|
fn iface_resolution(
  data : Bytes,
  options_at : Int32,
  options_end : Int32,
  little : Bool,
) -> (Bool, Int32) {
  let mut decimal = true
  let mut exponent = 6
  let mut at = options_at
  while at + 4 <= options_end {
    let code = match read_u16_wide(data, at, little) {
      Some(value) => value
      None => break
    }
    let len = match read_u16_wide(data, at + 2, little) {
      Some(value) => value
      None => break
    }
    if code == 0 {
      break
    }
    if code == 9 && len > 0 && at + 4 < data.length() {
      let raw = data[at + 4].to_int()
      decimal = (raw & 0x80) == 0
      exponent = raw & 0x7F
    }
    let padded = (len + 3) / 4 * 4
    at = at + 4 + padded
  }
  (decimal, exponent)
}

///|
fn read_pcapng(data : Bytes) -> Result[Array[RawPacket], ConvertError] {
  if data.length() < 28 {
    return Err(InvalidPcap)
  }
  let mut little = match pcapng_little(data, 0) {
    Some(value) => value
    None => return Err(InvalidPcap)
  }
  let interfaces : Array[PcapngIface] = []
  let packets : Array[RawPacket] = []
  let mut offset = 0
  while offset + 12 <= data.length() {
    let block_type = match read_u32_wide(data, offset, little) {
      Some(value) => value
      None => return Err(InvalidPcap)
    }
    let total = match read_u32_wide(data, offset + 4, little) {
      Some(value) => value
      None => return Err(InvalidPcap)
    }
    if total < 12L || total > 16777216L {
      return Err(InvalidPcap)
    }
    let total_i = total.to_int()
    if offset + total_i > data.length() {
      return Err(InvalidPcap)
    }
    if block_type == 0x0A0D0D0AL {
      little = match pcapng_little(data, offset) {
        Some(value) => value
        None => return Err(InvalidPcap)
      }
      interfaces.clear()
    } else if block_type == 1L {
      let link_type = match read_u16_wide(data, offset + 8, little) {
        Some(value) => value
        None => return Err(InvalidPcap)
      }
      let (decimal, exponent) = iface_resolution(
        data,
        offset + 16,
        offset + total_i - 4,
        little,
      )
      interfaces.push({ link_type, decimal, exponent, })
    } else if block_type == 6L {
      if offset + 28 > data.length() {
        return Err(InvalidPcap)
      }
      let iface_id = match read_u32_wide(data, offset + 8, little) {
        Some(value) => value.to_int()
        None => return Err(InvalidPcap)
      }
      let high = match read_u32_wide(data, offset + 12, little) {
        Some(value) => value
        None => return Err(InvalidPcap)
      }
      let low = match read_u32_wide(data, offset + 16, little) {
        Some(value) => value
        None => return Err(InvalidPcap)
      }
      let cap_len = match read_u32_wide(data, offset + 20, little) {
        Some(value) => value.to_int()
        None => return Err(InvalidPcap)
      }
      if cap_len < 0 || offset + 28 + cap_len > offset + total_i - 4 {
        return Err(InvalidPcap)
      }
      if iface_id >= 0 && iface_id < interfaces.length() {
        let iface = interfaces[iface_id]
        if iface.link_type == 1 {
          let ticks = (high << 32) | low
          let (seconds, millis) = stamp_from_ticks(
            ticks,
            iface.decimal,
            iface.exponent,
          )
          packets.push({
            timestamp_seconds: seconds,
            timestamp_millis: millis,
            payload: copy_bytes(data, offset + 28, offset + 28 + cap_len),
          })
        }
      }
    }
    offset = offset + total_i
  }
  Ok(packets)
}

///|
fn read_capture(data : Bytes) -> Result[Array[RawPacket], ConvertError] {
  if data.length() >= 4 &&
    data[0] == b'\x0a' &&
    data[1] == b'\x0d' &&
    data[2] == b'\x0d' &&
    data[3] == b'\x0a' {
    read_pcapng(data)
  } else {
    read_classic_pcap(data)
  }
}

///|
fn push_u32_wide(buf : Array[Byte], n : Int64, little : Bool) -> Unit {
  let b0 = (n & 255L).to_int().to_byte()
  let b1 = ((n >> 8) & 255L).to_int().to_byte()
  let b2 = ((n >> 16) & 255L).to_int().to_byte()
  let b3 = ((n >> 24) & 255L).to_int().to_byte()
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
fn pcapng_packets(packets : Array[OutPacket], little : Bool) -> Bytes {
  let buf : Array[Byte] = []
  push_u32(buf, 0x0A0D0D0A, little)
  push_u32(buf, 28, little)
  push_u32(buf, 0x1A2B3C4D, little)
  push_u16(buf, 1, little)
  push_u16(buf, 0, little)
  for i = 0; i < 8; i = i + 1 {
    buf.push(b'\xff')
  }
  push_u32(buf, 28, little)
  push_u32(buf, 1, little)
  push_u32(buf, 20, little)
  push_u16(buf, 1, little)
  push_u16(buf, 0, little)
  push_u32(buf, 65535, little)
  push_u32(buf, 20, little)
  for packet in packets {
    let cap_len = packet.payload.length()
    let pad = (4 - cap_len % 4) % 4
    let block_len = 32 + cap_len + pad
    let ticks = packet.seconds.to_int64() * 1000000L +
      packet.fraction.to_int64()
    push_u32(buf, 6, little)
    push_u32(buf, block_len, little)
    push_u32(buf, 0, little)
    push_u32_wide(buf, ticks >> 32, little)
    push_u32_wide(buf, ticks & 0xFFFFFFFFL, little)
    push_u32(buf, cap_len, little)
    push_u32(buf, cap_len, little)
    for i = 0; i < cap_len; i = i + 1 {
      buf.push(packet.payload[i])
    }
    for i = 0; i < pad; i = i + 1 {
      buf.push(b'\x00')
    }
    push_u32(buf, block_len, little)
  }
  Bytes::from_array(buf)
}
