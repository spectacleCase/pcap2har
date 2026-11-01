///|
fn pad2(n : Int32) -> String {
  if n < 10 {
    "0\{n}"
  } else {
    "\{n}"
  }
}

///|
fn pad4(n : Int32) -> String {
  if n >= 1000 {
    "\{n}"
  } else if n >= 100 {
    "0\{n}"
  } else if n >= 10 {
    "00\{n}"
  } else {
    "000\{n}"
  }
}

///|
fn civil_from_days(days : Int32) -> (Int32, Int32, Int32) {
  let z = days + 719468
  let era = z / 146097
  let doe = z - era * 146097
  let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
  let y = yoe + era * 400
  let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
  let mp = (5 * doy + 2) / 153
  let d = doy - (153 * mp + 2) / 5 + 1
  let m = if mp < 10 { mp + 3 } else { mp - 9 }
  let year = if m <= 2 { y + 1 } else { y }
  (year, m, d)
}

///|
fn unix_utc(seconds : Int32) -> String {
  if seconds < 0 {
    return "1970-01-01T00:00:00Z"
  }
  let days = seconds / 86400
  let tod = seconds % 86400
  let (year, month, day) = civil_from_days(days)
  let hour = tod / 3600
  let minute = tod % 3600 / 60
  let second = tod % 60
  "\{pad4(year)}-\{pad2(month)}-\{pad2(day)}T\{pad2(hour)}:\{pad2(minute)}:\{pad2(second)}Z"
}
