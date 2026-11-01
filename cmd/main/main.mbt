///|
extern "c" fn exit_raw(code : Int32) -> Unit = "pcap2har_exit"

///|
fn exit_process(code : Int32) -> Unit {
  if code != 0 {
    exit_raw(code)
  }
}

///|
fn usage() -> Unit {
  println(
    (
      #|pcap2har \{@pcap2har.version}
      #|
      #|Usage:
      #|  pcap2har sample
      #|  pcap2har convert <file.pcap>
      #|  pcap2har write-sample <file.pcap>
      #|
      #|sample prints HAR 1.2 for the built-in cleartext HTTP/1.1 capture.
      #|convert reads a classic pcap and prints HAR 1.2.
      #|write-sample writes that built-in capture to a pcap file.
    ),
  )
}

///|
fn print_har(bytes : Bytes) -> Int32 {
  match @pcap2har.pcap_to_har(bytes) {
    Ok(har) => {
      println(har)
      0
    }
    Err(@pcap2har.InvalidPcap) => {
      println("invalid pcap")
      1
    }
    Err(@pcap2har.HarRejected(message)) => {
      println(message)
      1
    }
  }
}

///|
async fn read_pcap(path : String) -> Bytes? {
  let bytes = @fs.read_file(path).binary() catch { _ => return None }
  Some(bytes)
}

///|
async fn write_sample(path : String) -> Bool {
  @fs.write_file(path, @pcap2har.sample_pcap()) catch {
    _ => return false
  }
  true
}

///|
async fn main {
  let args = @env.args()
  if args.length() < 2 || args[1] == "-h" || args[1] == "--help" {
    usage()
    return
  }
  if args[1] == "-V" || args[1] == "--version" {
    println(@pcap2har.version)
    return
  }
  let code = match args[1] {
    "sample" => print_har(@pcap2har.sample_pcap())
    "convert" =>
      if args.length() < 3 {
        usage()
        1
      } else {
        match read_pcap(args[2]) {
          Some(bytes) => print_har(bytes)
          None => {
            println("cannot read file: \{args[2]}")
            1
          }
        }
      }
    "write-sample" =>
      if args.length() < 3 {
        usage()
        1
      } else if write_sample(args[2]) {
        0
      } else {
        println("cannot write file: \{args[2]}")
        1
      }
    _ => {
      usage()
      1
    }
  }
  exit_process(code)
}
