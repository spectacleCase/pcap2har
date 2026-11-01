name = "spectacleCase/pcap2har"

version = "0.1.0"

readme = "README.mbt.md"

repository = "https://github.com/spectacleCase/pcap2har.git"

license = "Apache-2.0"

keywords = [ "pcap", "har", "http", "http-archive" ]

preferred_target = "native"

description = "Convert cleartext HTTP/1.1 in a classic pcap into HAR 1.2"

import {
  "cghyyrrt/moonbit-pcap@0.1.2",
  "cpypypypy/har-toolkit@0.1.0",
  "moonbitlang/async@0.22.7",
}
