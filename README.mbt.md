# pcap2har

pcap2har 把一份已经抓好的经典 pcap 里的明文 HTTP/1.1 请求和响应配成对，写成 [HAR 1.2](http://www.softwareishard.com/blog/har-12-spec/)。它不抓新的包，不发送请求，也不解密 HTTPS。

Wireshark 保存的是报文，浏览器 HAR 保存的是一次次 HTTP 交换。两边没有现成的官方导出。MoonBit 生态里，`cghyyrrt/moonbit-pcap` 负责读 pcap 和分层，`cpypypypy/har-toolkit` 负责解析和校验 HAR，但都不把 pcap 转成 HAR。本项目补的是这一段。

## 边界

- 只读经典 pcap。文件头按规范识别小端和大端，链路类型只接受 Ethernet，网络层按 IPv4，传输层按 TCP。
- 同一方向上被拆开或乱序的 TCP 段会用 `moonbit-pcap` 的 `TcpStreamReassembler` 拼回后再解析 HTTP。pcapng 和 TLS 不在这版里。
- 报文分层用 `parse_ethernet`、`parse_ipv4`、`parse_tcp`。pcap 文件头由本项目自己读，不用它的 `PcapReader` / `PcapWriter`：0.1.2 把 magic 和后面的字节序配反了，写出的文件 Wireshark 认不出。
- `parse_http` 目前只根据前缀判断是不是 HTTP，方法、路径和状态码由本项目从起始行解析。
- `startedDateTime` 使用请求首字节所在包的整秒 UTC。`time` 和 `timings.wait` 是响应首字节与请求首字节的毫秒差，`send` 和 `receive` 写 0。
- 有正文的请求会写成 `postData`。`Cookie` 和 `Set-Cookie` 会拆进 cookies 数组。

## 快速开始

```bash
moon test
moon run --target native cmd/main -- sample
moon run --target native cmd/main -- write-sample examples/sample.pcap
moon run --target native cmd/main -- convert examples/sample.pcap
```

`examples/sample.pcap` 是内置样例：客户端 `10.0.0.1:12345` 向 `10.0.0.2:80` 发送 `GET /api/users?id=7`，服务器返回 `200 OK` 和正文 `hello`。请求时间戳是 `1725148800`，对应 `2024-09-01T00:00:00Z`。

## 命令

```text
pcap2har sample
pcap2har convert <file.pcap>
pcap2har write-sample <file.pcap>
```

`convert` 在文件读不到或内容不是 pcap 时返回非 0。

## 库 API

```mbt check
///|
test "sample capture converts to HAR" {
  let har = @pcap2har.pcap_to_har(@pcap2har.sample_pcap()).unwrap()
  assert_true(har.contains("\"method\":\"GET\""))
  assert_true(har.contains("http://example.com/api/users?id=7"))
  assert_true(har.contains("\"status\":200"))
  assert_true(har.contains("\"text\":\"hello\""))
}
```

`extract_exchanges` 返回配对后的方法、URL、状态码和响应正文。`pcap_to_har` 在写出文本前会用 `cpypypypy/har-toolkit` 做 `parse_har` 和 `validate_har`。
