# pcap2har 项目申报书

## 基本信息

- 项目名称：pcap2har：把经典 pcap 或 pcapng 里的明文 HTTP/1.1 转成 HAR 1.2
- 参赛者：桌角的眼镜
- 联系方式：18875991125
- GitHub 仓库链接：[spectacleCase/pcap2har.git](https://github.com/spectacleCase/pcap2har.git)
- MoonBit 模块名：`spectacleCase/pcap2har`
- 项目方向：网络报文 / HTTP 交换记录 / HAR
- 是否为移植项目：不是移植。参考 HAR 1.2 规范，组合已有的 pcap 库和 HAR 库，补上两者之间缺少的转换

## 项目简介

pcap2har 面向已经落地的抓包文件。Wireshark、tcpdump 保存的是链路层报文；浏览器开发者工具导出的 HAR 是一条条 HTTP 请求和响应。两边描述的是同一次通信，但 MoonBit 生态里没有把前者转成后者的包。

`cghyyrrt/moonbit-pcap` 能拆 Ethernet / IPv4 / TCP，并判断一段字节是不是 HTTP。`cpypypypy/har-toolkit` 能解析、校验 HAR 1.2，并且明确不读文件、不抓包、不重放。pcap2har 做的是中间这件事：读入已有经典 pcap 或 pcapng，配对本机地址和端口上的请求与响应，写出一份 har-toolkit 能接受的 HAR。

它不抓新的包，不发送请求，不解密 TLS，也不做 HAR 统计分析。统计分析继续交给 har-toolkit。

申报书写明的范围已经完成：核心库重组 TCP，读取经典 pcap 和 pcapng，解码 chunked 正文，并写出带 cookies、postData 和 send / wait / receive 的 HAR。同时交付内置样例、Native CLI、自动化测试、README、申报书和 CI。

## 项目现有基础

已经完成：

- 初始化 `spectacleCase/pcap2har` 模块，Apache-2.0、README、CI 和 mooncakes 元数据；
- 依赖 `cghyyrrt/moonbit-pcap@0.1.2` 和 `cpypypypy/har-toolkit@0.1.0`；
- 内置一份经典 pcap：Ethernet + IPv4 + TCP，一次明文 HTTP/1.1 往返，`GET /api/users?id=7` 对 `200 OK`，正文 `hello`；
- 用本项目的经典 pcap 读写解析全局头和包记录，接受小端 `d4 c3 b2 a1` 和大端 `a1 b2 c3 d4`，链路类型必须是 Ethernet。`examples/sample.pcap` 是小端文件，系统 `file` 命令识别为 version 2.4、Ethernet、snaplen 65535；
- 自己读 pcapng，不依赖 `moonbit-pcap` 0.1.2 的 `PcapngReader`：它在确定字节序之前就按一种端序读块长度。本项目先看 Section Header Block 的 BOM（`4D 3C 2B 1A` 为小端，`1A 2B 3C 4D` 为大端），再读 Interface Description 和 Enhanced Packet Block。时间戳按接口的 `if_tsresol` 换成秒和毫秒，缺省是微秒。链路类型不是 Ethernet 的接口会跳过，不让整个文件失败；只有 Section Header 的空文件得到空 HAR；
- 不用 `moonbit-pcap` 0.1.2 的 `PcapReader` / `PcapWriter`。它写出的 magic 和后续字段字节序不一致，Wireshark 打不开；
- 用 `parse_ethernet`、`parse_ipv4`、`parse_tcp` 取出 TCP 载荷；
- 用 `parse_http` 判断载荷是不是 HTTP。该函数目前只认前缀，所以方法、路径、状态码和原因短语由本项目从起始行解析，并用 `parse_http_first_line` 切分前三个字段；
- 按方向收集 TCP 段，用 `TcpStreamReassembler` 按序号重组，乱序到达的段也会拼回同一条 HTTP 报文；
- 按相反的源/目的 IP 和端口把请求与响应按顺序配成一对。没有配上的响应会丢掉；
- 写出 HAR 1.2：`log.version`、creator、request、response、queryString、headers、cookies、postData、content。写出前调用 `parse_har` 和 `validate_har`，校验失败则返回 `HarRejected`；
- `startedDateTime` 取请求首字节所在包的整秒 UTC。样例时间戳 `1725148800` 写成 `2024-09-01T00:00:00Z`。`send` 是请求报文最后一个包减第一个包，`wait` 是响应第一个包减请求最后一个包，`receive` 是响应最后一个包减第一个包，`time` 是三者之和。样例两边各一个包、响应晚 1 毫秒，所以 send 0、wait 1、receive 0、time 1。请求被拆成两段、后段先到时，send 取这两段的捕获时间差；
- `Transfer-Encoding` 含 `chunked` 时按块解码。HAR 的 `bodySize` 是线上分块帧的字节数，`content.size` 和正文文本是解码后的长度和内容。不解码 gzip；
- `Cookie` 拆成请求 cookies，`Set-Cookie` 拆成响应 cookies（含 Path、HttpOnly、Secure）。有正文的请求写成 `postData`；
- 库 API：`sample_pcap`、`sample_pcapng`、`extract_exchanges`、`pcap_to_har`；
- Native CLI：`sample`、`convert <file>`、`write-sample <file.pcap>`、`write-sample-pcapng <file.pcapng>`。文件读不到或不是 pcap / pcapng 时返回非 0；
- 样例文件 `examples/sample.pcap` 和 `examples/sample.pcapng`，同一次往返分别放在经典 pcap 和 pcapng 里。测试覆盖 200、404、204、POST 正文、chunked、乱序 TCP、send / wait / receive、空文件、非 Ethernet 接口、大小端和非法输入。

## 核心功能范围

- 读取经典 pcap 或 pcapng 字节或文件；
- 识别 Ethernet 上的 IPv4 TCP 明文 HTTP/1.1，并把同一方向上拆开或乱序的 TCP 段重组后再解析；
- 用 Host 头和请求路径拼出绝对 `http://` URL，并拆出 queryString；
- 记录请求头、响应头、Cookie、POST 正文、响应 MIME、响应正文、两侧的 headersSize / bodySize。chunked 正文先解码。`send`、`wait`、`receive` 分别来自请求发送、等待响应和接收响应的捕获时间；
- 提供库 API 和 Native CLI；
- 保证成功返回的文本能通过 har-toolkit 的解析和校验。

## 移植或参考说明

- 原项目名称：无。不是某个现有仓库的移植
- 参考规范：HTTP Archive (HAR) format 1.2
- 规范链接：http://www.softwareishard.com/blog/har-12-spec/
- 使用的 MoonBit 库：`cghyyrrt/moonbit-pcap`（Apache-2.0）、`cpypypypy/har-toolkit`（Apache-2.0）
- 本项目许可证：Apache-2.0

和这两个库的分工：

- pcap 库负责 Ethernet / IPv4 / TCP 分层，不负责 HAR。0.1.2 的经典 pcap 容器读写和 Wireshark 的字节序不一致，pcapng 读取也在确定字节序之前解释块长度，所以两种容器头都由本项目按规范处理；
- HAR 库负责文档结构和校验，不负责读 pcap；
- 本项目只负责配对和字段映射。`parse_http` 不能提供真实的状态码，因此状态行由本项目解析，测试里用 `404 Not Found` 确认没有沿用依赖里写死的 200。

## 技术路线

库是纯函数，输入 `Bytes`，输出 HAR 文本，wasm、js 和 native 都能跑。CLI 只在 native 上读文件，用 `moonbitlang/async` 的文件系统接口。

pcapng、chunked 正文，以及按报文起止时间拆开的 `send` / `wait` / `receive` 都已经实现。申报范围到此完成，不再把这些功能留到后续。

## 项目边界

- 不抓包，不打开网卡，不发送请求，不重放；
- 不解密 TLS，看不到 HTTPS 的请求和响应；
- 经典 pcap 的链路类型必须是 Ethernet。pcapng 里不是 Ethernet 的接口会被跳过，不把整个文件判为非法；
- 解码 `Transfer-Encoding: chunked`，不解码 gzip 或其它 Content-Encoding。没有 `Content-Length`、也不是 chunked 的 POST，会把该方向剩余字节当成正文；
- 不实现 HAR 统计、瀑布图或脱敏，这些交给 har-toolkit。

## 预期交付

- MoonBit 核心库；
- Native CLI；
- 内置样例、`examples/sample.pcap` 和 `examples/sample.pcapng`；
- 单元测试；
- README 与项目申报书；
- GitHub Actions CI；
- mooncakes.io 发布所需元数据。
