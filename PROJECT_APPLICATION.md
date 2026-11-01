# pcap2har 项目申报书

## 基本信息

- 项目名称：pcap2har：把经典 pcap 里的明文 HTTP/1.1 转成 HAR 1.2
- 参赛者：桌角的眼镜
- 联系方式：18875991125
- GitHub 仓库链接：[spectacleCase/pcap2har.git](https://github.com/spectacleCase/pcap2har.git)
- MoonBit 模块名：`spectacleCase/pcap2har`
- 项目方向：网络报文 / HTTP 交换记录 / HAR
- 是否为移植项目：不是移植。参考 HAR 1.2 规范，组合已有的 pcap 库和 HAR 库，补上两者之间缺少的转换

## 项目简介

pcap2har 面向已经落地的抓包文件。Wireshark、tcpdump 保存的是链路层报文；浏览器开发者工具导出的 HAR 是一条条 HTTP 请求和响应。两边描述的是同一次通信，但 MoonBit 生态里没有把前者转成后者的包。

`cghyyrrt/moonbit-pcap` 能读经典 pcap，拆 Ethernet / IPv4 / TCP，并判断一段字节是不是 HTTP。`cpypypypy/har-toolkit` 能解析、校验 HAR 1.2，并且明确不读文件、不抓包、不重放。pcap2har 做的是中间这件事：读入已有 pcap，配对本机地址和端口上的请求与响应，写出一份 har-toolkit 能接受的 HAR。

它不抓新的包，不发送请求，不解密 TLS，也不做 HAR 统计分析。统计分析继续交给 har-toolkit。

报名阶段已经有可运行的 demo：核心库、内置样例 pcap、Native CLI、自动化测试、README、申报书和 CI。

## 项目现有基础

报名阶段已完成：

- 初始化 `spectacleCase/pcap2har` 模块，Apache-2.0、README、CI 和 mooncakes 元数据；
- 依赖 `cghyyrrt/moonbit-pcap@0.1.2` 和 `cpypypypy/har-toolkit@0.1.0`；
- 内置一份经典 pcap：Ethernet + IPv4 + TCP，一次明文 HTTP/1.1 往返，`GET /api/users?id=7` 对 `200 OK`，正文 `hello`；
- 用本项目的经典 pcap 读写解析全局头和包记录，接受小端 `d4 c3 b2 a1` 和大端 `a1 b2 c3 d4`，链路类型必须是 Ethernet。`examples/sample.pcap` 是小端文件，系统 `file` 命令识别为 version 2.4、Ethernet、snaplen 65535；
- 不用 `moonbit-pcap` 0.1.2 的 `PcapReader` / `PcapWriter`。它写出的 magic 和后续字段字节序不一致，Wireshark 打不开；
- 用 `parse_ethernet`、`parse_ipv4`、`parse_tcp` 取出 TCP 载荷；
- 用 `parse_http` 判断载荷是不是 HTTP。该函数目前只认前缀，所以方法、路径、状态码和原因短语由本项目从起始行解析，并用 `parse_http_first_line` 切分前三个字段；
- 按相反的源/目的 IP 和端口把请求与响应配成一对。没有配上的响应会丢掉；
- 写出 HAR 1.2：`log.version`、creator、request、response、queryString、headers、content。写出前调用 `parse_har` 和 `validate_har`，校验失败则返回 `HarRejected`；
- `startedDateTime` 取请求包的整秒 UTC。样例时间戳 `1725148800` 写成 `2024-09-01T00:00:00Z`。`time` 和 timings 写 0；
- 库 API：`sample_pcap`、`extract_exchanges`、`pcap_to_har`；
- Native CLI：`sample`、`convert <file.pcap>`、`write-sample <file.pcap>`。文件读不到或不是 pcap 时返回非 0；
- 样例文件 `examples/sample.pcap`，以及覆盖 200、404、204、POST 正文长度、空 pcap 和非法输入的测试。

## 核心功能范围

- 读取经典 pcap 字节或文件；
- 识别 Ethernet 上的 IPv4 TCP 明文 HTTP/1.1；
- 用 Host 头和请求路径拼出绝对 `http://` URL，并拆出 queryString；
- 记录请求头、响应头、响应 MIME、响应正文和两侧的 headersSize / bodySize；
- 提供库 API 和 Native CLI；
- 保证成功返回的文本能通过 har-toolkit 的解析和校验。

## 移植或参考说明

- 原项目名称：无。不是某个现有仓库的移植
- 参考规范：HTTP Archive (HAR) format 1.2
- 规范链接：http://www.softwareishard.com/blog/har-12-spec/
- 使用的 MoonBit 库：`cghyyrrt/moonbit-pcap`（Apache-2.0）、`cpypypypy/har-toolkit`（Apache-2.0）
- 本项目许可证：Apache-2.0

和这两个库的分工：

- pcap 库负责 Ethernet / IPv4 / TCP 分层，不负责 HAR，0.1.2 的 pcap 容器读写和 Wireshark 的字节序不一致，所以容器头由本项目按经典 pcap 规范处理；
- HAR 库负责文档结构和校验，不负责读 pcap；
- 本项目只负责配对和字段映射。`parse_http` 不能提供真实的状态码，因此状态行由本项目解析，测试里用 `404 Not Found` 确认没有沿用依赖里写死的 200。

## 技术路线

库是纯函数，输入 `Bytes`，输出 HAR 文本，wasm、js 和 native 都能跑。CLI 只在 native 上读文件，用 `moonbitlang/async` 的文件系统接口。

后续可以继续做：

- 用 `TcpStreamReassembler` 拼接被拆开的 HTTP 报文；
- 读取 pcapng；
- 从包时间戳计算 HAR timings，而不是写 0；
- 把 POST 正文写成 `postData`，把 Cookie 头拆进 cookies 数组。

## 项目边界

- 不抓包，不打开网卡，不发送请求，不重放；
- 不解密 TLS，看不到 HTTPS 的请求和响应；
- 不读 pcapng，也不读链路类型不是 Ethernet 的经典 pcap；
- 首版不做 TCP 重组，一个段里只处理一条 HTTP 报文；
- 不实现 HAR 统计、瀑布图或脱敏，这些交给 har-toolkit；
- 不把 timings 写成真实耗时。

## 预期交付

- MoonBit 核心库；
- Native CLI；
- 内置样例和 `examples/sample.pcap`；
- 单元测试；
- README 与项目申报书；
- GitHub Actions CI；
- mooncakes.io 发布所需元数据。
