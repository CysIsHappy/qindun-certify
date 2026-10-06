# 秦盾本地安全预检

> **v0.7.4** — 面向 Skill（技能）、Agent（智能体）和工作流作品包的
> 本地安全预检工具，支持确定性扫描、依赖清单、候选智能复核、持续集成报告和官方报告验签。

秦盾本地安全预检会读取本地目录、ZIP（压缩包）或用户指定的公开 GitHub 仓库，检查包结构、危险行为、
敏感信息、依赖、网络目标、提示词安全以及能力声明一致性，并生成 Markdown
（标记文本）、JSON（结构化文本）、HTML（网页）或 SARIF
（通用静态分析结果格式）报告。它也可以使用公钥离线验证秦盾平台签名报告。

它不会执行目标代码、安装目标依赖或访问作品内容中声明的网络地址。只有用户
提供 GitHub 仓库时才获取该仓库，只有明确启用 `--osv` 时才查询公开漏洞库。

> **重要说明**
>
> 本工具生成的是“本地预检结果”，不是秦盾平台安全评测报告。它不使用平台签名私钥，
> 不生成平台报告编号，也不能签发 A、A+、S 或 S+。ChinMarket 平台会重新读取
> 精确作品包版本，在服务端独立扫描后签发安全评测报告。

源码仓库：[CysIsHappy/qindun-certify](https://github.com/CysIsHappy/qindun-certify)。
签名安装包：[GitHub 发布页](https://github.com/CysIsHappy/qindun-certify/releases)。
请使用发布页的 `qindun-certify-版本号.zip`，不要把 GitHub 自动生成的源码压缩包当作签名安装包。

---

## 检测范围

### D2：包结构与解包安全

| 检查项 | 检查内容 |
| --- | --- |
| 路径安全 | 目录逃逸、绝对路径、Windows 驱动器路径 |
| 文件冲突 | 重名、大小写冲突、Unicode（统一字符编码）规范化冲突 |
| 异常文件 | 符号链接、设备文件及其他非常规文件类型 |
| 压缩安全 | 压缩炸弹、加密条目、总大小和文件数量限制 |
| 嵌套压缩 | 识别没有继续递归扫描的内层压缩包 |
| 作品结构 | 空包、作品类型冲突、无法识别的作品类型 |
| Skill 结构 | `SKILL.md` 是否包含有效的名称和说明 |
| Agent 结构 | `AGENTS.md` 或 `CLAUDE.md` 是否有效 |
| 工作流结构 | `chinmarket.yaml` 或 `langgraph.json` 及入口文件是否有效 |

### D3：恶意静态行为

| 检查项 | 检查内容 |
| --- | --- |
| 破坏性命令 | 删除根目录、用户目录等确定性危险操作 |
| 下载后执行 | 网络内容未经校验直接交给命令解释器 |
| 语法与数据流 | 检查 Python、Shell、PowerShell 和 JavaScript/TypeScript 中危险数据到危险操作的连接 |
| PowerShell 风险 | 下载内容直接进入表达式执行器 |
| 反向连接 | 命令解释器连接外部网络端点的典型组合 |
| 凭据外传 | 获取认证材料并组合外部传输能力 |
| 持久化 | 计划任务、系统服务、启动项等长期驻留行为 |
| 混淆执行 | 动态解码后交给代码执行函数 |
| 隐藏控制字符 | 影响文字显示顺序或隐藏指令边界的字符 |
| 二进制程序 | 基础预检无法解释其真实行为的原生可执行文件 |
| 智能体上下文 | 记忆、系统说明、设置、钩子和命令解释器启动文件写入 |
| 隐蔽外传 | 剪贴板、DNS、Git 远程地址等外传组合 |
| 条件触发 | 时间、主机、用户或计数条件下的动态执行 |
| 文件语境 | 区分安全文档、测试载荷与可达的真实执行，避免把检测示例当成攻击 |

### D4：依赖与供应链

| 检查项 | 检查内容 |
| --- | --- |
| 依赖清单 | 从常见声明和锁文件逐项对应生态、包名、精确版本和依赖来源 |
| 版本锁定 | 有实际依赖声明时要求匹配锁文件；无依赖项目不因缺少锁文件而失败 |
| 多项目工作区 | 识别 npm、Cargo、uv 和 Gradle 工作区，并尊重排除项 |
| 安装入口 | 记录 npm、Python、Cargo、Maven、Gradle、Composer 和 Ruby 构建或安装时可能执行的入口，但不执行它们 |
| 软件物料清单 | ZIP 根组件绑定原始包哈希，目录根组件绑定完整内容清单哈希，只把声明中确认的直接依赖标为直接关系 |
| 依赖来源 | 区分 public（公开包）、private（私有包）、local（本地路径）、vcs（版本库）和 unknown（未知） |
| 公开漏洞 | 只向 OSV 发送锁文件明确证明来自官方公开仓库的精确版本；缺少来源的依赖不会外发，整次查询受 120 秒和 64 MiB 总预算限制 |

### D5：密钥与敏感信息

| 检查项 | 检查内容 |
| --- | --- |
| 私钥 | RSA、EC、OpenSSH 等私钥文件头 |
| 通用密钥字段 | API Key、访问令牌、客户端密钥、密码等固定值 |
| 云平台密钥 | AWS 等常见云平台访问密钥格式 |
| 开发平台令牌 | GitHub、OpenAI、Slack 等常见令牌格式 |
| 固定身份令牌 | JWT（三段式身份令牌）等疑似硬编码凭据 |
| 常见敏感文件 | `.env` 和无扩展名文本同样进入检查 |

报告不会保存命中的原始密钥，也不会保存密钥长度或原值摘要；只记录规则、
位置和“已脱敏”证据，避免短密钥被长度或摘要反推，使扫描报告成为新的泄密源。

### D6：网络目标

| 检查项 | 检查内容 |
| --- | --- |
| 网页地址 | 从已检查文本中提取 HTTP/HTTPS 域名和 IP |
| 套接字目标 | 识别代码中硬编码的 IP 和端口 |
| 隐藏网络目标 | 网络调用附近的动态解码和目标混淆 |
| 报告清单 | 汇总观察到的域名和非 HTTP 网络端点 |

本地预检只分析代码和文档中写出的网络目标，不会主动连接这些地址，也不会
把“出现某个域名”直接等同于恶意行为。

Python 代码中，密钥仅通过标准认证头发送时保留为待复核候选，需要进一步确认
接收对象和凭据用途；这不代表安全放行。把凭据放进请求正文、网址参数，或者
读取凭据文件并外发，仍会按数据流检查。文字中的正常“静默跳过”说明不再仅凭
单词触发隐藏操作风险。

扫描 GitHub 仓库时还会保存仓库创建时间、更新时间、收藏数、派生数、归档
状态和作者类型等公开来源证据。来源信息只帮助用户判断，不参与本地安全等级。

### D7：提示词与能力声明

| 检查项 | 检查内容 |
| --- | --- |
| 提示词越权 | 试图绕过上级约束或改变既定安全边界 |
| 敏感信息外传 | 索取受保护上下文并要求向第三方披露 |
| 网络能力声明 | 实际观察到的网络目标是否已在能力声明中列出 |
| 进程能力声明 | 代码启动进程时，能力声明是否允许启动进程 |
| 文件与环境能力 | 检查文件读取、文件写入、普通环境变量和敏感环境变量是否如实声明 |
| 工具与状态能力 | 检查进程命令、模型上下文协议工具和跨会话持久状态是否如实声明 |
| 智能体特有风险 | 隐藏操作、工具滥用、长期记忆操纵、未信任内容驱动高权限动作和关闭安全边界 |
| 模型上下文协议风险 | 检查工具说明注入、令牌放入网址参数、可变远程组件和工具参数进入命令执行 |

确定性规则命中“需要复核”的候选时，秦盾可以生成经过摘要校验、内容限量和
密钥脱敏的复核输入，让智能体判断真实语境。该结果只作为补充证据，不修改
扫描器给出的本地等级，也不能替代真实动态扫描。

`capabilities.json` 是可选的本地能力声明文件。提供该文件时，格式应为
`qindun-capabilities/v1`。平台正式认证仍以平台从冻结作品包中提取并确认的
能力清单为准，不直接信任作者通过声明降低检查范围。

---

## 当前不包含的检查

本地工具明确不执行以下能力：

- D1 平台账号身份、实名信息和作品来源绑定；
- 商业威胁情报和私有恶意软件样本库；
- 自动展开短链接后的最终站点检查；
- 图片、音频、视频和 PDF 内容的语义识别；
- Go、Rust、Java 等尚无结构分析器语言的真实程序行为；
- 隔离环境动态运行和对抗测试；
- 高级动态重放；
- 人工复核；
- 平台数字签名、签名私钥保管和当前认证撤销查询。

这些能力由秦盾平台正式认证流程完成，不能通过本地提示词模拟。

---

## 等级说明

秦盾只维护一套安全等级。本地预检与平台使用同一份版本化定级策略，但本地
检查覆盖范围有限，因此等级上限固定为 B。

### 本地预检可能出现的结果

| 结果 | 含义 | 建议 |
| :---: | --- | --- |
| B | 扫描完整，当前基础规则未发现会把等级降至 C 或 D 的问题 | 仍需平台正式认证 |
| C | 发现高风险或严重风险候选，需要进一步复核 | 修复或确认真实用途 |
| D | 确定性规则已经确认严重危险 | 不要安装或运行 |
| 未生成等级 | 有内容没有完成检查，例如加密条目、嵌套压缩包或超限文件 | 补齐可扫描内容后重试 |

中风险候选最多把结果限制为 B，高风险或严重风险候选最多限制为 C；只有
确定性规则确认的严重危险才直接判为 D。扫描不完整不是一种安全等级，因此
不会被伪装成 C 或 D；如果已经发现确定严重危险，仍可直接提示 D。

### 秦盾平台完整等级

| 等级 | 主要含义 |
| :---: | --- |
| S+ | 完成高级动态检查，并经过管理员人工复核 |
| S | 完成适用的动态隔离运行检查 |
| A+ | 完成更深的网络与声明语义一致性检查 |
| A | 完成适用的依赖漏洞和供应链检查 |
| B | 完成基础静态网络与声明检查 |
| C | 检查证据较少，或存在高风险候选发现 |
| D | 已确认严重危险 |

正式等级严格绑定某一个精确作品包版本和服务端摘要。新作品包版本不会继承
旧版本认证。

---

## 安装

### 安装正式签名发布

不要先解压 ZIP 并运行其中的安装器。正式安装必须先用通过独立可信渠道取得的
启动验证器和固定发布公钥验证原始 ZIP，再执行已经验证的安装器。完整命令见
[references/release-verification.md](references/release-verification.md)。

安装器会再次核对原始 ZIP、发布清单、签名、固定公钥、来源提交号和解压后逐
文件摘要。缺少任一项都会拒绝正式安装。升级时还必须明确增加 `--replace`，原
目录会先移动到带时间戳的备份目录。可用 `--platform claude` 安装到 Claude，
也可以用 `--destination` 指定其他支持 `SKILL.md` 的技能根目录。

重新启动智能体应用后，可以直接提出“用秦盾预检这个 Skill 目录”，也可以
显式使用 `$qindun-certify`。

### 从已审查源码开发安装

维护者从已经独立审查的源码目录安装时，必须明确接受未验证源码模式：

```bash
python3 scripts/install.py --platform codex --allow-unverified-source
```

也可以手动复制完整目录，但不能只复制 `SKILL.md`，因为规则、扫描器和参考协议
都是运行所需文件。该方式不表示发布签名有效，不应用作普通用户的正式安装流程。

统一入口支持用户明确提供的公开 GitHub HTTPS 仓库地址。它只接受仓库根地址，
拒绝带账号凭据、查询参数或仓库子目录的地址。工具先把分支或标签解析为
完整提交号，再下载该提交的 ZIP 归档；这个过程不执行本机 Git 钩子、
`.gitattributes` 过滤器或 LFS 命令。子模块和 Git LFS 只有引用而没有原文时，
报告会标记扫描未完成，不会给出 B。

### 直接作为终端命令使用

运行版根目录提供可直接执行的 `qindun` 入口：

```bash
/完整路径/qindun-certify/qindun scan ./my-skill
```

不使用可执行入口时也可以直接运行 Python 文件：

```bash
python3 /完整路径/qindun-certify/scripts/qindun.py ./my-skill
```

要求：

- 已验证的 Python 版本为 3.10、3.11 和 3.12；
- 扫描和生成报告不需要第三方 Python 依赖；
- 验证 Ed25519 平台签名时需要 `cryptography`（Python 密码学库）；
- 扫描 GitHub 地址不需要本机 `git` 命令。

当前持续集成覆盖 Ubuntu。macOS 和 Windows 属于尽力支持；文件权限相关的正式
发布验证应优先使用能够保留 Unix 权限的环境。详情见 [SECURITY.md](SECURITY.md)。

---

## 使用方式

### 在智能体对话中使用

安装后可以用自然语言发起检查：

```text
用秦盾预检 /Users/me/Developer/my-skill 目录。
```

```text
检查我下载的 my-agent.zip，并解释最重要的风险。
```

```text
用秦盾扫描这个工作流目录，把完整报告保存为 Markdown。
```

```text
检查这个 Skill，给我 JSON 结果用于持续集成。
```

```text
检查这个 GitHub 仓库，生成可视化报告，并查询公开依赖漏洞。
```

```text
批量检查这三个作品，把 Markdown、JSON、HTML 和 SARIF 报告保存到同一个目录。
```

智能体必须把结果称为“本地预检”或“非官方报告”，不能称为秦盾平台已经完成
认证。

### 在终端中使用

统一入口扫描一个本地目标并显示 Markdown 报告：

```bash
./qindun scan ./my-skill
```

扫描 GitHub 仓库，绑定指定分支解析出的实际提交，并生成四种报告：

```bash
./qindun scan https://github.com/example/my-skill \
  --ref main \
  --format markdown --format json --format html --format sarif \
  --output-dir ./reports
```

批量扫描时必须提供报告目录；没有指定格式时默认生成 Markdown、JSON 和 HTML：

```bash
./qindun scan ./skill-a ./agent-b.zip ./workflow-c \
  --output-dir ./reports
```

离线扫描默认生成精确依赖清单和软件物料清单。明确查询 OSV 公开漏洞库：

```bash
./qindun scan ./my-skill --osv
```

联合本地安装的第三方工具补充候选证据：

```bash
./qindun scan ./my-skill \
  --external-scanner skillspector \
  --external-scanner cisco \
  --format json --output-dir ./reports
```

第三方工具不会随秦盾安装，也不会默认调用。SkillSpector 固定使用无模型模式，
Cisco 固定使用本地默认分析器。AIG 依赖模型分析，会把源码片段发送给调用方配置的
模型服务，因此必须明确允许源码披露：

```bash
./qindun scan ./my-skill \
  --external-scanner aig \
  --allow-source-disclosure \
  --format json --output-dir ./reports
```

外部结果只形成候选证据：不能提高等级、不与秦盾或其他工具做分数平均，也不能
单独签发 D。高风险或严重风险候选可把 B 限制为 C 并要求人工复核；秦盾原生 D
不会被外部“安全”结论抬高。完整协议和 T01-T09 映射见
[references/external-scanners.md](references/external-scanners.md)。
明确请求的外部工具未安装、超时、格式错误或等待源码披露授权时，秦盾保留原生
等级并以退出码 11 提示“外部证据未全部完成”，不会静默当作全部扫描成功。

验证平台导出的签名报告，并同时比对原始作品包：

```bash
./qindun verify report.qindun.json \
  --trust-store qindun-trusted-keys.json \
  --expected-trust-digest sha256:<官方公布的64位摘要> \
  --target artifact-package.zip
```

验签的可信边界和企业固定可信目录的方法见
[references/report-verification.md](references/report-verification.md)。
平台公开接口保存的单文件只证明报告历史签名；其中未签名的“有效”或“已撤销”
状态不参与结论，验证当前状态应在线查询或使用含受校验状态链的企业离线包。
Skill 发布包本身的签名清单、固定发布公钥和安装前验证方法见
[references/release-verification.md](references/release-verification.md)。

对候选发现进行智能复核时，先保存确定性 JSON 报告，再生成受限上下文：

```bash
python3 scripts/qindun_certify.py ./my-skill \
  --format json --output ./report.json
python3 scripts/qindun_review.py ./my-skill ./report.json \
  --output ./semantic-input.json
```

查看版本：

```bash
./qindun scan --version
```

运行当前规则包的内置正反例语料：

```bash
./qindun benchmark corpus --output ./qindun-corpus-result.json
```

已经独立安装 ClawScan 后，可用同一个秦盾适配入口运行公开基准：

```bash
./qindun benchmark SkillTrustBench \
  --limit 10 --output ./skilltrustbench-result.json
./qindun benchmark clawhub-security-signals \
  --split eval_holdout --limit 10 --output ./clawhub-signals-result.json
```

公开基准样本由 ClawScan 下载和管理；秦盾不捆绑第三方数据集。基准结果用于固定
版本间比较，不等同于真实世界检出率或秦盾平台正式认证。

报告目录不能等于或位于任何被扫描目录内部，避免旧报告改变下一次扫描对象。
GitHub 匿名接口额度不足时，可在环境变量 `QINDUN_GITHUB_TOKEN` 中提供最小权限
的只读令牌；令牌只会发送给 `api.github.com` 的元数据和提交解析接口，不会发送
给归档下载地址，也不会写入报告。它不会把当前工具扩展为私有仓库下载器。
限流错误会提示稍后重试或配置只读令牌。

### 退出码

| 退出码 | 含义 |
| :---: | --- |
| `0` | 扫描完整，本地等级提示为 B |
| `2` | 命令参数不合法 |
| `3` | 目标不存在、ZIP 无效或读取失败 |
| `10` | 发现 C 或 D 级风险 |
| `11` | 原生扫描覆盖不完整，或明确请求的外部扫描没有全部完成 |

持续集成流水线应分别处理“发现风险”“扫描未完成”和“工具运行失败”，不能把
它们合并成同一种失败。

---

## 命令参数

```text
qindun [scan] <一个或多个本地目标或 GitHub 地址> [选项]
qindun verify <平台签名报告> \
  (--trust-store <可信公钥目录> --expected-trust-digest <目录摘要> | --allow-embedded-key)
```

| 参数 | 必填 | 说明 |
| --- | :---: | --- |
| `<目标>` | 是 | 本地目录、ZIP 或 GitHub HTTPS 仓库地址 |
| `--ref <名称>` | 否 | GitHub 分支、标签或提交，默认使用远程 HEAD |
| `--format markdown` | 否 | 输出适合人阅读的文本报告 |
| `--format json` | 否 | 输出适合程序读取的结构化报告 |
| `--format html` | 否 | 输出可直接打开和打印的网页报告 |
| `--format sarif` | 否 | 输出可供 GitHub 代码扫描等工具读取的 SARIF 2.1.0 |
| `--output-dir <目录>` | 批量时是 | 保存报告；同一个格式参数可以重复使用 |
| `--osv` | 否 | 向 OSV 发送依赖名称和精确版本并查询公开漏洞 |
| `--external-scanner <名称>` | 否 | 运行 AIG、Cisco 或 SkillSpector，可重复指定 |
| `--allow-source-disclosure` | AIG 是 | 允许外部工具把源码片段发送给其模型服务 |
| `--external-timeout <秒>` | 否 | 每个外部扫描器时限，默认 600，最大 3600 |
| `--version` | 否 | 显示扫描器版本 |

验签命令默认要求用 `--expected-trust-digest` 固定可信目录摘要，防止把攻击者
自建的公钥目录误认成秦盾官方目录。仅在已经通过其他方式信任该目录时，才可
明确使用 `--accept-unpinned-trust-store`；此时结果会标明目录摘要没有固定。

底层 `qindun_certify.py` 仍支持单个本地目标以及 `--output <路径>`，适合持续
集成直接消费一个确定性 JSON 报告。

当前版本没有可关闭安全维度的开关。基础检查项由版本化规则决定，调用方不能
为了获得更高结果而跳过必做检查。

---

## 报告内容

JSON 报告格式为 `qindun-local-report/v3`。主要内容包括：

- 扫描器版本、规则包版本和等级策略版本；
- 扫描对象名称和识别出的作品类型；
- ZIP 原文件摘要或目录内容清单摘要；
- 摘要类型、摘要完整性、文件数量和展开大小；
- 每项检查是完整还是部分完成；
- 未完整原因和扫描统计；
- 能力声明是否存在、格式是否有效；
- 观察到的网络域名、类别、风险特征、IP、端口和进程启动位置；
- 依赖文件、精确版本、软件物料清单和可选 OSV 查询结果；
- 规则编号、风险程度、候选或确认状态、文件位置和脱敏证据；
- SARIF 规则帮助入口和面向使用者的通用修复方向；
- 智能复核是否执行以及候选数量；
- 可选外部扫描器状态、原始报告摘要、规范化候选、冲突和人工复核要求；
- 本地等级提示和能力边界。

字段的完整说明见
[references/report-format.md](references/report-format.md)。
正式 JSON Schema（JSON 格式约束）位于
[`references/qindun-local-report-v3.schema.json`](references/qindun-local-report-v3.schema.json)。

### 精确摘要如何绑定对象

- 扫描 ZIP 时，`target.sha256` 是原始 ZIP 文件每一个字节的摘要；
- 扫描目录时，摘要根据排序后的文件路径、文件类型、权限和完整内容摘要生成；
- 超过文本检查上限的文件仍会完整参与目录摘要；
- 摘要没有完整生成时，`digest_complete` 会明确显示为假。

本地摘要用于比较本地扫描对象，不替代平台重新从对象存储计算的服务端摘要。

---

## 规则库

当前规则索引位于：

```text
rules/current.json
```

它指向当前启用的版本化规则包：

```text
rules/rules-2026.08.6.json
```

规则包同时包含：

- 规则编号和独立规则版本；
- 所属检测维度；
- 风险程度；
- 候选或已确认状态；
- 本地、平台使用范围；
- 确定性匹配表达式；
- 本地与平台共同使用的等级策略。

当前证据策略规定：正则文本命中只能产生 `candidate`（需要复核），
只有 Python AST（Python 语法树）或 Shell、PowerShell、JavaScript/TypeScript
的结构与数据流证据确认内容确实进入危险操作时，才会使用同一规则编号
生成 `confirmed`（已确认）。因此，安全文档中引用攻击示例不会仅因关键词就判 D。

规则更新要求：

1. 每条规则必须提供至少两个彼此不同的真实命中样例；
2. 每条规则必须提供至少两个彼此不同的防误报边界样例；
3. 本地和平台规则文件必须保持字节一致；
4. 人工智能可以提出候选规则，但不能直接启用；
5. 修改扫描行为时必须更新对应版本和回归测试。

上述要求不是文档约定：`rule-corpus-2026.09.2.json` 为每条启用规则保存至少
两个正例和两个反例，规则加载时会校验数量、内容去重、规则编号、实际命中结果
和摘要；规则包与语料还分别受 JSON Schema（JSON 格式约束）限制。任何一条
规则语料不足、重复、正例未命中或反例误命中，扫描器都会拒绝启动。

为控制恶意输入造成的资源消耗，单条规则和整份报告都有命中数量上限。达到
上限后，报告会标记覆盖不完整，而不是静默丢弃证据后继续给出 B。

## 持续集成

发布包根目录包含 `action.yml`，可在 GitHub Actions（GitHub 自动化流水线）
中运行秦盾预检，产生 JSON、Markdown 和 SARIF 报告。示例：

```yaml
- uses: actions/checkout@v4
- id: qindun
  uses: CysIsHappy/qindun-certify@v0.7.4
  with:
    target: ./skills/my-skill
    osv: "true"
    fail-on-grade: C
```

`fail-on-grade: C` 表示 C 或 D 使步骤失败；改为 D 时只放行 C，报告中的等级
不会被改写。扫描覆盖不完整和 D 始终失败。操作会输出报告目录、三种报告路径、
扫描状态、安全等级和扫描器原始退出码，供后续上传制品或安全平台使用。
默认报告目录位于 GitHub 运行器临时目录，不会进入扫描目标。显式设置
`output-dir` 时必须使用扫描目标之外的仓库内相对目录。扫描 GitHub 地址且匿名
额度不足时，可由调用方把最小权限只读令牌显式传给 `github-token`；复合操作不会
自动取得或扩大仓库令牌权限。

仓库自带流水线在 Python 3.10、3.11 和 3.12 上运行测试，并使用正式格式约束
校验本地报告、批量摘要、能力声明、语义复核、发布协议、规则包、规则语料、
CycloneDX 1.6 和 SARIF 2.1.0。外部 Schema（格式约束）还固定 SHA-256 摘要，
上游内容变更时会显式失败。不同 Python 运行器会比较同一源码生成的 ZIP 摘要。
当前流水线生成标准 SARIF 文件，
但不会自行申请仓库安全写入权限；如需显示在 GitHub Code Scanning
（GitHub 代码扫描）中，应由使用方在仓库流水线中显式上传该输出。

`integrations/clawscan.yml` 提供 ClawScan 自定义扫描器配置；其门禁只产生警告，
不会改变秦盾等级或把平台发布关系与扫描器退出码耦合。`qindun benchmark` 会生成
等价的临时配置并固定使用秦盾配置运行公开基准。

---

## 项目结构

```text
qindun-certify/
├── SKILL.md                         # 智能体加载的技能入口和安全边界
├── README.md                        # 本文档
├── SECURITY.md                      # 安全报告、支持范围和信任锚要求
├── CONTRIBUTING.md                  # 规则、协议和代码贡献要求
├── CHANGELOG.md                     # 已发布与待发布变化
├── VERSION                          # Skill 和扫描器版本
├── LICENSE                          # MIT 许可证
├── qindun                           # 可直接执行的终端命令入口
├── action.yml                       # GitHub Actions 复合操作入口
├── bootstrap/
│   └── qindun_release_verify.py     # 不随 ZIP 分发的独立启动验证器源码
├── agents/
│   └── openai.yaml                  # 名称、简介和调用策略
├── integrations/
│   └── clawscan.yml                 # ClawScan 自定义扫描器配置
├── references/
│   ├── report-format.md             # 报告字段和等级解释
│   ├── report-verification.md       # 平台签名报告验证说明
│   ├── release-verification.md      # Skill 发布包签名和安装前验证
│   ├── external-scanners.md         # 外部候选证据、冲突与分类映射
│   ├── qindun-external-evidence-v1.schema.json
│   ├── qindun-local-report-v3.schema.json
│   ├── qindun-signed-report-v1.schema.json
│   ├── qindun-signed-report-v2.schema.json
│   ├── qindun-trusted-key-directory-v2.schema.json
│   ├── qindun-capabilities-v1.schema.json
│   ├── qindun-batch-summary-v1.schema.json
│   ├── qindun-semantic-review-*.schema.json
│   ├── qindun-release-*.schema.json
│   └── semantic-review.md           # 智能候选复核协议
├── rules/
│   ├── current.json                 # 当前规则包索引
│   ├── rules-2026.08.5.json         # 上一版规则快照
│   ├── rules-2026.08.6.json         # 当前规则、证据与共同等级策略
│   ├── rule-corpus-2026.08.6.json   # 每条规则至少两组正反例语料
│   ├── external-taxonomy-map-v1.json # T01-T09 到秦盾维度的映射
│   └── qindun-rule-*.schema.json    # 规则包与语料格式约束
├── scripts/
│   ├── install.py                   # 安装和可恢复升级
│   ├── qindun.py                    # GitHub、批量扫描和报告统一入口
│   ├── qindun_benchmark.py          # 内置语料和 ClawScan 公开基准入口
│   ├── qindun_certify.py            # 确定性扫描、定级和报告渲染
│   ├── qindun_dependencies.py       # 依赖清单、软件物料清单和 OSV
│   ├── qindun_external.py           # 外部扫描器执行、规范化与冲突策略
│   ├── qindun_review.py             # 受限、脱敏的智能复核输入
│   ├── qindun_sarif.py              # SARIF 2.1.0 报告转换
│   ├── qindun_trust.py              # 可信公钥目录校验
│   ├── qindun_verify.py             # 秦盾平台报告验签
│   └── package_release.py           # 源码仓库中的可重复发布构建脚本
└── tests/
    ├── test_qindun_certify.py       # 扫描、定级和安全边界测试
    ├── test_qindun_v4.py            # 依赖、复核、批量、HTML 和安装测试
    ├── test_package_release.py      # 发布包完整性和自检测试
    ├── test_qindun_integrations.py  # Schema、SARIF 和签名验证测试
    └── test_qindun_external.py      # 外部证据、基准和 ClawScan 适配测试
```

运行版 ZIP 只包含用户执行扫描、验签和阅读安全说明所需的文件，不包含测试目录、
发布构建脚本或独立启动验证器。独立验证器必须通过 ZIP 之外的可信渠道取得。
这样可以避免工具把测试中的恶意样例错误识别为待认证作品的真实行为。

---

## 从源码构建发布包

只用于本地测试可重复构建时，必须明确生成未签名开发包：

```bash
python3 scripts/package_release.py \
  --output-dir ./dist \
  --unsigned-development-build
```

命令会生成：

- `qindun-certify-0.7.4.zip`；
- `qindun-certify-0.7.4.zip.sha256`；
- `qindun-certify-0.7.4.zip.manifest.json`（逐文件发布清单）。

正式发布不接受该未签名模式，必须提供经批准的 Ed25519（现代数字签名算法）
发布私钥、密钥编号和来源提交号，并生成发布清单签名。仓库不会内置或自动生成
官方私钥。完整命令见
[references/release-verification.md](references/release-verification.md)。

发布 ZIP 使用固定文件顺序、时间戳、权限和不压缩归档策略，避免压缩库版本改变
最终字节。持续集成还会在独立运行器和不同 Python 版本间比较 ZIP 摘要。

发布前运行：

```bash
python3 -m unittest discover -s tests -v
```

还应使用技能校验器检查 `SKILL.md` 元数据，并让生成的运行版 ZIP 扫描自身；
当前版本的预期自检结果为 B。

## 新扫描器发布后的平台重新认证

本节仅供秦市平台维护者使用，所述管理后端脚本不包含在本公开仓库中。

平台部署新版扫描器后，先在管理后端目录预览当前已认证作品包版本：

```bash
poetry run python scripts/enqueue_qindun_recertification.py --limit 100
```

确认预览 JSON 后，由有权限的管理员显式执行：

```bash
poetry run python scripts/enqueue_qindun_recertification.py \
  --execute --admin-id <管理员编号> --scan-type basic --limit 100
```

脚本默认只预览，`--execute` 必须与有效的 `--admin-id` 同时提供。每页输出
`next_start_after_id`，下一页通过 `--start-after-id` 继续；任务幂等键绑定扫描器
版本、作品包版本和扫描类型，重复执行不会重复创建同一活动任务。动态或高级动态
重扫必须显式选择 `dynamic` 或 `advanced_dynamic`，不能由基础重扫自动扩大范围。
返回 `failed` 非空时进程退出码为 1，应先处理失败项再继续下一页。

---

## 安全边界

秦盾本地预检遵守以下原则：

- 只读取用户明确指定的本地目录、ZIP 或 GitHub 仓库；
- 拒绝把顶层符号链接当作扫描目标；
- 不执行包内代码；
- 不安装包内依赖；
- 不连接包内网络地址；
- 只有明确增加 `--osv` 时才把依赖名称和精确版本发送给 OSV；
- 只有用户明确选择才启动外部扫描器，AIG 还必须单独允许源码披露；
- 外部扫描器只收到最小环境变量集合，不能因环境中存在密钥自动扩大联网能力；
- 不把完整密钥写入报告；
- 不在报告中暴露扫描对象的绝对本地路径；
- 不把扫描不完整解释成“没有风险”；
- 不把本地结果伪装成平台官方认证；
- 不允许调用方通过关闭必做检查提高等级。

安全扫描只能降低已知风险，不能证明软件绝对安全。安装或运行高权限作品前，
仍应结合来源、代码审查、最小权限和隔离环境综合判断。

---

## 本地预检与平台认证的区别

| 对比项 | 本地 Skill / 终端命令 | 秦盾平台认证 |
| --- | --- | --- |
| 扫描对象 | 用户明确提供的本地目录、ZIP 或 GitHub 仓库 | 平台冻结的精确作品包版本 |
| 身份绑定 | 不支持 | 绑定上传者、来源和作品对象 |
| 静态检查 | 支持基础确定性检查 | 支持并保存完整审计证据 |
| 依赖漏洞库 | 明确启用后查询 OSV，仍是本地证据 | 按适用检查执行并保存审计证据 |
| 人工智能语义分析 | 只复核候选，不改变等级 | 按等级执行并进入策略引擎 |
| 动态隔离运行 | 不支持 | S 级适用 |
| 高级动态检查 | 不支持 | S+ 级适用 |
| 人工复核 | 不支持 | S+ 必须由有权限的管理员确认 |
| 数字签名 | 不签发；可用公钥验证平台报告 | 对正式报告签名并提供可信目录 |
| 最高等级 | B | S+ |

两种入口使用相同的基础规则和等级语义，但证据完整度、身份可信度和签发权限
不同，因此本地结果不能直接上传后冒充平台认证。

---

## 参考与致谢

本文档的信息组织参考了开源项目
[CLS-Certify](https://github.com/catrefuse/cls-certify) 的 README：优先让用户
看懂检测范围、等级、安装、使用方式和项目结构。

秦盾没有照搬其总分定级、可任意关闭检测维度或由提示词推测扫描结论的做法。
秦盾坚持由确定性规则和实际完成的检查决定本地结果，并把平台正式签发与本地
自查严格分开。

---

## 许可证

[MIT License](LICENSE)
