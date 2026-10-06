# 本地预检报告格式

报告格式为 `qindun-local-report/v3`。它是一份非官方本地预检结果，不能替代
平台签名报告。

## 结论字段

- `official_certification=false`：不是秦盾平台认证；
- `scan_status`：`completed` 表示本地检查完整，`partial` 表示有内容未检查；
- `local_grade_preview`：本地等级提示，最高为 B；扫描未完整时为 `null`；
- 已确认的严重危险可以直接提示 D，即使其他内容因为安全限制没有继续展开。

本地和平台使用同一份版本化等级策略：中风险候选最多降到 B，高风险或严重
风险候选最多降到 C，只有确定性规则已经确认的严重危险才直接判为 D。

明确选择外部扫描器后，`external_scanners` 保存版本化候选证据协议、各工具状态、
原始报告摘要、规范化发现、冲突和等级上限。`manual_review_required` 表示原生与
外部结果或多个外部结果需要人工判断。外部高风险候选可把 B 限制为 C，但不能
单独签发 D；外部安全结论也不能提高秦盾原生等级。

## 扫描对象摘要

- ZIP 使用原始 ZIP 文件的 SHA-256，绑定文件的每一个字节；
- 目录使用按路径排序的内容清单摘要，每个普通文件都计算完整内容摘要，包含
  超过文本检查上限的文件；
- `sha256_kind` 说明摘要属于 ZIP 原文件还是目录内容清单；
- `digest_complete` 明确摘要是否完整；
- `content_manifest_sha256` 用于比较规范化后的包内文件内容。

## 覆盖范围

`coverage.controls` 分别记录 D2 包结构、D3 恶意静态行为、D4 依赖清单、D5
敏感信息、D6 网络目标和 D7 提示词静态规则的完成状态。明确启用 `--osv` 后，
还会记录 D4 公开漏洞库查询状态。加密条目、嵌套压缩包、无法分析的
二进制文件、超过文本检查上限的文件或命中记录被截断，都会产生明确的未完整
原因。

PNG 文件的 `tEXt`、`zTXt` 和 `iTXt` 文本元数据会进入规则扫描。
当作品包包含尚未解释的 PNG 视觉内容、PDF 或其他多模态内容时，
扫描覆盖会标记为未完成，不会因为只扫描了文本就给出 B。

GitHub 归档中的 `.gitmodules` 和 Git LFS 指针表示有内容没有随归档取得，
也会将 `D2.source_materialization`（源内容取得状态）标记为部分完成。

扫描器会识别 `SKILL.md`、`AGENTS.md`、`CLAUDE.md`、`chinmarket.yaml` 和
`langgraph.json`，检查基本信息、作品类型和入口文件。无法识别作品类型、空包、
类型冲突或入口无效会形成结构风险发现。

`capabilities.json` 是可选的本地能力声明。作品包提供该文件时，扫描器会检查
`qindun-capabilities/v1` 格式，并将声明的网络域名、文件读写、环境变量、敏感
环境变量、进程启动与命令、模型上下文协议工具和持久状态与静态观察对比；平台
评测使用冻结的能力清单，并在服务端记录 declaration_source（声明来源）：
author（作者声明）、inferred（平台推导）、unknown（来源未知）。仅作者声明
与实际行为的差异支持“未声明”结论，自动推导空值不作作者承诺。该来源字段
是平台内部标记，不是本地 capabilities.json 可自行设置的免检开关。字段类型、未知字段或
缺少必填字段都不会被宽松解释为有效声明。

<dynamic>（命令尚未解析）会保留在观察结果中，不当成实际命令与声明做差集；
这不表示命令安全或已授权。文档链接、代码块标题和自然语言审计清单也不应
冒充已经确认的远程执行行为。

## 风险发现

`findings` 包含规则编号、规则版本、风险程度、候选或已确认状态、文件位置、
行号以及证据摘要。D5 敏感信息证据不会保存原始密钥、密钥长度或原值摘要；
证据摘要只绑定规则、位置和脱敏后的公开证据。
单条规则和整份报告都有命中数量上限，达到上限后覆盖状态会变为部分完成。

Python 中能追踪到的凭据或令牌响应写入标准输出、标准错误或常见日志方法时，
会生成 `QINDUN.D5.CREDENTIAL_OUTPUT`（敏感凭据输出）高风险候选。
这与正常请求鉴权是两条独立检查，不会因为目标服务可信就忽略输出泄漏。
目前令牌续期语境识别覆盖明确的 Google HTTPS 令牌端点、POST 方法、标准字段
及对应环境变量来源；不代表所有 OAuth（授权协议）实现都能自动识别。
本地必填头部字段支持普通、引号及块文本字符串；复杂 YAML（头部配置格式）
语法未作完整解析，平台另有完整 YAML 语法校验，不能把本地通过等同于全格式验证。

## 依赖与网络分析

- `dependency_inventory` 逐项对应声明和锁文件，保存精确版本、解析错误、来源
  类型和 CycloneDX 1.6（软件物料清单标准）数据，也记录构建或安装入口；
- 只有项目实际声明依赖时才要求匹配锁文件；没有依赖声明的空项目不会仅因缺少
  锁文件而标记不完整；
- 软件物料清单根组件对 ZIP 绑定原始包哈希，对目录绑定完整内容清单哈希；两者
  不混用。直接依赖只来自真实声明，不把锁文件中的全部传递依赖伪装成直接依赖；
- 依赖来源分为 public（公开包）、private（私有包）、local（本地路径）、vcs
  （版本库）和 unknown（未知）；
- `osv_audit` 只有在调用方明确启用 `--osv` 时才访问 OSV 公开漏洞库；查询
  只发送锁文件已明确证明来自官方公开仓库的 public 精确版本；缺少来源、未知、
  私有、本地和版本库依赖都不会发送，并受 120 秒和 64 MiB 整次预算限制；跳过项、
  成功批次和失败原因都会保留，响应不完整不会伪装成完整；
- `network_analysis` 对已观察域名给出服务类别、风险提示和短链接、动态域名、
  纯 IP 等可解释特征，不主动连接这些网络目标；
- 软件物料清单和 OSV 结果不会把本地等级提高到 B 以上。

## 智能复核

`semantic_review.status=not_run` 表示确定性扫描器没有代替智能体猜测作品意图。
需要复核候选时，使用 `qindun_review.py` 生成
`qindun-semantic-review-input/v1`，再按 `semantic-review.md` 输出独立的
`qindun-semantic-review/v1`。复核结果不能改写 `local_grade_preview`。

## 机器可读约束

- `qindun-local-report-v3.schema.json` 是本地 JSON 报告的 JSON Schema
  （JSON 格式约束）；
- `qindun-external-evidence-v1.schema.json` 约束第三方扫描器的候选证据、执行状态
  和冲突定级信息；
- `qindun-signed-report-v1.schema.json` 是平台签名报告外层结构的约束；
- `qindun-signed-report-v2.schema.json` 是使用秦盾专用签名域的新报告约束；
- `qindun-trusted-key-directory-v2.schema.json` 是带目录序号、前版摘要和失效时间
  的可信公钥目录约束；
- `qindun-capabilities-v1.schema.json` 是作者能力声明约束；
- `qindun-batch-summary-v1.schema.json` 是统一入口批量摘要约束；
- `qindun-semantic-review-input-v1.schema.json` 和
  `qindun-semantic-review-v1.schema.json` 约束智能复核输入与独立结果；
- `qindun-release-manifest-v1.schema.json` 和
  `qindun-release-signature-v1.schema.json` 约束发布清单与清单签名；
- `--format sarif` 输出 SARIF 2.1.0（通用静态分析结果格式），
  使用相对路径和稳定证据指纹，不把本地绝对路径写入报告。

## 能力边界

本地预检不做平台身份绑定、真实隔离运行、高级动态扫描、人工复核和平台数字
签名；公开漏洞查询和智能复核也只属于本地补充证据。平台只有重新读取精确作品包
版本、冻结服务端摘要和对象身份，并完成对应检查后，才能签发官方等级。
