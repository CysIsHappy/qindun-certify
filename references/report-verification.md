# 秦盾签名报告验证

秦盾平台现有签名报告的格式为 `qindun-signed-report/v1`。验证工具同时支持
`qindun-signed-report/v2`：v2 在签名前增加秦盾专用域，并把格式、认证编号、
报告摘要、算法和签名密钥编号与报告正文一同保护。v1 为兼容现有平台继续验证，
结果中的 `signature_scope=legacy_report_only` 会明确说明其签名范围较窄。验证过程只使用
签发公钥，不需要也不得获取平台签名私钥。
工具既接受后台导出的 `.qindun.json`，也接受把秦盾公开认证接口响应
直接保存成的 JSON 文件。可信公钥目录可以是目录本身，也可以是公开接口的
`data`（数据）外层响应。公开接口的 `qindun-report-envelope/v2`（秦盾平台报告
封装第二版）只对报告正文签名；封装外层的状态、撤销时间和状态检查时间不在
签名范围内，因此单文件只能证明历史报告签名，不能证明认证当前有效或已撤销。

## 可信验证

使用从秦盾官方渠道取得的可信公钥目录，并通过独立可信渠道固定目录摘要：

```bash
python3 scripts/qindun.py verify report.qindun.json \
  --trust-store qindun-trusted-keys.json \
  --expected-trust-digest sha256:<官方公布的64位摘要>
```

同时确认本地作品包就是报告绑定的原始文件：

```bash
python3 scripts/qindun.py verify report.qindun.json \
  --trust-store qindun-trusted-keys.json \
  --expected-trust-digest sha256:<官方公布的64位摘要> \
  --target artifact-package.zip
```

企业环境还可以限制最低目录序号，拒绝回退到更老的目录：

```bash
python3 scripts/qindun.py verify report.qindun.json \
  --trust-store qindun-trusted-keys.json \
  --expected-trust-digest sha256:<64位摘要> \
  --minimum-trust-sequence 12 \
  --json
```

目录轮换时还可以要求新目录明确衔接上一版摘要，并限制目录的生成时效：

```bash
python3 scripts/qindun.py verify report.qindun.json \
  --trust-store qindun-trusted-keys.json \
  --expected-trust-digest sha256:<当前目录摘要> \
  --expected-previous-trust-digest sha256:<上一版目录摘要> \
  --minimum-trust-sequence 12 \
  --max-trust-age-days 30
```

`qindun-trusted-key-directory/v2` 目录必须带有 `expires_at`（失效时间），过期后
工具会拒绝验证。现有 v1 目录继续兼容；企业应使用 `--max-trust-age-days` 给 v1
目录增加本地时效约束，并保存已经接受的最高序号用于下次验证。

公钥状态必须与生命周期时间一致：`active`（有效）不能填写停用或撤销时间；
`retired`（停用）必须填写停用时间且不能填写撤销时间；`revoked`（撤销）必须
填写撤销时间。已经停用后又被撤销的公钥，可以同时保留早先的停用时间。

如果可信目录已经通过企业镜像、只读介质等其他方式固定，可以明确接受当前
文件而不再传摘要：

```bash
python3 scripts/qindun.py verify report.qindun.json \
  --trust-store qindun-trusted-keys.json \
  --accept-unpinned-trust-store
```

这种结果只表示公钥符合“用户明确接受的当前目录”，不能仅凭该文件证明目录
来自秦盾官方。结果会是 `overall_status=unpinned_trust_directory`、`valid=false`，
命令退出码为 1，不得作为可信认证通过条件。

## 完整性检查

没有可信公钥目录时，可以只检查报告是否被篡改：

```bash
python3 scripts/qindun.py verify report.qindun.json --allow-embedded-key
```

这种方式使用报告自带的公钥，只能证明“报告和签名相互匹配”，
不能证明该公钥属于秦盾，不能称为可信签发方验证。结果会是
`overall_status=integrity_only`、`integrity_valid=true`、`valid=false`，命令退出码为 1。

## 结构化结果如何判断

- `signature_valid`：签名字节与受保护内容匹配；
- `trust_directory_pinned`：可信目录摘要已由调用方固定；
- `issuer_trusted`：只有固定目录中的公钥通过生命周期检查时才为真；
- `revocation_status`：受验证材料能够证明的撤销状态；平台单文件封装固定为
  `unknown`（未知）；
- `source_verification_status`、`source_revoked_at`、`source_status_checked_at`：原样
  保留公开接口随报告提供的未可信状态字段，仅供展示，不参与平台单文件封装的
  验证结论；
- `current_status_confirmed`：本工具只读取离线文件，因此始终为假，不能把文件中的
  “有效”字样当成刚刚完成的在线状态查询；
- `target_matches`：提供原始作品包时，其摘要是否一致；
- `trusted_certification_valid`：支持可信离线状态语义的格式通过全部条件时才为真；
  平台单文件封装始终为假，不能用于自动化放行；
- `valid`：为兼容旧调用方保留，与 `trusted_certification_valid` 使用相同的安全语义。

平台公开接口响应中的 `revoked_at`、`verification_status` 和 `status_checked_at`
会以 `source_*` 字段原样保留，但这些外层字段没有签名，攻击者把它们改成“有效”、
“已撤销”或未来时间都不能改变验签结论。报告正文和签发方验证通过时，平台单文件
封装统一显示
`overall_status=historical_platform_signature_valid_unsigned_status`、
`trusted_certification_valid=false` 和 `revocation_status=unknown`。要验证导出时的
受保护状态链，应使用完整企业离线包；要判断“现在是否仍有效”，必须在线查询
秦盾当前状态。

## 验证内容

工具会依次检查：

1. 报告格式和 Ed25519（现代数字签名算法）签名；
2. 报告正文摘要和认证编号是否一致；
3. 可信目录自身摘要、最低序号、上一版摘要、生成时效和失效时间是否符合要求；
4. 签发公钥是否在可信目录中，以及它的生效、停用或撤销状态；
5. 报告签发时间、有效期和 S/S+ 所需扫描与人工复核字段是否自洽；
6. D 以外的安全等级是否具有完整检查覆盖；D 可以在其他检查未完整时签发，
   但公开报告必须至少包含一条“严重风险且已经确认”的发现；
7. 提供 `--target` 时，本地原始作品包的 SHA-256（文件摘要）
   是否与报告中的服务端摘要一致。

公开报告没有导出风险发现的确定性或人工确认来源，因此离线工具只能验证
`severity=critical`（严重风险）与 `disposition=confirmed`（已经确认）这层签名投影，
不能仅凭离线文件进一步区分它来自确定性规则还是人工确认。平台签发侧仍负责
依据权威扫描事实执行完整的 D 级判定。

验签功能需要 `cryptography`（Python 密码学库）：

```bash
python3 -m pip install cryptography
```

## 能力边界

- 可信公钥目录本身必须从可信渠道获取，并优先使用
  `--expected-trust-digest` 固定已审核的摘要；目录内列出某把公钥，不等于
  目录本身已经得到秦盾官方背书。
- 平台单文件封装可以检查历史报告签名和目录中的签发公钥，但外层状态字段未签名，
  不能据此确认有效或撤销；完整企业离线包依靠受校验状态链证明包内快照。要确认
  “当前仍然有效”，仍需要最新的平台查询结果。
- 验签只证明报告的完整性、签发方与绑定对象，不代表作品永远没有风险。
