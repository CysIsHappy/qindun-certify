# 外部扫描器候选证据协议

秦盾可以在原生静态预检之后，按用户明确选择调用 AIG、Cisco skill-scanner 或
SkillSpector。外部工具扩展证据来源，不替代秦盾原生规则、等级策略、平台动态扫描、
人工复核、报告签名或撤销状态。

## 调用边界

- 默认不调用任何外部扫描器，也不自动安装外部依赖。
- AIG 会把源码片段发送给配置的模型服务，必须明确增加
  `--allow-source-disclosure`（允许披露源码）才能运行。
- SkillSpector 固定使用 `--no-llm`（关闭模型分析），Cisco 固定使用本地默认分析器；
  秦盾不会根据当前环境变量自动打开它们的联网分析器。
- 子进程使用参数数组而不是 shell（命令解释器），在目标之外的临时目录运行，设有
  单工具时限和 16 MiB 报告上限；主报告只保存原始报告摘要和最多 200 条规范化发现。
- 外部命令缺失、超时、拒绝源码披露或报告格式无效时，外部证据状态为“部分完成”；
  秦盾原生覆盖率和原生等级仍单独有效，同时终端返回退出码 11，避免调用方把已明确
  请求但没有完成的外部检查误认为成功。

## 等级与冲突

外部发现一律是 `candidate`（需要复核）且 `deterministic=false`（不是确定性证据）。
外部安全结论不能提高等级，外部分数不会与秦盾分数相加或平均，外部结果也不能单独
签发 D。高风险或严重风险外部候选最多把本地 B 限制为 C，并要求人工复核。

当秦盾原生结果与外部结果相反，或多个外部工具一方提示风险、一方提示安全时，报告
明确记录冲突并要求复核。已经由秦盾确定性证据签发的 D 不会因外部“安全”结论回升。

## SkillTrustBench T01-T09 映射

| 外部分组 | 中文含义 | 秦盾主维度 | 相关维度 |
| --- | --- | --- | --- |
| T01 | 指令劫持 | D7 | D7 |
| T02 | 记忆污染 | D7 | D7 |
| T03 | 远程载荷下载与执行 | D3 | D3、D6 |
| T04 | 嵌入恶意代码 | D3 | D3 |
| T05 | 权限提升或越权访问 | D3 | D3、D8 |
| T06 | 持久驻留 | D3 | D3 |
| T07 | 工具劫持或冒充 | D7 | D3、D7 |
| T08 | 不安全依赖 | D4 | D4 |
| T09 | 不安全编码 | D3 | D2、D3、D5 |

机器可读映射位于 `rules/external-taxonomy-map-v1.json`。T09 覆盖面较宽，因此只把
D3 作为统一主维度，同时保留 D2、D3、D5 作为相关维度；人工复核时应根据具体证据
进一步归类。

## 外部工具来源与许可证

- [Tencent AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) /
  `aig-skill-scan`：Apache-2.0；
- [Cisco AI Defense skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)：
  以其仓库当前许可证为准；
- [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector)：以其仓库当前
  许可证为准；
- [OpenClaw ClawScan](https://github.com/openclaw/clawscan)：以其仓库当前许可证
  为准。

秦盾不复制或捆绑这些项目的源码、模型、规则和数据集，只按公开命令行接口互操作。
安装、升级、许可证核对和模型费用由调用方管理。

ClawScan 可以通过 `qindun clawscan-adapter <目标>` 取得单行 JSON 证据。运行版中的
`integrations/clawscan.yml` 是配置示例，要求 `qindun` 已放入系统命令搜索路径；
直接使用 `qindun benchmark` 时会生成包含当前秦盾绝对路径的临时配置，不受此限制。
