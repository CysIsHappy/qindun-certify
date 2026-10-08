# 秦盾 Skill 发布包验证

正式发布由四个相互绑定的文件组成：原始 ZIP、逐文件发布清单、Ed25519
（现代数字签名算法）清单签名和固定发布公钥。SHA-256 校验和只能发现传输损坏，
不能单独证明发布者身份。

## 可信启动顺序

不要先解压 ZIP，再直接运行其中的 `install.py`。正确顺序如下：

1. 从发布页面取得 ZIP、清单和签名；
2. 从与 ZIP 不同的可信渠道取得发布公钥、独立启动验证器及验证器摘要；
3. 先核对独立验证器摘要；
4. 用独立验证器验证原始 ZIP，并由它安全解压；
5. 只有验证成功后，才执行已验证目录中的安装器。

独立验证器不导入 ZIP 中的任何代码。源码仓库中的位置为
`bootstrap/qindun_release_verify.py`，正式分发时必须把它和摘要放到独立可信
渠道，而不是只作为 ZIP 的同目录附件。

```bash
python3 /可信位置/qindun_release_verify.py \
  ./qindun-certify-0.7.7.zip \
  --manifest ./qindun-certify-0.7.7.zip.manifest.json \
  --signature ./qindun-certify-0.7.7.zip.manifest.sig.json \
  --public-key-file /只读可信位置/qindun-release-public-key \
  --extract-to ./qindun-verified
```

验证会检查固定公钥、清单签名、来源提交号、ZIP 名称、大小和摘要，以及 ZIP
中每个文件的路径、大小、摘要、权限和文件类型。解压目标必须尚不存在，验证器
不会覆盖已有目录。

验证成功后再安装；安装器会重新核对同一组发布材料：

```bash
python3 ./qindun-verified/qindun-certify/scripts/install.py \
  --platform codex \
  --release-manifest ./qindun-certify-0.7.7.zip.manifest.json \
  --release-signature ./qindun-certify-0.7.7.zip.manifest.sig.json \
  --release-public-key-file /只读可信位置/qindun-release-public-key \
  --release-archive ./qindun-certify-0.7.7.zip
```

正式安装缺少其中任一材料都会失败。只提供校验和、只提供清单、信任清单自带
公钥，或者从同一个未验证压缩包取得验证器和公钥，都不能证明这是秦盾正式发布。

## 从已审查源码开发安装

维护者从已经独立审查的源码目录安装时，可以明确跳过正式发布验签：

```bash
python3 scripts/install.py --platform codex --allow-unverified-source
```

该开关表示操作者自行承担源码来源验证责任，不得用于面向普通用户的正式发布
安装说明，也不能与发布验签参数同时使用。

## 构建发布包

签名发布必须写入 40 位来源提交号：

```bash
python3 scripts/package_release.py \
  --output-dir ./dist \
  --source-commit <40位小写Git提交号> \
  --signing-key-file /安全位置/release-private-key \
  --signing-key-id qindun-release-2026
```

仓库不内置、生成或假定官方私钥。正式发布系统应从受保护的密钥服务临时提供
私钥，并单独公布经过审核的发布公钥。只用于测试可重复构建的未签名包必须显式
增加 `--unsigned-development-build`，并且不能作为正式发布。

发布 ZIP 使用固定文件顺序、固定时间戳、固定权限和 `ZIP_STORED`（不压缩）
归档策略，避免不同 zlib（压缩库）版本产生不同字节。持续集成还会在独立运行器
和不同 Python 版本间比较最终 ZIP 摘要。

解压工具如果没有保留 Unix 文件权限，安装器会安全失败。正式流程应使用独立
验证器完成解压，不要为了通过验证而对整个目录批量增加执行权限。
