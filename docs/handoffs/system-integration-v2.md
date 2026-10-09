# V2 最终整合与验收 — 2026-10-04

主聊天已整合三个 GPT-6.1 sol Ultra 用户模块对话：DeepSeek/Mock 问答、工作台 UI、来源覆盖/SBOM。API Key 留空，本轮全程未调用真实 DeepSeek 或读取实际凭据。无安装依赖、目标扫描、修复执行、POC 下载执行或论文 PDF 下载。

## 最终验证

- `python3 -m unittest discover -s tests -q`：**587 项通过**，3.443 秒，使用当前 Python 3.14.6 与既有 Node。测试运行器输出两条 SQLite ResourceWarning，未导致测试失败；该测试时长不是系统响应指标。
- 原比赛 PDF SHA256：`37f28bc38db91ec0407551b1254c8bc882432a8488ce896c681e1210814c6cf3`，与升级前一致。
- 临时真实库 CLI `--provider mock status` 正常返回 Mock 与七个已配置来源，不访问外网。
- 新增集成回归覆盖：三种精选资料权限/撤回竞态、模型降级保留具体原因与 Mock 标识、模型设置变更阻止旧回答、Key 不入库不回传、SBOM 被动导入、NVD 显式 POC 到事实的完整出处、官方目录到带修订引用问答、重复导入不制造版本。
- 新订阅实际传输验收由 Coverage 对话完成：NIST 草案 10 条、博客 40 条。解析仅保留元数据，未将本次核验写为生产实采或时效证明。

## 浏览器与本机真实 HTTP

在 http://127.0.0.1:8849/ 完成：

1. Mock 资产影响/修复问答，输出已核验事实及独立建议、未知条件；同会话追问解析到同一漏洞。
2. 引用弹窗显示来源、观察 ID、采集时间、修订与使用条件，能查看历史修订。
3. 清除模型恢复事实模式，保存 Mock 并主动测试离线流程成功；未启用真实云请求。
4. 知识目录五项，标准/政策/指南及精选方式、日期、使用条件正确区分。
5. CycloneDX 导入包含已知版本与缺失版本的两个组件；未知暴露/认证保留，自动重算影响；演示清单随后恢复。英文实现提示及未知条件代码已改为中文用户措辞映射，未识别消息保留原文。
6. 当前回答生成后演示来源撤回，旧回答立即显示“引用已撤回或修订 · 历史回答”，提供重新提问。随后演示重放追加有效修订，保留撤回和旧会话，恢复三条可用情报、两项演示资产。
7. 展开处理记录，能查看检索、规划、只读工具反馈和综合的业务阶段；不显示隐藏 reasoning_content。
8. 1440×1000 桌面及 430×920 窄屏验证；窄屏页面与内容宽度同为430，无页面横向溢出。临时 viewport 设置已重置。最终浏览器 error/warn 日志为空。

截图：`docs/screenshots/system-v2-desktop.jpg`、`docs/screenshots/system-v2-mobile.jpg`。演示服务保持运行，提供方为 Mock，浏览器页已保留；终端 Ctrl+C 关闭，重新执行 `python3 -m aicti_core --provider mock serve --demo` 开启。

## 整合修正

精选目录使用 Coverage 的 catalog_records 投影，保留来源日历日期而不捏造 UTC 版本时间。主机新增 source_metadata 事实，并更新派生方法版本 core-v2，已有实体须重新派生。精选种子写入使用同一 SQLite BEGIN IMMEDIATE 事务内的撤回/授权检查，不能恢复已限制的资料。

NIST 两订阅注册到共享配置；NVD 原始 references 在扁平化前抽取明确 POC 标签，Exploit-only 另存未验证线索，不混入 POC。富化事实保留 class/basis/upstream_tags/upstream_source。格式错误、限流等模型降级保留原原因、Mock 标记与有效事实卡。

## 实际未验收内容

真实 DeepSeek/Ollama 的中文理解、模型质量、端到端时延与费用；赛事对云端推理的许可；完整标准/政策修订覆盖、真实 POC 可用性、全库召回与准确率均未证明。JSON Schema、引用/数字校验和587项测试不能替代这些评测。云投影有界脱敏也不能保证识别未知秘密，勿在问句或清单中提供凭据。

当前为本机单用户原型，标准订阅是开放草案快照，政策仅原版精选元数据。V1 架构研究、历史复核及测试数量属于旧快照；运行说明以 `docs/system-implementation-v2.md` 为准，接口与归属以 `docs/implementation-v2-contract.md` 为准。
