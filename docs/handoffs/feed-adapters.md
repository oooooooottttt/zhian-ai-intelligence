# Feed adapters handoff

完成日期：2026-09-30。仅编辑指定文件；未修改模型、调度、存储、配置或其他模块，未触碰原始竞赛 PDF。

## 文件与接口

- `aicti_monitor/adapters/arxiv.py`：`fetch(source, cursor, http, now)`、纯解析器 `parse_atom`（别名 `parse_arxiv`）。官方 API 按 `lastUpdatedDate` 倒序扫描，冻结窗口并保留时间重叠；分页一条边界重读校验，结果总数/边界漂移才重启。arXiv ID 去版本作为稳定 ID，版本单独保存；CC0 标题/摘要/作者姓名/分类/时间/DOI 和来源条件保留，不请求 PDF/正文。comment 明确撤回时保留带证据标记的撤回记录。
- `aicti_monitor/adapters/rss.py`：同样的 `fetch`、纯解析器 `parse_feed`（别名 `parse_rss`）；RSS 2.0、RDF RSS 1.0、Atom、Atom tombstone、next 分页、ETag/Last-Modified、UTC 日期、ID/相对链接/XML base 规范化。Atom ID 保留区分身份的 fragment/query，导航 URL 去跟踪参数；不保留全文 content/encoded。授权摘录需显式 `params.excerpt_authorized=true` 且有效条款 URL，默认 metadata_only 摘要为空。
- `tests/test_feed_adapters.py` 和 `tests/fixtures/feeds/`：自行构造离线夹具，不含下载的论文/远端文章全文。
- `docs/SOURCE_POLICY.md`：官方许可/限速原始链接、实际订阅响应、NIST 精确配置建议、OWASP 可启用依据、模糊授权/失败核查的保守默认值。

公共模型无需变更。异常直接从 `models.py` 导入。`FetchBudgetExceeded` 返回部分记录与 `complete=false` 游标；网络/解析/429/403 错误抛出且不修改调用者游标。记录与游标事务提交/失败回滚由主聊天的存储层负责。

## 真实 arXiv 问题与修复验证

主聊天发现首次真实分页反复回到 offset=0。诊断证明相邻页 `feed.updated` 分别为 `2026-09-30T11:29:05Z` 和 `2026-09-30T11:29:08Z`，两页总数均为 1376，第一页末 ID 与下一页重读首 ID 均为 `2609.30325`。**feed 更新时间是查询页级别值，不能作为结果集稳定快照。**已删除它对恢复重启的影响。

待处理游标现使用 `total_results`；自动升级旧 `snapshot=[updated,total]` 或 `snapshot=null`，保留已有 offset/anchor、冻结窗口和历史 restarts。新增回归测试验证不同页 feed.updated 不会卡住。

以公共配置的 arXiv 检索（30 天窗口、page_size=50），通过公共 HttpClient 的 DNS/HTTPS/共享限速边界真实验证；**每周期预算仅 1 请求**：

| 周期 | 本次记录 | 累计去重 | 游标 offset | complete | 新发生重启 |
| --- | --- | --- | --- | --- | --- |
| 1 | 50 | 50 | 50 | false | 0 |
| 2 | 50 | 100 | 100 | false | 0 |
| 3 | 40 | 140 | 已完成/无 pending | true | 0 |

最终提交冻结 watermark `2026-09-30T11:37:12.945813Z`。验证仅在内存使用游标，不修改主聊天的 live-smoke 数据库。所有获取均为官方元数据，无 PDF/正文下载。

## 测试与安全边界

离线执行：`python3 -m unittest tests.test_feed_adapters -v`。共 **33 项**，覆盖跨周期分页/预算耗尽、边界漂移/总数变化、feed 时间不同、旧游标升级、空页/异常短页、旧论文修订/明确撤回、Atom tombstone、条件 304、失败不移动传入游标/不提交根验证器、同源去重/不同源碰撞、UTC/小数秒更新时间、授权摘录/署名、HTML 去除、DOCTYPE/ENTITY/UTF-16/损坏/超限 XML、私网/凭据/敏感 query/下一页主机/分页环、429/403/Retry-After/头部注入。

XML 有界且仅 UTF-8；URL 的语法/私网 literal/凭据检查在适配器完成，DNS 公网地址、HTTPS、重定向和真实节奏由公共 HTTP 层完成。页面仍须转义所有存储文本；导出仍须展示来源、许可与修改说明。

## 可启用来源与限制

- **OWASP GenAI**：官方博客明确 RSS 订阅并标注除例外外 CC BY-SA 4.0；实际 `/feed/` 返回 200、RSS、10 条。可启用 `security_community` / `metadata_only`；不要误称正式标准。摘要默认关闭；摘录分发另须满足署名/ShareAlike。主聊天已启用，本模块未改配置。
- **NIST Standards**：实际 `https://www.nist.gov/news-events/standards/rss.xml` 返回 200、有效 RSS、40 条。精确 allowlist `["www.nist.gov"]`、条款 `https://www.nist.gov/open/license`。可启用 `standard` 的标题/链接/日期公告监测，保留 NIST 非 SRD 许可条件及第三方权利；完整建议配置在 SOURCE_POLICY。
- NIST Cybersecurity feed 实际返回空 RSS；Schneier Atom 可达但再分发许可未核实，建议默认禁用 metadata_only；Google 候选 feed 跳转 HTTP FeedBurner 后超时，未建议启用/放宽白名单。
- NVD API 特定条款本次真实返回 403 Cloudflare，未绕过；NIST 通用许可已核查。SOURCE_POLICY 明确把 NVD 新条款/限速核查列为未完成，不把 secondary 搜索结果当成已核实官方原文。整合方如已有官方核验可补充文档。
- 搜索 API 没有原子快照；边界/总数检查针对可观察的漂移，不能保证捕捉任意延迟索引、超出重叠窗口的回填、检索匹配条件变化或历史删除。超过 30000 上限失败而不推进窗口，应缩小查询/另行实现 OAI-PMH。滚动 RSS 也不是历史档案，缺失条目不推断撤回。
- arXiv 配置 `initial_lookback_days`、`page_size`、`overlap_seconds` 与主聊天一致；默认 overlap=2 天，但主配置 1 小时是整合方选择，较短重叠更容易漏延迟索引。官方手册建议同查询缓存一天；未擅自改轮询配置。
