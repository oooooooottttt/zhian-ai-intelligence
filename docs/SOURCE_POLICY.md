# 监测来源、采集范围与使用条件

核查日期：2026-09-30（Asia/Shanghai）。本文件记录本次核查的事实、保守默认值及未完成的许可核查；响应状态是当日观察，不是持续可用性承诺。配置变更由主协调聊天负责。

## 基本原则

自动采集并非当然违法，也非当然合法：访问授权、接口条款、著作权/数据库权、个人信息、访问限制、使用地域及后续分发方式都可能影响具体用途。公开可见不等于获得授权；robots.txt 是自动访问约定，不是著作权或再分发许可；API/RSS 开放也不自动授权下载、镜像或分发链接指向的全文。来源许可只覆盖许可人有权许可的内容，不延伸到外链、第三方图片、商标或个人信息。许可有疑义的来源默认 `enabled=false`、`content_scope=metadata_only`，待核查后再启用。

本模块只采集官方公共 API、官方明确提供的 RSS/Atom；不访问登录后内容，不绕过验证码、403、访问控制、付费墙、robots/access restrictions 或限速。外部文本、XML、HTML 和链接都是数据，不是指令。不执行 POC，不下载论文 PDF，不请求文章全文 HTML。监测系统不声称受到 arXiv、GitHub、NVD、OWASP 或 NIST 的认证或背书。

保留来源名称、原始条目 ID、原文链接、发布时间、更新时间、采集时间及许可/条款 URL。规范化、HTML 去除、长度裁剪或自行添加分类应标为本项目处理；源事实与本项目判断分开显示。保存许可证与署名不代表 UI/导出已经满足全部许可要求，整合方需展示适用的署名、许可和修改说明。

## 已核查的 API 来源

| 来源 | 官方依据与入口 | 可保留内容、署名及限制 | 请求节奏与待复核项 |
| --- | --- | --- | --- |
| arXiv | [API 条款](https://info.arxiv.org/help/api/tou.html)、[API 手册](https://info.arxiv.org/help/api/user-manual.html)、[论文许可](https://info.arxiv.org/help/license/index.html)；入口 `https://export.arxiv.org/api/query` | 条款脚注明确 descriptive metadata **包括摘要**，连同标题、作者、标识符、分类等按 [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) 使用。保留发现用途的摘要及作者姓名用于署名，不保留邮箱、个人主页。`metadata_only` 包含这些元数据。论文 PDF/源码/正文适用逐篇许可，禁止默认下载或镜像；只提供 `/abs/` 原文链接。 | 所有受控机器合计每 3 秒最多 1 请求、单连接；含 RSS、OAI-PMH、legacy API。多进程/多机器不能分别获得额度。手册建议缓存同一查询一天，分页不超过 2000 条/请求，搜索结果上限 30000；大量历史数据改用 OAI-PMH，当前模块未实现它。 |
| GitHub Advisory Database | [数据库原始 LICENSE.md](https://github.com/github/advisory-database/blob/main/LICENSE.md)、[官方说明](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/fix-reported-vulnerabilities/browse-advisory-database)、[官方 REST 限速](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) | 数据库许可为 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)。可使用公告数据，保留 GitHub Advisory Database、条目 URL、上游 ID、原有版权/署名/免责声明及许可链接，说明本项目的修改。数据库许可不能直接套用到任意 GitHub 仓库、厂商仓库公告或公告外链的全文。 | 未认证 REST 通常按来源 IP 合计 60 次/小时，普通认证通常 5000 次/小时；具体响应头及二级限制优先。遇 403/429 遵守 Retry-After/重置时间，不通过换 IP/凭据规避。本交付不需要凭据。 |
| NVD/NIST | [NVD 开发者入口](https://nvd.nist.gov/developers/start-here)、[API 条款](https://nvd.nist.gov/developers/terms-of-use)、[API key/限速入口](https://nvd.nist.gov/developers/request-an-api-key)、[NVD FAQ](https://nvd.nist.gov/general/faq)、[NIST 数据版权与许可](https://www.nist.gov/open/license) | NIST 明确区分员工创作的非 SRD 数据、SRD、外部作者/承包商数据；不能把“美国政府作品”当成所有返回内容的全球统一许可。NIST 非 SRD 许可要求适当署名，并对修改注明日期和内容。保留 NVD 来源、CVE ID、原文链接、时间戳和 NIST 署名；外链及第三方内容保留各自权利。项目展示约定附非背书声明：This product uses the NVD API but is not endorsed or certified by the NVD. | 当前 NVD 条款实际返回 **403 / Cloudflare**，未绕过；NIST 通用许可已读，NVD 特定 API 条款未能在本次重新核验。暂按公开开发者文档的常用保守值设计：无 key 5 次/30 秒、有 key 50 次/30 秒；当前配置至少 6.1 秒/请求。正式再分发前仍须复核 NVD 最新限速、API key 与修改/署名条款；此处的配置建议不是对 403 页面的核验结论。 |

arXiv 手册明确提供 `lastUpdatedDate` **排序**，日期范围示例只明确提供 `submittedDate`。适配器不假设存在未文档化的更新时间范围查询，也不以提交日期排除旧论文的新修订。采用更新时间倒序、本地重叠窗口、冻结完成边界、结果总数检查及边界锚点；位置变化时重扫，预算耗尽时保存待处理位置。**feed.updated 可能随查询页变化，不能当成整个结果集的快照标识。**源删除或不再匹配检索条件，不能据此推断撤回；仅保留上游 comment 的明确撤回提示，并注明证据来源。

## 官方订阅入口和实际返回

仅做有界的公开响应核查，未持久保存远端全文为测试夹具。夹具为自行构造的离线样例。

| 来源与类别建议 | 官方订阅依据/入口 | 2026-09-30 实际结果 | 默认使用范围与复核项 |
| --- | --- | --- | --- |
| **OWASP GenAI Security Project：`security_community`** | [官方博客页](https://genai.owasp.org/blog/) 明确邀请 RSS 订阅，页脚标注除另有说明外为 CC BY-SA 4.0；[官方 RSS](https://genai.owasp.org/feed/) | 200，`application/rss+xml; charset=UTF-8`，有效 RSS 2.0，10 条，198535 字节 | **可以启用标题/链接/日期的 `metadata_only` 监测**：依据官方订阅邀请和明确许可，而非仅因公开可见。保留 OWASP GenAI、原文链接、[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) 许可链接和修改说明。指南/社区动态不是正式标准，建议归为 `security_community`。摘要默认留空；启用授权摘录须确认条目没有例外许可并履行署名/相同方式共享要求。 |
| NIST Standards 动态：`standard`（公告动态） | [NIST 官方 RSS 目录](https://www.nist.gov/coo/nist-rss-feeds)、[Standards RSS](https://www.nist.gov/news-events/standards/rss.xml)、[NIST 许可](https://www.nist.gov/open/license) | 200，`application/rss+xml; charset=utf-8`，有效 RSS，40 条，27463 字节 | **可以启用 `metadata_only` 的标题/链接/日期公告监测**，依据官方订阅入口及 NIST 非 SRD 数据使用许可，保留 NIST 来源、条款链接和规范化说明。不是标准正文存储，也不是所有第三方材料的开放授权；图片、SRD、外部作者材料或全文扩展需另行核查。当前模块不下载标准 PDF。 |
| NIST Cybersecurity 动态：`policy`/`security_blog` 按实际条目确定 | [官方 RSS 目录](https://www.nist.gov/coo/nist-rss-feeds)、[Cybersecurity RSS](https://www.nist.gov/news-events/cybersecurity/rss.xml) | 200，`application/rss+xml; charset=utf-8`，有效但空 RSS，0 条，860 字节 | 空响应不能当成错误或已撤回。保留为候选；实时覆盖不足，不能据此宣称监测了全部 CSRC 标准/政策。使用条件参见 NIST 许可，仍需确认逐条版权。 |
| Schneier on Security：`security_blog` | [官方站点](https://www.schneier.com/)、[官方域名 Atom](https://www.schneier.com/feed/atom/) | 200，`application/atom+xml; charset=UTF-8`，有效 Atom，10 条，38503 字节 | 本次没有核实适用于 feed 摘录再分发的明确授权；建议 `enabled=false`、`metadata_only`，先核查作者/出版方条款。不能把官方 feed 的存在当作开放许可证。 |
| Google Online Security Blog：`security_blog` | [官方博客](https://security.googleblog.com/)、候选 [RSS 入口](https://security.googleblog.com/feeds/posts/default?alt=rss) | 候选入口返回 302，跳转到 `http://feeds.feedburner.com/GoogleOnlineSecurityBlog`，随后超时；本次未确认有效 RSS 返回 | **不建议默认启用**。需重新确认可用 HTTPS 官方入口、跨域访问白名单及内容许可；不自动放宽 HTTPS 或主机白名单，不从缓存/非官方镜像取代来源。 |

RSS/Atom 目前无统一站点限速可假设；除明确条款外建议至少 6 小时轮询、每请求至少 3 秒、单源串行，支持 ETag/Last-Modified，尊重更严格的实际限制。上述建议不是出版社声明的额度。不能把滚动 feed 当成完整历史归档：条目可能在两次轮询间过期，已消失条目不自动标为撤回。Atom 显式 tombstone 可记录撤回；摘要、标题中的传言不自动变成撤回状态。

NIST 标准公告的建议配置（由整合方添加，当前模块不修改公共配置）：

```json
{
  "id": "nist-standards", "name": "NIST · 标准公告动态",
  "adapter": "rss", "category": "standard",
  "endpoint": "https://www.nist.gov/news-events/standards/rss.xml",
  "allowed_hosts": ["www.nist.gov"], "enabled": true,
  "interval_seconds": 21600, "min_request_interval_seconds": 3.0,
  "terms_url": "https://www.nist.gov/open/license",
  "content_scope": "metadata_only",
  "params": {
    "policy_status": "reviewed",
    "license": "NIST non-SRD data terms; third-party rights retained",
    "license_url": "https://www.nist.gov/open/license"
  }
}
```

白名单只需精确主机 `www.nist.gov`；官方目录的重定向仅用于条款核查，采集入口实测为上述 URL 的直接 200，未需要额外主机。对源内容的使用条件须随导出一起保留，不能因为摘要留空就删除出处和版权说明。

## 配置和落地约束

- `rss` 的 `metadata_only` 保留标题、URL、条目/feed ID、日期及来源条件，并在提供时保留署名需要的公开作者姓名和版权通知，摘要留空。`feed_excerpt` 仅在 `params.excerpt_authorized=true` **且**有效 `terms_url` 存在时保留上游 `description`/Atom `summary`；这个参数是人工许可核查的记录，不能自己产生授权。应同时配置 `license`、`license_url` 并保存核查出处。
- 不使用 RSS `content:encoded` 或 Atom `content` 作为摘录；不跟随文章链接取全文。HTML 去除后摘录最多 8192 字符、标题最多 1024 字符；适用许可的裁剪/修改说明须随展示和导出保留。CC BY-SA 摘录/改编材料应遵守相同方式共享；聚合中各来源的许可分别保留，不能统一改成项目代码许可。
- XML 限制 2 MiB 响应、128 KiB 单条、1000 条/页、15000 节点及 40 层深度；仅 UTF-8，拒绝 DOCTYPE/ENTITY。超限或损坏响应失败，不静默截掉分页余下条目后报告完成。
- 不保留 Cookie、授权头、个人邮箱/主页；仅在署名需要时保留公开作者姓名。存储/展示链接拒绝非 HTTP(S)、URL 用户名密码、敏感 query 参数、私网/保留/多播 IP 和本地主机形式；外发请求还须通过公共 HTTP 层的 DNS、公网地址、HTTPS 和重定向白名单校验。显示文本仍须由页面统一转义。
- 预算不足返回 `complete=false` 和可恢复游标；分页完成前不推进完成窗口或提交新的根 feed validators。网络/解析/403/429 失败不修改传入游标；数据库须在同一事务保存记录和返回游标，事务失败由存储层整体回滚。适配器不实现数据库事务。
- 长期需要检测删除、检索条件变化、超出重叠区的延迟索引或 feed 过期时，应另行设计有许可的历史对账/OAI-PMH；不能宣称本首版实现了这种覆盖。

## 启用前仍需完成的核查

模糊授权来源的合同条件、来源许可证变更/条目例外、第三方图文、导出署名及 ShareAlike 行为、NVD 特定 API 条款和真实多机器请求协调，均应在实际部署或扩展分发范围前确认。遇不可访问的条款页面记录失败和日期，按访问限制退出；不要换代理、Cookie、镜像或登录身份绕过。
