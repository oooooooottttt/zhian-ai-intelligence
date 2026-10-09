# NIST 离线测试样例来源

本目录的两份 XML 是 2026-10-04 从 NIST 官方公开 feed 采集后选取的条目，用于离线解析与安全边界测试。它们是选定条目的历史样例，不是完整 feed、NIST 全库或当前有效状态的证明。采集与验证记录见[Coverage V2 交接](../../../docs/handoffs/coverage-v2.md)。

| 文件 | 官方 feed | 选定条目 |
| --- | --- | --- |
| `drafts-2026-10-04.xml` | [NIST CSRC Draft Publications Atom](https://csrc.nist.gov/CSRC/media/feeds/pubs/drafts-open-for-comment.xml) | [SP 1353 初始公开草案](https://csrc.nist.gov/pubs/sp/1353/ipd) |
| `blog-2026-10-04.xml` | [NIST Cybersecurity Insights RSS](https://www.nist.gov/blogs/cybersecurity-insights/rss.xml) | [Back to the Future: Why Agentic AI Needs a Strong Identity Foundation](https://www.nist.gov/blogs/cybersecurity-insights/back-future-why-agentic-ai-needs-strong-identity-foundation) |

来源署名为 National Institute of Standards and Technology（NIST）。上游提供的作者字段原样保留：博客条目的 `dc:creator` 为 `Bill Fisher, Ryan Galluzzo`；所选草案条目没有作者字段，本项目未补写作者。修改说明：本项目于 2026-10-04 摘选条目并保留离线测试所需的 feed 结构，未收录其链接指向的 PDF 或其他正文文件。

这些来源材料适用[NIST 数据与技术出版物使用条件](https://www.nist.gov/open/license)及[NIST 网站版权与免责声明](https://www.nist.gov/copyrights-disclaimers)。保留来源、作者和使用条件；NIST 非 SRD 数据、SRD、第三方材料及标识等分别适用各自条件，项目代码的许可不替代来源材料的条件。进一步转载或修改时，应保留适用署名，并注明修改日期和内容。

This project uses selected NIST feed entries but is not endorsed or certified by NIST.

相邻 `feeds/` 和 `vulnerabilities/` 目录中的其余离线 fixtures 是本项目自行构造的合成输入；其中的漏洞编号、测试凭据、邮箱、私网地址和不安全 URL 用于测试解析及安全边界，不代表真实凭据或资产。
