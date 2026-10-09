# 最终集成层独立审查（2026-10-03）

结论：**本文记录的代码快照通过所列离线安全与一致性检查，没有遗留的已复现阻断项。** 本轮发现的两个 P2 问题及一个同类深层异常均已由主聊天修正，复核通过。结论限于下述范围和快照，后续 semantic recall / host card catalog 集成及浏览器验收不包含在本次结论内。

审查读取了 `AGENTS.md`、`docs/implementation-contract.md`、`docs/handoffs/integration-security-review.md`，重点核对 `aicti_core/store.py`、`service.py`、`web.py`、`cli.py`、`demo.py`；只为解释集成行为读取 QA / enrichment / UI 代码，没有修改这些实现文件。测试均使用临时 SQLite 数据库或替换服务器构造函数的内存 HTTP handler；没有启动或操作 8849 服务、联网采集、安装依赖、读取凭据、下载或执行 POC/PDF。

## 验证结果

- 最终运行 `python3 -m unittest tests.test_core_store tests.test_core_service tests.test_core_web`：**48 tests，OK**。包括事务回滚、修订/撤回、租约过期和重新领取、取消、资产/政策变更、引用重建、映射隔离与重复确认、模型异常回退、Host/Origin/token/CSP/JSON 边界。
- 另做 9 项离线断言：跨实体 impact、未被 evidence_ids 覆盖的指针、未选中 material target、POC verified 升级均拒绝；合法 related_material 接受；最新 permission deny 隐藏历史与当前证据；取消任务和重启前旧 owner 不能提交；过期 crash 租约由重开 store 的 worker 以新 attempt 领取。
- 重新打开数据库后，会话列表、续问上下文及 session_detail 的完整 assistant payload / citations 保留。撤回后旧回答标记 stale，当前来源权限收紧后旧回答内容与引用隐藏。内存 handler 验证 `GET /api/sessions/<id>`：合法会话 200，非法 ID 400，不存在会话 404。
- 演示公告撤回后重新打开数据库并调用 seed_demo，不会重新播种或复活公告。CLI 的演示分支使用独立固定库，不启动采集；非演示分支拒绝 demo 文件名和已有 demo-* 观察数据。
- 模型对收到的副本进行修改，不能改变宿主 baseline；当前 claims 必须匹配宿主事实卡，正文必须与获准卡一致；引用最终由数据库重建。来源、库存、映射、政策变化导致旧答案被拒绝，不能通过降级分支绕过最终事务校验。

## 本轮发现并修复的问题

### P2：合法事实卡缺少引用或实体依赖时未正确降级 — resolved

原复现：临时演示库完成富化，启用注入假 gateway；替换 `aicti_core.qa.answer`，只有 gateway 路径保持合法 claims / answer 但令 citations=[]。`Application.ask` 抛出 `ValueError("Missing claim citation")`；HTTP 层会返回 400。citations=[{}] 或 entities=[] 则返回 pending 并声称资料发生变化，尽管 knowledge_epoch 没有变化。

修正后，服务先校验引用与实体依赖；输出声明失败回退到已生成的 reference，最终提交仍使用相同 baseline 门槛。三种原输入均得到 **mode=degraded 和两条有效事实卡**，没有误报资料变化。提交处 ValueError / TypeError 的回退仍重新执行 save_answer，不绕过当前知识检查。

### P2：深层异常编号在受保护校验之外触发 TypeError — resolved

补充复现：同一假模型路径令 claims[0].id=[] 或 citations[0].evidence_id=[]，分别在字典 membership 与集合构造处触发 unhashable TypeError，无法降级。

修正后，在受保护的输出结构校验内要求 claim id、citation evidence_id、evidence_ids 元素为字符串，claim text 为字符串、entity_id 为整数。新增 `test_unhashable_model_identifiers_degrade` 回归通过，两种输入均降级到宿主 reference。

### P2：库存有效期在 sync 后等待写锁期间届满，旧判断仍被保存 — resolved

原复现使用真实时间与真实 SQLite 写锁：将演示库存 observed_at 设为 24 小时阈值前 1 秒，正常处理得到 demo-patched 的 not_affected_with_reason；在 save_answer 的 sync 完成后，另一个 writer 持写锁 1.2 秒。原代码取得锁时库存年龄约 86400.32 秒，却仍保存并返回 mode=facts 及 not_affected_with_reason；下一次 snapshot 才提高 epoch 并置 dirty。

修正后，claim / publish / save_answer 在取得最终写锁后再次执行库存时效检查。publish / save_answer 先提交失效写入再抛 StaleResult，失效不会随拒绝回滚；claim 正常退出提交失效，下一轮重新排任务。

用相同真实 1.2 秒持锁用例复核：**返回 pending、claims=[]，没有保存旧回答；过期集合已持久化，实体为 dirty**。新增两项 sync 后时间流逝回归也通过。原先锁后租约采样回归继续通过。

## 前次报告风险的当前状态

1. 原始历史 alias 不作为当前身份真相；当前关系分离产生 quarantined，重复完整分区确认不会把可见实体永久退休。
2. revision 与 observation event_id 变化触发失效；触发器写入与原始监测事务一起回滚。
3. worker 发布在写事务取得后检查当前 owner / attempt / lease / generation / signature；完成写入与结果发布原子提交。
4. 分区确认校验当前 generation、完整覆盖、非空和互斥；最新修订后的再隔离不能因旧确认自动恢复 ready。
5. 每条回答支持需在 requested 的当前 ready 实体范围内；伪造引用字段会被数据库重建，最新权限否定同时阻断历史证据读取。
6. 模型和纯模块接收分离值；宿主 baseline 独立保留。模型不能用自由正文或变更卡片内容替代当前事实。
7. 新 web 层限制 loopback Host、同源 Origin、随机 token、JSON schema / body size，提供 nonce CSP；离线 handler 检查通过。

## 未验证边界

- 不涵盖正在进行的 QA / UI 可读性更改、随后引入的 host_card_catalog / semantic recall 集成，或其后发生的代码修改。主聊天需对最终集成再运行相关测试。
- 没有连接真实模型、embedding 服务、远程模型或官方采集接口。不能据此声称真实语义检索质量、模型准确率、生产网络行为或外部来源覆盖率达标。
- 没有操作运行中的浏览器或服务器；浏览器布局、点击链路和最终会话恢复显示由主聊天验收。HTTP 检查通过的是内存 handler，不是部署或公网安全认证。
- 没有作容量、吞吐、端到端时延或大规模历史回填测量。当前全局保守失效及显式观察/候选上限仍是原型约束。

## 审查快照

快照时间：2026-10-03T15:01:24Z。下列 SHA-256 用于区别后续集成修改：

| 文件 | SHA-256 |
|---|---|
| aicti_core/store.py | 2351a0d599577644a6e7f19f8c6dcad288a56f3ae475b37e938fcbdf5ec57ee9 |
| aicti_core/service.py | 220dd6693e6a159ca12db5d3ee9d9aa0affc33f77ed7c671548c9da0c178479f |
| aicti_core/web.py | ef2a7e4ef65ed50210248bed3859de3d543a104981f61ec67497bc5a1b34464d |
| aicti_core/cli.py | d01846eb30550d4bdaf3ad3088af99e24ec65d4bbde5b4deb339dee30a8b592e |
| aicti_core/demo.py | 90c1242965db50feff935d75b92864cc30a59b38d55f5de4972f9be011448a78 |
