# Cloud / Mock QA V2 handoff — 2026-10-04

模块代码已落地；按最新用户指令本轮使用无凭据、无联网的 Mock，没有读取实际 API Key，没有真实或付费推理。原 PDF、数据库和其他归属模块均未修改。完整四页赛题、AGENTS.md、V2 契约和系统说明已读取。

主聊天反馈的 `CVE-2099-99001影响哪些资产，应该如何处置并说明依据？` 已复现并修复：NFKC 隐私净化的比较现在按归一化文本比较，正常中文标点不会误使分析消失；Mock 资产题优先保留资产评估和修复事实。新增同一 seed_demo 案例的归属测试，当前输出含两项资产评估、fix 卡和带精确证据并集的分析。没有删除或放松主聊天测试。

## 入口和流程

`aicti_core.qa.answer(question, snapshot, history=..., gateway=...)` 保留原接口。

```text
主机当前快照 / 许可 / 最新修订
  → 当前有界目录与请求内匿名别名
  → 规划与排序：严格 MODEL_PLAN_SCHEMA
  → 主机生成完整六字段事实卡
  → Harness 登记 read_facts / relations，只读工具反馈
  → 综合：严格 MODEL_SYNTHESIS_SCHEMA
  → 匿名引用还原为主机事实/证据 IDs
  → grounding 引用、数字、身份和明显越界断言检查
  → compose_answer 分别显示已核验事实 / 模型分析与建议
  → 主聊天独立重建事实卡、来源、权限、配置代次和提交事务重核
```

本轮不新增模型创建的事实字段。`claims` 仍精确为既有六字段 `id,text,evidence_ids,entity_id,predicate,value`。模型仅选择主机卡，`analysis_sections` 单独为精确四字段 `kind,text,claim_ids,evidence_ids`。每节须引用当前已选择的 claim，其 evidence IDs 必须等于这些 claim 的证据并集。

公开可复用常量位于 `qa.py`：`MODEL_PLAN_SCHEMA`（别名 `PLANNING_SCHEMA`）、`ANALYSIS_SECTION_SCHEMA`、`MODEL_SYNTHESIS_SCHEMA`（别名 `SYNTHESIS_SCHEMA`）、`READ_FACTS_ARGUMENT_SCHEMA`、`RELATIONS_ARGUMENT_SCHEMA`、`TOOL_ARGUMENT_SCHEMAS`。`validate_model_output(data, stage='plan'|'synthesis', allowed_ids=...)` 执行标准库有界严格检查并返回脱离输入的副本；不是通用 JSON Schema 引擎。`tool_argument_schemas(event_ids,max_depth=3)` 在脱离常量的副本上绑定本次主机允许的匿名实体 enum。Harness 再独立验证工具参数。

## Gateway 合同

`DeepSeekGateway(api_key=None, *, model='deepseek-v4-pro', timeout=20.0, reasoning_effort='none', transport=None)`：provider=`deepseek`；`configured/enabled/credential_configured` 均表示是否有内存凭据。`api_key=None` 只读专用 DEEPSEEK_API_KEY；显式 `api_key=''` 无条件禁用并避免环境读取。**按本轮最新指令，初始设置请使用显式空字符串。** repr、状态、异常、正文均不包含 Key。

`complete(messages, tools=None, max_tokens=800, response_format=None)` 归一化为 `{content,tool_calls:[{id,name,arguments:dict}],model,provider,reasoning_content?}`。`with_timeout(seconds)` 只收紧时限，保留内存设置，不联网。没有 embed 方法，`embedding_enabled=False`，没有伪造 DeepSeek embedding API。

固定 TLS host `api.deepseek.com`、443 端口与 `/chat/completions`；所有 DNS 地址必须为公网非保留/非组播地址，数值连接固定这些地址，TLS 仍校验官方 SNI/证书。不使用代理或重定向，不自动重试。请求最多 262144 bytes、响应 2097152 bytes、响应头 16384 bytes；单次 Gateway 超时最多30秒。阻塞 libc DNS 无法跨平台取消；超时后至多该次无凭据 daemon resolver 继续完成，调用方按期限返回。注入 transport 是主机离线测试 seam，不是用户可选端点。

默认显式 `thinking:{type:'disabled'}` 与 `reasoning_effort:'none'`；low/high/max 显式启用。Thinking 的 reasoning_content 最多16384 UTF-8 bytes，超限拒绝而不截断。Harness 在 transient assistant 工具轮完整保留 reasoning_content、原工具 call ID 和对应 tool_call_id；不会把隐藏思考放入 trace、结果、说明或持久化。截断、内容过滤、认证、余额、限流、超时和 malformed 输出均有净化的类型/代码。限流只保留0..60秒 Retry-After，不重试。

JSON Output 使用官方 `response_format:{type:'json_object'}`，提示显式说明 JSON 并附应用 Schema；服务器 JSON 模式不等于应用 Schema 合规，主机继续严格核验。[官方 JSON Output](https://api-docs.deepseek.com/guides/json_mode/)。官方 Beta strict Function Calling 要求 `/beta` 端点及所有工具 function.strict=true；冻结契约仅允许 `/chat/completions`，本版不擅自启用 Beta，也不发送该接口未规定的 json_schema response_format。[官方 Tool Calls](https://api-docs.deepseek.com/guides/tool_calls/)、[官方 Chat Completions](https://api-docs.deepseek.com/api/create-chat-completion/)。

`MockGateway(*, timeout=20.0, scenario='normal')`：provider=`mock`、model=`mock-deepseek-v4-pro`、enabled/configured=True、credential_configured=False、embedding_enabled=False；不访问环境变量、网络、数据库。相同 normalized complete / response_format / with_timeout 协议。正常路径实际消耗规划 → 模型提出只读工具 → 主机工具反馈 → 规范综合，通常3次模型、1次工具；关系/比较题可并行提议多项主机只读读取。Mock 的固定演示规则不代表真实语义理解。`/api/model/test` 的单调用 JSON `{ok:true}` 自检已支持。Mock fault scenarios：invalid_json/schema_violation/unsafe_tool/invalid_arguments/invented_analysis/no_progress/rate_limited/timeout。

## 返回字段与主聊天接入

- 真实成功：mode=`cloud_model`，retrieval=`llm_semantic`（仅真实规划成功后）。模拟成功：mode=`mock_model`，retrieval=`mock_plan`，明确附模拟范围警告。
- 增加 `analysis_sections`、`model_provider`、`model`、`generation_count`、`tool_call_count`。云端/模拟失败保留 mode=`degraded` 与原因；也通过 compose_answer 生成显示文本，使主机二次重建一致。
- 共享单个物理 RunBudget，规划也计费：最多4次模型、6次实际工具、10步骤、30秒；超时或超额停止后续工具。重复调用使用原缓存且仍精确关联当次 call ID。
- 本次目录最多32实体/24000 bytes/192证据依赖，合成最多8选中实体/64事实/48000 bytes投影目录，全结果最多32实体/256引用。整个已发送规划目录的实体代次与证据仍计入签名，即使最终没有选择它们。路径读取也有界并记录实际依赖。
- 继续从独立原始事实 answer 与 `host_card_catalog` 比较全部六字段；不要仅核对模型的 citation ID。允许 cloud_model/mock_model，并根据公开 provider 显示状态。
- 在 claim 独立批准后，调用 `validate_analysis_sections(detached(sections),detached(claims))`；再用 `compose_answer(detached(claims),sections,empty_answer=reference['answer'])` 确定性重建显示文本。原实体/修订/权限/资产快照与 store 提交门槛继续保留。配置代次变更也应拒绝旧结果。
- 全局资产数量只用主机原来的确定性问题范围和去重计算；plan.count_assets 是意图提示，不授权改变数量统计范围或捏造计数。超过32依赖实体的全局数量会明确要求缩小范围，避免发布部分总数。

主聊天新增 `source_metadata` 已获支持：`_LABELS/_INTENTS/_render_fact/host_card_catalog` 可处理 value=`{kind,title,summary,url,updated_at,monitoring}`。只引用当前许可主证据，准许摘要最多1000字符；curated 明确非实时，feed 明确已观测元数据；未核验全文，policy 不形成当前法律适用/合规结论。根 service 负责添加和许可这些事实，不在此模块写库。

## 外发范围与实际校验能力

不序列化 snapshot、raw inventory、asset.value 或原始 history answers。规划发送有界公共资料标题/公开别名/事实摘要；只有已相关的资产请求带少量匿名 assessment status/version_match。综合与工具反馈只含相关卡的匿名 id、predicate、最小文本、匿名证据 ID；必要安装版本/状态/缺失条件可保留，但原始资产名称/ID 被替换。问题与近期问题历史同步替换；历史只保留近期问题和有效实体锚点。未授权 inventory 名称也仅用作本机脱敏词，不外发。

请求内事件/事实/证据/资产使用 E/C/D/A 别名；来源链接、完整源历史、原始 ID 与凭据样式字符串不外发。净化包含 NFKC/控制字符、asset terms、常见凭据字段、链接/用户信息、邮箱、内部主机与私有 IPv4/IPv6。Gateway 另阻止当前真实 Key 出现在 body 或返回值中。通用凭据分类不可能覆盖任意未标记秘密；用户输入仍需主聊天现有敏感字段入口规则。模型 opaque 正文不会反向替换内部名称，也不能输出 A/C/D/E 别名；host verified facts 保留真实本机名称。

grounding 逐节拒绝缺引用、并集不一致、未知引用、未知可识别标识/ASCII产品名、可见事实之外的数值/版本、错误数值角色（如版本号充当分数）、模型 URL/HTML/明显注入、肯定的利用/攻击链，以及 source_metadata 的全文核验/合规过度断言。**这些是边界护栏，不能证明自然语言语义蕴含或防止所有中文误读。** 测试特意记录同词反向语义仍可能通过的限制，所有分析始终标注推断/建议，不被视为原始事实。

## 归属验证

截至此交接：198项归属离线测试全部通过（gateway24、Harness30、QA72、DeepSeek37、grounding23、Mock12）。运行：

```sh
python3 -m unittest tests.test_core_cloud_gateway tests.test_core_grounding tests.test_core_mock_gateway tests.test_core_qa tests.test_core_harness tests.test_core_gateway -q
```

覆盖真实线协议 request/response 解析假对象、公网 DNS/TLS pinning/证书失败/头与响应限制、认证/限流/余额/超时、秘密和错误上下文不泄漏、Thinking精确tool ID、JSON重复/类型混淆/额外字段/未知身份、中文语义规划 seam、多轮当前锚点、当前引用、撤回与权限、输入投影隐私、未知工具与参数完整批次拒绝、生成与工具共享预算、Mock正常和故障全流程，以及元数据摘要边界。没有执行跨模块整合测试；主聊天按归属负责 full suite 和浏览器验收。离线测试不能证明真实模型可用、真实语义质量、赛题准确率或<=5秒性能。
