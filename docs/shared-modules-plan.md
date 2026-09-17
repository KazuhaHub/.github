# KazuhaHub 共享安全模块（authcore）执行计划

> **修订说明（v2）**：本版相对上一版做了以下改动，原因见第 2 节。(1) **砍掉 `identity`（账号模型统一层）和 `authflow`（登录编排）两个包**——判断标准是"共享机制，不共享策略"，三个项目的账号模型（Group / Org / 账号链接）和会话下发方式（Bearer+localStorage vs HttpOnly Cookie）互不兼容，强行统一是错误抽象。(2) 基于一轮 build-vs-buy 调研（19 个库级 + 11 个服务级候选，含 3 条源码级核实）重新核实了 `ratelimit` 和 `oidc`，两者改成基于现成库（`go-chi/httprate` + `middleware.ClientIPFromXFFTrustedProxies`、`zitadel/oidc` 的 `rp` 包）做薄封装，不再从零写。(3) 在动手抽取任何身份相关包之前，新增一个零耦合的前置阶段——共享安全测试套件（见新文档 `docs/security-test-suite.md`），先跑出真实复用率数据，再决定 P1 的 `saml`/`passkey`/`audit` 三个包做不做。(4) 交付方式从"连续冻结 7~8 周、一次性迁移"改成"按包增量、3~4 个独立批次，不强求三项目同步切换"。(5) 因为不再统一账号模型，三个项目的适配工作量相应下调，Report-Portal 的前置解耦范围也缩小。**范围从 10 个包砍到 8 个，authcore 自身的搬迁工作量从约 20.75~24.75 人日下调到约 11.5~14.5 人日**（见第 10 节，三个项目各自的接入成本单独列在第 6 节，同样下调）。第 1/3/7/8 节（现状实测数据、许可证分析、git 搬迁命令、版权复核）基本未受影响，原样保留，仅第 8.3 节依赖清单因 oidc/ratelimit 改用新库而更新。

- 文档状态：待 kazuha 确认后执行
- 面向读者：**没有读过前期调研、没参与过讨论的工程师**——本文自包含，照做即可
- 涉及仓库：`Passwall-Sub-Panel`、`Passwall-Node`、`AlertHub`、`StockAnalysisPrediction-Report-Portal`（以下简称 PSP / Node / AlertHub / Report-Portal），组织均为 `KazuhaHub`
- 新建仓库：`github.com/KazuhaHub/authcore`（Apache-2.0）
- 配套文档：`docs/security-test-suite.md`（阶段 -1 的共享安全测试套件设计，P1 的前置门槛，与本文档同目录）

---

## 1. 为什么做

KazuhaHub 组织下 4 个 Go 项目里，有 **3 个（PSP、AlertHub、Report-Portal）各自独立实现了同一套身份认证与审计代码**。以下数字全部为实测（`wc -l` 逐文件核对），非估算：

| 模块 | PSP | AlertHub | Report-Portal |
|---|---:|---:|---:|
| OIDC | 979 行 | 276 行 | 449 行 |
| SAML | 1,530 行（`saml.go` 逐函数核对为 636 行，表中含配套文件） | 239 行（`saml.go` 170 行） | 596 行 |
| SSO 总装 | 458 行 | — | 1,383 行 |
| auth | 2,489 行 | 365 行 | 157 行 |
| passkey / WebAuthn | 933 行（`passkey.go` 461 行） | 393 行（`passkey.go` 198 行） | 373 行（`passkey.go` 373 行） |
| audit | 791 行 | 468 行 | 545 行 |
| captcha | 246 行 | — | 557 行 |
| mail | 2,490 行 | — | 309 行 |
| geoip | 205 行 | — | 171 行 |
| ratelimit | 96 行 | 77 行 | 221 行（`throttle.go`，原表遗漏，本轮复核发现） |
| metrics | 282 行（重新实测为 888 行，见第 9 节说明） | 55 行 | — |

**身份认证相关（OIDC+SAML+SSO 总装+auth+passkey）合计约 10,695 行写了三遍；连同 audit 与辅助模块，重复面约 17,000 行。**

比行数更重要的三条实测结论：

1. **三个项目都独立实现了 passkey/WebAuthn**（PSP 461 行 / AlertHub 198 行 / Report-Portal 373 行），用的是同一个库（`go-webauthn/webauthn v0.17.4`）、同一套 ceremony 结构（AlertHub 代码注释明写"modeled on the Passwall panel"）。这是**安全敏感代码被写了三遍**，不是业务逻辑重复。
2. **SAML 断言重放（replay）防护**：`crewjam/saml` 库本身不做这个检查。PSP 和 Report-Portal 各自独立发现并写了一套几乎等价的 replay cache（PSP 有专门的 ADR 文档 `docs/adr/0023-saml-assertion-replay-protection.md`），**AlertHub 至今没有这个防护，是一个真实的安全缺口**。
3. **审计防篡改**：只有 AlertHub 做了哈希链设计（`prev_hash`/`hash`/`VerifyAuditChain`），PSP 和 Report-Portal 的审计表都是普通行，**任何有数据库写权限的人都能悄悄改一行审计记录而不留痕迹**。

结论：这不是"三份长得像的代码"，而是**同一批安全关键逻辑被三个团队独立实现、质量互不相同**——有的项目做对了别人没做的事（Report-Portal 的 discovery 缓存校验、AlertHub 的哈希链、Report-Portal 的 trusted-proxy 解析），但没有一个项目三件事都做对。抽取共享库的首要价值是**把已验证正确的安全设计发给所有消费方**，省代码量是次要收益。

（提示：上面这批重复代码里，"auth"这一行和 SSO 总装里混杂着协议握手逻辑和账号模型/会话编排逻辑两种东西。第 2 节会说明，本轮调研后只有前者——协议握手 + 安全机制——值得抽取共享；后者是账号模型/登录编排，三个项目本来就不同，上一版计划里试图统一它们的 `identity`/`authflow` 两个包已被砍掉，理由和判断标准见下节。）

---

## 2. 缩小范围建

**判断标准（大厂通行做法）：共享"机制"，不共享"策略"。**

- **机制**（怎么做）：SAML 断言怎么防重放、WebAuthn challenge 怎么存取、XFF 怎么解析可信代理边界、验证码怎么出题——这类逻辑在任何项目里的正确做法应该相同，做错的后果是安全漏洞，该共享。
- **策略**（做什么）：用户属于哪个组织、登录后给什么权限、租户怎么隔离、会话怎么下发——这类逻辑天然因为业务不同而不同，强行统一等于把业务决策焊进一个不属于它的共享库里。

**做什么：**

- 新建一个 Apache-2.0 的 Go module `github.com/KazuhaHub/authcore`，只抽取**机制层**，共 8 个包：OIDC 协议握手（薄封装 `zitadel/oidc` 的 `rp` 包）、SAML SP（含 replay 防护，市面无现成方案，自研）、WebAuthn/passkey ceremony 会话（市面无现成方案，自研）、审计事件模型 + 可选哈希链、captcha（薄封装 `mojocn/base64Captcha`）、geoip（薄封装 `oschwald/maxminddb-golang`）、ratelimit 计数器 + XFF 解析（薄封装 `go-chi/httprate` + `middleware.ClientIPFromXFFTrustedProxies`）、SMTP 传输原语。
- 三个项目（PSP、AlertHub、Report-Portal）**按包增量**切换，不要求同步、不要求连续冻结。Passwall-Node 只是 SSO 客户端消费方，改动量很小，一并处理。

**不做什么，以及为什么（这是本轮修订的核心变化）：**

- **砍掉 `identity`（账号模型统一层）和 `authflow`（登录编排）。** 这两者属于"策略"：PSP 单租户 + 资源 Group、AlertHub 真多租户 Org/Membership、Report-Portal 单租户 + 账号链接，三者的账号模型本来就互不兼容，实测证实强行合并等于业务迁移而非抽库；会话下发上 AlertHub 是 Bearer token + localStorage（SPA 架构），PSP/Report-Portal 是 HttpOnly Cookie（服务端会话架构），两者威胁模型正交（XSS vs CSRF）。上一版计划里 `identity.Resolver` 被设计成"全模块的根"，这个设计本身就是把三种互不相同的策略往一个接口里塞——这正是 Sandi Metz 所说的 "the wrong abstraction"：一个勉强兼容三方的抽象，比三份各自清楚的实现更难改、更难懂。**这两个包从计划中完全移除，不再是 authcore 的一部分。**
- 保留的 8 个包**必须账号模型无关**：只接受一个**不透明的 account/actor 引用**（泛型 ID 或窄接口），不得理解 Group / Org / 账号链接的语义。具体地：`audit.Entry.Actor` 是一个不透明字符串，`audit` 包从不解析它；`oidc`/`saml`/`passkey` 三个协议包各自返回自己的协议原生结果（`oidc.Claims`、`saml.Assertion`、`passkey.Credential`），**不再提供一个跨协议共享的 `Claims`/`Principal`/`Resolver` 类型**——账号映射完全留给各项目自己写，不进 authcore。
- 其余"不做什么"维持上一版结论不变：不统一会话下发方式、不统一 metrics（PSP 刻意无第三方依赖、AlertHub 标准 Prometheus，两个正交答案）、不动 mail 的业务通知引擎（只抽最底层 SMTP 传输原语）、不碰 version / health / migration / config 加载 / 日志封装 / 分页（同名不同质的假阳性或规模太小不值得抽取，详见第 3 节现状分析）。

**build-vs-buy 调研结论（本轮新增，已核实）：**

扫了 **19 个库级候选 + 11 个服务级候选**，结论是"胶水与流程编排层"确实大部分没有现成货，但具体到每个包结论并不一致——这也是本轮把 `ratelimit`/`oidc` 从"自研"改成"薄封装"的直接依据：

| 包 | 市面结论 | 依据 |
|---|---|---|
| `captcha` | 有现成库，纯包装即可 | `mojocn/base64Captcha` 已在用，无需自研 |
| `geoip` | 有现成库，纯包装即可 | `oschwald/maxminddb-golang` 已在用 |
| `ratelimit` + XFF | **有现成方案，上一版"自研"的判断是错的** | `go-chi/httprate` 做计数器，`go-chi/chi` 的 `middleware.ClientIPFromXFFTrustedProxies`（已核实存在于 `middleware/client_ip.go`）做可信代理边界声明，按 CIDR/跳数显式声明，比三个项目各自的 `parseTrustedProxies` 自研实现更安全 |
| `oidc` state/nonce | **部分有现成方案，工作量下调** | `zitadel/oidc` 的 `pkg/client/rp`（已核实 `relying_party.go` 存在）自带 `AuthURLHandler`/`CodeExchangeHandler`，state 生成/校验和 PKCE 基本不用自己写，只剩 nonce 校验需要接线 |
| `saml`（replay 缓存 + 密钥管理） | **市面确认无解，维持自研** | 见下方 `crewjam/saml` 源码级核实 |
| `passkey`（WebAuthn ceremony 会话） | **市面确认无解，维持自研** | `go-webauthn/webauthn` 官方文档明确把 ceremony session 存取完全留给调用方 |
| `identity` / `authflow` | **不是 build-vs-buy 问题——这是策略层，不该被任何一方（自研或买）统一** | 见上方"共享机制不共享策略" |

具体证据：

- `markbates/goth`（6602★）和 `aarondl/authboss`（4195★）——市面上最像"全家桶"的两个，**零 SAML、零 WebAuthn**；authboss 官方声明不做限流。
- `crewjam/saml`（1115★，BSD-2）——源码 grep `service_provider.go` 全文确认**没有 assertion-ID 级 replay 缓存**，只有 90 秒时间窗口。真实安全公告如下（`gh api repos/crewjam/saml/security-advisories` 实查，共 5 条）：

  | 公告 | 等级 | 时间 | 内容 |
  |---|---|---|---|
  | GHSA-rrfw-hg9m-j47h | CRITICAL | 2020-09-29 | Signature Validation Bypass |
  | GHSA-4hq8-gmxx-h6w9 | HIGH | 2020-12-14 | XML Processing |
  | GHSA-j2jp-wvqg-wc2g | CRITICAL | 2022-11-28 | Signature bypass via multiple Assertion elements |
  | GHSA-5mqj-xc49-246p | MEDIUM | 2023-03-22 | Denial Of Service Via Deflate Decompression Bomb |
  | GHSA-267v-3v32-g6q5 | MEDIUM | 2023-10-14 | XSS via missing Binding syntax validation |

  这张表除了论证"没有现成的 replay 防护方案"之外，第 9 节还会用它作为"共享安全模块单点风险"的具体例证。

- `go-webauthn/webauthn`（1334★，BSD-3）——官方文档明确把 ceremony session 存取**完全留给调用方**，这是三家各写一遍的直接原因。
- 服务级方案（Ory Kratos/Hydra、ZITADEL、Keycloak、authentik、Casdoor、Logto、Dex 等共 11 个）全部排除，理由见下方"分发形态假设"。

**分发形态假设：**

三个项目都是 Go 单二进制 + `go:embed` 前端、自托管下载即跑。据此排除所有服务级方案：`dex` 官方明确"不建议在生产环境中嵌入式使用"；ZITADEL 是 **AGPL-3.0**，对闭源自建产品有额外法律风险；其余方案都要求独立部署 + 自有账号表结构，与"单二进制自托管"的分发形态直接冲突，引入的代价远超自建共享库。

**迭代频率（机会成本，原估算未计入）：** 过去 30 天 PSP 180 次提交、Report-Portal 105 次提交。在这个频率下冻结身份层 7~8 周代价很高——这是本轮把交付方式改为"按包增量、3~4 个独立批次、不强求三项目同步切换"的直接原因，具体安排见第 5 节。

---

## 3. 现状

### 3.1 四个项目

| 项目 | 路径 | 规模 | 架构 | 许可证 |
|---|---|---|---|---|
| Passwall-Sub-Panel | `/Users/kazuha/Codes/Passwall-Sub-Panel` | 271 文件 / 73,272 行 | 六边形：`internal/{domain,ports,adapters,service,transport,pkg,config,web}`，三者中最成熟 | AGPL-3.0 |
| Passwall-Node | `/Users/kazuha/Codes/Passwall-Node` | 95 文件 / 18,628 行 | 节点端。几乎没有重复实现（仅 689 行 SSO 客户端侧 + 116 行 config），是**消费方**不是重复方 | Apache-2.0 |
| AlertHub | `/tmp/claude-501/dup/AlertHub` | 58 文件 / 8,018 行 | 最小最新 | AGPL-3.0 |
| Report-Portal | `/Users/kazuha/Codes/StockAnalysisPrediction-Report-Portal` | 118 文件 / 37,789 行 | 扁平 `package app`（101 个非测试文件）。身份代码焊在 `*Server` 上：9 个 SSO/审计文件经 `s.` 访问了 **59 个 Server 成员**，含裸 SQL 助手 `exec`/`query`/`queryRow`/`likeOp`——解耦难度远高于另外两个 | AGPL-3.0 |

Report-Portal 刚从个人账号（`KKazuhaK`）迁入 `KazuhaHub` 组织。

### 3.2 已实测确认的 go.mod 现状（本次复核，直接 cat 得到）

```
PSP:            module github.com/KazuhaHub/passwall-sub-panel
                go 1.26.0
                toolchain go1.26.8

Passwall-Node:  module github.com/KazuhaHub/passwall-node
                go 1.26.0
                toolchain go1.26.8

AlertHub:       module github.com/kazuha/alerthub          <- 坏路径，见第 7 节
                go 1.26
                toolchain go1.26.6

Report-Portal:  module github.com/KKazuhaK/StockAnalysisPrediction-Report-Portal   <- 坏路径，见第 7 节
                go 1.26.6
```

四个 go.mod 里 `go` 指令的写法有 `1.26.0`、`1.26`、`1.26.6` 三种不一致的形式，`toolchain` 也不统一。本机实际 Go 版本是 1.26.3。第 5 节的执行步骤会统一处理。

### 3.3 组织与许可证

- 5 个仓库（PSP、Passwall-Node、AlertHub、Report-Portal，加上即将新建的 authcore）全部在 `KazuhaHub` 组织下，free 套餐，仓库全 public。
- 分支保护已生效：禁 force push、禁删分支、管理员豁免、暂无 required checks。
- 组织成员 4 人：kazuha、MLChinoo、FeiFei-SS 为 admin，danikahe 为 member。
- 许可证现状：PSP / AlertHub / Report-Portal 是 **AGPL-3.0**；Passwall-Node 是 **Apache-2.0**。
- **共享库必须是 Apache-2.0**：Apache-2.0 → AGPL-3.0 方向的引用是被允许的（宽松协议的代码可以被更严格协议的项目引用），这样 4 个项目（3 个 AGPL + 1 个 Apache）都能正常 import，不会出现许可证不兼容。反过来如果共享库是 AGPL-3.0，Passwall-Node（Apache-2.0）引用它会有争议（AGPL 的强 copyleft 条款是否传染到 Node 尚无定论，没必要冒这个风险）。

### 3.4 版权归属与第三方贡献者（关键约束）

- Report-Portal 的提交者只有 kazuha（474 个提交）、`Claude <noreply@anthropic.com>`（71 个提交）、dependabot（1 个提交）——**没有第三方人类贡献者**，版权链干净。
- **PSP 有第三方人类贡献者 `MLChinoo`（14 个提交）**。已核实这 14 个提交的改动集中在代理领域：
  - `adapters/sqlstore/node_repo*`
  - `adapters/sui/*`
  - `adapters/yaml/ruleset_repo*`
  - `domain/types.go`
  - `pkg/nodespec/*`
  - `service/health/*`
  - `service/render/proxy_group*`
  - `transport/http/handler/admin_node*`
  - `admin_rules*`

  **不碰 auth/audit 相关文件**。本次要迁入共享库的文件清单（`config/oidc.go`、`config/saml.go`、`service/auth/*.go`、`service/passkey/*.go`、`adapters/sqlstore/oidc_config_repo.go`/`saml_config_repo.go`/`saml_replay_repo.go`/`webauthn_credential_repo.go`）逐一核对后**没有一个落在 MLChinoo 触碰过的路径清单里**。

  **但这不等于验证完毕**。执行者在第 5 节"迁移前置检查"步骤里，**必须对每一个计划迁入共享库的文件单独跑 `git log --follow -- <文件路径>`**，确认提交者列表里没有 MLChinoo（或除 kazuha / Claude / dependabot 之外的任何人类账号）。若发现重叠，**该文件的代码不能进 Apache-2.0 共享库，除非事先取得 MLChinoo 本人的书面同意**（例如 GitHub 上一条明确同意的评论/邮件，留存链接）。这是一条硬性阻断条件，不是建议。

---

## 4. 目标架构

### 4.1 module 路径与包划分（8 个包，比上一版少 2 个）

```
module github.com/KazuhaHub/authcore   // Apache-2.0

authcore/
├── oidc/           // OIDC RP 协议实现：薄封装 zitadel/oidc 的 rp 包 + nonce 校验
├── saml/           // SAML SP 协议实现（含 replay 防护），市面无现成方案，自研
├── passkey/        // WebAuthn ceremony 会话包装，市面无现成方案，自研
├── audit/          // 审计事件契约 + 可选 HashChain 装饰器，无跨包依赖
├── captcha/        // 验证码 Provider 抽象：薄封装 mojocn/base64Captcha
├── geoip/          // 薄封装 oschwald/maxminddb-golang
├── ratelimit/      // 薄封装 go-chi/httprate + middleware.ClientIPFromXFFTrustedProxies
└── mail/smtp/      // 纯 SMTP 传输原语，无跨包依赖
```

**`identity` 和 `authflow` 已从上一版移除**（原因见第 2 节）。上一版里 `authflow.Store` 承担的"pending state 单次消费"职责，现在按协议内联在各自包里（`oidc` 包自己管 state/nonce——大部分委托给 `zitadel/oidc` 的 `rp` 包、`saml` 包自己管 RelayState、`passkey` 包自己管 ceremony session），不再抽成一个跨协议共享的包——三个协议的 pending-state 被重放的后果并不一样（OIDC state 重放是 CSRF，SAML RelayState 重放是 open redirect，WebAuthn ceremony session 重放是账号接管），拆开定义比强行统一更清楚，也避免了"为了共用一个 Store 接口而把三种不同风险揉进同一套抽象"。

### 4.2 依赖图：8 个包互相独立，没有"根"

```
  oidc    saml    passkey    audit    captcha    geoip    ratelimit    mail/smtp

        （八个包互相不 import，每个包零跨包依赖）
```

上一版依赖图里 `identity` 是"全模块的根"，`oidc`/`saml`/`passkey` 都依赖它拿 `Claims`/`Resolver`。这一版**没有根**：每个协议包直接返回自己的协议原生结果类型（`oidc.Claims`、`saml.Assertion`、`passkey.Credential`），消费方在自己的代码里把这些结果映射到自己的账号模型——这一步完全在 authcore 之外发生，authcore 不提供、也不该提供一个跨协议统一的"Resolver"接口，因为怎么把 SAML NameID 或 OIDC subject 映射到本地账号，PSP/AlertHub/Report-Portal 三家的做法在业务含义上本来就不同（Group vs Org vs 账号链接），没有共同点可抽。

消费方需要**实现**（而不是调用）的接口，比上一版少了 `identity.Resolver` 和 `authflow.Store`：

| 接口 | 用途 | 备注 |
|---|---|---|
| `audit.Writer` | 落到各自的 GORM / 裸 SQL | 共享库不碰数据库 |
| `saml.KeySource` | SP 签名密钥来源 | 库自带两种参考实现（上传证书 / 自动生成+加密存储），可选或自定义第三种 |
| `saml.ReplayStore` | 断言重放检测 | 库自带 SQL 参考实现 `NewSQLReplayStore`，也可自定义 |
| `oidc.Directory` | provider 配置查找（单例还是多行目录） | 由消费方的存储层实现 |
| `ratelimit.Store`（可选） | 分布式部署下计数器要不要落到 Redis/DB | 单实例部署直接用 `httprate` 自带的内存实现，不需要自定义 |

### 4.3 关键接口（节选，完整签名见 PR 中的代码）

**`saml` 包**（本次调研安全价值最高的部分，代码不变）：

```go
type ReplayStore interface {
	// CheckAndRemember 若 assertionID 在 notOnOrAfter 之前已出现过，
	// 返回 ErrReplayed；否则记录并返回 nil。
	CheckAndRemember(ctx context.Context, assertionID string, notOnOrAfter time.Time) error
}

var ErrReplayed = errors.New("saml: assertion already consumed")

// NewSQLReplayStore 是任何消费方数据库都能直接用的参考实现：
// 一张表 (assertion_id, expires_at)，insert-or-conflict。
func NewSQLReplayStore(db SQLExecutor) ReplayStore

type KeySource interface {
	KeyPair(ctx context.Context, spEntityID string) (tls.Certificate, error)
}

func UploadedKeySource(certPEM, keyPEM []byte) KeySource       // Passwall 模式
func GeneratedKeySource(secretStore SecretStore) KeySource     // Report-Portal 模式

// Assertion 是协议原生结果，不做账号语义解释——不再有一个跨协议的
// identity.Claims 类型，NameID/Attributes 直接透传给消费方自己处理。
type Assertion struct {
	NameID     string
	Attributes map[string][]string
	Raw        []byte
}
```

**`passkey` 包**——必须把安全语义做成显式参数，不给默认值：

```go
// Policy 把"能否免密码登录 / 注册前要不要 step-up"这条已证实的真实
// 产品安全分歧变成必填构造参数。这里没有"合理默认值"——选错了要么把
// 强制双因素账号降级成单因素，要么破坏依赖免密码登录的账号体验。
type Policy struct {
	RequireResidentKey    bool // 要求 discoverable credential，免密码登录的前提
	AllowPasswordless     bool // Passwall/AlertHub: true；Report-Portal: false
	RequireStepUpToEnroll bool // Report-Portal: true；Passwall/AlertHub: false
}

var (
	ErrStepUpRequired       = errors.New("passkey: step-up authentication required before enrolling a new device")
	ErrPasswordlessDisabled = errors.New("passkey: passwordless login is disabled by policy")
)

// Credential 是协议原生结果，同样不含账号语义。
type Credential struct {
	ID         []byte
	UserHandle []byte
}
```

**`audit` 包**（`Actor` 字段从上一版的 `identity.Principal` 改成不透明字符串——因为 `identity` 包已经不存在了）：

```go
type Entry struct {
	At     time.Time
	Actor  string // 不透明标识符，由消费方自己决定编码方式（如 "user:123"、
	              // "org:5/user:123"）。audit 包从不解析它，只按原样落库/上链，
	              // 这就是第 2 节要求的"不透明 account/actor 引用"。
	Action string
	Target Target
	Detail map[string]any
	IP     string
	Ext    map[string]any // 消费方自定义字段（如 Report-Portal 的 actor_ou）
}

type Writer interface {
	Write(ctx context.Context, e Entry) error
}

// BestEffort：写入失败不拖垮业务操作，只回调 onError。
func BestEffort(w Writer, onError func(error)) Writer

// HashChain：把 AlertHub 现有的防篡改设计（hash = SHA256(prevHash‖canonical(entry))）
// 包装成任意 Writer 的装饰器，让 PSP/Report-Portal 也能获得同样的防篡改能力。
func HashChain(w Writer, prevHash string) Writer

// anchor 标记链从哪一行开始生效，参见第 9 节"审计哈希链上线瞬间假警报"风险条。
func Verify(ctx context.Context, r Reader, anchor string) (brokenAt int, err error)
```

**`oidc` 包**（本次调研下调工作量最多的包——不是重新实现协议，是给 `zitadel/oidc` 的 `rp` 包接 nonce 校验）：

```go
import "github.com/zitadel/oidc/v3/pkg/client/rp"

// Directory 由消费方实现：单 provider 的项目（PSP/AlertHub 现状）直接返回
// 固定一行；多 provider 的项目（Report-Portal 现状）按 hint 查自己的存储。
// authcore 不关心 hint 的语义（是 slug 还是 tenant ID），只透传。
type Directory interface {
	Lookup(ctx context.Context, hint string) (rp.RelyingParty, error)
}

// Claims 是协议原生结果，不做账号语义解释。
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Raw           map[string]any
}

// AuthURLHandler / CodeExchangeHandler 是对 rp.AuthURLHandler /
// rp.CodeExchangeHandler 的直接透传——state 生成/校验和 PKCE 由 rp 包处理，
// 这一层基本不用自己写。VerifyNonce 是唯一需要自己补的部分：rp 包不强制
// 校验 nonce，留给调用方，这也是三个项目此前各自实现、又各自可能漏掉的地方。
func VerifyNonce(claims Claims, expectedNonce string) error

// 具体签名以 zitadel/oidc 当前发布版本的 go doc 为准，执行时用
// `go doc github.com/zitadel/oidc/v3/pkg/client/rp` 核实一次再接线，
// 不同版本之间的 Handler 签名可能有出入。
```

**`ratelimit` 包**（薄封装，不再是从零写的定长窗口计数器）：

```go
import (
	"github.com/go-chi/httprate"
	"github.com/go-chi/chi/v5/middleware"
)

// ClientIP 直接透传 chi 的 middleware.ClientIPFromXFFTrustedProxies——
// 按 CIDR/跳数显式声明可信代理边界，不再自己解析 X-Forwarded-For。
// 这是本轮调研的结论：三个项目现有的 parseTrustedProxies/clientIP 自研实现
// 应该被这个换掉，而不是被原样抽进共享库保留。
func ClientIP(trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return middleware.ClientIPFromXFFTrustedProxies(trustedProxies)
}

// Limiter 是对 httprate.Limit 的薄封装，只加 KazuhaHub 统一的默认响应格式
// （429 + JSON body），计数器本体是 httprate 的，不是自研。
func Limiter(requests int, window time.Duration, keyFunc httprate.KeyFunc) func(http.Handler) http.Handler

// 具体签名以 go-chi/httprate 和 go-chi/chi 当前发布版本的 go doc 为准，
// 执行时核实一次（尤其 ClientIPFromXFFTrustedProxies 的参数类型，不同
// 版本之间可能是 []*net.IPNet 还是 []string CIDR，需要现查再定）。
```

### 4.4 配置注入约定

三个协议包（`oidc`/`saml`/`passkey`）统一约定：**构造函数只接收值类型的 Config/Policy + 接口类型的存储依赖，不接收 `*sql.DB`、不接收 ORM 句柄、不接收任何具体框架类型（`*gin.Context` 等一律不出现在包签名里）**。

这条约定直接对应 Report-Portal 的"焊在 `*Server` 上"问题：Report-Portal 要用共享库，必须先把自己的实现改造成同样的显式依赖注入形态——这是第 6 节里 Report-Portal 前置重构无法绕开的原因，不是共享库设计上的可选项（不过因为 `identity`/`authflow` 已经砍掉，需要重构的文件范围比上一版小，见 6.3 节）。

HTTP 框架适配（Gin `HandlerFunc` vs `net/http`）一律不进共享库——协议包方法返回的是纯数据（URL 字符串、各协议自己的 Claims/Assertion/Credential 类型），由消费方自己包一层 handler。

---

## 5. 分阶段执行步骤

每一步都写明**可执行的命令**和**可验证的验收标准**（"跑 X 命令，看到 Y 输出"，不是"确认正常"）。zsh 环境下，涉及数组变量一律加引号，不依赖未加引号变量的分词。

**交付方式（本轮修订）**：不再要求"连续冻结、一次性迁移"。整个计划拆成 **3~4 个独立批次**，按第 2 节的优先级顺序交付：

- **批次 1（P0）**：`geoip` → `captcha` → `ratelimit`，互相独立、无需阶段 -1 的测试套件把关，随时可以开始。
- **批次 2（P1，需先过阶段 -1 的门槛）**：`saml` → `passkey` → `audit`，这三个包涉及"市面确认无解"的安全机制，必须先有真实复用率数据再决定做不做。
- **批次 3（P2，可延后）**：`oidc` → `mail/smtp`，优先级最低，`mail/smtp` 尤其"与身份编排关系不大，可延后"。
- 三个消费方项目**不要求同步切换**：AlertHub 可以只接了 `saml`（补上此前缺失的 replay 防护）就先上线，不必等 PSP/Report-Portal 也切完 `passkey`/`audit` 才动。

---

### 阶段 -1：共享安全测试套件（新增，P1 的前置门槛）

在抽取 `saml`/`passkey`/`audit` 这三个"市面确认无解、必须自研"的包之前，先花 **1~3 人日**做一个零耦合的前置步骤：写一套**不依赖任何 authcore 代码、也不改动三个项目任何一行代码**的共享安全测试套件，直接针对三个项目**现有**的 SAML replay 防护、WebAuthn ceremony 会话、审计防篡改行为跑同一批测试用例，拿到真实的"这三份实现到底有多像"的数据，而不是像上一版那样只凭行数和代码走读判断相似度。

详细设计见 `docs/security-test-suite.md`（与本文档同目录），这里只写这一步在整个计划里的位置和产出：

- **产出**：一份复用率报告——针对每个安全属性（assertion replay 检测、ceremony session 单次消费、审计哈希链防篡改），记录三个项目现有实现的通过/失败情况和实现差异点。
- **决策门槛**：
  - 如果三个项目的行为高度一致（测试用例几乎不用改就能套三家），说明 P1 抽取价值高，按计划进入阶段 3。
  - 如果发现某个属性其实做法分歧很大（例如某项目的"重放检测"实际上是应用层去重，不是协议层 replay 防护，测试套件跑起来行为完全对不上），说明这一块可能不该整体抽取，需要回到第 2 节的"机制 vs 策略"标准重新判断，缩小或调整 P1 范围，而不是硬着头皮抽一个勉强兼容三家的接口。
  - 这一步同时会**提前暴露安全缺口**（例如 AlertHub 目前没有 SAML replay 防护，测试套件对 AlertHub 跑这个用例会直接失败），这本身就是有价值的产出，不依赖后续是否真的抽取共享库。
- **不做什么**：这一步不写 authcore 的任何代码，不改三个项目的任何代码，纯测试。测试套件本身产出后建议留在三个项目的 CI 里长期跑（不是一次性用完就扔），持续监控三家的安全行为有没有漂移。

**验收标准**：`docs/security-test-suite.md` 里定义的测试用例全部跑完（无论通过还是失败，失败也是产出），复用率报告写成文档，kazuha 看过报告后确认是否按原计划推进 P1（`saml`/`passkey`/`audit`）。**没有这份报告之前，不要开始阶段 3。**

---

### 阶段 0：迁移前置检查（不写代码，纯核查）

**0.1 逐文件复核 MLChinoo 的提交历史**

对第 3.4 节列出的每一个计划迁入共享库的 PSP 文件执行：

```bash
cd /Users/kazuha/Codes/Passwall-Sub-Panel
for f in \
  internal/config/oidc.go \
  internal/config/saml.go \
  internal/service/auth/oidc.go \
  internal/service/auth/saml.go \
  internal/service/auth/saml_replay.go \
  internal/service/passkey/passkey.go \
  internal/adapters/sqlstore/oidc_config_repo.go \
  internal/adapters/sqlstore/saml_config_repo.go \
  internal/adapters/sqlstore/saml_replay_repo.go \
  internal/adapters/sqlstore/webauthn_credential_repo.go
do
  echo "=== $f ==="
  if [ ! -f "$f" ]; then
    echo "!!! 文件不存在，先用 find 核对真实路径，不要把空输出当成'无其他作者' !!!"
    continue
  fi
  git log --follow --format='%an <%ae>' -- "$f" | sort -u
done
```

（本文档原稿把 OIDC 文件写成 `internal/service/auth/auth_oidc.go`，本轮复核发现真实文件名是 `internal/service/auth/oidc.go`，已在上面改正；这也是为什么必须加 `[ ! -f "$f" ]` 判断——`git log --follow` 对一个不存在的路径会**静默返回空输出、退出码 0**，不会报错，执行者如果不逐行核对文件是否存在，会把"命令跑空了"误读成"没有其他作者"，直接放过一个根本没被检查过的文件。其余文件名已用 `find internal/service/auth internal/service/passkey internal/config internal/adapters/sqlstore -name '*.go'` 核对无误；执行前仍建议整体跑一遍这条 `find` 命令，防止本文档列出的路径与实际代码库有偏差。）

**验收标准**：每个文件的作者列表里，除了 kazuha 本人的 git 用户名和邮箱、`Claude <noreply@anthropic.com>`、`dependabot[bot]` 之外**不出现任何其他账号**。若出现 MLChinoo（或其他账号），**停止该文件的迁移**，记录下来，去 GitHub 拿到本人书面同意后才能继续，同意记录（截图或链接）存进 `docs/authcore-copyright-clearance.md`。

**核对方式请按邮箱、不要只按显示名字符串匹配**：本轮复核发现 MLChinoo 在 PSP 仓库里至少用两个不同的 git 用户名提交过（`MLChinoo <mlchinoo@kazuhahub.com>` 12 个提交 + `馬良※チノ <mlchinoo@kazuhahub.com>` 2 个提交，同一邮箱、不同显示名，后两个经核实是无实质改动的 merge commit，不影响本次结论，但说明**同一个人可以在 `%an` 里显示成完全不像"MLChinoo"的字符串**）。上面的命令已经用 `%an <%ae>'` 把邮箱一起打印出来，执行者验收时必须扫一遍邮箱列，而不是只搜"MLChinoo"这个词；已知需要警惕的邮箱至少包括 `mlchinoo@kazuhahub.com`，若发现列表里有 kazuha 本人已知邮箱（`kazuhak@uci.edu`/`lianxltz@gmail.com`/`me@kazuha.org`）、`noreply@anthropic.com`、`dependabot[bot]` 之外的任何邮箱，一律按"发现第三方作者"处理。

**0.2 确认三个仓库当前工作区干净**

```bash
for repo in \
  /Users/kazuha/Codes/Passwall-Sub-Panel \
  /tmp/claude-501/dup/AlertHub \
  /Users/kazuha/Codes/StockAnalysisPrediction-Report-Portal
do
  echo "=== $repo ==="
  git -C "$repo" status --porcelain
done
```

**验收标准**：三个仓库的 `git status --porcelain` 输出均为空（无未提交改动）。若非空，先让 kazuha 决定是提交还是暂存，不要在脏工作区上开始迁移。

**0.3 确认 AlertHub 的真实远程地址**

AlertHub 当前工作副本在 `/tmp/claude-501/dup/AlertHub`（临时挂载），需要确认它对应的真实 GitHub 仓库：

```bash
git -C /tmp/claude-501/dup/AlertHub remote -v
```

**验收标准**：输出中的 URL 指向 `github.com/KazuhaHub/AlertHub`。若指向别处或为空，先向 kazuha 确认正确的 clone 地址，后续步骤一律对**真实仓库的本地 clone**操作，不直接改 `/tmp` 下的临时副本（`/tmp` 内容可能在会话结束后消失）。

（本轮复核已经跑过这条命令：`/tmp/claude-501/dup/AlertHub` 的 `origin` 确实指向 `https://github.com/KazuhaHub/AlertHub.git`，地址本身没有问题。但这不代表这一步可以跳过——`/tmp` 路径本身仍然是临时挂载，不保证跨会话存活，执行者仍需要 `git clone https://github.com/KazuhaHub/AlertHub.git /Users/kazuha/Codes/AlertHub` 建一个和 PSP/Report-Portal 并列的固定本地路径，后续所有 AlertHub 相关操作都在这个固定路径下做，不要继续依赖 `/tmp` 副本。）

---

### 阶段 1：建立 authcore 仓库骨架

**1.1 建仓**

在 GitHub 组织 `KazuhaHub` 下新建 public 仓库 `authcore`，不勾选自动生成 README/LICENSE/.gitignore（手动加，内容要与组织现有仓库风格一致）。

```bash
gh repo create KazuhaHub/authcore --public --description "Shared security-mechanism layer for KazuhaHub Go services"
git clone https://github.com/KazuhaHub/authcore.git /Users/kazuha/Codes/authcore
cd /Users/kazuha/Codes/authcore
```

**1.2 初始化 module**

```bash
go mod init github.com/KazuhaHub/authcore
```

用统一写法设置 Go 版本（三个消费方现状里 PSP/Node 是 `go 1.26.0` + `toolchain go1.26.8`，Report-Portal 是 `go 1.26.6` 无 toolchain 行，AlertHub 是 `go 1.26` + `toolchain go1.26.6`——**本次统一到 `go 1.26.0` + `toolchain go1.26.8`**，与 PSP/Node 对齐，因为它们代表了组织内最新验证过的工具链版本）：

```bash
cat > go.mod <<'GOMOD'
module github.com/KazuhaHub/authcore

go 1.26.0

toolchain go1.26.8
GOMOD
```

**1.3 加 LICENSE / README / NOTICE**

- `LICENSE`：Apache-2.0 全文（`curl -s https://www.apache.org/licenses/LICENSE-2.0.txt > LICENSE`，人工核对下载内容与官方文本一致后再提交）。
- `README.md`：说明本 module 的定位（**协议/安全机制层，不含账号/会话/HTTP 路由/租户语义**），列出 4.1 节的 8 个包划分表，并明确写一句"本仓库不提供跨协议的账号模型统一层，`identity`/`authflow` 已在设计阶段被排除，理由见 KazuhaHub/kazuhahub-github 仓库 `docs/shared-modules-plan.md` 第 2 节"，避免未来有人把账号模型代码错塞进来（呼应第 9 节"共享库变成垃圾桶"风险）。
- `NOTICE`：列出直接依赖的第三方库及其许可证（见第 8.3 节清单，本轮已更新为 `zitadel/oidc`、`go-chi/httprate`、`go-chi/chi`）。

**验收标准**：

```bash
cd /Users/kazuha/Codes/authcore
go build ./...   # 此时无 .go 文件，预期输出为空、退出码 0
cat go.mod        # 确认 module 路径、go/toolchain 行与上面一致
```

---

### 阶段 2：搬迁批次 1（P0）——geoip / captcha / ratelimit

这一批不需要等阶段 -1 的报告，三个包互相独立、无跨包依赖，随时可以开始。

**2.1 geoip：用 `git subtree split` 从 PSP 保留历史地搬出**

选 `geoip` 第一个搬，因为两家实现（PSP 205 行 / Report-Portal 171 行）结构已实测完全一致，唯一差异是返回类型，风险最低，适合验证"保留 git 历史的搬迁流程"本身有没有问题。

```bash
cd /Users/kazuha/Codes/Passwall-Sub-Panel
# 确认 geoip 包的真实路径（调研中未给出精确路径，执行前先定位）
find . -type d -iname geoip

# 假设路径为 internal/pkg/geoip，按实际路径替换下一行
git subtree split --prefix=internal/pkg/geoip -b geoip-split
```

**验收标准**：命令输出一个 commit hash，且不报错。`git log geoip-split --oneline | wc -l` 输出大于 0，说明历史被正确提取。

```bash
cd /Users/kazuha/Codes/authcore
git remote add psp-history /Users/kazuha/Codes/Passwall-Sub-Panel
git fetch psp-history geoip-split
git merge --allow-unrelated-histories -m "Import geoip package history from Passwall-Sub-Panel" psp-history/geoip-split
mkdir -p geoip
git mv <搬入后的文件> geoip/   # 按 git status 实际路径调整
```

**验收标准**：`git log --follow geoip/geoip.go | grep -c '^commit'` 大于 1（说明历史保留而不是一个新的初始提交）。

改写返回类型为共享库自己的 `geoip.Location`，删除 PSP 专属的 `domain.GeoLocation` 依赖：

```bash
go build ./geoip/...
go vet ./geoip/...
```

两条命令都必须无错误退出（`echo $?` 为 0）。`go build` 有错误说明还残留了对消费方包的依赖，必须清干净。

**2.2 captcha：同样方式搬迁**

`captcha` 是纯包装 `mojocn/base64Captcha`，无状态无账号语义，重复 2.1 的 `git subtree split` 套路即可，验收标准同上（`go build ./captcha/... && go vet ./captcha/...` 无错误退出）。

**2.3 ratelimit：不是从消费方搬迁计数器，而是新写一个薄封装**

**这里和上一版计划不一样，务必注意**：上一版打算把 PSP/Report-Portal 自研的计数器逻辑用 `git subtree split` 搬进共享库；本轮 build-vs-buy 调研确认 `go-chi/httprate` + `middleware.ClientIPFromXFFTrustedProxies` 已经是更安全的现成方案（见第 2 节），所以 `ratelimit` 包**不搬迁任何消费方的计数器代码**，直接依照 4.3 节的接口新写：

```bash
mkdir -p /Users/kazuha/Codes/authcore/ratelimit
go get github.com/go-chi/httprate
go get github.com/go-chi/chi/v5
# 写入 ClientIP / Limiter，按 4.3 节接口
go build ./ratelimit/...
go vet ./ratelimit/...
```

**验收标准**：两条命令无错误退出；额外要求一条对照测试——伪造一批带不同 `X-Forwarded-For` 的请求，确认 `ClientIP` 在声明的可信代理 CIDR 之外时不会信任客户端自报的 IP（这是 XFF 解析最常见的安全漏洞，必须有测试覆盖）。

（历史背景，供理解为什么这里和 `mail/smtp` 不一样：PSP 的计数器原本写在 `internal/transport/http/middleware/ratelimit.go`（96 行），**同一个文件里**混了纯计数器逻辑和直接 import `github.com/gin-gonic/gin` 的 `Handler() gin.HandlerFunc`，`git subtree split` 切不出"文件里的一部分函数"，上一版为此专门设计了两套搬迁方案。本轮因为不再抽取这段自研计数器代码——改用 `httprate` 直接替换它——这个"文件内混合"的问题对 `ratelimit` 已经不成立了，不需要再做物理挪文件的前置 PR。`mail/smtp` 没有对应的现成库，下面 2.4 节的处理方式依然适用。）

**2.4 mail/smtp：待抽代码与框架耦合代码混在同一文件里，处理方式和 ratelimit 不同**

PSP 的 SMTP 收发段落写在 `internal/service/mailer/mailer.go`（约 1900+ 行，账号通知模板、任务队列、SMTP 发信全在一个文件里），真正要抽的 `net/smtp` 收发段落只是其中几十行，是"文件内一部分"，不是可以整体 split 的独立文件/目录（Report-Portal 同理，见 `mail.go`）。因为市面上没有对应的现成微型库能直接替换（这不是 `ratelimit` 那种可以整体买现成方案的情况），处理方式二选一，执行前先定，不要走到一半发现套路不适用：

1. **推荐**：先在 PSP（Report-Portal 同理）开一个很小的前置 PR，把这几十行纯函数物理搬进新文件（如 `internal/service/mailer/smtp_transport.go`），不改变行为，只挪代码位置；这个 PR 合并之后，新文件就是一个可以正常 `git subtree split --prefix=` 的独立路径，历史从这次挪动开始保留（挪动之前的逐行历史保留不了，这是可接受的代价，因为挪动本身可以在 commit message 里写清楚"从 XX 文件移出，行为不变"）。
2. **兜底**：直接手写迁移（对照现有代码重新实现，不追求 git 历史保留），跑通 `go build`/`go vet`/`go test` 即可。工作量比方案 1 小，但会丢失这段代码的完整提交历史。

两种方式都要在对应的搬迁 PR 描述里写明选了哪一种，不要默默按方案 2 处理却在 PR 描述里写得像方案 1（保留了历史）。`mail/smtp` 属于批次 3（P2），可以在批次 1/2 做完之后再排期，不影响其他包的进度。

---

### 阶段 3：搬迁批次 2（P1）——saml → passkey → audit

**这一阶段只有在阶段 -1 的共享安全测试套件报告确认"抽取有价值"之后才开始。** 报告如果显示某个属性的实现分歧太大，先回到第 2 节重新判断范围，不要跳过这个门槛直接开始搬代码。

**3.1 saml：从 PSP 搬 SAML replay 逻辑作为起点**

PSP 是三家中唯一带 ADR 文档的实现，`docs/adr/0023-saml-assertion-replay-protection.md` 一并搬到 authcore 的 `docs/adr/` 下作为设计依据留档：

```bash
cd /Users/kazuha/Codes/Passwall-Sub-Panel
find . -path '*service/auth/saml*'   # 定位真实文件
git subtree split --prefix=internal/service/auth -b saml-split   # 若 saml 与 auth 混在一个目录，split 整个目录后在 authcore 侧再挑文件
```

同时把 Report-Portal 的 `GeneratedKeySource`（自动生成 RSA-2048 自签证书 + 加密存储）作为第二种 `KeySource` 实现搬入，来源文件是 Report-Portal 的 `internal/app/saml.go`（对应 `SPKeyEnc`/`openSecret` 那部分）。

**验收标准**：

```bash
cd /Users/kazuha/Codes/authcore
go build ./saml/...
go test ./saml/...   # 至少要有一条测试用例：伪造重放同一个 assertion ID 两次，断言第二次返回 ErrReplayed
```

后一条测试是硬性要求——这个包存在的意义就是补 replay 防护，没有一条测试证明它真的拦截了重放，就不能算搬迁完成。

**3.2 passkey：ceremony 骨架来自 PSP**

`Policy` 结构体的两种预设——`AllowPasswordless:true`/`RequireStepUpToEnroll:true`——分别对应现有 PSP/AlertHub 行为和 Report-Portal 行为。

**验收标准**：

```bash
go build ./passkey/...
go vet ./passkey/...
go test ./passkey/...
```

**3.3 audit：以 AlertHub 现有的哈希链设计为蓝本**

AlertHub 现有的哈希链实现（`prev_hash`/`hash`/`VerifyAuditChain`/`PruneAudit` 保留 anchor）基本就是 `audit.HashChain`/`Verify` 的设计蓝本，迁移时应把 AlertHub 的实现原地提炼成共享库代码，而不是重写一遍。

**验收标准**：

```bash
go build ./audit/...
go vet ./audit/...
go test ./audit/...   # 至少覆盖：篡改中间一行后 Verify 能定位到 brokenAt；anchor 之前的行不参与验证
```

批次 2 整体验收：

```bash
cd /Users/kazuha/Codes/authcore
go build ./saml/... ./passkey/... ./audit/...
go vet ./...
go test ./...
go mod tidy   # 确认 go.sum 生成且没有多余的间接依赖残留
```

---

### 阶段 3.5：搬迁批次 3（P2，可延后）——oidc / mail-smtp

优先级最低，可以在批次 1、2 稳定之后再排期，也可以和批次 2 并行（两者互不依赖）。

**oidc**：按 4.3 节接口，基于 `zitadel/oidc` 的 `rp` 包薄封装，只需要自己写 `VerifyNonce` 和 `Directory` 接口定义；协议握手本身不用重新实现。

**mail/smtp**：按 2.4 节给出的两个选项之一执行（PR 描述里写明选了哪个）。

**验收标准**（两者一致）：

```bash
go build ./oidc/... ./mail/smtp/...
go vet ./...
go test ./...
```

---

### 阶段 4：每个批次做完后打一个 tag，供联调使用

不再是"一次性打一个 v0.1.0"，而是每个批次各自打一个 tag，方便三个项目按自己的节奏挑批次接入：

```bash
cd /Users/kazuha/Codes/authcore
git add -A
git commit -m "authcore batch 1: geoip, captcha, ratelimit"
git tag v0.1.0
git push origin main --tags
# 批次 2 做完后：
git commit -m "authcore batch 2: saml, passkey, audit"
git tag v0.2.0
git push origin main --tags
# 批次 3 做完后：
git commit -m "authcore batch 3: oidc, mail/smtp"
git tag v0.3.0
git push origin main --tags
```

**验收标准**（每次打 tag 后都跑一遍）：`git ls-remote --tags origin` 里能看到对应 tag；`go list -m github.com/KazuhaHub/authcore@vX.Y.Z` 在一个干净的临时目录里能成功解析（证明是公开可拉取的合法 Go module）：

```bash
mkdir -p /tmp/authcore-smoke && cd /tmp/authcore-smoke
go mod init smoke
go get github.com/KazuhaHub/authcore@v0.1.0
```

`go get` 必须无错误退出，且 `go.sum` 里出现对应条目。

---

### 阶段 5：用 `go work` 做联调（不改任何消费方代码，先验证类型契合）

每完成一个批次，都可以用这一步验证接口签名与消费方现有类型能不能对上，不必等全部三个批次都做完：

```bash
mkdir -p /Users/kazuha/Codes/authcore-integration-check
cd /Users/kazuha/Codes/authcore-integration-check
go work init \
  /Users/kazuha/Codes/authcore \
  /Users/kazuha/Codes/Passwall-Sub-Panel \
  /Users/kazuha/Codes/StockAnalysisPrediction-Report-Portal
# AlertHub 若还在 /tmp 临时副本，先按 0.3 步确认的真实地址 clone 到本地固定路径再加入
```

在 PSP 里写一个不提交的临时文件，用共享库对应批次的包套一层适配 PSP 现有逻辑，验证类型能编译通过。

**验收标准**：`go build ./...`（在 PSP 目录下，`go.work` 生效时会优先用本地 authcore 源码而不是已发布的 tag）无编译错误。跑完后删除临时文件，不提交，`go work` 文件也不提交进任何仓库（联调专用，事后 `rm -rf authcore-integration-check`）。

---

### 阶段 6：三个项目按各自节奏接入

**不再要求固定的"AlertHub → PSP → Report-Portal"顺序、也不要求三家同步切换同一批次**。每个项目可以在自己需要的包发布后就接入，例如 AlertHub 可以先只接批次 2 的 `saml`（补上此前缺失的 replay 防护），不必等批次 1 的 `ratelimit`/批次 3 的 `oidc` 也一起接。具体每个项目的适配范围和工作量见第 6 节。

对每个项目，接入的通用步骤模板：

**6.x.1** 新建分支：

```bash
cd <项目路径>
git checkout -b migrate/authcore-<批次名>
```

**6.x.2** 加依赖：

```bash
go get github.com/KazuhaHub/authcore@v0.X.0   # 按要接入的批次选 tag
```

**6.x.3** 逐文件替换：把项目里对应的协议逻辑文件改成调用 authcore 包，本地保留的部分改造成实现 `audit.Writer`/`saml.ReplayStore`/`saml.KeySource`/`oidc.Directory` 等接口，账号映射逻辑（拿到 `oidc.Claims`/`saml.Assertion`/`passkey.Credential` 之后怎么落到本地用户表）**留在项目自己的代码里**，不再需要满足一个共享的 `identity.Resolver` 签名——这是本轮比上一版简单的地方。**每替换完一个协议单独提交一次**，不要一次性全改完再提交——出问题时能 `git bisect`。

**6.x.4** 每次提交后跑：

```bash
go build ./...
go vet ./...
go test ./...
```

**验收标准（每个协议替换后都要过）**：三条命令全部无错误退出；额外要求：

- OIDC 替换后：跑一次真实的登录流程（对接测试用的 IdP 或 mock），确认能拿到 `oidc.Claims` 并成功登录，浏览器/客户端侧行为与替换前一致（cookie 还是 cookie、Bearer 还是 Bearer，会话下发这层完全没变）。
- SAML 替换后：额外跑 `go test ./... -run Replay`，确认新的 replay 防护测试通过；对 AlertHub 而言这是**新增能力**，验收标准是"replay 测试从无到有，且通过"。
- passkey 替换后：确认现有的 usernameless / 需要 step-up 的行为分别符合各项目的 `Policy` 设定（AlertHub/PSP 是 `AllowPasswordless:true`，Report-Portal 是 `RequireStepUpToEnroll:true`）——写一条测试用例分别断言。
- audit 替换后：若该项目选择接入 `HashChain`（AlertHub 保留自己的，PSP/Report-Portal 新增），**PSP/Report-Portal 现有 `audit_log` 表没有 `prev_hash`/`hash` 列，这是从零新增字段，不是接一个已有的链**——迁移 PR 必须先加这两列（历史行留空/NULL，不做回填），并在代码里、PR 描述里明确记录"链从哪一次提交、哪一行 ID 开始生效"这个 anchor（具体用什么形式记录 anchor 尚未拍板，见第 11 节新增的待决问题）。验收标准相应地是：`Verify()` 对**迁移生效点之后**新写入的记录返回 `brokenAt == 0, err == nil`；不要求、也不可能让迁移前的历史行通过验证（见第 9 节"审计哈希链上线瞬间假警报"风险条）。

**6.x.5** 全部要接入的协议替换完、本地验收通过后，提 PR 到该项目的 `main` 分支，PR 描述里列出：替换了哪些文件、删除了多少行本地实现、新增了哪些依赖、跑过哪些验收命令及结果。**不自行合并**，等 kazuha 审核。

**6.x.6** 合并后打一个该项目的版本 tag（如 `v-migrate-authcore-alerthub-saml`），作为回滚锚点。

---

### 阶段 7：清理（按批次/按项目逐步做，不等"全部切换完成"）

- 每个项目每接入一个批次后，确认该项目 `go.mod` 里的 `github.com/KazuhaHub/authcore` 版本号，和它已经接入的其他包版本不冲突（例如不会出现同一个项目里一部分代码依赖 v0.1.0 一部分依赖 v0.3.0 这种同库多版本混用——Go module 本身不允许，但要注意不要因为分批接入而遗漏升级）。
- 在 authcore 仓库补齐单元测试覆盖率报告，`go test ./... -cover`，把结果记录进 authcore 的 README，每个批次发布后更新一次。
- 每个协议在对应项目里全部切换完成后，在该项目 `docs/` 下留一份链接，说明"该协议相关代码已迁移至 github.com/KazuhaHub/authcore@vX.Y.Z，本地不再维护"。

---

## 6. 逐项目适配清单

### 阶段 -1 完成情况与由此修正的估算（2026-09-17）

安全测试套件已交付，代码在 `docs/security-test-suite/`（独立 Go module），
`./selfcheck.sh` 可一键验证其有效性（27 条用例：22 条对 safe/vulnerable 参照桩有真实区分度，
2 条版本闸门、1 条配置依赖闸门、2 条白盒闸门，均有文档说明为何"两边都过/都跳过"仍然诚实）。

**由此修正的两处估算**，执行者请按修正后的数字排期：

1. **passkey 接入真实项目的成本此前被低估。**
   套件的 passkey 用例用的是自造的简化 JSON（`mode`/`challenge`/`counter`/`origin`/`rp_id`/`user_handle`），
   **打不到真实端点上**——三个项目走的是 `go-webauthn/webauthn`，begin 返回真正的
   `PublicKeyCredentialCreationOptions`，finish 需要 CBOR `attestationObject` + `clientDataJSON`
   + 对其 hash 的真实签名。要黑盒测真实项目，得先补一个**软件模拟认证器**。
   **追加 1~1.5 人日**，且这部分不应挤占原定"三个项目分别接入"的 0.5~1 人日预算。

2. **OIDC 接入需要独立的 mock IdP。**
   套件目前依赖参照桩自带的 `/oidc/mock/*`，真实项目没有这个端点。
   接入时需要真起一个 mock OIDC provider（建议 `oauth2-proxy/mockoidc`）并重写三个辅助函数
   去打它的真实接口——比"换个 URL"工作量大。已含在接入预算内，但不要按"换 URL"估。

**已决：审计的"直连测试库篡改"辅助（`mustTestOnlyDB`）不在本阶段实现。**
理由：它只有指向某个真实项目的测试库时才有意义，而三个项目的 schema 和 DSN 各不相同，
现在写等于凭空猜。留到"三个项目分别接入"时按各自实际情况实现。
当前套件用参照桩的 HTTP hook 模拟篡改，两条依赖直连 DB 的用例已如实标注为白盒闸门，
注释里引用了 AlertHub 真实源码的函数名与行号作为依据。


### 迁移注意：`authcore/captcha` 的两处接口契约变化（已决，2026-09-17）

这两条不影响正确性，是刻意的设计取舍，PSP / Report-Portal 接入时要处理：

1. **配置从"每次调用传入"变成"构造时固化"。**
   两个项目原来是 `Verify(ctx, set Settings, r Response)`——管理员改 secret / provider / 允许域名后
   不用重启就生效。`authcore` 的 `NewTokenVerifier(...)` 在构造时固化这些值。
   **决定：接受。** 理由：这是 Go 的主流形态（对照 `http.Client`），而且构造函数**不做任何网络 I/O**，
   每次 `Verify` 前按当前配置现造一个是免费的。
   **迁移做法**：在调用点按当前配置现造，或自己做"配置变了就重建"的缓存。
   ⚠️ **不要让单例长期持有一个 `TokenVerifier`**——它不会感知配置热更新。

2. **包内不再打日志。**
   原来的 `verifyToken` 在校验失败 / hostname 不符时会自己 `log.Warn`。
   `authcore/captcha` 不做任何日志输出，而是把 `ErrorCodes` 和 `HostnameMismatch` 放进 `Result`。
   **决定：接受。** 理由：日志库和日志格式是各项目的策略，不该由纯机制包决定——
   这正是"共享机制、不共享策略"这条原则在接口层面的体现。
   **迁移做法**：想保留原来那两行运维可见的日志，在各自调用点按 `Result` 自己记。


**因为不再统一账号模型（`identity`/`authflow` 已砍掉），三个项目都不需要再写一个满足跨协议 `Resolver` 接口的适配层——协议包返回的 `Claims`/`Assertion`/`Credential` 直接喂给项目自己已有的账号逻辑即可。以下三项估算都比上一版明显下调。**

### 6.1 Passwall-Sub-Panel——抽取起点，改动"反向"：先搬出再接回来

- 迁出：`service/auth/{oidc,saml,passkey}.go`（注意文件名是 `oidc.go`，不是 `auth_oidc.go`，见阶段 0.1 的核实说明）、`config/{oidc,saml}.go`、`adapters/sqlstore/{oidc_config_repo,saml_config_repo,saml_replay_repo,webauthn_credential_repo}.go` 中的协议逻辑部分（含 `newSafeHTTPClient`、SAML replay 逻辑、`saml_replay.go` 对应的 ADR 文档）。
- 本地保留并精简：`adapters/sqlstore/*_repo.go` 收窄为纯粹的 `audit.Writer`/`oidc.Directory`/`saml.ReplayStore`（可直接用 `NewSQLReplayStore`）/`saml.SecretStore` 实现，不再包含协议判断逻辑；`oidc.Claims`/`saml.Assertion` 拿到手之后到 PSP 自己 `service/user` 的映射逻辑保持原样，**不需要再包一层 `identity.Resolver` 适配**，这是本轮比上一版省下的工作量。
- `service/passkey/passkey.go`（461 行）拆成：调用共享库 `passkey.Manager`（`Policy{AllowPasswordless: true, RequireStepUpToEnroll: false}`）+ 本地 `UserHandleFunc`（保留现有数值 ID 编码方式）。
- `pkg/geoip`/`pkg/ratelimit`/`internal/service/captcha`/`mailer.go` 中的 SMTP 传输段落直接替换为共享库调用，`ratelimit` 这次是换成 `httprate`+`ClientIPFromXFFTrustedProxies` 而不是接自己原来的计数器，类型映射（`domain.GeoLocation` ← `geoip.Location`）各写一行转换函数。
- **不改**：`mailer.go` 里的通知引擎（账号禁用/密码重置/到期提醒调度）、`middleware.AuditWrites` 中间件本身（只是内部改调 `audit.BestEffort(audit.HashChain(...))`）、PSP 自己的账号/角色/Group 模型（这本来就不在 authcore 范围内）。
- **工作量估计**：约 15~20 个文件的 import 路径与类型替换（比上一版的 20~30 个文件少，因为不再需要写 `identity.Resolver`/`authflow.Store` 两层适配），不涉及数据模型改动。估计 **2~3 人日**（含阶段 0 的逐文件版权复核；可以按批次分开做，不必一次接完全部协议）。

### 6.2 AlertHub——消费方兼"哈希链原型贡献者"

- 拿到 `oidc.Claims`/`saml.Assertion` 之后，直接在现有的 `ensureSSOUser` + `AddMembership(orgID, ...)` JIT 逻辑里用即可，**不需要再实现一个满足 `identity.Resolver` 接口签名的适配层**——上一版这里是唯一有实质工作量的部分，本轮因为接口被砍掉，工作量明显下降。
- 补齐目前缺失的 SAML replay 防护——直接用共享库 `saml.NewSQLReplayStore`，这是本次抽取给 AlertHub 带来的**唯一净新增安全能力**，也是建议 AlertHub 优先只接批次 2 的 `saml` 的原因。
- `server/internal/sso/oidc.go` 里的 `sso.OIDCConfig` 单例改接共享库 `oidc.Directory`（实现一个只返回一行的 Directory 即可，不强迫改成多 provider）。
- **贡献方向**：AlertHub 现有的哈希链实现（`prev_hash`/`hash`/`VerifyAuditChain`/`PruneAudit` 保留 anchor）基本就是共享库 `audit.HashChain`/`Verify` 的设计蓝本，迁移时应把 AlertHub 的实现原地提炼成共享库代码，而不是重写一遍——阶段 3.3 搬 `audit` 包时以 AlertHub 现有代码为准。
- 会话层（Bearer + localStorage）**不动**，只在拿到协议原生结果之后接自己现有的 `/exchange` 桥接逻辑。
- **工作量估计**：SAML replay 接入 0.5 人日，OIDC Directory 适配 0.5 人日，audit 贡献+接入 0.5 人日，其余（geoip/captcha/ratelimit 若也接）0.5~1 人日，共 **1.5~2.5 人日**（比上一版 2.5~3.5 人日下降，主要来自不用写 `identity.Resolver` 适配层）。

### 6.3 Report-Portal——改动量仍最大，但范围比上一版缩小

**为什么仍然不轻松**：9 个 SSO/审计文件经 `s.`（`*Server`）访问了 **59 个 Server 成员**，包括裸 SQL 助手 `exec`/`query`/`queryRow`/`likeOp`。共享库的每个接口（`Writer`/`ReplayStore`/`KeySource`/`Directory`）都要求**无状态、参数显式传入**的实现——Report-Portal 现状完全不满足这个前提。这不是"换个 import 路径"能解决的，是一轮真正的内部重构。

**但范围比上一版小**：上一版的解耦范围是为了同时满足 `identity.Resolver`（覆盖 `identity.go` 这个 Report-Portal 自己的账号链接文件）和各协议接口；本轮 `identity`/`authflow` 已经砍掉，**`internal/app/identity.go`（账号链接策略）和 `internal/app/authreq.go` 不需要为了接 authcore 而做无状态化改造**——账号链接怎么做完全是 Report-Portal 自己的策略，不需要满足任何共享库的接口签名。真正需要"收窄接口、摘掉 `*Server` 依赖"的文件缩小到 `oidc.go`/`saml.go`/`passkey.go`/`audit.go`/`sso_provider.go` 这 5 个（`throttle.go` 经复核本来就不依赖 `*Server`/`*Store`，且本轮 `ratelimit` 改用 `httprate` 之后甚至不需要搬这个文件的计数器逻辑；`email.go` 对应 P2 的 `mail/smtp`，优先级低，可以和其余四个分开排期）。

**分步解耦路径（必须先做，和接共享库是两件不同的事，不要在一个 PR 里混着做）**：

1. **盘点阶段**（0.5 人日）：对这 5 个文件（不再是 9 个）逐个跑：
   ```bash
   cd /Users/kazuha/Codes/StockAnalysisPrediction-Report-Portal
   grep -n 's\.' internal/app/{sso_provider,oidc,saml,passkey,audit}.go | wc -l
   ```
   （文件名已核对，与实际代码库一致）产出一张表：文件 → 用到的 `s.xxx` 成员列表 → 每个成员的真实类型（`*sql.DB`？`*Cache`？还是别的 `*Server` 自身状态）。这张表是后续拆分的依据，务必先做，不要边拆边发现漏了什么。

   **这条 `grep 's\.'` 命令只能算粗筛，不要直接拿它的计数当"耦合程度"看**：本轮复核发现，这些文件里 `s` 这个变量名同时被 `func (s *Server) ...` 和 `func (s *Store) ...` 两种完全不同的方法接收者使用，`grep 's\.'` 不区分这两种，会把"访问 `*Store`（已经是收窄过的存储层，本来就该留在 Report-Portal 里，不算强耦合）"和"访问 `*Server`（真正焊死、必须解耦的部分）"混在一次计数里。实测：
   ```bash
   for f in sso_provider oidc saml passkey audit; do
     file="internal/app/$f.go"
     echo "$file: server_receiver_funcs=$(grep -c '^func (s \*Server)' "$file") store_receiver_funcs=$(grep -c '^func (s \*Store)' "$file")"
   done
   ```
   跑出来 `sso_provider.go`（0 个 `*Server` 方法，7 个 `*Store` 方法）**已经基本没有"焊在 Server 上"的问题**，真正需要下面第 3 步"收窄接口"的重活集中在 `oidc.go`/`saml.go`/`passkey.go`（`*Server` 方法数明显更多）以及 `audit.go` 的部分函数。盘点阶段产出的那张表**必须按"是 `*Server` 方法还是 `*Store` 方法"分列**，而不是笼统写一个 `s.` 总数；后面第 3 步的工作量应该按这张表分文件排优先级，而不是假设 4~5 个文件难度均等。

2. **抽取无状态辅助函数**（0.5 人日）：`likeOp` 这类纯函数式的 SQL 辅助工具，直接提到一个独立的包（不进 authcore，留在 Report-Portal 内部），去掉对 `*Server` 的隐式依赖。

3. **把数据库访问收窄成显式接口**（1~1.5 人日）：把这几个文件里对 `s.db`/`s.st` 的直接访问，改成接收一个显式传入的、范围更小的接口（例如 `type ssoStore interface { GetProvider(slug string) (...); ... }`），由 `*Server` 在构造时把自己的 db 句柄包一层传进去。这一步做完之后，这几个文件应该不再直接引用 `*Server` 类型。

4. **验收这一步单独完成**：

   ```bash
   grep -c 's\.' internal/app/{sso_provider,oidc,saml,passkey,audit}.go
   go build ./... && go test ./...
   ```

   验收标准：上面 grep 的计数应显著下降（目标是降到个位数或 0，剩余的如果是无法避免的必须逐条说明原因）；`go build`/`go test` 全部通过；且这一步产出一个独立的 PR，**不携带任何 authcore 依赖**，先合并，让 Report-Portal 的解耦本身先稳定下来。

5. **接共享库**（在第 4 步的基础上，1~1.5 人日）：这时候 `audit.Writer`/`saml.ReplayStore`/`saml.KeySource`/`oidc.Directory` 等接口的实现只是把第 3 步已经抽出来的显式接口再包一层适配，工作量会明显小于"直接从焊在 Server 上的状态开始接"。

**Report-Portal 同时是增量能力的贡献方，不是单纯的迁移对象**——以下几项在设计 authcore 时应直接采用 Report-Portal 现有实现作为参考起点，而不是被推倒重来：

1. discovery 持久化缓存 + issuer 校验（并入 `oidc` 包对 `zitadel/oidc` 的 `Directory` 实现参考）
2. passkey 强制第二因子 + `RequireStepUpToEnroll` 策略
3. trusted-proxy XFF 解析的现状经验（虽然 `ratelimit` 包本身改用 `middleware.ClientIPFromXFFTrustedProxies`，但 Report-Portal 现有 `throttle.go` 里"哪些请求该被限流"的判断逻辑仍是有价值的参考）

（账号 `LinkBy` 策略和 `identity.go` 里的账号链接设计，因为账号模型层已经不进 authcore，不再作为"贡献给共享库"的内容，继续留在 Report-Portal 自己的代码和文档里。）

- `internal/app/sso_provider.go` 的多 Provider 目录直接对应共享库 `oidc.Directory`，适配成本低。
- SAML SP 密钥管理用 `saml.GeneratedKeySource`，`SecretStore` 接口直接包一层现有的 `openSecret`。

**工作量估计**：解耦前置工作 2~2.5 人日（盘点 0.5 + 抽取辅助函数 0.5 + 收窄接口 1~1.5）+ 接共享库 1.5~2 人日 = **3.5~4.5 人日**（比上一版 5.5~7.5 人日明显下降，主要来自：`identity.go`/`authreq.go` 不再需要解耦，涉及文件从 9 个缩小到 5 个）。仍然建议放在 AlertHub、PSP 都接过至少一个批次、共享库接口已经稳定之后再做。

### 6.4 Passwall-Node——消费方，改动最小

- 只涉及 689 行 SSO 客户端侧代码 + 116 行 config。改动是把它现有对接 PSP SSO 端点的客户端逻辑，确认协议字段与 authcore 归一化后的 `oidc.Claims`/`saml.Assertion` 序列化格式兼容（如果 Node 是直接调 PSP 暴露的 HTTP 端点而不是直接依赖 Go 包，可能根本不需要加 `go.mod` 依赖，只需要确认 PSP 切换后端点返回的 JSON 结构没变）。
- **工作量估计**：0.5~1 人日，不变，主要是回归测试，不是代码改动。

---

## 7. 顺带要修的：两个失效的 module 路径

**这是本次迁移里必须一并处理的技术债，不是可选项**——两个 go.mod 目前指向的路径已经不对应真实仓库位置，如果不修，`go get github.com/KazuhaHub/...` 这种标准拉取方式对这两个项目会失败。

### 7.1 AlertHub

```
现状：module github.com/kazuha/alerthub
应为：module github.com/KazuhaHub/AlertHub
```

修复步骤：

```bash
cd <AlertHub 真实本地 clone 路径，见 0.3 步确认结果>
sed -i '' 's#module github.com/kazuha/alerthub#module github.com/KazuhaHub/AlertHub#' go.mod
grep -rl 'github.com/kazuha/alerthub' --include='*.go' . | xargs sed -i '' 's#github.com/kazuha/alerthub#github.com/KazuhaHub/AlertHub#g'
go build ./...
```

**验收标准**：`grep -r 'github.com/kazuha/alerthub' --include='*.go' .` 无任何输出（全部替换干净）；`go build ./...` 通过。

### 7.2 Report-Portal

```
现状：module github.com/KKazuhaK/StockAnalysisPrediction-Report-Portal
应为：module github.com/KazuhaHub/StockAnalysisPrediction-Report-Portal
```

修复步骤同上（换路径、换仓库）：

```bash
cd /Users/kazuha/Codes/StockAnalysisPrediction-Report-Portal
sed -i '' 's#github.com/KKazuhaK/StockAnalysisPrediction-Report-Portal#github.com/KazuhaHub/StockAnalysisPrediction-Report-Portal#' go.mod
grep -rl 'github.com/KKazuhaK/StockAnalysisPrediction-Report-Portal' --include='*.go' . | xargs sed -i '' 's#github.com/KKazuhaK/StockAnalysisPrediction-Report-Portal#github.com/KazuhaHub/StockAnalysisPrediction-Report-Portal#g'
go build ./...
```

**验收标准**：同上，grep 无输出、`go build ./...` 通过。

**时机建议**：这两个修复应该**在第 6.3/6.2 节各自项目切换到 authcore 的同一个 PR 里顺带做完**，不要单独开一轮 PR——因为改 module 路径本身会导致所有内部 import 语句跟着变，如果先单独改一次、再在切换 authcore 时改一次，中间会有两次大范围 import 路径变更，容易互相冲突增加 review 难度。两件事一起做，一次性把 import 路径改对。

---

## 8. 许可证与合规

### 8.1 为什么 authcore 必须是 Apache-2.0

- 消费方许可证现状：PSP / AlertHub / Report-Portal 是 AGPL-3.0，Passwall-Node 是 Apache-2.0。
- Apache-2.0 是宽松许可证，允许被任何许可证（包括 AGPL-3.0）的项目引用而不产生许可证冲突——这是单向兼容：**宽松协议的代码可以被更严格协议的项目吸收，反过来不行**。
- 如果 authcore 选择 AGPL-3.0，Passwall-Node（Apache-2.0）引用它会带来争议：AGPL-3.0 的强 copyleft 条款是否会要求 Node 也变成 AGPL-3.0 尚无定论（AGPL 的"网络使用即分发"条款传染范围本身在业界都有争议），没有必要为了省一次许可证选择而给 Node 埋下法律不确定性。
- 结论：authcore 选 Apache-2.0，是唯一能让 4 个项目（3 AGPL + 1 Apache）同时无障碍引用的选择。

### 8.2 双授权依据

authcore 里搬迁自 AGPL-3.0 项目（PSP、AlertHub、Report-Portal）的代码，其著作权人（根据第 3.4 节核实的提交历史，PSP 是 kazuha 本人 + Claude 生成，AlertHub/Report-Portal 同样是 kazuha 本人 + Claude 生成，没有第三方版权人）有权决定以何种许可证重新发布自己拥有著作权的代码。因为：

1. 三个源项目（PSP/AlertHub/Report-Portal）的 auth/audit 相关文件，经第 3.4 节和 0.1 步的逐文件核实，**版权仅归属 kazuha 本人**（`Claude <noreply@anthropic.com>` 提交按 KazuhaHub 组织现有的贡献惯例视为 kazuha 名下的工作产出，不构成独立版权主张）。
2. kazuha 作为这些文件的著作权人，有权把自己拥有完整著作权的代码以 Apache-2.0 重新发布到 authcore，同时原项目继续以 AGPL-3.0 许可这些代码的历史版本——这是标准的"著作权人对自己作品的双重授权"（dual licensing），不需要额外的法律文书，但**建议在 authcore 仓库的 README 里写一句明确声明**：

   > "本仓库部分代码最初以 AGPL-3.0 发布于 KazuhaHub 组织下的 Passwall-Sub-Panel / AlertHub / StockAnalysisPrediction-Report-Portal 仓库，著作权人（kazuha）现以 Apache-2.0 重新授权这部分代码用于本仓库。"

3. **唯一的例外和硬性前提**是第 3.4 节和阶段 0.1 步反复强调的：**任何被 0.1 步复核出有 MLChinoo（或其他第三方）参与的文件，不能援引上述"著作权人自我双授权"的逻辑**，必须先取得该第三方的书面同意才能进入 Apache-2.0 的 authcore。这条检查不能跳过，也不能事后补——一旦代码发布到 public 仓库，撤回的实际效果有限（历史 commit、fork、镜像都可能已经留存）。

### 8.3 第三方依赖许可证清单（authcore 的 go.mod 会直接依赖这些库，本轮因 oidc/ratelimit 改用现成库而更新）

| 依赖 | 许可证 | 用途 |
|---|---|---|
| `github.com/zitadel/oidc/v3` | Apache-2.0 | OIDC RP（**本轮新增**，替代上一版计划里直接实现协议握手的方案，薄封装 `pkg/client/rp`） |
| `github.com/crewjam/saml` | Apache-2.0 | SAML SP |
| `github.com/go-webauthn/webauthn` | BSD-3-Clause | WebAuthn/passkey |
| `github.com/mojocn/base64Captcha` | Apache-2.0 | 图形验证码 |
| `github.com/oschwald/maxminddb-golang` | ISC | geoip 数据库读取 |
| `github.com/go-chi/httprate` | MIT | ratelimit 计数器（**本轮新增**，替代自研定长窗口计数器） |
| `github.com/go-chi/chi/v5` | MIT | `middleware.ClientIPFromXFFTrustedProxies`（**本轮新增**，替代自研 XFF 解析） |

以上全部是宽松许可证（Apache-2.0 / BSD-3-Clause / ISC / MIT），与 authcore 自身的 Apache-2.0 定位兼容，不会引入 copyleft 传染。**执行者在 `go mod tidy` 产出最终依赖列表后，需要重新核对这张表与 `go.sum` 实际列出的间接依赖是否有遗漏**（间接依赖也要过一遍许可证扫描，可以用 `go-licenses check ./...` 这类工具自动跑一遍；`zitadel/oidc` 和 `go-chi/chi` 会各自带入一批间接依赖，务必扫一遍再定稿）。

### 8.4 MLChinoo 复核结论重申

已核实的结论（基于本次调研中读取到的文件列表）：MLChinoo 的 14 个提交集中在 `node_repo*`、`sui/*`、`ruleset_repo*`、`domain/types.go`、`nodespec/*`、`health/*`、`proxy_group*`、`admin_node*`/`admin_rules*` 等代理领域路径，与本次计划迁入 authcore 的 auth/audit 相关文件（`config/oidc.go`、`config/saml.go`、`service/auth/*.go`、`service/passkey/*.go`、`adapters/sqlstore/oidc_config_repo.go`/`saml_config_repo.go`/`saml_replay_repo.go`/`webauthn_credential_repo.go`）**没有路径重叠**。

**这是"没发现重叠"，不是"验证完毕"**——阶段 0.1 步的逐文件 `git log --follow` 复核是正式迁移前的强制门槛，不能用本文档里的结论代替那一步实际执行。若 `domain/types.go` 因为同时承载了用户/SSO 相关字段定义而被认为与 auth 有关联，需要特别注意：调研已确认 MLChinoo 对 `domain/types.go` 的改动"集中在代理领域"，但这个文件本身混合了多个领域的类型定义，**迁移时如果要把 `domain/types.go` 里与 auth 相关的类型定义搬进 authcore，必须先确认 MLChinoo 具体改过的是文件里的哪些行**（`git log -p --follow -- internal/domain/types.go` 逐个 diff 看行号范围），而不是因为文件级别的作者列表里有 MLChinoo 就一刀切排除整个文件，也不能因为"大部分不相关"就整体照搬。

---

## 9. 风险清单

| 风险 | 触发条件 | 缓解措施 |
|---|---|---|
| **生产回归**：接入后某项目的登录/审计功能在生产环境出现异常 | 第 5/6 节验收标准里某一步的测试覆盖不到的边界情况（例如某个 IdP 的非标准 claim 格式）在生产流量里才暴露 | 每个项目按协议逐个提交、逐个验收，不一次性合并；每次合并后打回滚锚点 tag；因为不再强求同步，建议先在 AlertHub（三者里用户量最小最新）只接批次 2 的 `saml`，观察至少 1 周无异常后再推 PSP/Report-Portal |
| **共享库变成垃圾桶**：后续有人往 authcore 里加各项目专属逻辑，破坏"协议/机制层"边界 | 没有明确的 PR 准入标准，出于"顺手"心态把项目特定代码（尤其是账号模型/租户逻辑，正是上一版被砍掉的部分）塞回共享库 | 在 authcore 的 `CONTRIBUTING.md` 里写死一条规则："新增代码必须不依赖任何具体消费方的类型/框架，不得引入账号/组织/租户语义，且至少被两个消费方使用才能进入 authcore；只服务一个项目的代码、或者试图统一账号模型的代码一律留在该项目自己的仓库"；PR 模板里加一个复选框强制确认这条 |
| **共享安全模块的单点风险**：三个项目的协议/安全代码集中到一个仓库后，authcore 一旦出现漏洞，影响面从"一个项目"变成"三个项目同时中招" | authcore 的某个协议实现（尤其是 `saml`/`oidc` 这种密码学相关代码）被发现漏洞。**这不是假设性风险**——第 2 节已经列出 `crewjam/saml` 本身过去 5 个安全公告（2 个 CRITICAL：签名校验绕过、多重 Assertion 签名绕过），如果 authcore 的 `saml` 包引入类似缺陷，PSP/AlertHub/Report-Portal 会同时暴露 | 这是抽取共享库的固有代价，用以下方式对冲：(1) 每次 authcore 发布新 tag 前跑 `govulncheck ./...`；(2) 各消费方升级 authcore 版本走阶段 6 的逐项目验收流程，不做"自动跟随最新版"这种会瞬间扩散风险的机制；(3) 安全相关变更（尤其 `saml`/`oidc`/`passkey` 包）的 PR，即使只有 kazuha 一人 review，也要求间隔至少一天冷静期再合并，不当天写当天发版；(4) 三个项目**不强求同一时刻升到同一 authcore 版本**（本轮交付方式的改动），一旦某个版本出问题，还没升级的项目不受影响，天然降低了"三个项目同时中招"的概率 |
| **单人维护下发版成瓶颈**：kazuha 是唯一深度理解三个项目差异的人，authcore 发新版本、各消费方跟进升级都依赖他一人排期 | 组织只有 4 人，FeiFei-SS/danikahe 对三个项目细节了解程度未知（本次调研未覆盖），MLChinoo 只熟悉代理领域 | 短期内接受这个瓶颈是既定现实，不强行分摊；authcore 的 README/ADR 要写得足够详细（尤其是 `Policy`/`KeySource` 这类"必须显式选择、没有默认值"的接口，必须在文档里逐项解释后果），降低未来交接给他人的门槛；每个协议包的关键安全设计决策（replay 防护、哈希链、trusted-proxy 解析）单独写 ADR，不要只写在代码注释里；因为本轮改成按包增量交付，单次发版的改动面变小，冷静期/review 负担也相应分散，缓解了"一次性大版本"对单人瓶颈的压力 |
| **"抽错抽象"：某个已抽取的包实际上无法在不修改语义的情况下同时服务三个项目** | 出现下列任一信号：(a) 为了让某个消费方能用，不得不往包的公开接口加只对它有意义的字段/选项（例如只有 Report-Portal 需要的一个 flag）；(b) 同一个接口在两个消费方那里被以完全不同的方式解释，导致文档里必须写"如果你是 XX 项目就这样用，如果是 YY 项目就那样用"；(c) 修一个 bug 要同时改三个项目的调用代码才能避免行为倒退——这正是上一版 `identity`/`authflow` 出现过的问题，也是本轮把它们砍掉的直接原因 | 出现以上信号时，把该包**退回**到各项目自建实现：该包的消费方各自 `go get` 停在当时的最后一个正常版本（不再升级），把接口实现直接拷贝进自己仓库改名（不再 import authcore），authcore 侧对应包标记 `Deprecated` 并在 README/ADR 里说明退出原因，不删除历史版本（已发布的 tag 不可变，遵守 Go module 的不可变发布约定）。这不是失败，是"机制 vs 策略"判断在实践中出现偏差后的正常纠正，比硬撑一个不合适的抽象成本更低——阶段 -1 的共享安全测试套件本身也是提前发现这个信号的机制之一 |
| **第三方贡献者版权**：MLChinoo 或未来的其他贡献者对已迁入 authcore 的代码提出版权异议 | 阶段 0.1 的复核有遗漏，或未来 MLChinoo 在别的文件（如 `domain/types.go`）里补充过 auth 相关改动但没被发现 | 见第 8.4 节；此外，authcore 仓库应长期保留原始迁移 PR 的完整 diff 与来源说明（迁移自哪个仓库的哪次 commit），一旦出现异议可以精确定位争议代码的来源和作者，不要用 squash 合并抹掉迁移历史 |
| **Report-Portal 前置重构引入新 bug** | 阶段 6.3 的"焊在 Server 上"解耦本身是一轮有实质代码改动的重构，不是纯粹的搬迁（虽然本轮范围比上一版缩小到 5 个文件） | 严格按第 6.3 节要求，把"解耦"和"接共享库"拆成两个独立 PR；解耦 PR 合并后单独跑一轮完整回归测试（如果 Report-Portal 目前没有 auth/audit 相关的集成测试，这轮重构前必须先补，否则无法验证行为没变） |
| **go.mod 路径修复引入的连锁改动被漏改** | 第 7 节的 sed 替换如果遗漏了某个非 `.go` 文件里的路径引用（如 CI 配置、Dockerfile、文档里写死的 import 路径） | 替换后额外跑一次 `grep -r 'KKazuhaK\|kazuha/alerthub' . --exclude-dir=.git`（不限 `.go` 后缀），确认整个仓库没有遗留旧路径引用，包括 `.github/workflows/*.yml`、`README.md` 里的 badge 链接等 |
| **审计哈希链上线瞬间"链已损坏"假警报** | PSP/Report-Portal 现在的 `audit_log` 表没有 `prev_hash`/`hash` 列（PSP 实测为 `schema.go` 里的 GORM 模型 `auditRow`，走的是 AutoMigrate，新增列会是 NULL 而不是历史补算出来的哈希）。切换到 `audit.HashChain(...)` 装饰器后，如果不做任何处理就对全表跑 `audit.Verify()`，**上线前的所有历史行必然因为没有 `prev_hash` 而被判定"链断裂"**，这不是真的被篡改，是迁移本身造成的假阳性 | 阶段 3.3/6.x.4 里 PSP/Report-Portal 接入 `audit.HashChain` 时必须显式规定"哈希链从哪一行开始生效"（对应 `audit.Verify(ctx, r, anchor)` 的 `anchor` 参数），并在迁移 PR 里写清楚：迁移前的历史行不参与验证、只有迁移之后新写入的行才进入链；验收标准不是"对全表 Verify 通过"，而是"对迁移时间点之后的新行 Verify 通过，且迁移 PR 描述里注明了 anchor 位置"。anchor 具体用什么形式记录（PR 描述文本？DB 里一条特殊锚点行？代码里的硬编码常量？）尚未拍板，见第 11 节新增的待决问题 |

---

## 10. 工作量（authcore 包本身的搬迁/封装，按人日，假设只有 kazuha 一人执行）

| 优先级 | 包 | 人日 | 说明 |
|---|---|---:|---|
| P0 | `captcha` | 0.5 | 纯包装 `mojocn/base64Captcha`，无状态无账号语义 |
| P0 | `geoip` | 0.5 | 纯包装 `oschwald/maxminddb-golang` |
| P0 | `ratelimit` + XFF | 1.5 | 基于 `go-chi/httprate` + `middleware.ClientIPFromXFFTrustedProxies` 做薄封装，不从零写 |
| P1 | `saml`（replay 缓存 + SP 元数据/密钥管理） | 4~5 | 市面确认无解，需先过阶段 -1 的门槛 |
| P1 | `passkey`（WebAuthn ceremony 会话） | 3~4 | 市面确认无解，需先过阶段 -1 的门槛 |
| P1 | `audit`（事件模型 + 可选哈希链） | 2~3 | 必须以不透明 `Actor` 字符串设计，需先过阶段 -1 的门槛 |
| P2 | `oidc`（state/nonce） | 2 | 基于 `zitadel/oidc` 的 `rp` 包，state/PKCE 基本不用自己写，只剩 nonce 校验接线 |
| P2 | `mail-smtp` | 1 | 低风险纯工具，与身份编排关系不大，可延后 |
| ~~砍~~ | ~~`identity`~~ | 0 | 见第 2 节：这是策略层，不是机制层，不应该被统一 |
| ~~砍~~ | ~~`authflow`~~ | 0 | 同上 |

**P0 + P1 合计约 11.5~14.5 人日**——这是本文档给出的核心估算，覆盖 authcore 自身的搬迁/封装工作（不含三个项目各自的接入成本，接入成本见第 6 节，本轮同样下调）。P2（`oidc`/`mail-smtp`，约 3 人日）优先级最低，可以作为独立的第 4 个批次延后排期，不计入核心估算。

**为什么比原估算（约 20.75~24.75 人日）低将近一半：**

1. **砍掉 `identity`/`authflow`**——上一版这两个包本身的搬迁估算是 3 人日（阶段 3），且它们是驱动三个项目"适配估算"里最贵部分的直接原因（每个项目都要写一层满足 `identity.Resolver` 签名的适配代码）。砍掉之后，authcore 侧省下 3 人日，三个项目侧的适配估算也相应下调（见第 6 节，PSP 从 4~5 降到 2~3，AlertHub 从 2.5~3.5 降到 1.5~2.5，Report-Portal 从 5.5~7.5 降到 3.5~4.5）。
2. **`ratelimit`/`oidc` 改薄封装现成库**——不再从零实现定长窗口计数器、XFF 解析、OIDC state/PKCE 处理，工作量直接对应"写胶水代码"而不是"写协议实现"。
3. **不再需要为"一次性迁移"预留 2 人日缓冲**——上一版因为要求连续冻结、三项目同步切换，接口设计一旦要返工代价很大，所以预留了缓冲；本轮按包增量交付，每个批次独立验证、独立上线，接口设计的试错成本被拆散到多个小批次里，不需要一次性预留大块缓冲。
4. **阶段 -1 的共享安全测试套件本身是一种风险前移**——用 1~3 人日提前验证 P1 三个包是否真的值得抽，避免在 P1 上投入 9~12 人日后才发现某个包其实抽错了（对应第 9 节"抽错抽象"风险），这个前置投入本身没有计入上面的 P0+P1 合计，是额外但值得的支出。

---

## 11. 交接清单：开工前需要什么

**权限/工具**：

- [ ] GitHub 组织 `KazuhaHub` 下创建新仓库的权限（建 `authcore`）
- [ ] 四个现有仓库（PSP、Passwall-Node、AlertHub、Report-Portal）的 push 权限（已有，kazuha 是 owner/admin）
- [ ] AlertHub 的**真实本地 clone**（当前只在 `/tmp/claude-501/dup/AlertHub` 这个临时挂载点下有副本，阶段 0.3 步需要先确认并建立一个不会随会话结束消失的本地 clone 路径，建议 `/Users/kazuha/Codes/AlertHub`，与其他三个项目并列）
- [ ] 本机 Go 工具链：已确认为 1.26.3，满足 `go 1.26.0`/`toolchain go1.26.8` 要求（工具链版本高于声明版本即可，`go build` 会自动处理）
- [ ] `gh` CLI 已登录且对 `KazuhaHub` 组织有效（用于阶段 1.1 建仓）
- [ ] （可选，用于第 8.3 节许可证扫描）`go-licenses` 工具：`go install github.com/google/go-licenses@latest`
- [ ] （可选，用于第 9 节风险缓解）`govulncheck` 工具：`go install golang.org/x/vuln/cmd/govulncheck@latest`

**需要 kazuha 本人回答的问题**：

1. **MLChinoo 版权确认的兜底方案**：如果阶段 0.1 的逐文件复核意外发现某个计划迁移文件有 MLChinoo 的提交历史，是优先联系 MLChinoo 取得同意，还是直接放弃迁移那个文件、改为在 authcore 里重写一份等价逻辑？（本文档默认前者优先，后者兜底，需要 kazuha 确认这个优先级对不对）*——尚未回答，未受本轮修订影响。*
2. **AlertHub 的本地 clone 路径**：仓库地址本身已经确认（`/tmp/claude-501/dup/AlertHub` 的 `git remote -v` 指向 `https://github.com/KazuhaHub/AlertHub.git`，本轮复核已跑过，不用再问 kazuha 这一点），但还是需要 kazuha 确认：把它 clone 到 `/Users/kazuha/Codes/AlertHub`（与其他三个项目并列）可以吗，还是有其他偏好路径——后续所有操作都要在这个固定路径下进行，不能继续依赖会话结束就消失的 `/tmp` 副本。*——尚未回答，未受本轮修订影响。*
3. **各项目接入 PR 的 review 节奏**：文档默认"每个协议单独提交、每次合并后打 tag"，但没有 CI required checks（组织现状是"暂无 required checks"）。是否需要在这轮迁移里顺便给三个仓库加上 CI（至少 `go build`/`go vet`/`go test` 的 GitHub Actions），还是继续手动跑验收命令？如果要加 CI，这是本计划之外的额外工作量，需要 kazuha 决定是否纳入本轮排期。*——尚未回答，未受本轮修订影响。*
4. **AGPL 双授权声明的确切措辞**：第 8.2 节给出的声明文本是本文档拟的草稿，正式发布前建议 kazuha 过一遍或找人核对法律表述是否准确（本文档执行者不是法律顾问，这条声明只是操作性建议，不构成法律意见）。*——尚未回答，未受本轮修订影响。*
5. ~~**Report-Portal 前置解耦是否要单独排期**~~——**这个问题已经被本轮修订回答**：第 2 节决策三（分发形态/交付方式）和第 5 节明确"按包增量、3~4 个独立批次，不强求三项目同步切换"，Report-Portal 完全可以作为独立批次单独排期，不需要 kazuha 再决定"是否要等 AlertHub/PSP 切换完再做"这件事本身。**残留的小问题**：具体排在第几批、是否和 PSP/AlertHub 的某个批次并行，仍需 kazuha 在阶段 6 开始前按当时三个项目的迭代节奏拍板，但这只是排期细节，不再是阻塞性问题。
6. **（新增）`ratelimit`/`mail-smtp` 用哪种搬迁方式**：`mail-smtp` 在第 5 节阶段 2.4 已给出两个选项——(1) 先在源项目开小 PR 物理挪文件保留部分历史，(2) 直接手写不保历史。需要 kazuha 选一个再开始执行，不要由执行者自行决定后在 PR 描述里才说明（`ratelimit` 本身因为改用 `httprate` 已经不存在这个选择，只有 `mail-smtp` 还需要这个决定）。
7. **（新增）审计哈希链 anchor 怎么记录**：第 9 节风险清单已要求"迁入 `audit.HashChain` 时必须显式记录 anchor"，但记录形式未定——是写进迁移 PR 描述里的一行文本、在 `audit_log` 表里插入一条特殊的"锚点行"、还是在消费方代码里硬编码一个生效时间戳/ID 常量？三种方式的实现成本和可维护性不同（PR 描述文本最省事但容易在未来被遗忘，锚点行最可靠但需要多写一点代码，硬编码常量介于两者之间），需要 kazuha 或执行者在阶段 6.x.4 之前选定一种，并写进对应项目的 ADR，不要让 PSP 和 Report-Portal 各自选了不同的方式。

---

*本文档所有行数、文件路径、go.mod 内容均为实测所得（前期调研的 `wc -l` 统计 + 本次 `cat go.mod` 直接核对），标注"未验证"或"需要执行前核实"的地方是因为本次调研没有逐一确认精确文件路径/行号/第三方库 API 签名，执行者在对应步骤里已给出核实命令，执行前务必先跑一遍核实，不要直接假设文档里的路径或库签名与实际情况完全一致。本版新增的 build-vs-buy 调研结论（19+11 个候选扫描、`crewjam/saml` 的 5 条安全公告、`middleware.ClientIPFromXFFTrustedProxies`/`rp.AuthURLHandler` 源码级核实）来自本轮调研，具体依赖库的版本号和确切函数签名请在开工时用 `go doc` 重新核对一遍，本文档不代替那一步。*
