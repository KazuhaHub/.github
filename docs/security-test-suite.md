# 共享安全测试套件设计（阶段 -1）

- 文档状态：待 kazuha 确认后执行
- 面向读者：没有读过 `shared-modules-plan.md` 全部讨论的工程师——本文自包含
- 与 `docs/shared-modules-plan.md` 的关系：本文档是该计划**阶段 -1** 的详细设计，是 P1（`saml`/`passkey`/`audit` 三个包）能不能抽取共享库的前置门槛，先跑完本文档的测试套件、拿到复用率报告，再回到主计划第 5 节阶段 3 决定要不要继续。

---


> **本文档的三个已决事项**（2026-09-16，依据实测证据，执行者不需要再问）
>
> 1. **预算接受 3.25~3.75 人日**，高于原定的 1~3 人日。理由：这是整个计划里投入产出比最高、
>    风险最低的一段——用 0.75 人日换完整的安全测试覆盖是划算的。不要为了压回预算砍用例。
> 2. **GHSA-267v-3v32-g6q5（XSS via missing Binding syntax validation）确认不适用，标记为"不适用"即可，
>    不需要执行者再去 grep 验证。** 实测依据（2026-09-16）：对三个仓库跑
>    `grep -rn 'saml\.IdentityProvider|samlidp\.' --include='*.go'`，
>    Passwall-Sub-Panel / AlertHub / Report-Portal **IdP 角色命中均为 0**，三者均为纯 SP 角色，
>    而该漏洞发生在 SAML IdP 校验第三方 SP 元数据的路径上。
> 3. **当前依赖版本已实测，无未修漏洞**——`crewjam/saml` 的全部 5 条公告修复于 ≤ v0.4.14，
>    三个项目分别为 v0.4.14 / v0.5.1 / v0.5.1；`go-webauthn/webauthn`(v0.17.4 三方一致) 与
>    `coreos/go-oidc`(v3.20.0/v3.18.0/v3.20.0) **均为零公告**。
>    因此本套件的价值不是"救火"，而是**防回归**：确保将来升级或改动不会把已有防护弄丢。
>
> **顺带发现的真实问题（不属于本套件范围，但应记入 plan 的风险清单）**：
> Passwall-Sub-Panel 的 `crewjam/saml` 停在 **v0.4.14，正好是最后一条公告的修复线，零余量**，
> 而另外两个项目已在 v0.5.1；`coreos/go-oidc` 同样存在漂移（AlertHub v3.18.0 落后两个小版本）。
> **这种版本漂移正是重复实现的直接症状**，也是共享模块最容易兑现的收益：一处升级、三处同时生效。


## 1. 为什么需要这一步

`shared-modules-plan.md` 第 2 节把 `saml`/`passkey`/`audit` 归为"市面确认无解、必须自研"的 P1 包，估算工作量 9~12 人日。这个估算基于**代码走读和行数统计**（三个项目各自实现了多少行、大致结构像不像），不是基于**运行时行为的实测**。

这里有一个盲点：两段代码"看起来结构差不多"，不等于"运行时行为一致"。例如：

- 三个项目都有一个叫"SAML replay 防护"的函数，但如果 AlertHub 的实现实际上只检查了时间窗口、没有真正记住 assertion ID，它和 PSP 的实现在**代码结构**上可能很像（都在校验一个时间戳），但在**安全行为**上完全不是一回事——抽出来的共享包如果照着"结构相似"的假设设计接口，会把这个真实差异掩盖掉。
- 反过来，如果三个项目的实现在**行为**上高度一致（同样的攻击输入产生同样的拒绝结果），那即使代码写法不同，抽取共享库的价值也更确定。

所以在投入 9~12 人日之前，先用 1~3 人日写一套**只依赖公开可观察行为、不读任何项目内部代码**的测试套件，直接对三个项目现有的实现跑同一批攻击/边界用例，把"看起来像不像"换成"行为一不一致"。

**测试用例的攻击构造依据**：下面 SAML 部分的 5 个用例逐条对应 `shared-modules-plan.md` 第 2 节列出的 `crewjam/saml` 5 条真实安全公告，攻击原理和受影响版本号均来自公开的 GitHub Security Advisory 页面（`github.com/crewjam/saml/security/advisories/<GHSA-ID>`）核实，不是凭 CVE 编号猜的。三个消费项目当前锁定的 `crewjam/saml` 版本是否已经包含对应修复，**需要执行者在跑测试前先用 `go list -m -json github.com/crewjam/saml` 逐项目核实一遍**——如果版本已经高于修复版本，对应用例预期是"通过"（库层面已经修了），如果仍在受影响版本区间，才预期是"能复现漏洞行为"；本文档不假设三个项目当前用的是哪个版本。

## 2. 设计原则：零耦合

- **不 import 任何项目的内部包**——测试套件只通过每个项目已有的公开接口（HTTP 端点、CLI、或者一个专门导出的最小测试 hook）驱动，不读 `internal/` 下的任何类型。
- **不改任何项目一行代码**——这一步的产出是"发现了什么"，不是"修了什么"。如果发现 AlertHub 没有 replay 防护，测试套件如实记录"失败"，不去帮 AlertHub 补上（补上是阶段 3/6 的事）。
- **不依赖 authcore**——此时 authcore 仓库可能还没建，或者只完成了批次 1（P0）。这套测试套件完全独立，可以在 authcore 项目开始之前就先跑。
- **测试套件本身可以长期留用**——完成一次性评估之后，建议把它整理成三个项目 CI 里都能跑的一个共享测试集（各自的 CI 配置里指向同一个测试用例仓库/子模块），持续监控三家的安全行为有没有随时间漂移。这也是它比"读代码给出印象"更有长期价值的地方。

## 3. 测试目标怎么驱动——两种模式，按项目现状选

三个项目都是 Go 单二进制服务，最直接的驱动方式是**跑一个真实实例 + 发 HTTP 请求**，而不是导入内部包直接调函数（那样就不是零耦合了）。具体两种模式：

1. **HTTP 黑盒模式（优先）**：用 `docker compose` 或直接 `go run` 起一个测试用的项目实例（用测试专用配置：本地 SQLite/内存存储、mock IdP），测试套件作为独立的 Go 测试二进制，只通过 HTTP 请求驱动被测服务的 SAML ACS 端点、WebAuthn ceremony 端点、审计查询端点，断言 HTTP 响应/状态码/副作用（例如再查一次审计日志，确认没有多出一条）。
2. **协议 fixture 重放模式（用于 replay 防护）**：对 SAML replay 这类用例，测试套件自己构造一份合法签名的 SAML Response（用一个测试用的 IdP 私钥签），先发一次拿到成功响应，再发第二次同样的 assertion，断言第二次被拒绝。这一步不需要真的跑通完整登录流程，只需要能打到 ACS 端点。

三个项目选哪种模式、需要起哪些依赖服务（数据库、mock IdP），执行者在动手前先针对每个项目单独确认一遍，写进执行记录里，不要假设三个项目的本地起服务方式完全一样。

**测试套件本身的运行方式（补充说明，避免执行者不知道怎么落地成代码）**：整套测试写成一个独立的 Go module（建议 `kazuhahub-github/docs/security-test-suite/`，见第 5 节），入口是标准 `go test`，被测服务的地址通过环境变量传入（例如 `SECTEST_BASE_URL=http://localhost:8080`），不写死任何项目的默认端口——三个项目本地起服务用的端口不一定一样，写死会导致换个项目跑就要改代码。下面每个用例给出的 Go 骨架都遵循这个约定。

## 4. 测试用例清单（按 P1 的三个候选包分组，另加 OIDC 与限流/XFF 两组）

### 4.1 SAML assertion replay 与已知 CVE 复现

对应 `shared-modules-plan.md` 里"AlertHub 至今没有这个防护"的结论，以及第 2 节列出的 `crewjam/saml` 5 条安全公告。下表是总览，逐条的攻击构造细节和 Go 骨架在 4.1.1~4.1.6 展开——**总览表本身不是可执行的规格，只是索引，真正要照着写代码的是后面的子节**。

| 编号 | 用例 | 对应 GHSA | 期望行为 |
|---|---|---|---|
| 4.1.1 | 原样重放同一个 assertion | 无（不是某个 CVE，是协议层设计缺口） | 应该被拒绝 |
| 4.1.2 | 重放窗口边界 + 并发重放 | 无 | 90 秒内外都应该被拒绝；并发只有一次成功 |
| 4.1.3 | 签名校验类型混淆绕过 | GHSA-rrfw-hg9m-j47h（CVE-2020-27812） | 应该被拒绝 |
| 4.1.4 | 多重 Assertion 元素签名绕过 | GHSA-j2jp-wvqg-wc2g（CVE-2022-41912） | 应该被拒绝 |
| 4.1.5 | XML 往返解析不一致导致签名绕过 | GHSA-4hq8-gmxx-h6w9（CVE-2020-29509/29510/29511） | 应该被拒绝 |
| 4.1.6 | Deflate 解压炸弹拒绝服务 | GHSA-5mqj-xc49-246p（CVE-2023-28119） | 应该被限制大小、不应该导致进程崩溃 |
| 4.1.7 | ACS Binding 校验缺失导致的 XSS | GHSA-267v-3v32-g6q5（CVE-2023-45683） | **仅在项目同时扮演 SAML IdP 角色时适用**，见 4.1.7 的适用性说明 |

#### 4.1.1 原样重放同一个 assertion（核心用例，无关 CVE）

**攻击原理**：`crewjam/saml` 本身不做 assertion-ID 级的重放检测（第 2 节已核实源码），如果消费方也没有自己补上，攻击者截获一份合法的 SAML Response（例如通过浏览器历史、代理日志、网络中间人），可以在受害者会话之外再次提交同一份 Response，重新换取一个登录会话。

**输入构造**：用测试用的 IdP 私钥签发一份合法的 `<samlp:Response>`，包含一个未过期的 `<saml:Assertion>`（`NotOnOrAfter` 设在未来几分钟），先原样发送一次到被测项目的 ACS 端点，记录返回的会话（cookie 或 token）。不做任何修改，原样再发一次同一份 XML。

```go
package securitytest

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestSAML_ReplaySameAssertionRejected posts the exact same signed SAML
// Response twice and expects the second attempt to be rejected. The first
// call establishes a baseline (must succeed) so a failure there means the
// test fixture itself is broken, not the target.
func TestSAML_ReplaySameAssertionRejected(t *testing.T) {
	base := mustBaseURL(t) // reads SECTEST_BASE_URL, fails the test if unset
	acsURL := base + "/saml/acs"

	resp := mustSignedSAMLResponse(t, samlResponseParams{
		nameID:       "replay-test@example.com",
		notOnOrAfter: nowPlus(5 * time.Minute),
	})

	first := postSAMLResponse(t, acsURL, resp)
	if first.StatusCode >= 400 {
		t.Fatalf("baseline login failed, fixture is broken: got %d", first.StatusCode)
	}

	second := postSAMLResponse(t, acsURL, resp)
	if second.StatusCode < 400 {
		t.Errorf("replayed assertion was accepted (status %d), expected rejection", second.StatusCode)
	}
}

func postSAMLResponse(t *testing.T, acsURL, samlResponseXML string) *http.Response {
	t.Helper()
	form := url.Values{"SAMLResponse": {base64StdEncode(samlResponseXML)}}
	resp, err := http.PostForm(acsURL, form)
	if err != nil {
		t.Fatalf("POST %s: %v", acsURL, err)
	}
	return resp
}
```

（`mustSignedSAMLResponse`/`base64StdEncode`/`mustBaseURL`/`nowPlus` 是测试套件自己的 fixture 辅助函数，签名逻辑见第 5 节"fixture 组织方案"；这里只展示用例本身的结构，不是完整可编译代码。）

#### 4.1.2 重放窗口边界 + 并发重放

**攻击原理**：如果某项目的"防重放"实际上只是 `crewjam/saml` 默认的约 90 秒时间窗口校验（`NotOnOrAfter`/`NotBefore`），而不是真正记住已用过的 assertion ID，那么攻击者只需要等窗口过期之后再重放——如果这时候还被接受，说明根本没有 ID 级缓存，只是时间窗口凑巧还没到。并发重放测的是另一个维度：即使有 ID 级缓存，如果"检查是否已存在"和"写入已用标记"这两步不是原子操作，两个并发请求可能都读到"未使用"，都被放行。

**输入构造**：
- 窗口边界用例：构造一份 `NotOnOrAfter` 刚好还剩几秒的 assertion，先在窗口内用一次（应成功），等窗口过期后再用同一份（**依然应该被拒绝**——如果这时候被接受，说明是纯时间窗口防护，没有 ID 缓存，这正是要测出来的差异，如实记录，不代表测试写错）。
- 并发用例：同一份合法 assertion，用两个 goroutine 同时 POST 到 ACS 端点，断言 `http.StatusOK`（或等价的成功状态）只出现一次。

```go
// TestSAML_ConcurrentReplayOnlyOneSucceeds fires the same assertion twice
// concurrently and expects exactly one acceptance. This targets a
// check-then-write race in the replay store, not the replay logic itself.
func TestSAML_ConcurrentReplayOnlyOneSucceeds(t *testing.T) {
	base := mustBaseURL(t)
	acsURL := base + "/saml/acs"
	resp := mustSignedSAMLResponse(t, samlResponseParams{
		nameID:       "concurrent-replay@example.com",
		notOnOrAfter: nowPlus(5 * time.Minute),
	})

	results := make(chan int, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := postSAMLResponse(t, acsURL, resp)
			results <- r.StatusCode
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	for code := range results {
		if code < 400 {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("expected exactly 1 success out of 2 concurrent identical assertions, got %d", successes)
	}
}
```

#### 4.1.3 签名校验类型混淆绕过（GHSA-rrfw-hg9m-j47h / CVE-2020-27812）

**已核实的漏洞机制**：漏洞实际在 `crewjam/saml` 依赖的 `russellhaering/goxmldsig`（0.4.1 及更早版本）里，是签名验证时的类型混淆问题（CWE-347，不正确的加密签名验证）——攻击者可以构造一份 XML，使签名验证逻辑校验的元素和实际被业务逻辑读取、信任的元素不是同一个，导致一份未被 IdP 真正签发的 Response 通过验证。`crewjam/saml` 通过升级 `goxmldsig` 到 0.4.2+ 修复。

**测试怎么做**：这类"库内部类型混淆"漏洞**不适合从测试套件外部用一份通用 fixture 直接复现**（需要精确构造触发混淆的 XML 结构，且随库版本演进 payload 会失效），零耦合测试套件在这里能做的、且有实际价值的，是**版本闸门检查**而不是攻击复现：

```go
// TestSAML_GoxmldsigVersionNotVulnerable is a gate check, not an exploit
// replay: it confirms the target's resolved goxmldsig version is at or
// above the fixed version, using the build info the target binary itself
// reports (assumes the project exposes a /debug/vars or /version endpoint
// that includes module versions — confirm this exists per project before
// relying on this test; if it doesn't, this check has to be done manually
// via `go list -m -json github.com/russellhaering/goxmldsig` against the
// project's go.sum instead, and this test case should be skipped with a
// clear reason, not silently passed).
func TestSAML_GoxmldsigVersionNotVulnerable(t *testing.T) {
	t.Skip("requires per-project confirmation of a version-reporting endpoint; " +
		"until then, verify manually via `go list -m -json github.com/russellhaering/goxmldsig`")
}
```

**如实说明**：这条用例目前只能是"人工核实 + 一个占位测试"，不是"自动攻击复现"，执行者不要把它当成和 4.1.1/4.1.2 一样级别的自动化用例来报告结果——复用率报告里这一行应该写"版本核实：通过/未通过 + 实际版本号"，而不是"测试通过/失败"。

#### 4.1.4 多重 Assertion 元素签名绕过（GHSA-j2jp-wvqg-wc2g / CVE-2022-41912）

**已核实的漏洞机制**：0.4.9 之前的版本在解析 SAML Response 时，如果 Response 里包含**多个** `<saml:Assertion>` 元素，签名验证可能只验证了其中一个，但业务逻辑实际读取的是另一个（未经验证的）——这是一个真实的认证绕过（CVSS 9.1，由 Google Project Zero 的 Felix Wilhelm 报告），影响 `ParseResponse`/`ParseXMLResponse`/`ParseXMLArtifactResponse` 等多个方法。

**输入构造**：构造一份 `<samlp:Response>`，里面放两个 `<saml:Assertion>`：第一个是攻击者自己拼的、`NameID` 指向高权限账号（如 `admin@example.com`）、**不带有效签名**；第二个是用测试 IdP 私钥正常签名的、`NameID` 指向一个低权限的正常测试账号。断言被测系统**要么整体拒绝这份 Response（因为出现多个 Assertion 本身就该被拒），要么明确只信任被正确签名的那个**，而不是采用了未签名的第一个。

```go
// TestSAML_MultipleAssertionsSignatureBypass builds a Response containing
// two Assertion elements: an unsigned attacker-controlled one claiming an
// admin identity, and a validly signed one for a low-privilege test
// account. The target must not authenticate the caller as the admin
// identity from the unsigned assertion.
func TestSAML_MultipleAssertionsSignatureBypass(t *testing.T) {
	base := mustBaseURL(t)
	acsURL := base + "/saml/acs"

	resp := mustRawSAMLResponseWithTwoAssertions(t,
		unsignedAssertion{nameID: "admin@example.com"},
		signedAssertion{nameID: "low-priv-test@example.com", notOnOrAfter: nowPlus(5 * time.Minute)},
	)

	r := postSAMLResponse(t, acsURL, resp)
	if r.StatusCode >= 400 {
		return // rejected outright — acceptable and the safest outcome
	}

	gotIdentity := extractAuthenticatedIdentity(t, r) // e.g. decode session cookie / call a whoami endpoint
	if gotIdentity == "admin@example.com" {
		t.Fatalf("session was established as the UNSIGNED assertion's identity %q — signature bypass reproduced", gotIdentity)
	}
}
```

#### 4.1.5 XML 往返解析不一致导致签名绕过（GHSA-4hq8-gmxx-h6w9 / CVE-2020-29509/29510/29511）

**已核实的漏洞机制**：根因在 Go 标准库 `encoding/xml` 的三个历史问题，`crewjam/saml` 0.4.3 之前的版本受影响（CVSS 9.8）。核心是"XML 往返不保语义"——签名计算时序列化出来的字节和后续业务逻辑反序列化读取出来的结构可以不是同一份内容（例如重复的 XML 属性、命名空间前缀混淆），攻击者构造一份精心设计的 XML，让签名覆盖的是"看起来正常"的一份表示，而实际被读取执行的是被篡改过的另一份表示。

**测试怎么做**：和 4.1.3 类似，这是标准库层面的历史漏洞，用当前 Go 版本 + 已修复的 `crewjam/saml` 版本几乎不可能可靠复现原始 payload（触发条件与当时的 `encoding/xml` 具体版本绑定）。此处同样以**版本闸门**为主：

```go
// TestSAML_LibraryVersionNotVulnerable_XMLProcessing gate-checks that the
// resolved crewjam/saml version is >= 0.4.3 (the fix for GHSA-4hq8-gmxx-h6w9).
// Same caveat as 4.1.3: this is a version check, not an exploit replay.
func TestSAML_LibraryVersionNotVulnerable_XMLProcessing(t *testing.T) {
	t.Skip("requires per-project confirmation via `go list -m -json github.com/crewjam/saml`; " +
		"fixed in 0.4.3+")
}
```

如果执行者希望把这一条做成真正的自动化用例而不是占位，可行的替代方案是：**对着一份已知的、历史上曾经能触发这个问题的公开 PoC XML payload**（`crewjam/saml` 仓库自己的漏洞修复 commit 里通常附带回归测试用例）跑一遍，断言被测端点拒绝——但这需要先去 `crewjam/saml` 的修复 commit 里找到官方回归测试用的 payload，本文档不代替这一步去凭空编造 payload。

#### 4.1.6 Deflate 解压炸弹拒绝服务（GHSA-5mqj-xc49-246p / CVE-2023-28119）

**已核实的漏洞机制**：`crewjam/saml` 0.4.13 之前，处理 HTTP-Redirect 绑定的 SAML 请求/响应时用 `flate.NewReader` 解压，没有限制解压后的输出大小——攻击者发一个体积很小但解压后膨胀到很大（例如远超 1MB）的 deflate 压缩包，反复发送可以让进程因为内存耗尽被系统杀死，这是一个可靠触发的 DoS（CVSS 7.5）。

**输入构造**：构造一个小体积、高压缩比的 deflate payload（例如全零字节流压缩，压缩比可以轻松做到几百到几千倍），作为 HTTP-Redirect 绑定的 `SAMLRequest`/`SAMLResponse` 查询参数发给被测端点，断言响应要么明确拒绝（因为解压后超过大小上限），要么至少不会让服务进程崩溃/无响应。

```go
// TestSAML_DeflateBombRejected sends a small, highly compressible deflate
// payload as an HTTP-Redirect-binding SAMLResponse and expects the target
// to reject it (or at minimum stay responsive) rather than attempting to
// decompress an unbounded amount of data.
func TestSAML_DeflateBombRejected(t *testing.T) {
	base := mustBaseURL(t)
	redirectURL := base + "/saml/acs" // adjust to the project's actual Redirect-binding endpoint

	bomb := buildDeflateBomb(t, 10*1024*1024) // compress 10MB of zero bytes; real ratio makes the wire payload tiny
	q := url.Values{"SAMLResponse": {base64StdEncode(bomb)}}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(redirectURL + "?" + q.Encode())
	if err != nil {
		t.Fatalf("target became unresponsive while decompressing, treat as a reproduced DoS: %v", err)
	}
	if resp.StatusCode < 400 {
		t.Errorf("deflate bomb was accepted (status %d), expected the request to be rejected as oversized", resp.StatusCode)
	}
}
```

**执行提醒**：这个用例会真的给被测服务施加内存压力，**只在测试专用实例上跑，不要对着生产环境或共享的开发环境跑**；跑之前确认被测实例是独立进程/容器，崩溃了不影响别人。

#### 4.1.7 ACS Binding 校验缺失导致的 XSS（GHSA-267v-3v32-g6q5 / CVE-2023-45683）—— 适用性存疑，需先核实再决定是否测

**已核实的漏洞机制**：0.4.14 之前的版本，在**作为 IdP 角色**校验外部注册的 Service Provider 元数据时，没有按 SAML Binding 类型校验 ACS Location URI 的语法，攻击者可以在 IdP 上注册一个恶意 SP，把 ACS Location 设成 `javascript:...` 之类的 payload，诱导受害者走一遍 IdP-initiated SSO 流程时在 IdP 的域下执行任意 JS。

**关键澄清（本条与其余 4 条的本质区别）**：这个漏洞的触发点是 `crewjam/saml` 的 **IdP（身份提供方）组件**校验第三方注册的 SP 元数据，而 `shared-modules-plan.md` 第 2 节明确 PSP/AlertHub/Report-Portal 三个项目都是 **SAML SP（服务提供方）**——即消费外部 IdP（如 Okta/Azure AD）签发的断言，不是自己充当 IdP 给别人签发断言。**如果三个项目都只用了 `crewjam/saml` 的 SP 组件、没有启用 IdP 组件，这条用例在这三个项目身上根本没有可攻击的入口，不适用**。

执行者在写这条用例之前，必须先确认一件事：三个项目里有没有任何一个同时运行了 `crewjam/saml` 的 IdP 角色（例如给 Passwall-Node 或别的内部服务当 IdP）。确认方式：

```bash
grep -rn "saml\.IdentityProvider\|samlidp\." --include='*.go' .
```

- 如果三个项目里这条命令都没有匹配，**这条用例标记为"不适用"写进报告**，不要为了凑数硬造一个测试场景。
- 如果某个项目确实有 IdP 组件，再针对那个项目单独构造"注册一个 ACS Location 为 `javascript:alert(1)` 的恶意 SP 元数据，走一遍 IdP-initiated 流程，断言浏览器侧不会执行"的用例，写法上和前面几条类似（HTTP 黑盒 + 断言响应/重定向目标不包含可执行 payload），此处不重复给出骨架，等确认有 IdP 组件之后再补。

### 4.2 WebAuthn / passkey ceremony 会话

对应"三个项目都独立实现了 ceremony session 存取，`go-webauthn/webauthn` 官方文档把这块完全留给调用方"的结论。

| 用例 | 输入 | 期望行为 | 备注 |
|---|---|---|---|
| 完整注册流程 | begin → 客户端模拟响应 → finish | 注册成功 | 基线 |
| 重放 finish 请求 | 同一次 begin 产生的 challenge，finish 两次 | 第二次应该被拒绝（session 单次消费） | 核心用例 |
| ceremony session 过期 | begin 之后等待超过项目声明的过期时间再 finish | 应该被拒绝 | 需要先确认三个项目各自声明的过期时间（可能不同，本身也是复用率报告要记录的差异点） |
| usernameless（免密码）登录尝试 | 在声明 `AllowPasswordless:false` 的项目（Report-Portal）上尝试 usernameless 登录 | 应该被拒绝或要求额外因素 | 对应 `passkey.Policy` 的 `AllowPasswordless`/`RequireStepUpToEnroll` 字段 |

**注意**：WebAuthn ceremony 的 `finish` 步骤需要客户端侧提供一个对 `begin` 返回的 challenge 做签名的 assertion，这一步在真实浏览器里由平台认证器（Touch ID/Windows Hello/安全密钥）完成，测试套件里必须用一个**软件模拟的认证器**（例如 `go-webauthn/webauthn` 生态里常见的测试用虚拟 authenticator，或者自己用一对测试 ECDSA 密钥手写签名逻辑）来产生这个响应，不能依赖真实硬件——执行前先确认三个项目各自用的 WebAuthn 库版本支持哪种测试方式。

```go
// TestPasskey_ReplayFinishRejected replays the exact same ceremony-finish
// payload twice against the same begin challenge; the second call must be
// rejected because the ceremony session should be single-use.
func TestPasskey_ReplayFinishRejected(t *testing.T) {
	base := mustBaseURL(t)

	beginResp := postJSON(t, base+"/webauthn/register/begin", registerBeginRequest{
		Username: "sectest-passkey-user",
	})
	challenge := beginResp.PublicKey.Challenge

	finishPayload := simulateAuthenticatorResponse(t, challenge, testAuthenticatorKeyPair())

	first := postJSON(t, base+"/webauthn/register/finish", finishPayload)
	if first.StatusCode >= 400 {
		t.Fatalf("baseline registration failed, fixture is broken: got %d", first.StatusCode)
	}

	second := postJSON(t, base+"/webauthn/register/finish", finishPayload)
	if second.StatusCode < 400 {
		t.Errorf("ceremony finish was accepted twice (status %d on replay), expected single-use rejection", second.StatusCode)
	}
}

// TestPasskey_UsernamelessRejectedWhenPolicyDisallows checks that a project
// declaring AllowPasswordless:false (Report-Portal, per shared-modules-plan.md)
// actually enforces it at the HTTP layer, not just in a doc comment.
func TestPasskey_UsernamelessRejectedWhenPolicyDisallows(t *testing.T) {
	base := mustBaseURL(t) // point this at the Report-Portal instance specifically
	resp := postJSON(t, base+"/webauthn/login/usernameless/begin", struct{}{})
	if resp.StatusCode < 400 {
		t.Errorf("usernameless login flow was accepted (status %d) on a project whose policy declares AllowPasswordless:false", resp.StatusCode)
	}
}
```

### 4.3 审计防篡改（哈希链）

对应"只有 AlertHub 做了哈希链设计，PSP/Report-Portal 的审计表是普通行"的结论。这组用例分两部分：一部分测 AlertHub 现有的哈希链，另一部分确认 PSP/Report-Portal 目前确实没有防护（作为"抽取有价值"的证据，不是发现新问题）。

| 用例 | 输入 | 期望行为 | 备注 |
|---|---|---|---|
| AlertHub：正常写入一批审计事件后跑 `VerifyAuditChain` | 若干条正常业务操作触发的审计事件 | 验证通过，`brokenAt` 为空/0 | 基线 |
| AlertHub：直接改数据库里某一行的 `Detail` 字段（不经过应用层） | 用测试专用的直连 DB 权限篡改一行 | `VerifyAuditChain` 应该能检测到 | 核心用例 |
| PSP / Report-Portal：同样直连 DB 篡改一行审计记录 | 同上 | **预期：检测不到**（因为目前没有哈希链） | 如实记录现状，不是"测试失败" |

这一组**不是纯 HTTP 黑盒**——"直连数据库改一行"这一步需要测试套件对被测实例的数据库有直接写权限，这在"零耦合"原则下仍然允许（数据库不是项目的 Go 内部包，是外部可观察的状态），但要求测试环境用的是**测试专用数据库实例**，不能对着生产数据库做这一步。

```go
// TestAudit_TamperDetectedByHashChain writes a batch of normal audit
// entries via the target's own HTTP API, then tampers with one row
// directly via a test-only DB connection (bypassing the application
// entirely), and expects a verification endpoint/CLI to flag the tampered
// row. Only run this against a disposable test database.
func TestAudit_TamperDetectedByHashChain(t *testing.T) {
	base := mustBaseURL(t)
	db := mustTestOnlyDB(t) // fails loudly if DSN doesn't look like a test/throwaway instance

	triggerNormalAuditEvents(t, base, 5) // e.g. a handful of harmless authenticated actions

	var targetID int64
	row := db.QueryRow(`SELECT id FROM audit_log ORDER BY id DESC LIMIT 1 OFFSET 2`)
	if err := row.Scan(&targetID); err != nil {
		t.Fatalf("could not pick a row to tamper with: %v", err)
	}
	if _, err := db.Exec(`UPDATE audit_log SET detail = ? WHERE id = ?`, `{"tampered":true}`, targetID); err != nil {
		t.Fatalf("tamper write failed: %v", err)
	}

	result := runVerifyAuditChain(t, base) // hits whatever endpoint/CLI wraps VerifyAuditChain
	if result.BrokenAt == 0 {
		t.Errorf("hash chain verification did not detect the tampered row (id=%d)", targetID)
	}
}
```

### 4.4 OIDC state / nonce / claims 校验

对应 `shared-modules-plan.md` 第 4.3 节的调研结论：`zitadel/oidc` 的 `rp` 包已经处理了大部分 state/PKCE 逻辑，但 nonce 校验、以及 id_token 本身几项关键 claim（`alg`/`aud`/`iss`/`exp`）的校验仍然是三个项目此前各自实现、也各自可能遗漏的地方——这也是为什么值得单独测。

| 用例 | 输入 | 期望行为 | 备注 |
|---|---|---|---|
| state 缺失 | callback 请求不带 `state` 参数 | 应该被拒绝 | CSRF 防护基线 |
| state 不匹配 | callback 带一个和发起时不一致的 `state` | 应该被拒绝 | |
| nonce 缺失 | id_token 里没有 `nonce` claim，但发起时请求过 nonce | 应该被拒绝 | |
| nonce 重放 | 用同一个 nonce 值发起两次独立的登录流程，第二次的 id_token 复用第一次的 nonce | 应该被拒绝（nonce 应绑定到本次授权流程，不能跨流程复用） | |
| `alg=none` 伪造 id_token | 构造一个 header 为 `{"alg":"none"}`、无签名的 id_token | 应该被拒绝 | 经典 JWT 攻击手法，必须显式测 |
| `aud` 不匹配 | id_token 的 `aud` 不是本项目的 `client_id` | 应该被拒绝 | |
| `iss` 不匹配 | id_token 的 `iss` 不是配置的 provider issuer | 应该被拒绝 | |
| `exp` 已过期 | id_token 的 `exp` 是过去的时间戳 | 应该被拒绝 | |
| 授权码重放 | 同一个 authorization code 兑换 token 两次 | 第二次应该被拒绝 | 依赖 mock IdP 是否正确实现了这个行为，见下方说明 |

**这一组用例需要一个 mock OIDC IdP**，不能直接打真实的 Okta/Azure AD（没有权限伪造恶意 claim，也不该对真实第三方 IdP 发起攻击测试）。建议用一个轻量的开源 mock OIDC provider（测试套件自己起一个进程，配置好签名密钥），让三个项目在测试环境里把 provider 指向这个 mock 实例。

```go
// TestOIDC_AlgNoneRejected forges an id_token with header {"alg":"none"}
// and an empty signature, and expects the callback to reject it. This is
// the classic "alg confusion" JWT attack and must never be silently
// accepted regardless of which JWT library is underneath.
func TestOIDC_AlgNoneRejected(t *testing.T) {
	base := mustBaseURL(t)
	mockIdP := mustMockOIDCProvider(t) // started once per test run, see fixture notes in section 5

	forgedIDToken := buildUnsignedJWT(t, map[string]any{
		"iss":   mockIdP.Issuer,
		"aud":   mockIdP.ClientID,
		"sub":   "attacker-controlled-subject",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"nonce": "irrelevant-for-this-test",
	}) // header alg=none, no signature segment

	callbackURL := base + "/oidc/callback?code=irrelevant&state=" + mockIdP.LastIssuedState
	mockIdP.NextTokenResponseIDToken = forgedIDToken // mock IdP will return this on the code-exchange call

	resp := httpGet(t, callbackURL)
	if resp.StatusCode < 400 {
		t.Errorf("alg=none forged id_token was accepted (status %d), expected rejection", resp.StatusCode)
	}
}

// TestOIDC_AuthorizationCodeReplayRejected exchanges the same authorization
// code twice and expects the second exchange to fail.
func TestOIDC_AuthorizationCodeReplayRejected(t *testing.T) {
	base := mustBaseURL(t)
	mockIdP := mustMockOIDCProvider(t)
	code := mockIdP.IssueAuthorizationCode(t, "sectest-oidc-user")

	callbackURL := base + "/oidc/callback?code=" + code + "&state=" + mockIdP.LastIssuedState

	first := httpGet(t, callbackURL)
	if first.StatusCode >= 400 {
		t.Fatalf("baseline code exchange failed, fixture is broken: got %d", first.StatusCode)
	}

	second := httpGet(t, callbackURL)
	if second.StatusCode < 400 {
		t.Errorf("authorization code was accepted a second time (status %d), expected rejection on replay", second.StatusCode)
	}
}
```

**如实说明**：授权码重放这一条的可靠性部分依赖 mock IdP 自己是否正确地"用过一次就作废"这个码——如果 mock IdP 实现得不严谨，这条用例可能测出假阳性（mock 允许重复兑换，而不是被测项目的问题）。执行前先给 mock IdP 本身写一条自检用例，确认它自己的码作废行为符合预期，再拿它去测三个项目。

### 4.5 限流与 XFF 可信代理边界

对应 `shared-modules-plan.md` 第 2 节 build-vs-buy 结论：`ratelimit` 包改用 `go-chi/httprate` + `middleware.ClientIPFromXFFTrustedProxies`，这组用例验证的与其说是"三个项目现有实现像不像"，不如说是"三个项目现有的自研 `parseTrustedProxies`/`clientIP` 逻辑有没有已知的 XFF 伪造漏洞"——这也是决定要不要换成现成库的直接证据。示例 IP 全部使用 RFC 5737 为文档保留的地址段（`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`），不使用任何真实公网地址。

| 用例 | 输入 | 期望行为 | 备注 |
|---|---|---|---|
| 正例：可信代理范围内的 XFF 生效 | 从被声明为可信代理的地址（如 `203.0.113.10`，模拟内部反向代理）发起请求，带 `X-Forwarded-For: 198.51.100.5` | 限流应该按 `198.51.100.5` 计数 | 验证"该生效的时候确实生效" |
| 反例：不可信来源伪造 XFF | 直接从测试客户端（不在可信代理范围内，如 `198.51.100.99`）发起请求，自行带上 `X-Forwarded-For: 192.0.2.1` | 限流应该按**实际连接地址** `198.51.100.99` 计数，**不能**信任伪造的 XFF | 核心用例——这是 XFF 解析最常见的绕过手法：不受信任的客户端可以在自己的请求里随便写 XFF 头 |
| 可信代理边界配置过宽 | 检查项目当前配置的可信代理 CIDR 范围 | 不应该是 `0.0.0.0/0` 或未做限制 | 配置审查用例，不是运行时攻击用例 |

```go
// TestRateLimit_UntrustedXFFIgnored sends a request directly from an
// address that is NOT in the project's configured trusted-proxy CIDR list,
// forging an X-Forwarded-For header to impersonate a different client IP.
// The target must key its rate limiter on the real connecting address, not
// the forged header — otherwise an attacker can rotate the XFF value to
// bypass per-IP throttling entirely.
func TestRateLimit_UntrustedXFFIgnored(t *testing.T) {
	base := mustBaseURL(t)
	endpoint := base + "/api/login" // pick a rate-limited endpoint per project

	limit := discoverConfiguredLimit(t, endpoint) // e.g. read from a known low-limit test config

	// Fire more than `limit` requests, each claiming a DIFFERENT forged
	// X-Forwarded-For value, from the SAME real connection.
	var lastStatus int
	for i := 0; i < limit+5; i++ {
		req, _ := http.NewRequest(http.MethodPost, endpoint, nil)
		req.Header.Set("X-Forwarded-For", forgedIPForIteration(i)) // e.g. 192.0.2.1, 192.0.2.2, ...
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		lastStatus = resp.StatusCode
	}

	if lastStatus != http.StatusTooManyRequests {
		t.Errorf("after exceeding the limit with rotating forged X-Forwarded-For values, "+
			"expected the final request to be throttled (429), got %d — "+
			"this means the rate limiter trusted the forged header", lastStatus)
	}
}
```

## 5. 怎么用

### 5.1 目录结构建议

测试套件本身作为一个独立的 Go module，建议放在：

```
kazuhahub-github/docs/security-test-suite/
├── go.mod                       // 独立 module，不依赖任何消费方项目
├── fixtures/                    // 测试 IdP 私钥、mock OIDC provider 配置等
│   ├── test-idp-key.pem         // 仅测试用，不是真实凭证
│   └── mock-oidc/
├── saml_test.go                 // 4.1 节用例
├── passkey_test.go              // 4.2 节用例
├── audit_test.go                // 4.3 节用例
├── oidc_test.go                 // 4.4 节用例
├── ratelimit_test.go            // 4.5 节用例
└── internal/harness/            // mustBaseURL / postSAMLResponse 等共享辅助函数
```

### 5.2 三个项目怎么接入

每个项目按下面的步骤对接，彼此独立，不要求同步：

1. 项目侧准备一份**测试专用配置**：本地 SQLite/内存存储或独立的测试数据库、指向 `fixtures/mock-oidc` 里 mock provider 的 OIDC 配置、一个已知的 SAML 测试 IdP 元数据（对应 `fixtures/test-idp-key.pem` 的公钥部分）。
2. 用该配置起一个测试实例：`go run . --config=testdata/sectest.yaml`（具体命令按各项目实际的启动方式调整）。
3. 设置 `SECTEST_BASE_URL` 指向这个实例，跑 `go test ./... -run <项目当前能跑的用例前缀>`。
4. 把结果记录进第 6 节的复用率报告模板。

### 5.3 fixture 组织方案

评估了两个选项：

- **选项 A：独立仓库**——把测试套件和 fixture 放进一个新建的 `KazuhaHub/security-test-suite` 仓库，三个项目各自在 CI 里拉取。优点是版本管理干净；缺点是多一个仓库要维护权限和发布流程，对于一次性评估阶段有点重。
- **选项 B：各自复制**——三个项目各自把测试套件代码复制一份进自己仓库的 `internal/securitytest/`（或等价目录），各自维护。优点是接入零门槛，不需要新仓库；缺点是三份复制品会逐渐漂移，将来测试用例更新时容易漏改某一份。

**推荐折中方案**：fixture（测试 IdP 私钥、mock provider 配置、Go 测试骨架源码）**唯一权威源**放在 `kazuhahub-github/docs/security-test-suite/`（本文档同目录下的子文件夹，随本次评估一起产出），三个项目需要跑测试时，**各自复制一份进自己的 CI 流程**（不是 `go get` 依赖，因为这是测试代码不是要被生产依赖的库），但复制时保留一个注释头注明"来源：`kazuhahub-github/docs/security-test-suite/`，最后同步日期：YYYY-MM-DD"，未来更新时靠这个注释头人工比对差异，不追求自动同步。这个方案不引入新仓库，也比放任三份代码各自漂移要可控。

## 6. 怎么产出复用率报告

跑完上面五组用例后，按下面的模板整理成一份文档（可以直接追加在本文件末尾，或另开一个 `security-test-suite-report.md`，由 kazuha 决定）：

```
## 复用率报告（YYYY-MM-DD 跑测）

### SAML（含 replay 与 5 条 CVE 闸门检查）
| 用例 | PSP | AlertHub | Report-Portal | 三家行为一致？ |
|---|---|---|---|---|
| 4.1.1 原样重放 | 拒绝 | ？ | 拒绝 | ？ |
| 4.1.3/4.1.5 库版本闸门 | 版本号：？ | 版本号：？ | 版本号：？ | N/A（人工核实项） |
| 4.1.7 IdP 角色 XSS | 不适用/适用：？ | 不适用/适用：？ | 不适用/适用：？ | N/A |
| ...

### passkey ceremony
（同样格式）

### audit 哈希链
（同样格式）

### OIDC
（同样格式）

### ratelimit / XFF
（同样格式）

### 结论
- 复用率：X/Y 条可执行用例三家行为一致（人工核实项、"不适用"项不计入分母，单独列出）
- 发现的安全缺口：（如实列出，例如"AlertHub 无 replay 防护"）
- 建议：P1 是否按原计划推进 / 是否需要调整范围
```

**决策规则（供参考，最终由 kazuha 拍板）**：

- 一致率高（多数用例三家行为一致或差异可以用"有没有做"而不是"做法完全不同"来解释）→ 抽取价值高，按 `shared-modules-plan.md` 阶段 3 继续。
- 某个属性的分歧本质上是"做法不同"而不是"有没有做"（例如某项目的"防重放"其实是应用层按用户去重、不是协议层的 assertion-ID 缓存，两者能防护的攻击面不一样）→ 回到 `shared-modules-plan.md` 第 2 节的"机制 vs 策略"标准重新判断，这个属性可能不适合直接抽成一个共享接口，需要调整设计或范围。

## 7. 不在本阶段做的事

- 不修任何项目现有的实现（哪怕测出了明确的安全缺口，例如 AlertHub 的 replay 防护缺失——记录下来，留给阶段 3/6 处理，因为"直接抽共享库"本身就是最终修复手段，没必要在这里先打个补丁）。
- 不产出任何 authcore 代码。
- 不要求三个项目同时具备测试环境——如果某个项目暂时起不来测试实例，先跑另外两个，报告里如实标注"待补"，不要用另外两家的结果去猜测第三家的行为。
- 不对生产环境或共享的开发环境跑任何用例，尤其是 4.1.6 的解压炸弹用例——只对一次性/可丢弃的测试实例执行。

## 8. 工作量分解

| 项目 | 人日 | 说明 |
|---|---:|---|
| 测试套件骨架 + fixture（测试 IdP 私钥、mock OIDC provider） | 0.5 | 一次性投入，5 组用例共用 |
| SAML 用例（4.1.1~4.1.7） | 0.75 | 含 5 条 CVE 的版本闸门检查（轻量）+ 2 条可执行的重放/并发用例（较重） |
| passkey / WebAuthn 用例（4.2） | 0.5 | 软件模拟认证器是主要工作量来源 |
| audit 哈希链用例（4.3） | 0.25 | 依赖测试专用数据库直连权限，逻辑本身简单 |
| OIDC 用例（4.4） | 0.5 | mock OIDC provider 的自检（确认它本身行为正确）占一部分时间 |
| ratelimit / XFF 用例（4.5） | 0.25 | 逻辑简单，主要是构造伪造 XFF 的请求序列 |
| 三个项目分别接入 + 跑测 + 整理报告 | 0.5~1 | 取决于三个项目起测试实例的难度是否一致 |

**合计约 3.25~3.75 人日**，比 `shared-modules-plan.md` 第 1 节和阶段 -1 给出的预算（1~3 人日）略高——原因是本轮把 4.1 节的 CVE 用例从"只写一句话描述"扩展成了逐条给出攻击原理和可执行的 Go 骨架（含两条需要人工核实库版本的闸门检查），并新增了 4.4/4.5 两组此前完全没写的用例。**这个差异需要 kazuha 知晓并确认是否接受**：要么接受略超预算的 3.25~3.75 人日换取更完整的用例覆盖，要么明确砍掉某几组用例（例如把 4.1.3/4.1.5 的版本闸门检查降级为纯人工核对、不写测试代码）以压回 1~3 人日的原预算——本文档不擅自替 kazuha 做这个取舍，两种做法在上面的分解表里都能看出对应哪部分工作量，需要时按此增减。

## 9. 验收标准

- 三组核心用例（4.1/4.2/4.3）覆盖的项目数 ≥ 2（允许有一个项目因为环境问题暂时跳过，但不能三个都跳过）；4.4/4.5 两组新增用例同样适用这条标准。
- 4.1.7 的适用性核实（`grep saml.IdentityProvider`）必须跑过，不能跳过直接假设"不适用"。
- 复用率报告写完，kazuha 看过并在 `shared-modules-plan.md` 第 5 节阶段 3 开始前给出"继续/调整范围"的决定。
- 测试套件代码本身（不含被测项目的任何代码）按第 5.3 节的折中方案落地到 `kazuhahub-github/docs/security-test-suite/`，供未来在三个项目 CI 里复用；这一步不是硬性要求，但如果不做，需要在报告里说明为什么放弃长期复用测试套件的机会。
- 第 8 节的工作量取舍（是否接受 3.25~3.75 人日的实际范围，还是砍用例压回 1~3 人日）已经由 kazuha 明确答复，不能由执行者自行决定后才在报告里说明。
