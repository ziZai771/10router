/**
 * 华为云码道（CodeArts Agent / snap）共享协议模块。
 *
 * 逆向自官方 AIIDE 插件与开源 codearts2api：
 *   - OAuth2 + PKCE（client_id=codearts-agent），授权页 codearts.huaweicloud.com/portal/authorize
 *   - 换/刷 token：POST sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens
 *     必须携带 DPoP Proof（P-256/ES256 JWT）；refresh_token 与 DPoP 公钥指纹绑定，
 *     每次刷新必须复用同一把私钥，私钥随连接 providerSpecificData 持久化。
 *   - 业务请求：华为云 SDK-HMAC-SHA256 签名（AK/SK + X-Security-Token）。
 *     聊天 /api/v2/chat/completions 额外带 x-auth-token=security_token；
 *     运营（签到/活动）/v1/ops/* 不带 x-auth-token，纯签名鉴权。
 *   - 会话槽位：上游按 Session-Id 头限 3 并发/账号/模型，同会话必须复用同一
 *     Session-Id（sha256("codearts-session:"+chatID) 前 16 字节 hex）。
 *   - 福利模型直接按模型 ID 请求；不要额外带 maas_type: benefit（实测会报 benefit not found）。
 */

import crypto from "crypto";
import { proxyAwareFetch } from "../utils/proxyFetch.js";

export const CODEARTS_STS_TOKEN_URL = "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens";
export const CODEARTS_AUTHORIZE_URL = "https://codearts.huaweicloud.com/portal/authorize";
export const CODEARTS_SNAP_HOST = "snap-access.cn-north-4.myhuaweicloud.com";
export const CODEARTS_CHAT_URL = `https://${CODEARTS_SNAP_HOST}/api/v2/chat/completions`;
export const CODEARTS_CLIENT_ID = "codearts-agent";
export const CODEARTS_REDIRECT_URI = "http://127.0.0.1:7866/oauth/callback";

// 限时体验模型清单（仅作元数据；请求时不要注入 maas_type 头）。
export const CODEARTS_BENEFIT_MODELS = new Set([
  "deepseek-v4.1-flash",
  "deepseek-v4.1-flash-1017",
  "kimi-k3",
  "kimi-k3.1-pro",
  "glm-5.3",
  "glm-5.3-flash",
]);

// ---------------- DPoP ----------------

export function generateDpopKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
    publicKeyEncoding: { type: "spki", format: "jwk" },
    privateKeyEncoding: { type: "pkcs8", format: "jwk" },
  });
  return { publicKeyJwk: publicKey, privateKeyJwk: privateKey };
}

export function buildDpopProof(privateKeyJwk, publicKeyJwk, method, url) {
  const header = {
    alg: "ES256",
    typ: "dpop+jwt",
    jwk: { kty: "EC", crv: "P-256", x: publicKeyJwk.x, y: publicKeyJwk.y },
  };
  const payload = {
    htm: method.toUpperCase(),
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomBytes(16).toString("hex"),
  };
  const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
  const input = `${b64url(header)}.${b64url(payload)}`;
  const signer = crypto.createSign("SHA256");
  signer.update(input);
  const keyObj = crypto.createPrivateKey({ key: privateKeyJwk, format: "jwk" });
  const sig = signer.sign({ key: keyObj, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return `${input}.${sig}`;
}

// ---------------- SDK-HMAC-SHA256 ----------------

/**
 * 对齐 @huaweicloud/huaweicloud-sdk-core AKSKSigner：
 * signed headers = 传入的全部头（小写排序），调用方负责先把业务头放进来。
 */
export function signSdkHmacSha256({ ak, sk, securityToken, method, url, headers = {}, body = "" }) {
  const u = new URL(url);
  const out = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = String(v);

  const dateStr = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
  out["host"] = u.host;
  out["x-sdk-date"] = dateStr;
  if (securityToken) out["x-security-token"] = securityToken;
  const payloadHash = crypto.createHash("sha256").update(body || "").digest("hex");
  out["x-sdk-content-sha256"] = payloadHash;

  const sortedKeys = Object.keys(out).sort();
  const canonicalHeaders = sortedKeys.map((k) => `${k}:${out[k].trim()}\n`).join("");
  const signedHeaders = sortedKeys.join(";");

  let canonicalUri = u.pathname.split("/").map(encodeURIComponent).join("/");
  if (!canonicalUri.endsWith("/")) canonicalUri += "/";

  // canonical query：key 排序、值排序、percent-encode
  let canonicalQuery = "";
  if (u.searchParams && [...u.searchParams.keys()].length > 0) {
    const keys = [...new Set([...u.searchParams.keys()])].sort();
    const parts = [];
    for (const k of keys) {
      const vs = u.searchParams.getAll(k).sort();
      for (const v of vs) parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
    }
    canonicalQuery = parts.join("&");
  }

  const canonicalRequest = [
    method.toUpperCase(),
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");
  const stringToSign = [
    "SDK-HMAC-SHA256",
    dateStr,
    crypto.createHash("sha256").update(canonicalRequest).digest("hex"),
  ].join("\n");
  const signature = crypto.createHmac("sha256", sk).update(stringToSign).digest("hex");
  out["authorization"] =
    `SDK-HMAC-SHA256 Access=${ak}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return out;
}

// ---------------- 会话亲和 ----------------

export function codeartsSessionId(chatKey) {
  return crypto.createHash("sha256").update(`codearts-session:${chatKey}`).digest("hex").slice(0, 32);
}

// ---------------- 凭证读写辅助 ----------------

/** 从连接凭证里取 STS 三元组（oauth 连接存在 providerSpecificData）。 */
export function credsFromConnection(credentials) {
  const psd = credentials?.providerSpecificData || {};
  const ak = psd.ak;
  const sk = psd.sk;
  // accessToken 存的就是当下生效的 security_token；刷新后它先更新，
  // providerSpecificData.securityToken 是同一份副本，可能落后。
  const securityToken = credentials?.accessToken || psd.securityToken;
  if (!ak || !sk || !securityToken) return null;
  return { ak, sk, securityToken };
}

// ---------------- STS 换/刷 token ----------------

export async function exchangeCodeForTokens({ code, codeVerifier, proxyOptions = null }) {
  const { publicKeyJwk, privateKeyJwk } = generateDpopKeypair();
  const dpop = buildDpopProof(privateKeyJwk, publicKeyJwk, "POST", CODEARTS_STS_TOKEN_URL);
  const params = new URLSearchParams({
    client_id: CODEARTS_CLIENT_ID,
    code,
    code_verifier: codeVerifier,
    grant_type: "authorization_code",
    redirect_uri: CODEARTS_REDIRECT_URI,
  });
  const response = await proxyAwareFetch(CODEARTS_STS_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", DPoP: dpop },
    body: params.toString(),
  }, proxyOptions);
  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { throw new Error(`STS 返回非 JSON (${response.status}): ${text.slice(0, 200)}`); }
  if (!response.ok || !(data.credentials || data.credential)) {
    throw new Error(data.error_msg || data.error || `STS 换 token 失败 (${response.status})`);
  }
  return { tokenResponse: data, dpopPrivateKeyJwk: privateKeyJwk, dpopPublicKeyJwk: publicKeyJwk };
}

/**
 * 刷新 STS 凭证。复用持久化的 DPoP 私钥（refresh_token 与其公钥指纹绑定）。
 * 返回可合并进连接的对象：accessToken/refreshToken/expiresIn/providerSpecificData。
 */
export async function refreshCodeartsSts({ refreshToken, providerSpecificData, proxyOptions = null }) {
  const psd = providerSpecificData || {};
  const privateKeyJwk = psd.dpopPrivateKeyJwk;
  const publicKeyJwk = psd.dpopPublicKeyJwk;
  if (!privateKeyJwk || !publicKeyJwk) {
    throw new Error("缺少 DPoP 私钥，无法刷新（需重新 OAuth 授权）");
  }
  const dpop = buildDpopProof(privateKeyJwk, publicKeyJwk, "POST", CODEARTS_STS_TOKEN_URL);
  const params = new URLSearchParams({
    client_id: CODEARTS_CLIENT_ID,
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  });
  const response = await proxyAwareFetch(CODEARTS_STS_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", DPoP: dpop },
    body: params.toString(),
  }, proxyOptions);
  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { throw new Error(`STS 刷新返回非 JSON (${response.status})`); }
  if (!response.ok || !(data.credentials || data.credential)) {
    const msg = data.error_msg || data.error || `STS 刷新失败 (${response.status})`;
    const err = new Error(msg);
    if (response.status === 400 || response.status === 401) err.invalidGrant = true;
    throw err;
  }
  const cred = data.credentials || data.credential;
  const ak = cred.access_key_id || cred.access;
  const sk = cred.secret_access_key || cred.secret;
  const securityToken = cred.security_token || cred.securitytoken;
  const expiration = cred.expiration || cred.expires_at || null;
  const expiresIn = expiration
    ? Math.max(60, Math.floor((new Date(expiration).getTime() - Date.now()) / 1000))
    : 7200;
  return {
    accessToken: securityToken,
    refreshToken: data.refresh_token || refreshToken,
    expiresIn,
    providerSpecificData: {
      ...psd,
      ak,
      securityToken,
      expiration,
      userId: data.user_id || psd.userId || null,
      userName: data.user_name || psd.userName || null,
      domainId: data.domain_id || psd.domainId || null,
      // sk 不随刷新轮换，但防御性回填
      sk: sk || psd.sk,
    },
  };
}

// ---------------- 签到 / 活动（ops，纯签名，不带 x-auth-token） ----------------

async function opsRequest(creds, method, path, query = "", bodyObj = null, proxyOptions = null) {
  const body = bodyObj ? JSON.stringify(bodyObj) : "";
  const url = `https://${CODEARTS_SNAP_HOST}${path}${query ? `?${query}` : ""}`;
  const headers = signSdkHmacSha256({
    ...creds,
    method,
    url,
    headers: {
      "content-type": "application/json",
      "agent-type": "PromptCenter",
      "x-language": "zh-cn",
    },
    body,
  });
  const response = await proxyAwareFetch(url, { method, headers, body: body || undefined }, proxyOptions);
  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { data = null; }
  return { status: response.status, data, raw: text };
}

/**
 * 积分用量汇总（门户「个人用量」同源）：
 *   GET /snap-manager/v1/statistics/plugin
 * 注意：路径前缀必须带 snap-manager，且必须带 agent-type: PromptCenter；
 * 该路由用 x-security-token 鉴权（不是 x-auth-token），头名参与签名，不能换成驼峰。
 * 返回 metrics[]，其中 usageTotalPackageCredit / usageBasicPackageCredit /
 * usageBonusPackageCredit / usageOnDemandPackageCredit 带 package_credit_* 数值。
 */
export const CODEARTS_STAT_URL = `https://${CODEARTS_SNAP_HOST}/snap-manager/v1/statistics/plugin`;

export async function fetchCreditStatistics(creds, proxyOptions = null) {
  const headers = signSdkHmacSha256({
    ...creds,
    method: "GET",
    url: CODEARTS_STAT_URL,
    headers: { "content-type": "application/json", "agent-type": "PromptCenter" },
    body: "",
  });
  const response = await proxyAwareFetch(CODEARTS_STAT_URL, { method: "GET", headers }, proxyOptions);
  const text = await response.text();
  let data = null;
  try { data = JSON.parse(text); } catch { /* 非 JSON 视为失败 */ }
  if (response.status !== 200 || !data) {
    throw new Error(data?.error_msg || `积分用量查询失败 (${response.status})`);
  }
  return data;
}

/** 拉取活动投放列表（含每日签到状态）。 */
export async function fetchCreditCampaigns(creds, proxyOptions = null) {
  const { status, data, raw } = await opsRequest(creds, "GET", "/v1/ops/delivery", "channel=IDE", null, proxyOptions);
  if (status !== 200 || data?.code !== 0) {
    throw new Error(data?.message || raw?.slice(0, 200) || `活动查询失败 (${status})`);
  }
  return { items: data?.data?.items || [], serverTime: data?.data?.serverTime || null };
}

/**
 * 每日签到：找 type=USER_LOGIN（每日签到领100积分）活动，
 * ELIGIBLE+claimable → claim + confirm；CLAIMED → 补 confirm；其余视为已完成。
 * 返回 { status: "checked-in"|"already"|"unavailable"|"error", message, credits }
 */
export async function claimDailyCheckin(creds, proxyOptions = null) {
  const { items, serverTime } = await fetchCreditCampaigns(creds, proxyOptions);
  const now = serverTime || Date.now();
  const campaign = items.find((it) => it.type === "USER_LOGIN");
  if (!campaign) {
    return { status: "unavailable", message: "账号无每日签到活动", credits: 0 };
  }
  const st = String(campaign.status || "").trim();
  if (st === "CONFIRMED" || st === "CONSUMED") {
    return { status: "already", message: "今日已签到", credits: 0 };
  }
  if (st === "ELIGIBLE") {
    if (!campaign.claimable) {
      return { status: "unavailable", message: "暂不可领取，稍后重试", credits: 0 };
    }
    const claim = await opsRequest(creds, "POST", "/v1/ops/claim", "", {
      campaignId: campaign.campaignId,
      channel: "IDE",
      idempotentKey: `claim_${campaign.campaignId}_${now}`,
    }, proxyOptions);
    if (claim.status !== 200 || claim.data?.code !== 0) {
      return { status: "error", message: claim.data?.message || `领取失败 (${claim.status})`, credits: 0 };
    }
  } else if (st !== "CLAIMED") {
    return { status: "unavailable", message: `活动状态不可用: ${st || "无资格"}`, credits: 0 };
  }
  // CLAIMED → confirm
  const confirm = await opsRequest(creds, "POST", "/v1/ops/confirm", "", { campaignId: campaign.campaignId }, proxyOptions);
  if (confirm.status !== 200 || confirm.data?.code !== 0) {
    return { status: "error", message: confirm.data?.message || `确认失败 (${confirm.status})`, credits: 0 };
  }
  const credits = Number(campaign.pendingTotalAmount || campaign.benefitAmount || 0);
  return { status: "checked-in", message: `签到成功（+${credits} 积分）`, credits };
}
