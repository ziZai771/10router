import { CODEARTS_CONFIG } from "../constants/oauth.js";
import {
  CODEARTS_AUTHORIZE_URL,
  CODEARTS_CLIENT_ID,
  CODEARTS_REDIRECT_URI,
  exchangeCodeForTokens,
} from "open-sse/shared/codearts.js";

// 华为云码道 CodeArts Agent —— authorization_code + PKCE + DPoP 流程：
// 1. 浏览器打开华为授权页（固定回调 http://127.0.0.1:7866/oauth/callback）
// 2. 授权后浏览器跳到 127.0.0.1 本地地址（页面打不开属正常），用户把地址栏
//    整条 URL（或其中的 code）粘贴回来
// 3. exchange：STS /v1/oauth2/tokens 换 STS 临时 AK/SK + security_token，
//    请求携带 DPoP Proof（P-256/ES256）；DPoP 私钥随连接持久化供刷新复用
const codearts = {
  config: CODEARTS_CONFIG,
  flowType: "authorization_code_pkce",
  buildAuthUrl: (config, redirectUri, state, codeChallenge) => {
    const params = new URLSearchParams({
      theme: "2",
      locale: "zh-cn",
      uri_scheme: "codearts-agent",
      client_id: CODEARTS_CLIENT_ID,
      port: "7866",
      code_challenge: codeChallenge,
      code_challenge_method: "SHA-256",
      ticket_id: state,
      "plugin-name": "snap_AIIDE",
      "plugin-version": "5.2.0",
    });
    return `${CODEARTS_AUTHORIZE_URL}?${params.toString()}`;
  },
  exchangeToken: async (config, code, redirectUri, codeVerifier) => {
    // 用户可能粘贴整条回调 URL（http://127.0.0.1:7866/oauth/callback?code=...&state=...）
    // 或只粘贴 code 参数本身。
    let authCode = String(code || "").trim();
    if (authCode.includes("code=")) {
      try {
        const u = new URL(authCode);
        authCode = u.searchParams.get("code") || authCode;
      } catch {
        const m = authCode.match(/[?&]code=([^&]+)/);
        if (m) authCode = m[1];
      }
    }
    if (!authCode) throw new Error("未解析到授权 code，请粘贴完整的回调地址");

    const { tokenResponse, dpopPrivateKeyJwk, dpopPublicKeyJwk } = await exchangeCodeForTokens({
      code: authCode,
      codeVerifier,
    });
    return { ...tokenResponse, _dpopPrivateKeyJwk: dpopPrivateKeyJwk, _dpopPublicKeyJwk: dpopPublicKeyJwk };
  },
  mapTokens: (tokens) => {
    const cred = tokens.credentials || tokens.credential || {};
    const ak = cred.access_key_id || cred.access;
    const sk = cred.secret_access_key || cred.secret;
    const securityToken = cred.security_token || cred.securitytoken;
    const expiration = cred.expiration || cred.expires_at || null;
    const expiresIn = expiration
      ? Math.max(60, Math.floor((new Date(expiration).getTime() - Date.now()) / 1000))
      : 7200;
    return {
      accessToken: securityToken,
      refreshToken: tokens.refresh_token || "",
      expiresIn,
      providerSpecificData: {
        ak,
        sk,
        securityToken,
        expiration,
        dpopPrivateKeyJwk: tokens._dpopPrivateKeyJwk,
        dpopPublicKeyJwk: tokens._dpopPublicKeyJwk,
        userId: tokens.user_id || null,
        username: tokens.user_name || null,
        domainId: tokens.domain_id || null,
      },
    };
  },
};

export default codearts;
