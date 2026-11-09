import crypto from "crypto";
import { DefaultExecutor } from "./default.js";
import { resolveSessionId } from "../utils/sessionManager.js";
import {
  CODEARTS_CHAT_URL,
  codeartsSessionId,
  credsFromConnection,
  signSdkHmacSha256,
} from "../shared/codearts.js";

/**
 * CodeartsExecutor — 华为云码道 https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions
 *
 * OpenAI 兼容协议，但鉴权特殊（全部在本类内注入，registry transport.auth=null）：
 *   - x-auth-token: STS security_token
 *   - Authorization: SDK-HMAC-SHA256（AK/SK，签名覆盖全部请求头 + payload hash）
 *   - Session-Id: 会话亲和（上游按它限 3 并发/账号/模型；同会话复用同一槽位，
 *     从下游会话身份派生稳定值，与官方客户端 sha256("codearts-session:"+chatID) 对齐）
 *   - 不额外注入 maas_type：实测该头会让当前账号报 benefit not found；
 *     福利模型直接按模型 ID 请求即可（与旧桥接及官方客户端一致）。
 *
 * 签名 payload hash 取 JSON.stringify(transformedBody)——base.js execute() 在
 * buildHeaders 之后立即用同一对象 stringify 发送，字节一致。
 */
export class CodeartsExecutor extends DefaultExecutor {
  constructor() {
    super("codearts");
  }

  buildUrl() {
    return CODEARTS_CHAT_URL;
  }

  transformRequest(model, body, stream, credentials) {
    const transformed = super.transformRequest(model, body, stream, credentials);
    // chat_id / prompt_cache_key 与 Session-Id 同源，对齐官方客户端行为
    try {
      const sessionId = resolveSessionId({
        headers: credentials?.rawHeaders,
        body: transformed,
        connectionId: credentials?.connectionId,
        scope: "codearts",
      });
      const chatKey = transformed.chat_id || sessionId || "codearts-default";
      const sid = codeartsSessionId(chatKey);
      // body 里保存原始 chatKey；Session-Id 才是 sha256("codearts-session:"+chatKey)。
      if (!transformed.chat_id) transformed.chat_id = chatKey;
      if (!transformed.prompt_cache_key) transformed.prompt_cache_key = chatKey;
      transformed.__codeartsSessionId = sid;
    } catch {
      /* 会话派生失败不阻断请求 */
    }
    return transformed;
  }

  buildHeaders(credentials, stream = true, url, model, transformedBody) {
    const creds = credsFromConnection(credentials);
    if (!creds) {
      throw new Error("CodeArts 连接缺少 STS 凭证（ak/sk/securityToken），请重新 OAuth 授权");
    }
    const securityToken = creds.securityToken;

    const sid = transformedBody?.__codeartsSessionId
      || codeartsSessionId(credentials?.connectionId || "codearts-default");
    // 内部标记字段不进上游 body
    if (transformedBody && transformedBody.__codeartsSessionId) {
      delete transformedBody.__codeartsSessionId;
    }

    const headers = {
      "content-type": "application/json",
      "accept": stream ? "text/event-stream" : "application/json, text/event-stream",
      "x-auth-token": securityToken,
      "x-snap-traceid": crypto.randomUUID().replace(/-/g, ""),
      "x-language": "zh-cn",
      "app-id": "CodeAgent3.0",
      "is_confidential": "false",
      "session-id": sid,
    };
    const bodyStr = JSON.stringify(transformedBody || {});
    return signSdkHmacSha256({
      ...creds,
      method: "POST",
      url: CODEARTS_CHAT_URL,
      headers,
      body: bodyStr,
    });
  }
}

export default CodeartsExecutor;
