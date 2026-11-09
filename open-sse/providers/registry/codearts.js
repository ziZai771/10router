export default {
  id: "codearts",
  // 模型前缀 codearts/GLM-5.2；alias "ca" 备用短前缀
  alias: "ca",
  uiAlias: "codearts",
  hidden: false,
  priority: 89,
  display: {
    name: "CodeArts (华为云码道)",
    icon: "cloud",
    color: "#C7000B",
    website: "https://devcloud.cn-north-4.huaweicloud.com/",
    notice: {
      signupUrl: "https://devcloud.cn-north-4.huaweicloud.com/",
      webUrl: "https://devcloud.cn-north-4.huaweicloud.com/codearts/agent",
    },
  },
  category: "oauth",
  authModes: ["oauth"],
  hasOAuth: true,
  transport: {
    baseUrl: "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions",
    // 上游 OpenAI 兼容；签名与鉴权头全部由 executors/codearts.js 注入
    //（SDK-HMAC-SHA256 + x-auth-token + Session-Id 会话亲和）。
    forceStream: false,
    thinkingFormat: "openai",
    // 签名在 executor 内自行完成，不走 transport.auth 的 Bearer 注入
    auth: null,
    usage: {
      // 占位：实际查询在 services/usage/codearts.js 内签名调用 /v1/ops/delivery
      url: "https://snap-access.cn-north-4.myhuaweicloud.com/v1/ops/delivery",
    },
  },
  // 模型目录：华为云 /v1/model/builtin 2026-11-06 实测清单。
  // benefit: true = 限时体验模型（仅元数据；不注入 maas_type 请求头）。
  models: [
    { id: "deepseek-v4.1-flash", name: "DeepSeek-V4.1-Flash", benefit: true },
    { id: "deepseek-v4.1-flash-1017", name: "DeepSeek-V4.1-Flash-1017", benefit: true },
    { id: "kimi-k3", name: "Kimi-K3", benefit: true },
    { id: "kimi-k3.1-pro", name: "Kimi-K3.1-Pro", benefit: true },
    { id: "kimi-k2.6-vl", name: "Kimi-K2.6-VL" },
    { id: "glm-5.3", name: "GLM-5.3", benefit: true },
    { id: "glm-5.3-flash", name: "GLM-5.3-Flash", benefit: true },
    { id: "GLM-5.2", name: "GLM-5.2" },
    { id: "glm-5.2-sft-harmony", name: "GLM-5.2-SFT-Harmony" },
    { id: "openpangu-2.0-pro", name: "OpenPangu-2.0-Pro" },
    { id: "openpangu-2.0-flash", name: "OpenPangu-2.0-Flash" },
    { id: "Qwen3-VL-235B", name: "Qwen3-VL-235B" },
    { id: "speed", name: "Speed (智能调度)" },
  ],
  oauth: {
    baseUrl: "https://codearts.huaweicloud.com",
    // 记录用途：实际 PKCE/DPoP 交换在 src/lib/oauth/providers/codearts.js 内实现
    tokenUrl: "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens",
    refreshUrl: "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens",
    clientId: "codearts-agent",
    platform: "CLI",
    pollInterval: 5000,
  },
  features: {
    usage: true,
  },
};
