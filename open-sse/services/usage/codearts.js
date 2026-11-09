/**
 * CodeArts（华为云码道）usage handler
 *
 * 只展示一行「积分总量」，数据来自与门户「个人用量」同源的签名接口：
 *   GET /snap-manager/v1/statistics/plugin
 *   metrics[].usageTotalPackageCredit 带 package_credit_amount / used / remain，
 *   used/total 原样透传，不做折算。
 */

import {
  credsFromConnection,
  fetchCreditStatistics,
} from "../../shared/codearts.js";

function round2(n) {
  return Math.round(Number(n || 0) * 100) / 100;
}

async function getCodeartsUsage(accessToken, apiKey, providerSpecificData, proxyOptions = null) {
  const creds = credsFromConnection({ providerSpecificData, accessToken });
  if (!creds) {
    return { message: "CodeArts 凭证不可用（缺少 STS ak/sk），请重新授权。" };
  }

  try {
    const stat = await fetchCreditStatistics(creds, proxyOptions);
    const metrics = Array.isArray(stat?.metrics) ? stat.metrics : [];
    const total = metrics.find((x) => x.name === "usageTotalPackageCredit");
    if (!total) {
      return { message: "CodeArts 已连接，上游未返回积分数据。" };
    }
    return {
      quotas: {
        积分总量: {
          used: round2(total.package_credit_used),
          total: round2(total.package_credit_amount),
          // 上游不给下个刷新时间，留空以免显示错误的倒计时。
          resetAt: null,
          unlimited: false,
          recurring: false,
        },
      },
    };
  } catch (err) {
    return { message: `CodeArts 积分查询失败: ${err?.message || err}` };
  }
}

export { getCodeartsUsage };
export default getCodeartsUsage;
