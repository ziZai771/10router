// CodeArts（华为云码道）每日自动签到。
//
// 对齐 codebuddyCheckin 的节奏与失败语义：每 ~2h（+抖动）tick 一次，账号当日
// 确认完成后记忆到设置（codeartsDailyDone），全天不再重复；单账号失败不拖垮
// 整轮。签到走华为活动接口（GET /v1/ops/delivery → POST claim → POST confirm），
// 凭证过期先经 tokenRefresh 自动刷新（DPoP 私钥随连接持久化）。

import * as log from "../utils/logger.js";
import { isNeedsReauthCooling } from "open-sse/services/accountFallback.js";
import {
  credsFromConnection,
  claimDailyCheckin,
} from "open-sse/shared/codearts.js";

const TICK_MS = 2 * 60 * 60 * 1000;
const TICK_JITTER_MS = 10 * 60 * 1000;

let started = false;
let timerHandle = null;
let doneMap = null;

function dayKey(nowMs = Date.now()) {
  const d = new Date(nowMs);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

async function getDoneMap() {
  if (doneMap) return doneMap;
  const settings = await loadSettingsSafe();
  const raw = settings?.codeartsDailyDone;
  doneMap = raw && typeof raw === "object" && !Array.isArray(raw) ? { ...raw } : {};
  return doneMap;
}

async function persistDoneMap() {
  if (!doneMap) return;
  const today = dayKey();
  const pruned = {};
  for (const [id, day] of Object.entries(doneMap)) {
    if (day === today) pruned[id] = day;
  }
  try {
    const { updateSettings } = await import("../../lib/localDb.js");
    await updateSettings({ codeartsDailyDone: pruned });
    for (const k of Object.keys(doneMap)) delete doneMap[k];
    Object.assign(doneMap, pruned);
  } catch (err) {
    log.warn("CODEARTS_CHECKIN", "Persist daily-done map failed (swallowed)", {
      error: err?.message ?? String(err),
    });
  }
}

async function loadSettingsSafe() {
  try {
    const { getSettings } = await import("../../lib/localDb.js");
    return await getSettings();
  } catch {
    return {};
  }
}

async function loadActiveConnections() {
  const { getProviderConnections } = await import("../../lib/db/repos/connectionsRepo.js");
  return getProviderConnections({ provider: "codearts" });
}

function isEligibleCodeartsConnection(conn) {
  if (!conn || conn.provider !== "codearts") return false;
  if (conn.isActive === false) return false;
  if (!credsFromConnection(conn)) return false;
  return true;
}

/**
 * 单账号签到（含一次刷新重试）。
 * @returns {Promise<{status: string, message?: string, credits?: number, error?: string}>}
 */
export async function checkinOne(conn, deps = {}) {
  const proxyOptions = conn.proxyOptions || null;
  try {
    const outcome = await claimDailyCheckin(credsFromConnection(conn), proxyOptions);
    return outcome;
  } catch (err) {
    const msg = err?.message || String(err);
    // 凭证过期/失效：刷新一次再试
    if (/expired|401|403|APIG\.03|decrypt token/i.test(msg) && !deps._retried) {
      log.info("CODEARTS_CHECKIN", `${conn.name || conn.id}: 凭证疑似过期，刷新后重试`, { id: conn.id });
      const refreshed = await refreshConnection(conn);
      if (refreshed) {
        return checkinOne({ ...conn, providerSpecificData: refreshed.providerSpecificData || conn.providerSpecificData }, { ...deps, _retried: true });
      }
    }
    return { status: "error", error: msg };
  }
}

async function refreshConnection(conn) {
  try {
    const { refreshTokenByProvider } = await import("open-sse/services/tokenRefresh.js");
    const { updateProviderConnection } = await import("../../lib/db/repos/connectionsRepo.js");
    const result = await refreshTokenByProvider("codearts", conn);
    if (!result || result.error) return null;
    try {
      await updateProviderConnection(conn.id, {
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        ...(result.expiresIn ? {
          expiresIn: result.expiresIn,
          expiresAt: new Date(Date.now() + result.expiresIn * 1000).toISOString(),
          lastRefreshAt: new Date().toISOString(),
        } : {}),
        providerSpecificData: { ...(conn.providerSpecificData || {}), ...(result.providerSpecificData || {}) },
      });
    } catch {
      /* 回写失败不阻断本次签到 */
    }
    return result;
  } catch {
    return null;
  }
}

/**
 * 一轮签到：所有活跃 codearts 连接各尝试一次。
 * @param {{ skipIfCheckedToday?: boolean, memo?: object }} [deps]
 */
export async function runCodeartsCheckinTick(deps = {}) {
  const results = [];
  let connections = [];
  try {
    connections = await loadActiveConnections();
  } catch (err) {
    log.warn("CODEARTS_CHECKIN", "Load connections failed (swallowed)", { error: err?.message ?? String(err) });
    return results;
  }

  const eligible = (Array.isArray(connections) ? connections : []).filter(
    (c) => isEligibleCodeartsConnection(c) && !isNeedsReauthCooling(c)
  );
  if (eligible.length === 0) {
    log.debug("CODEARTS_CHECKIN", "Tick: no eligible codearts connections");
    return results;
  }

  const memo = deps.memo || null;
  const today = dayKey();

  for (const conn of eligible) {
    try {
      if (deps.skipIfCheckedToday && memo && memo[conn.id] === today) {
        continue;
      }
      const outcome = await checkinOne(conn, deps);
      if (memo && (outcome.status === "checked-in" || outcome.status === "already")) {
        memo[conn.id] = today;
      }
      results.push({
        id: conn.id,
        name: conn.name || conn.id,
        status: outcome.status,
        ...(outcome.message ? { message: outcome.message } : {}),
        ...(outcome.credits ? { credits: outcome.credits } : {}),
        ...(outcome.error ? { error: outcome.error } : {}),
      });
      log.info("CODEARTS_CHECKIN", `${conn.name || conn.id}: ${outcome.message || outcome.status}`, { id: conn.id });
    } catch (err) {
      results.push({ id: conn.id, name: conn.name || conn.id, status: "failed", error: err?.message ?? String(err) });
      log.warn("CODEARTS_CHECKIN", "Connection check-in failed (swallowed)", {
        id: conn?.id,
        error: err?.message ?? String(err),
      });
    }
  }
  return results;
}

// ─── Scheduler ─────────────────────────────────────────────────────────────

async function safeTick(how) {
  try {
    const settings = await loadSettingsSafe();
    if (settings.codeartsCheckin === true) {
      const done = await getDoneMap();
      await runCodeartsCheckinTick({ skipIfCheckedToday: true, memo: done });
      await persistDoneMap();
    } else {
      log.debug("CODEARTS_CHECKIN", `Scheduled ${how}: setting off, skipping`);
    }
  } catch (err) {
    log.warn("CODEARTS_CHECKIN", `Scheduled ${how} rejected (swallowed)`, {
      error: err?.message ?? String(err),
    });
  }
}

function msUntilNextTick() {
  return TICK_MS + Math.floor(Math.random() * TICK_JITTER_MS);
}

function scheduleNext() {
  if (!started) return;
  clearTimer();
  timerHandle = setTimeout(() => {
    safeTick("tick").finally(() => scheduleNext());
  }, msUntilNextTick());
  if (timerHandle.unref) timerHandle.unref();
}

function clearTimer() {
  if (timerHandle) {
    clearTimeout(timerHandle);
    timerHandle = null;
  }
}

export function startCodeartsCheckin() {
  if (started) return;
  started = true;
  log.info("CODEARTS_CHECKIN", "CodeArts auto check-in scheduler started");
  safeTick("boot").finally(() => scheduleNext());
}

export function stopCodeartsCheckin() {
  started = false;
  clearTimer();
}
