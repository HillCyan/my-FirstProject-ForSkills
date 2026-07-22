#!/usr/bin/env node
/**
 * Skill 安全流水线
 *
 * 检测层只负责「标记」，一旦有问题 → 进沙箱做动态验证。
 * 检测层不做最终放行决定。
 *
 * 用法:
 *   node security/pipeline.js a-demo2
 *   node security/pipeline.js a-demo a-demo2
 */

const path = require("path");
const { scanSkillDir } = require("../scanner/scan-skill");
const { setupSandbox, teardownSandbox } = require("./sandbox/setup");
const { runSandboxEval } = require("./sandbox/run");

// 未来接入特化模型时，在此调用 auditor 服务
async function auditWithModel(skillDir) {
  // TODO: 调用 training/ 微调后的审查模型
  // 返回 { flagged: boolean, risk, categories, confidence }
  return { flagged: false, risk: "low", categories: [], confidence: 0, source: "model" };
}

function isFlaggedByScanner(scanResult) {
  return scanResult.findings.length > 0;
}

function isFlaggedByModel(auditResult) {
  return auditResult.flagged || auditResult.risk !== "low";
}

async function processSkill(skillDir) {
  const absDir = path.resolve(skillDir);
  const name = path.basename(absDir);

  console.log(`\n${"─".repeat(60)}`);
  console.log(`处理 Skill: ${name}`);

  // ── 第 1 层：静态扫描 ──
  const scanResult = scanSkillDir(absDir);
  const scannerFlagged = isFlaggedByScanner(scanResult);

  console.log(`  [静态扫描] ${scannerFlagged ? "⚠️  已标记" : "✅ 未标记"} (${scanResult.findings.length} 项)`);

  // ── 第 2 层：模型语义审查（后续接入） ──
  const auditResult = await auditWithModel(absDir);
  const modelFlagged = isFlaggedByModel(auditResult);

  console.log(`  [模型审查] ${modelFlagged ? "⚠️  已标记" : "✅ 未标记"} (risk=${auditResult.risk})`);

  const flagged = scannerFlagged || modelFlagged;

  if (!flagged) {
    console.log(`  [结论]     ✅ 两层均未标记 → 直接放行，不进沙箱`);
    return { name, flagged: false, verdict: "allow", scanResult, auditResult };
  }

  // ── 只要被标记 → 进沙箱 ──
  console.log(`  [结论]     ⚠️  已被标记 → 进入沙箱动态验证`);

  const sandbox = setupSandbox(name);
  let evalResult;

  try {
    evalResult = await runSandboxEval({
      skillDir: absDir,
      sandbox,
      scanResult,
      auditResult,
    });
  } finally {
    teardownSandbox(sandbox);
  }

  console.log(`  [沙箱]     ${evalResult.passed ? "✅ 沙箱验证通过" : "❌ 沙箱验证失败"}`);
  console.log(`  [最终]     ${evalResult.verdict}`);

  return {
    name,
    flagged: true,
    verdict: evalResult.verdict,
    scanResult,
    auditResult,
    sandboxResult: evalResult,
  };
}

async function main() {
  const targets = process.argv.slice(2);

  if (targets.length === 0) {
    console.log("Skill 安全流水线\n");
    console.log("规则: 静态扫描或模型审查任一标记 → 自动进沙箱");
    console.log("\n用法: node security/pipeline.js <skill目录> [...]");
    process.exit(1);
  }

  console.log("🔒 Skill 安全流水线启动");
  console.log("   检测 = 标记 | 标记有问题 = 进沙箱");

  const results = [];
  for (const target of targets) {
    results.push(await processSkill(target));
  }

  console.log(`\n${"=".repeat(60)}`);
  console.log("总结:");
  for (const r of results) {
    const icon = r.verdict === "allow" ? "✅" : r.verdict === "block" ? "❌" : "⚠️";
    console.log(`  ${icon} ${r.name} → ${r.verdict}${r.flagged ? " (经沙箱)" : ""}`);
  }

  const blocked = results.some((r) => r.verdict === "block");
  process.exit(blocked ? 1 : 0);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { processSkill };
