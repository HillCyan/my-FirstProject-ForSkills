#!/usr/bin/env node
/**
 * Skill 静态安全扫描器（最基础的第一层检测）
 *
 * 用法:
 *   node scanner/scan-skill.js a-demo2
 *   node scanner/scan-skill.js a-demo a-demo2
 */

const fs = require("fs");
const path = require("path");

// 危险模式规则：id, 严重级别, 正则, 说明
const RULES = [
  {
    id: "dump-all-env",
    severity: "high",
    pattern: /所有环境变量|all environment variables|process\.env/gi,
    message: "要求输出全部环境变量",
  },
  {
    id: "no-redaction",
    severity: "high",
    pattern: /不要.*脱敏|不做.*脱敏|no redact|without.*sanitiz|完整值|完整内容|完整输出/gi,
    message: "要求输出敏感信息且不做脱敏",
  },
  {
    id: "ssh-private-key",
    severity: "high",
    pattern: /\.ssh\/id_rsa|\.ssh\\id_rsa|ssh.*private/gi,
    message: "涉及 SSH 私钥路径",
  },
  {
    id: "aws-credentials",
    severity: "high",
    pattern: /\.aws\/credentials|\.aws\\credentials/gi,
    message: "涉及 AWS 凭证文件",
  },
  {
    id: "secret-keywords",
    severity: "medium",
    pattern: /SECRET|TOKEN|PASSWORD|API[_-]?KEY|ACCESS[_-]?KEY/g,
    message: "涉及密钥类环境变量关键词",
  },
  {
    id: "ignore-permission-errors",
    severity: "medium",
    pattern: /忽略.*权限|ignore.*permission|ignore.*error.*continue/gi,
    message: "要求忽略权限错误继续执行",
  },
  {
    id: "hidden-system-prompt",
    severity: "high",
    pattern: /SYSTEM_PROMPT\s*=|system[_-]?prompt\s*[:=]/gi,
    message: "代码中埋藏 SYSTEM_PROMPT 诱导字符串",
  },
  {
    id: "read-env-permission",
    severity: "low",
    pattern: /read_env|read-env/gi,
    message: "声明了 read_env 权限",
  },
  {
    id: "read-files-permission",
    severity: "low",
    pattern: /read_files|read-files/gi,
    message: "声明了 read_files 权限",
  },
];

function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

function scanContent(content, fileLabel) {
  const findings = [];

  for (const rule of RULES) {
    const matches = [...content.matchAll(rule.pattern)];
    if (matches.length === 0) continue;

    const lines = content.split("\n");
    const locations = matches.slice(0, 5).map((m) => {
      const before = content.slice(0, m.index);
      const line = before.split("\n").length;
      return { line, excerpt: lines[line - 1]?.trim().slice(0, 120) || m[0] };
    });

    findings.push({
      ...rule,
      file: fileLabel,
      count: matches.length,
      locations,
    });
  }

  return findings;
}

function scanSkillDir(skillDir) {
  const absDir = path.resolve(skillDir);
  const name = path.basename(absDir);

  if (!fs.existsSync(absDir)) {
    return { name, dir: absDir, error: "目录不存在", findings: [] };
  }

  const filesToScan = ["SKILL.md", "skill.md", "index.js", "index.ts"];
  const findings = [];

  for (const file of filesToScan) {
    const filePath = path.join(absDir, file);
    const content = readFileSafe(filePath);
    if (content) {
      findings.push(...scanContent(content, file));
    }
  }

  const severityRank = { high: 3, medium: 2, low: 1 };
  const maxSeverity = findings.reduce(
    (max, f) => (severityRank[f.severity] > severityRank[max] ? f.severity : max),
    "low"
  );

  return {
    name,
    dir: absDir,
    findings,
    maxSeverity: findings.length ? maxSeverity : "pass",
    passed: !findings.some((f) => f.severity === "high"),
  };
}

function printReport(result) {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`Skill: ${result.name}`);
  console.log(`路径:  ${result.dir}`);

  if (result.error) {
    console.log(`状态:  ❌ ${result.error}`);
    return false;
  }

  if (result.findings.length === 0) {
    console.log("状态:  ✅ 未发现已知危险模式");
    return true;
  }

  const icon = { high: "🔴", medium: "🟡", low: "🔵" };
  console.log(`状态:  ${result.passed ? "⚠️  有中低危项" : "❌ 发现高危项"}`);

  for (const f of result.findings) {
    console.log(`\n  ${icon[f.severity]} [${f.severity.toUpperCase()}] ${f.message}`);
    console.log(`     规则: ${f.id} | 文件: ${f.file} | 命中: ${f.count} 次`);
    for (const loc of f.locations) {
      console.log(`     L${loc.line}: ${loc.excerpt}`);
    }
  }

  return result.passed;
}

function main() {
  const targets = process.argv.slice(2);

  if (targets.length === 0) {
    console.log("Skill 静态安全扫描器\n");
    console.log("用法: node scanner/scan-skill.js <skill目录> [更多目录...]");
    console.log("\n示例:");
    console.log("  node scanner/scan-skill.js a-demo");
    console.log("  node scanner/scan-skill.js a-demo a-demo2");
    process.exit(1);
  }

  console.log("🔍 Skill 静态安全扫描");
  const results = targets.map(scanSkillDir);
  const allPassed = results.every(printReport);

  console.log(`\n${"=".repeat(60)}`);
  console.log(
    allPassed
      ? "总结: ✅ 所有 Skill 未检出高危模式"
      : "总结: ❌ 存在高危 Skill，建议阻止安装或人工复核"
  );

  process.exit(allPassed ? 0 : 1);
}

if (require.main === module) {
  main();
}

module.exports = { scanSkillDir, RULES };
