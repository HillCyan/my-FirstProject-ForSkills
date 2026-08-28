# skills-security

skills-security 是一个本地优先（Local-First）的 Skill 安全评估工具，用于扫描 Skills 目录中的潜在风险模式，适配 Trae、OpenClaw、Claude Code（cc）、Cursor 等生态。

## 一键安装

### 方式 A：使用 skhub（推荐）

先安装 skhub CLI：

```bash
npm install -g skhub-cli
```

然后直接安装本 Skill：

```bash
skhub install skills-security
```

SkillHub 地址：

- 公测地址：`https://skillhub.quanmwl.com`
- 正式地址：`https://skillhub.xin`

### 方式 B：使用仓库安装脚本

Windows（PowerShell）：

```powershell
iwr https://raw.githubusercontent.com/Damond-Fung/skills-security/main/install.ps1 -UseBasicParsing | iex
```

Linux / macOS：

```bash
curl -fsSL https://raw.githubusercontent.com/Damond-Fung/skills-security/main/install.sh | bash
```

默认安装到：

- Windows: `%USERPROFILE%\.trae\skills\skills-security`
- Linux/macOS: `$HOME/.trae/skills/skills-security`

安装后可直接运行：

```bash
py -3 %USERPROFILE%\.trae\skills\skills-security\main.py <skills_dir>
```

## 拉取后能否直接用

可以。只要仓库根目录包含 `main.py`、`SKILL.md`、`skill.json`，拉取后即可直接运行，无需额外依赖包。

## 快速开始

1. 拉取仓库

```bash
git clone <你的仓库地址>
cd <仓库目录>
```

2. 扫描目标 Skills 目录

```bash
py -3 main.py <skills_dir>
```

示例：

```bash
py -3 main.py d:\path\to\skills
```

3. 指定报告输出目录（可选）

```bash
py -3 main.py <skills_dir> <output_dir>
```

示例：

```bash
py -3 main.py d:\path\to\skills d:\path\to\output
```

## 项目结构

```text
skills-security/
├── install.ps1
├── install.sh
├── main.py
├── SKILL.md
├── skill.json
├── README.md
├── LICENSE.txt
├── checklists/
├── docs/
├── examples/
└── templates/
```

## 输出说明

- `skill_basic_info`：被评估 Skill 基本信息（名称/类型/路径）
- `skill_basic_info[].platforms`：每个 Skill 的平台兼容列表
- `detection_items`：命中的检测项目清单
- `risk_counts`：高/中/低风险统计
- `scanned_files`：扫描文件数
- `findings`：风险发现列表
- `summary`：结果摘要
- `report_files.json`：JSON 报告路径
- `report_files.md`：Markdown 报告路径
- `report_files.summary`：汇总文本路径

Markdown 报告包含：

- 被评估 Skill 基本信息
- 检测项目
- 中高低风险明细
- 整改建议

## 规则范围（当前版本）

- 高风险：`rm -rf`、`eval(...)`、硬编码密钥模式
- 中风险：`child_process.exec/execSync(...)`
- 低风险：`http://` 明文链接

## 发布建议

- 保持仓库根目录即 Skill 根目录
- 不提交本地产物：`auto_reports/`、`.history/`、`__pycache__/`
- 如需在平台导入，直接使用仓库目录或打包 zip（根目录需保持为 `skills-security/`）

## 附：用户提供的统一 API 模型清单（逐个点名：可用 / 不适用）

以下对应 CLI 用法：

```bash
# 统一骨架（所有"✅可用"模型都套这一条，--model 直接抄下面完整名）
python main.py /path/to/skill \
  --llm \
  --provider custom \
  --base-url https://<你的网关，通常到/v1 或完整 /v1/chat/completions 两种都可以> \
  --model <模型全名，和控制台显示一字不差> \
  --api-key sk-xxxx

# 跑之前先做配置校验（快速解决 401/模型名拼写错误）
python main.py --provider custom --base-url <网关> --model <模型全名> --api-key <真实key> --diagnose-llm
```

### A. ✅ 灰区裁定推荐（快、便宜、JSON 稳定）
可直接用于 `--llm` 的灰区裁定（80% 日常首选），逐个点名：

- `GLM-4-Flash`、`GLM-4.5-Flash`、`GLM-5.3-Flash`、`GLM-4V-Flash`
- `Qwen3.8-Flash`、`Qwen3.6-Flash`、`Qwen3.6-Plus`、`Qwen3.7-Plus`、`Qwen3.5-Plus`
- `MiniMax-M1-80k`、`MiniMax-M2`、`MiniMax-M2.5`、`MiniMax-M2.7`、`MiniMax-Text-01`
- `Baichuan-M2`
- `GLM-Z1-Flash`、`GLM-Z1-Air`、`GLM-Z1-AirX`
- `Kimi-K2.5`、`Kimi-K2.6`

示例：
```bash
python main.py ./mySkills/demo --llm --provider custom --base-url https://api.siliconflow.cn/v1 --model GLM-4-Flash --api-key sk-xxx
python main.py ./mySkills/demo --llm --provider custom --base-url https://api.siliconflow.cn/v1 --model Qwen3.7-Plus --api-key sk-xxx
```

### B. ✅ 全量深挖 / 大推理 / 高难混淆类 推荐（慢但质量高）
建议用于 `--llm-full`（混淆、base64 编码、自然语言诱导、权限诱导等需要理解上下文的场景），逐个点名：

- `GLM-5`、`GLM-5.1`、`GLM-5.2`、`GLM-5.3`、`GLM-4.7`、`GLM-4-Plus`
- `DeepSeek-V4-Pro`、`DeepSeek-V4-Pro-0813`、`DeepSeek-V4-Flash`、`DeepSeek-V4-Flash-0731`
- `DeepSeek-R1`、`DeepSeek-R1-0528`（推理/思考类模型，会慢，必要时调大 `REQUEST_TIMEOUT`）
- `DeepSeek-V3.2-Thinking`、`DeepSeek-V3.2-Instruct`、`DeepSeek-V3.2`、`DeepSeek-V3.2-Exp`、`DeepSeek-V3.1`、`DeepSeek-V3.1-Terminus`、`DeepSeek-V3-250324`
- `Kimi-K3`
- `ERNIE-5.0-Thinking-Preview`（思考类，同 R1 较慢）
- `Baichuan-M3`
- `Qwen3.7-Max`、`Qwen3.8-Max`
- `MiniMax-M3`
- `Intern-S2-Preview`

示例：
```bash
python main.py ./mySkills/obfuscated-skill --llm-full --provider custom --base-url https://api.siliconflow.cn/v1 --model GLM-5.3 --api-key sk-xxx
python main.py ./mySkills/obfuscated-skill --llm-full --provider custom --base-url https://api.siliconflow.cn/v1 --model DeepSeek-R1 --api-key sk-xxx
python main.py ./mySkills/obfuscated-skill --llm-full --provider custom --base-url https://api.siliconflow.cn/v1 --model Kimi-K3 --api-key sk-xxx
```

### C. ✅ 长上下文 / 多模态底座 / 大尺寸参数 Chat 兼容类
Chat 接口完全兼容，但参数量大或主打长上下文，只建议在 `--llm-full` / 超大型 skill 仓库时使用，逐个点名：

- `GLM-4.5`、`GLM-4.5-Air`、`GLM-4.5-AirX`、`GLM-4.5-X`
- `GLM-4.6`、`GLM-4.6V`
- `GLM-4.5V`、`GLM-4V`、`GLM-4V-Plus-0111`
- `GLM-4-Long`、`GLM-4-9B`、`GLM-4-Air`、`GLM-4-AirX`、`GLM-4-FlashX`
- `Qwen-Long`
- `Qwen3.5-27B`、`Qwen3.6-27B`、`Qwen3.8-27B`、`Qwen3.5-35B-A3B`、`Qwen3.5-122B-A10B`、`Qwen3.5-397B-A17B`
- `ERNIE-4.5-Turbo-32K`、`ERNIE-4.5-Turbo-128K`、`ERNIE-4.5-Turbo-VL-32K`
- `Baichuan-M2-128K`
- `MiniMax-M1-80k`

### D. ❌ 完全不适用（调用只会报错或返回乱，不要试）
以下模型虽然在你的 API 控制台"显示可用"，但**不是聊天/文本生成模型**，或其输入/输出和本工具的 `chat/completions + JSON 安全判定` 完全不匹配，属于必错类：

**Embedding / 重排类**（返回向量数组，不是 JSON 判定报告）：
- `GLM-Embedding-2`、`GLM-Embedding-3`、`GLM-Rerank`

**文生图 / 图生图 类**（返回二进制 / base64 图片，不是 JSON）：
- `GLM-CogView3-Flash`
- `Doubao-Seedream-3.0-T2I`、`Doubao-Seedream-4.0`、`Doubao-Seedream-4.5`、`Doubao-Seedream-5.0-lite`
- `WanX2.1-T2I-Turbo`、`WanX2.1-T2I-Plus`

**视频生成 / 动作生成 类**（返回视频或视频描述流）：
- `MiniMax-I2V-01`、`MiniMax-I2V-01-Live`、`MiniMax-I2V-01-Director`
- `MiniMax-T2V-01`、`MiniMax-T2V-01-Director`
- `Doubao-Seedance-1.0-Pro`
- `MiniMax-Hailuo-02`

**ASR 类**（输入应该是音频，本工具输入是纯文本 skill 源码）：
- `GLM-ASR-2512`

**OCR 类**（输入应该是图片，不是纯文本）：
- `PaddleOCR-VL-0.9B`、`PaddleOCR-VL-1.5`
