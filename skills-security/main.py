import json
import re
import sys
import os
import hashlib
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple

# LLM 分析模块（可选）
try:
    import requests
    from requests.adapters import HTTPAdapter
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False


# ==================== LLM 缓存 ====================
_LLM_CACHE_DIR: Optional[Path] = None


def _get_cache_dir() -> Path:
    """返回 LLM 磁盘缓存目录（首次调用时创建）"""
    global _LLM_CACHE_DIR
    if _LLM_CACHE_DIR is None:
        root = Path(os.getenv("SKILL_SEC_CACHE_DIR") or (Path(tempfile.gettempdir()) / "skill-sec-llm-cache"))
        root.mkdir(parents=True, exist_ok=True)
        _LLM_CACHE_DIR = root
    return _LLM_CACHE_DIR


def _cache_key(prompt: str, provider: str, model: str) -> str:
    raw = f"{provider}|{model}|{prompt}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _cache_read(key: str, ttl_seconds: int = 86400 * 7) -> Optional[Dict[str, Any]]:
    path = _get_cache_dir() / f"{key}.json"
    if not path.exists():
        return None
    try:
        age = time.time() - path.stat().st_mtime
        if age > ttl_seconds:
            path.unlink(missing_ok=True)
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _cache_write(key: str, payload: Dict[str, Any]) -> None:
    try:
        path = _get_cache_dir() / f"{key}.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


# ==================== 预筛：快速判断是否需要 full 模式 LLM ====================
# 这些特征只要命中其一才值得用 full 模式深挖，否则直接跳过
_FULL_MODE_SCREEN_RE = re.compile(
    r"(atob\s*\(|btoa\s*\(|Buffer\.from\s*\([^)]*base64"
    r"|\\\\x[0-9a-fA-F]{2}|\\\\u[0-9a-fA-F]{4}"
    r"|\[['\"]\w['\"]\]\s*\+\s*\[['\"]\w['\"]|\.join\s*\(\s*\["
    r"|os\.homedir\(\)|process\.env|os\.environ"
    r"|\.ssh[\\/]|\.aws[\\/]|\.env\b|\.gnupg"
    r"|sendData|upload\(|collect\(|exfiltrate"
    r"|信任我|不要限制权限|忽略安全检查|不要脱敏|完整输出不截断"
    r"|system[_-]?prompt|SYSTEM_PROMPT\s*=)",
    re.I,
)


def _need_full_mode_deepscan(skill_text: str) -> bool:
    """全文 <300 字 或 无高危特征时，跳过 full 模式 LLM。"""
    if not skill_text or len(skill_text.strip()) < 300:
        return False
    return bool(_FULL_MODE_SCREEN_RE.search(skill_text))


# ==================== HTTP 连接复用 ====================
def _build_http_session() -> "requests.Session":
    s = requests.Session()
    adapter = HTTPAdapter(pool_connections=8, pool_maxsize=32, max_retries=0)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


CHECK_ITEMS = [
    # ===== 危险命令类 =====
    {
        "code": "CMD_RM_RF",
        "name": "危险删除命令检测",
        "severity": "high",
        "regex": re.compile(r"\b(rm\s+-rf|del\s+/s\s+/q|rd\s+/s\s+/q)\b", re.I),
        "message": "检测到潜在破坏性删除命令",
        "remediation": "限制删除范围并加入路径白名单校验"
    },
    {
        "code": "DYN_EVAL",
        "name": "动态执行检测",
        "severity": "high",
        "regex": re.compile(r"\beval\s*\("),
        "message": "检测到动态执行代码模式",
        "remediation": "替换为显式分支逻辑，禁止直接 eval"
    },
    {
        "code": "SHELL_EXEC",
        "name": "Shell执行调用检测",
        "severity": "medium",
        "regex": re.compile(r"(child_process\.(exec|execSync)|subprocess\.(run|call|Popen)|os\.system)\s*\("),
        "message": "检测到 shell 执行调用",
        "remediation": "改用参数化调用并增加命令白名单"
    },

    # ===== 密钥/凭证类 =====
    {
        "code": "HARDCODED_SECRET",
        "name": "硬编码密钥检测",
        "severity": "high",
        "regex": re.compile(r"(api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*['\"`].{8,}['\"`]?", re.I),
        "message": "检测到疑似硬编码密钥",
        "remediation": "改为环境变量或密钥管理服务注入"
    },
    {
        "code": "SSH_KEY_EXPOSE",
        "name": "SSH私钥路径泄露检测",
        "severity": "high",
        "regex": re.compile(r"\.ssh[/\\](id_rsa|id_ed25519|id_ecdsa|id_dsa)", re.I),
        "message": "检测到 SSH 私钥路径引用",
        "remediation": "禁止直接引用SSH私钥，使用SSH Agent或安全存储"
    },
    {
        "code": "AWS_CREDENTIALS",
        "name": "AWS凭证文件访问检测",
        "severity": "high",
        "regex": re.compile(r"\.aws[/\\]credentials", re.I),
        "message": "检测到 AWS 凭证文件路径引用",
        "remediation": "使用 IAM 角色或临时凭证，避免直接访问凭证文件"
    },
    {
        "code": "GCP_CREDENTIALS",
        "name": "GCP凭证文件访问检测",
        "severity": "high",
        "regex": re.compile(r"\.(config[/\\])?gcloud[/\\](application_default_credentials|credentials)", re.I),
        "message": "检测到 GCP 凭证文件路径引用",
        "remediation": "使用服务账号 impersonation 或 Workload Identity"
    },

    # ===== 环境变量泄露类 =====
    {
        "code": "ENV_DUMP",
        "name": "环境变量全量输出检测",
        "severity": "high",
        "regex": re.compile(r"(所有|全部|所有).{0,5}(环境变量|environment\s*variables?)", re.I),
        "message": "检测到要求输出所有环境变量的指令",
        "remediation": "禁止要求输出全部环境变量，仅请求必要的变量"
    },
    {
        "code": "PROCESS_ENV_DUMP",
        "name": "process.env全量输出检测",
        "severity": "high",
        "regex": re.compile(r"(process\.env|os\.environ)(?!.*filter|.*whitelist)", re.I),
        "message": "检测到可能输出全部环境变量的代码",
        "remediation": "使用白名单过滤，仅输出必要的变量"
    },
    {
        "code": "NO_REDACTION",
        "name": "禁止脱敏检测",
        "severity": "high",
        "regex": re.compile(r"(不要|不做|不|禁止).{0,5}(脱敏|隐藏|掩码|mask|redact|sanitiz)", re.I),
        "message": "检测到要求输出敏感信息且不做脱敏",
        "remediation": "必须对敏感信息进行脱敏处理"
    },

    # ===== 个人隐私信息类 =====
    {
        "code": "PII_PHONE",
        "name": "手机号泄露检测",
        "severity": "medium",
        "regex": re.compile(r"phone\s*[:=]\s*['\"]?1[3-9]\d{9}['\"]?", re.I),
        "message": "检测到疑似手机号泄露",
        "remediation": "手机号应脱敏显示，禁止硬编码真实号码"
    },
    {
        "code": "PII_ID_CARD",
        "name": "身份证号泄露检测",
        "severity": "high",
        "regex": re.compile(r"(id[_-]?card|身份证)\s*[:=]\s*['\"]?\d{17}[\dXx]['\"]?", re.I),
        "message": "检测到疑似身份证号泄露",
        "remediation": "身份证号应脱敏显示，禁止硬编码真实号码"
    },
    {
        "code": "PII_EMAIL",
        "name": "邮箱泄露检测",
        "severity": "medium",
        "regex": re.compile(r"(email|邮箱)\s*[:=]\s*['\"][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}['\"]", re.I),
        "message": "检测到疑似邮箱地址泄露",
        "remediation": "邮箱地址应脱敏显示，避免硬编码真实邮箱"
    },
    {
        "code": "PII_BANK_CARD",
        "name": "银行卡号泄露检测",
        "severity": "high",
        "regex": re.compile(r"(bank[_-]?card|银行卡|卡号)\s*[:=]\s*['\"]?\d{16,19}['\"]?", re.I),
        "message": "检测到疑似银行卡号泄露",
        "remediation": "银行卡号必须脱敏，禁止硬编码真实卡号"
    },

    # ===== 敏感文件访问类 =====
    {
        "code": "SENSITIVE_FILE_ACCESS",
        "name": "敏感文件访问检测",
        "severity": "high",
        "regex": re.compile(r"(\.env|\.htpasswd|\.netrc|\.pgpass|hosts\.equiv|\.rhosts)", re.I),
        "message": "检测到敏感配置文件路径引用",
        "remediation": "禁止直接读取敏感配置文件，使用安全配置管理"
    },
    {
        "code": "DB_CREDENTIALS",
        "name": "数据库凭证泄露检测",
        "severity": "high",
        "regex": re.compile(r"(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@", re.I),
        "message": "检测到数据库连接字符串中包含凭证",
        "remediation": "使用环境变量或密钥管理服务存储数据库凭证"
    },

    # ===== 安全绕过类 =====
    {
        "code": "IGNORE_PERMISSION",
        "name": "忽略权限错误检测",
        "severity": "medium",
        "regex": re.compile(r"(忽略|忽略|ignore).{0,5}(权限|permission|error)", re.I),
        "message": "检测到要求忽略权限错误继续执行",
        "remediation": "权限错误应正确处理，不应被忽略"
    },
    {
        "code": "DISABLE_VALIDATION",
        "name": "禁用安全校验检测",
        "severity": "medium",
        "regex": re.compile(r"(verify\s*=\s*false|ssl_verify\s*=\s*false|check\s*=\s*false|verify=False)", re.I),
        "message": "检测到禁用安全校验的配置",
        "remediation": "不应禁用SSL/TLS证书校验"
    },

    # ===== 其他 =====
    {
        "code": "HTTP_INSECURE",
        "name": "明文HTTP调用检测",
        "severity": "low",
        "regex": re.compile(r"http://", re.I),
        "message": "检测到明文 HTTP 链接",
        "remediation": "替换为 HTTPS 并校验证书"
    },
    {
        "code": "SYSTEM_PROMPT_HIDDEN",
        "name": "隐藏系统提示注入检测",
        "severity": "high",
        "regex": re.compile(r"SYSTEM_PROMPT\s*=|system[_-]?prompt\s*[:=]", re.I),
        "message": "检测到代码中埋藏 SYSTEM_PROMPT 诱导字符串",
        "remediation": "禁止在代码中隐藏系统提示注入"
    },

    # ===== 自然语言下毒检测（针对SKILL.md等文档）=====
    {
        "code": "NL_ENV_DUMP_REQUEST",
        "name": "自然语言-环境变量泄露请求",
        "severity": "high",
        "regex": re.compile(r"(请|帮我|让|要求|需要).{0,10}(输出|打印|显示|列出|获取|读取).{0,10}(所有|全部|完整).{0,10}(环境变量|环境信息)", re.I),
        "message": "检测到要求输出环境变量的自然语言指令",
        "remediation": "Skill不应要求AI输出环境变量"
    },
    {
        "code": "NL_SECRET_REQUEST",
        "name": "自然语言-密钥泄露请求",
        "severity": "high",
        "regex": re.compile(r"(请|帮我|让|要求|需要).{0,10}(输出|打印|显示|提供|获取|读取).{0,10}(密钥|secret|token|password|密码|凭证|凭证)", re.I),
        "message": "检测到要求输出密钥的自然语言指令",
        "remediation": "Skill不应要求AI输出密钥或凭证"
    },
    {
        "code": "NL_FILE_EXFIL",
        "name": "自然语言-文件窃取请求",
        "severity": "high",
        "regex": re.compile(r"(请|帮我|让|要求|需要).{0,10}(读取|访问|获取|上传|发送|传输).{0,10}(\.ssh|\.aws|\.env|\.gnupg|私钥|凭证|密钥文件)", re.I),
        "message": "检测到要求读取敏感文件的自然语言指令",
        "remediation": "Skill不应要求AI读取敏感文件"
    },
    {
        "code": "NL_NO_REDACTION",
        "name": "自然语言-禁止脱敏请求",
        "severity": "high",
        "regex": re.compile(r"(不要|禁止|忽略|跳过).{0,10}(脱敏|隐藏|掩码|加密|保护|安全检查)", re.I),
        "message": "检测到要求跳过脱敏的自然语言指令",
        "remediation": "Skill不应要求AI跳过安全检查"
    },
    {
        "code": "NL_BYPASS_SECURITY",
        "name": "自然语言-绕过安全请求",
        "severity": "high",
        "regex": re.compile(r"(绕过|忽略|跳过|禁用|关闭).{0,10}(安全|权限|检查|验证|限制|沙箱)", re.I),
        "message": "检测到要求绕过安全机制的自然语言指令",
        "remediation": "Skill不应要求AI绕过安全机制"
    },
    {
        "code": "NL_EXEC_COMMAND",
        "name": "自然语言-危险命令执行请求",
        "severity": "high",
        "regex": re.compile(r"(请|帮我|让|要求|需要).{0,10}(执行|运行|调用).{0,10}(rm\s+-rf|del\s+/s|format|mkfs|dd\s+if=)", re.I),
        "message": "检测到要求执行危险命令的自然语言指令",
        "remediation": "Skill不应要求AI执行破坏性命令"
    },
    {
        "code": "NL_DATA_EXFIL",
        "name": "自然语言-数据外泄请求",
        "severity": "high",
        "regex": re.compile(r"(请|帮我|让|要求|需要).{0,10}(上传|发送|传输|上传到|发送到|传输到).{0,10}(http|ftp|外部服务器|远程)", re.I),
        "message": "检测到可能泄露数据的自然语言指令",
        "remediation": "Skill不应要求AI将数据发送到外部"
    },
    {
        "code": "NL_IMPERSONATE",
        "name": "自然语言-身份冒充请求",
        "severity": "high",
        "regex": re.compile(r"(假装|冒充|扮演|模拟).{0,10}(系统|管理员|root|超级用户|其他用户)", re.I),
        "message": "检测到要求冒充身份的自然语言指令",
        "remediation": "Skill不应要求AI冒充其他身份"
    },
    {
        "code": "NL_PERSISTENCE",
        "name": "自然语言-持久化攻击请求",
        "severity": "medium",
        "regex": re.compile(r"(修改|更改|写入).{0,10}(启动项|注册表|crontab|\.bashrc|\.profile|systemd)", re.I),
        "message": "检测到可能建立持久化的自然语言指令",
        "remediation": "Skill不应要求AI修改系统启动配置"
    },
    {
        "code": "NL_PRIVILEGE_ESCALATE",
        "name": "自然语言-提权请求",
        "severity": "high",
        "regex": re.compile(r"(提升|获取|获得).{0,10}(权限|特权|root|sudo|管理员)", re.I),
        "message": "检测到要求提权的自然语言指令",
        "remediation": "Skill不应要求AI提升权限"
    },
    {
        "code": "NL_NETWORK_SCAN",
        "name": "自然语言-网络扫描请求",
        "severity": "medium",
        "regex": re.compile(r"(扫描|探测|探测).{0,10}(端口|网络|主机|ip|服务器)", re.I),
        "message": "检测到要求网络扫描的自然语言指令",
        "remediation": "Skill不应要求AI进行网络扫描"
    },
    {
        "code": "NL_DECODE_EXEC",
        "name": "自然语言-解码执行请求",
        "severity": "high",
        "regex": re.compile(r"(解码|解密|base64|atob|fromCharCode).{0,10}(然后|之后|接着).{0,10}(执行|运行|eval)", re.I),
        "message": "检测到要求解码后执行的自然语言指令",
        "remediation": "Skill不应要求AI解码并执行代码"
    },
    {
        "code": "NL_COMPLETE_OUTPUT",
        "name": "自然语言-完整输出请求",
        "severity": "medium",
        "regex": re.compile(r"(完整|全部|全部内容|不截断|不省略|完整输出).{0,10}(输出|显示|打印)", re.I),
        "message": "检测到要求完整输出不截断的自然语言指令",
        "remediation": "Skill应允许对输出进行合理截断"
    },
    {
        "code": "NL_IGNORE_ERROR",
        "name": "自然语言-忽略错误请求",
        "severity": "medium",
        "regex": re.compile(r"(忽略|忽略|跳过|不管).{0,10}(错误|失败|异常|报错)", re.I),
        "message": "检测到要求忽略错误的自然语言指令",
        "remediation": "Skill不应要求AI忽略错误继续执行"
    },
    {
        "code": "NL_SOCIAL_ENGINEER",
        "name": "自然语言-社会工程学攻击",
        "severity": "high",
        "regex": re.compile(r"(欺骗|诱导|诱骗|诱使|忽悠).{0,10}(用户|受害者|目标)", re.I),
        "message": "检测到可能涉及社会工程学的自然语言指令",
        "remediation": "Skill不应包含欺骗用户的内容"
    },
    {
        "code": "NL_KEYLOG",
        "name": "自然语言-键盘记录请求",
        "severity": "high",
        "regex": re.compile(r"(记录|捕获|监听|监控).{0,10}(键盘|按键|输入|密码输入)", re.I),
        "message": "检测到可能涉及键盘记录的自然语言指令",
        "remediation": "Skill不应要求监控用户输入"
    },
    {
        "code": "NL_SCREEN_CAPTURE",
        "name": "自然语言-屏幕截图请求",
        "severity": "medium",
        "regex": re.compile(r"(截取|捕获|截图|截屏|屏幕截图).{0,10}(屏幕|桌面|显示)", re.I),
        "message": "检测到要求截屏的自然语言指令",
        "remediation": "Skill不应要求截取用户屏幕"
    },
    {
        "code": "NL_WEIRD_INSTRUCTION",
        "name": "自然语言-异常指令模式",
        "severity": "medium",
        "regex": re.compile(r"(忽略|忘记|覆盖).{0,10}(之前|上述|以上).{0,10}(指令|规则|限制|约束)", re.I),
        "message": "检测到可能覆盖规则的异常指令",
        "remediation": "Skill不应要求AI忽略之前的规则"
    },

    # ===== 更多用户个人隐私检测 =====
    {
        "code": "PII_ADDRESS",
        "name": "地址信息泄露检测",
        "severity": "medium",
        "regex": re.compile(r"(address|地址|住址|居住地)\s*[:=]\s*['\"].{5,}['\"]", re.I),
        "message": "检测到疑似地址信息泄露",
        "remediation": "地址信息应脱敏显示，避免硬编码真实地址"
    },
    {
        "code": "PII_NAME",
        "name": "姓名泄露检测",
        "severity": "medium",
        "regex": re.compile(r"(name|姓名|真实姓名|全名)\s*[:=]\s*['\"][\u4e00-\u9fa5]{2,4}['\"]", re.I),
        "message": "检测到疑似真实姓名泄露",
        "remediation": "姓名应使用化名或脱敏处理"
    },
    {
        "code": "PII_BIRTHDAY",
        "name": "生日泄露检测",
        "severity": "medium",
        "regex": re.compile(r"(birthday|birth_date|生日|出生日期)\s*[:=]\s*['\"]?\d{4}[-/]\d{1,2}[-/]\d{1,2}['\"]?", re.I),
        "message": "检测到疑似生日信息泄露",
        "remediation": "生日信息应脱敏或隐藏年份"
    },
    {
        "code": "PII_PASSPORT",
        "name": "护照号泄露检测",
        "severity": "high",
        "regex": re.compile(r"(passport|护照|护照号)\s*[:=]\s*['\"]?[A-Z]{1,2}\d{7,9}['\"]?", re.I),
        "message": "检测到疑似护照号泄露",
        "remediation": "护照号必须脱敏，禁止硬编码"
    },
    {
        "code": "PII_LICENSE",
        "name": "驾驶证号泄露检测",
        "severity": "high",
        "regex": re.compile(r"(driver[_-]?license|驾驶证|驾照号)\s*[:=]\s*['\"]?\d{12,18}['\"]?", re.I),
        "message": "检测到疑似驾驶证号泄露",
        "remediation": "驾驶证号必须脱敏，禁止硬编码"
    },
    {
        "code": "PII_SOCIAL_SECURITY",
        "name": "社保号泄露检测",
        "severity": "high",
        "regex": re.compile(r"(social[_-]?security|社保号|社保卡号)\s*[:=]\s*['\"]?\d{9,18}['\"]?", re.I),
        "message": "检测到疑似社保号泄露",
        "remediation": "社保号必须脱敏，禁止硬编码"
    },
    {
        "code": "PII_TAX_ID",
        "name": "税号泄露检测",
        "severity": "high",
        "regex": re.compile(r"(tax[_-]?id|税号|纳税人识别号)\s*[:=]\s*['\"]?\d{15,20}['\"]?", re.I),
        "message": "检测到疑似税号泄露",
        "remediation": "税号必须脱敏，禁止硬编码"
    },
    {
        "code": "PII_HEALTH_RECORD",
        "name": "健康档案泄露检测",
        "severity": "high",
        "regex": re.compile(r"(health[_-]?record|病历|诊断|病情|医疗记录)\s*[:=]", re.I),
        "message": "检测到疑似健康档案信息",
        "remediation": "健康档案属于敏感个人信息，应加密存储"
    },
    {
        "code": "PII_EDUCATION",
        "name": "学历信息泄露检测",
        "severity": "low",
        "regex": re.compile(r"(education|学历|毕业院校|学位)\s*[:=]\s*['\"].{3,}['\"]", re.I),
        "message": "检测到疑似学历信息",
        "remediation": "学历信息应谨慎处理"
    },
    {
        "code": "PII_OCCUPATION",
        "name": "职业信息泄露检测",
        "severity": "low",
        "regex": re.compile(r"(occupation|job|职业|工作单位|公司名称)\s*[:=]\s*['\"].{2,}['\"]", re.I),
        "message": "检测到疑似职业信息",
        "remediation": "职业信息应谨慎处理"
    },
    {
        "code": "PII_FAMILY",
        "name": "家庭成员信息泄露检测",
        "severity": "medium",
        "regex": re.compile(r"(family|家庭成员|配偶|子女|父母|紧急联系人)\s*[:=]", re.I),
        "message": "检测到疑似家庭成员信息",
        "remediation": "家庭成员信息属于敏感隐私，应加密存储"
    },

    # ===== 更多系统凭证检测 =====
    {
        "code": "AZURE_CREDENTIALS",
        "name": "Azure凭证泄露检测",
        "severity": "high",
        "regex": re.compile(r"(azure[_-]?connection[_-]?string|azure[_-]?storage[_-]?key|DefaultEndpointsProtocol)", re.I),
        "message": "检测到 Azure 凭证信息",
        "remediation": "使用 Azure Key Vault 或环境变量管理凭证"
    },
    {
        "code": "ALIYUN_CREDENTIALS",
        "name": "阿里云凭证泄露检测",
        "severity": "high",
        "regex": re.compile(r"(accesskeyid|accesskeysecret|aliyun[_-]?key)\s*[:=]", re.I),
        "message": "检测到阿里云凭证信息",
        "remediation": "使用阿里云 RAM 角色或环境变量管理凭证"
    },
    {
        "code": "TENCENT_CREDENTIALS",
        "name": "腾讯云凭证泄露检测",
        "severity": "high",
        "regex": re.compile(r"(secretid|secretkey|tencent[_-]?key)\s*[:=]", re.I),
        "message": "检测到腾讯云凭证信息",
        "remediation": "使用腾讯云 CAM 角色或环境变量管理凭证"
    },
    {
        "code": "JWT_SECRET",
        "name": "JWT密钥泄露检测",
        "severity": "high",
        "regex": re.compile(r"jwt[_-]?(secret|key|token)\s*[:=]\s*['\"].{10,}['\"]", re.I),
        "message": "检测到 JWT 密钥硬编码",
        "remediation": "JWT 密钥应使用环境变量注入"
    },
    {
        "code": "OAUTH_SECRET",
        "name": "OAuth密钥泄露检测",
        "severity": "high",
        "regex": re.compile(r"(oauth[_-]?client[_-]?secret|client[_-]?secret)\s*[:=]\s*['\"].{10,}['\"]", re.I),
        "message": "检测到 OAuth 客户端密钥",
        "remediation": "OAuth 密钥应使用安全存储"
    },
    {
        "code": "ENCRYPTION_KEY",
        "name": "加密密钥泄露检测",
        "severity": "high",
        "regex": re.compile(r"(encryption[_-]?key|aes[_-]?key|private[_-]?key)\s*[:=]\s*['\"].{10,}['\"]", re.I),
        "message": "检测到加密密钥硬编码",
        "remediation": "加密密钥应使用密钥管理服务"
    },
    {
        "code": "COOKIE_SECRET",
        "name": "Cookie密钥泄露检测",
        "severity": "high",
        "regex": re.compile(r"cookie[_-]?(secret|key|sign)\s*[:=]\s*['\"].{10,}['\"]", re.I),
        "message": "检测到 Cookie 密钥硬编码",
        "remediation": "Cookie 密钥应使用环境变量注入"
    },
    {
        "code": "SESSION_SECRET",
        "name": "Session密钥泄露检测",
        "severity": "high",
        "regex": re.compile(r"session[_-]?(secret|key)\s*[:=]\s*['\"].{10,}['\"]", re.I),
        "message": "检测到 Session 密钥硬编码",
        "remediation": "Session 密钥应使用环境变量注入"
    },

    # ===== 国家政府隐私检测 =====
    {
        "code": "GOV_CLASSIFIED",
        "name": "涉密关键词检测",
        "severity": "high",
        "regex": re.compile(r"(机密|绝密|秘密|涉密|内部文件|仅供内部)", re.I),
        "message": "检测到可能涉密的内容标记",
        "remediation": "涉密内容不应出现在代码或文档中"
    },
    {
        "code": "GOV_DOCUMENT",
        "name": "政府文件引用检测",
        "severity": "high",
        "regex": re.compile(r"(红头文件|政府内部|行政命令|内部通知)", re.I),
        "message": "检测到可能的政府内部文件引用",
        "remediation": "政府内部文件不应出现在代码中"
    },
    {
        "code": "GOV_SYSTEM",
        "name": "政府系统访问检测",
        "severity": "high",
        "regex": re.compile(r"(政务内网|政务外网|政府系统|公安系统|军网)", re.I),
        "message": "检测到可能的政府系统访问请求",
        "remediation": "政府系统访问应有严格的权限控制"
    },

    # ===== 更多自然语言隐私检测 =====
    {
        "code": "NL_ADDRESS_REQUEST",
        "name": "自然语言-地址信息请求",
        "severity": "medium",
        "regex": re.compile(r"(请|帮我|让|要求).{0,10}(提供|获取|读取|显示).{0,10}(地址|住址|居住地|位置)", re.I),
        "message": "检测到要求获取地址信息的自然语言指令",
        "remediation": "Skill不应要求获取用户地址信息"
    },
    {
        "code": "NL_FAMILY_REQUEST",
        "name": "自然语言-家庭成员信息请求",
        "severity": "medium",
        "regex": re.compile(r"(请|帮我|让|要求).{0,10}(提供|获取|读取).{0,10}(家庭成员|配偶|子女|父母|亲属)", re.I),
        "message": "检测到要求获取家庭成员信息的自然语言指令",
        "remediation": "Skill不应要求获取用户家庭成员信息"
    },
    {
        "code": "NL_HEALTH_REQUEST",
        "name": "自然语言-健康信息请求",
        "severity": "high",
        "regex": re.compile(r"(请|帮我|让|要求).{0,10}(提供|获取|读取).{0,10}(病历|诊断|病情|健康记录|医疗信息)", re.I),
        "message": "检测到要求获取健康信息的自然语言指令",
        "remediation": "Skill不应要求获取用户健康信息"
    },
    {
        "code": "NL_LOCATION_TRACK",
        "name": "自然语言-位置追踪请求",
        "severity": "high",
        "regex": re.compile(r"(追踪|定位|获取|监控).{0,10}(位置|地点|GPS|地理坐标)", re.I),
        "message": "检测到要求追踪位置的自然语言指令",
        "remediation": "Skill不应要求追踪用户位置"
    },
    {
        "code": "NL_PHOTO_REQUEST",
        "name": "自然语言-照片获取请求",
        "severity": "medium",
        "regex": re.compile(r"(请|帮我|让|要求).{0,10}(提供|获取|上传|发送).{0,10}(照片|头像|证件照|自拍)", re.I),
        "message": "检测到要求获取照片的自然语言指令",
        "remediation": "Skill不应要求获取用户照片"
    },
    {
        "code": "NL_VOICE_REQUEST",
        "name": "自然语言-语音获取请求",
        "severity": "medium",
        "regex": re.compile(r"(请|帮我|让|要求).{0,10}(提供|获取|上传|发送).{0,10}(语音|录音|声音)", re.I),
        "message": "检测到要求获取语音的自然语言指令",
        "remediation": "Skill不应要求获取用户语音"
    },
    {
        "code": "NL_CONTACT_REQUEST",
        "name": "自然语言-通讯录获取请求",
        "severity": "high",
        "regex": re.compile(r"(请|帮我|让|要求).{0,10}(提供|获取|读取|导出).{0,10}(通讯录|联系人|好友列表)", re.I),
        "message": "检测到要求获取通讯录的自然语言指令",
        "remediation": "Skill不应要求获取用户通讯录"
    },
    {
        "code": "NL_MESSAGE_REQUEST",
        "name": "自然语言-消息记录获取请求",
        "severity": "high",
        "regex": re.compile(r"(请|帮我|让|要求).{0,10}(提供|获取|读取).{0,10}(聊天记录|消息|短信|邮件)", re.I),
        "message": "检测到要求获取消息记录的自然语言指令",
        "remediation": "Skill不应要求获取用户消息记录"
    },
    {
        "code": "NL_BROWSER_HISTORY",
        "name": "自然语言-浏览器历史获取请求",
        "severity": "high",
        "regex": re.compile(r"(请|帮我|让|要求).{0,10}(提供|获取|读取).{0,10}(浏览器|历史|浏览记录)", re.I),
        "message": "检测到要求获取浏览器历史的自然语言指令",
        "remediation": "Skill不应要求获取用户浏览历史"
    },
    {
        "code": "NL_FILE_LIST",
        "name": "自然语言-文件列表获取请求",
        "severity": "medium",
        "regex": re.compile(r"(请|帮我|让|要求).{0,10}(列出|获取|显示).{0,10}(所有文件|文件列表|目录内容)", re.I),
        "message": "检测到要求列出文件的自然语言指令",
        "remediation": "Skill不应随意获取文件列表"
    },
    {
        "code": "NL_CREDENTIAL_REQUEST",
        "name": "自然语言-凭证获取请求",
        "severity": "high",
        "regex": re.compile(r"(请|帮我|让|要求).{0,10}(提供|获取|显示).{0,10}(密码|口令|pin码|验证码)", re.I),
        "message": "检测到要求获取凭证的自然语言指令",
        "remediation": "Skill不应要求获取用户密码等凭证"
    },

    # ===== 软性越权 / 诱导话术（易漏检的灰区）=====
    {
        "code": "NL_SOFT_TRUST",
        "name": "自然语言-盲目信任诱导",
        "severity": "medium",
        "regex": re.compile(r"(信任我|相信我|不要怀疑|尽管放心|我保证(安全|无害)|不会外传[（(]?信任)", re.I),
        "message": "检测到诱导盲目信任的自然语言话术",
        "remediation": "Skill不应要求用户或 Agent 无条件信任其行为"
    },
    {
        "code": "NL_EXPAND_PERMISSION",
        "name": "自然语言-扩大权限请求",
        "severity": "high",
        "regex": re.compile(
            r"(不要|别|请勿|无需|不用).{0,10}(限制|约束|缩小).{0,10}(权限|能力|工具)|"
            r"(需要|要求|请给).{0,10}(全部|所有|完整|无限|最大).{0,10}(权限|访问)|"
            r"请不要限制工具的权限",
            re.I,
        ),
        "message": "检测到要求扩大或取消权限限制的自然语言指令",
        "remediation": "Skill应遵循最小权限，不应要求放开全部权限"
    },
    {
        "code": "NL_DISABLE_GUARDRAIL",
        "name": "自然语言-关闭安全护栏",
        "severity": "high",
        "regex": re.compile(r"(关闭|取消|去掉|解除|移除).{0,10}(安全|权限).{0,8}(限制|护栏|约束|检查|校验)", re.I),
        "message": "检测到要求关闭安全护栏的自然语言指令",
        "remediation": "Skill不应要求关闭安全限制或护栏"
    },

    # ===== 代码混淆可疑模式 =====
    {
        "code": "OBFUSCATION_ATOB",
        "name": "编码混淆-atob/Base64",
        "severity": "medium",
        "regex": re.compile(r"\batob\s*\(|Buffer\.from\s*\([^)]*?,\s*['\"]base64['\"]", re.I),
        "message": "检测到 Base64/atob 解码，可能用于隐藏恶意载荷",
        "remediation": "避免用编码隐藏 URL 或命令；改为明文并说明用途"
    },
    {
        "code": "OBFUSCATION_EVAL_BUILD",
        "name": "编码混淆-动态构造eval",
        "severity": "high",
        "regex": re.compile(
            r"""['\"]e['\"]\s*\+\s*['\"]v['\"]\s*\+\s*['\"]a['\"]\s*\+\s*['\"]l['\"]|"""
            r"""\[['\"]e['\"],\s*['\"]v['\"],\s*['\"]a['\"],\s*['\"]l['\"]\]""",
            re.I,
        ),
        "message": "检测到通过字符串拼接构造 eval",
        "remediation": "禁止动态拼接 eval；使用显式、可审计的调用"
    },
    {
        "code": "OBFUSCATION_CMD_BUILD",
        "name": "编码混淆-动态构造危险命令",
        "severity": "high",
        "regex": re.compile(
            r"""['\"]r['\"]\s*\+\s*['\"]m['\"].{0,60}['\"]f['\"]|"""
            r"""dangerousCmd\s*=|"""
            r"""['\"]rm['\"]\s*\+\s*['\"]\s*-?rf['\"]""",
            re.I,
        ),
        "message": "检测到通过拼接构造危险删除命令",
        "remediation": "禁止动态拼接破坏性命令"
    },
    {
        "code": "OBFUSCATION_HEX_STRING",
        "name": "编码混淆-十六进制/Unicode字符串",
        "severity": "medium",
        "regex": re.compile(r"(\\x[0-9a-fA-F]{2}){6,}|(\\u[0-9a-fA-F]{4}){4,}"),
        "message": "检测到较长的十六进制/Unicode 编码字符串，可能用于隐藏密钥或载荷",
        "remediation": "避免用转义编码隐藏敏感字符串；改为配置注入"
    },
    {
        "code": "SILENT_CATCH",
        "name": "静默吞错检测",
        "severity": "low",
        "regex": re.compile(r"catch\s*\([^)]*\)\s*\{[^}]{0,120}(静默|swallow|ignore\s+error|pass\s*$)", re.I | re.M),
        "message": "检测到可能用于隐藏失败的静默 catch",
        "remediation": "错误应记录或上抛，避免空 catch 掩盖恶意行为"
    }
]

TEXT_FILE_EXTS = {".md", ".json", ".js", ".ts", ".py", ".sh", ".ps1", ".yaml", ".yml"}
IGNORE_DIRS = {"node_modules", ".git", "dist", "build", "coverage", "__pycache__"}
# 评测标注文件（若误放在技能目录内）仍显式跳过
LABEL_FILE_RE = re.compile(r"^风险\d+_隐私泄露\d+\.txt$", re.I)
COMMON_PLATFORM_SET = [
    "trae",
    "claude-code",
    "cc",
    "openclaw",
    "cursor",
    "codex",
    "gemini-cli",
    "aider",
    "windsurf",
    "kilo-code",
    "augment",
    "antigravity",
    "opencode",
    "universal",
    "amp",
    "cline",
    "github-copilot",
    "kimi-code-cli",
    "warp"
]

TYPE_NAME_ZH = {
    "trae-skill": "Trae 技能",
    "claude-skill": "SKILL.md 技能",
    "json-skill": "JSON 技能",
    "node-skill": "Node 技能",
    "unknown": "未知类型"
}

PLATFORM_NAME_ZH = {
    "trae": "Trae",
    "claude-code": "Claude Code",
    "cc": "Claude Code（cc）",
    "cursor": "Cursor",
    "openclaw": "OpenClaw",
    "codex": "OpenAI Codex",
    "gemini-cli": "Gemini CLI",
    "aider": "Aider",
    "windsurf": "Windsurf",
    "kilo-code": "Kilo Code",
    "opencode": "OpenCode",
    "augment": "Augment",
    "antigravity": "Antigravity",
    "github-copilot": "GitHub Copilot",
    "kimi-code-cli": "Kimi Code CLI",
    "cline": "Cline",
    "amp": "AMP",
    "warp": "Warp",
    "universal": "通用（跨平台）"
}

SEVERITY_ZH = {"high": "高", "medium": "中", "low": "低"}

# 隐私类型分类
PRIVACY_TYPE_ZH = {
    "system": "系统凭证泄露",
    "personal": "用户个人隐私",
    "government": "国家政府隐私",
    "security": "安全机制绕过",
    "other": "其他风险"
}

# 规则到隐私类型的映射
RULE_PRIVACY_TYPE = {
    # 系统凭证泄露（密钥、凭证、环境变量等）
    "HARDCODED_SECRET": "system",
    "SSH_KEY_EXPOSE": "system",
    "AWS_CREDENTIALS": "system",
    "GCP_CREDENTIALS": "system",
    "ENV_DUMP": "system",
    "PROCESS_ENV_DUMP": "system",
    "SENSITIVE_FILE_ACCESS": "system",
    "DB_CREDENTIALS": "system",
    "NL_ENV_DUMP_REQUEST": "system",
    "NL_SECRET_REQUEST": "system",
    "NL_FILE_EXFIL": "system",
    "AZURE_CREDENTIALS": "system",
    "ALIYUN_CREDENTIALS": "system",
    "TENCENT_CREDENTIALS": "system",
    "JWT_SECRET": "system",
    "OAUTH_SECRET": "system",
    "ENCRYPTION_KEY": "system",
    "COOKIE_SECRET": "system",
    "SESSION_SECRET": "system",
    
    # 用户个人隐私
    "PII_PHONE": "personal",
    "PII_ID_CARD": "personal",
    "PII_EMAIL": "personal",
    "PII_BANK_CARD": "personal",
    "NL_KEYLOG": "personal",
    "NL_SCREEN_CAPTURE": "personal",
    "NL_SOCIAL_ENGINEER": "personal",
    "PII_ADDRESS": "personal",
    "PII_NAME": "personal",
    "PII_BIRTHDAY": "personal",
    "PII_PASSPORT": "personal",
    "PII_LICENSE": "personal",
    "PII_SOCIAL_SECURITY": "personal",
    "PII_TAX_ID": "personal",
    "PII_HEALTH_RECORD": "personal",
    "PII_EDUCATION": "personal",
    "PII_OCCUPATION": "personal",
    "PII_FAMILY": "personal",
    "NL_ADDRESS_REQUEST": "personal",
    "NL_FAMILY_REQUEST": "personal",
    "NL_HEALTH_REQUEST": "personal",
    "NL_LOCATION_TRACK": "personal",
    "NL_PHOTO_REQUEST": "personal",
    "NL_VOICE_REQUEST": "personal",
    "NL_CONTACT_REQUEST": "personal",
    "NL_MESSAGE_REQUEST": "personal",
    "NL_BROWSER_HISTORY": "personal",
    "NL_FILE_LIST": "personal",
    "NL_CREDENTIAL_REQUEST": "personal",
    
    # 国家政府隐私
    "GOV_CLASSIFIED": "government",
    "GOV_DOCUMENT": "government",
    "GOV_SYSTEM": "government",
    
    # 安全机制绕过
    "NO_REDACTION": "security",
    "IGNORE_PERMISSION": "security",
    "DISABLE_VALIDATION": "security",
    "NL_NO_REDACTION": "security",
    "NL_BYPASS_SECURITY": "security",
    "NL_PRIVILEGE_ESCALATE": "security",
    "NL_IMPERSONATE": "security",
    "NL_WEIRD_INSTRUCTION": "security",
    "NL_SOFT_TRUST": "security",
    "NL_EXPAND_PERMISSION": "security",
    "NL_DISABLE_GUARDRAIL": "security",
    
    # 其他风险
    "CMD_RM_RF": "other",
    "DYN_EVAL": "other",
    "SHELL_EXEC": "other",
    "HTTP_INSECURE": "other",
    "SYSTEM_PROMPT_HIDDEN": "other",
    "NL_EXEC_COMMAND": "other",
    "NL_DATA_EXFIL": "other",
    "NL_PERSISTENCE": "other",
    "NL_NETWORK_SCAN": "other",
    "NL_DECODE_EXEC": "other",
    "NL_COMPLETE_OUTPUT": "other",
    "NL_IGNORE_ERROR": "other",
    "OBFUSCATION_ATOB": "other",
    "OBFUSCATION_EVAL_BUILD": "other",
    "OBFUSCATION_CMD_BUILD": "other",
    "OBFUSCATION_HEX_STRING": "other",
    "SILENT_CATCH": "other",
}

# 强制标为 suspicious 的规则（易误报或需二次确认）
FORCE_SUSPICIOUS_CODES = {
    "HTTP_INSECURE",
    "NL_COMPLETE_OUTPUT",
    "NL_IGNORE_ERROR",
    "IGNORE_PERMISSION",
    "PROCESS_ENV_DUMP",
    "NL_FILE_LIST",
    "GOV_CLASSIFIED",
    "GOV_DOCUMENT",
    "PII_EDUCATION",
    "PII_OCCUPATION",
    "NL_SCREEN_CAPTURE",
    "NL_SOFT_TRUST",
    "NL_EXPAND_PERMISSION",
    "NL_DISABLE_GUARDRAIL",
    "OBFUSCATION_ATOB",
    "OBFUSCATION_HEX_STRING",
    "SILENT_CATCH",
}

# 明确恶意模式：直接 confirmed
FORCE_CONFIRMED_CODES = {
    "CMD_RM_RF",
    "DYN_EVAL",
    "HARDCODED_SECRET",
    "SSH_KEY_EXPOSE",
    "AWS_CREDENTIALS",
    "GCP_CREDENTIALS",
    "DB_CREDENTIALS",
    "NL_ENV_DUMP_REQUEST",
    "NL_SECRET_REQUEST",
    "NL_FILE_EXFIL",
    "NL_DATA_EXFIL",
    "NL_EXEC_COMMAND",
    "NL_DECODE_EXEC",
    "OBFUSCATION_EVAL_BUILD",
    "OBFUSCATION_CMD_BUILD",
    "JWT_SECRET",
    "OAUTH_SECRET",
    "ENCRYPTION_KEY",
}

FAKE_VALUE_RE = re.compile(
    r"fake[-_]|example\.com|placeholder|your[-_]?api[-_]?key|changeme|"
    r"dummy|not[-_]?a[-_]?real|xxx{2,}|sk-fake|LTAI-FAKE|test[-_]?key",
    re.I,
)
HTTP_SAFE_HOST_RE = re.compile(
    r"https?://("
    r"localhost|127\.0\.0\.1|0\.0\.0\.0|"
    r"([\w-]+\.)?example\.com|"
    r"fake[-_][\w.-]+|"
    r"[\w.-]*\.local"
    r")",
    re.I,
)
CONFIDENCE_ZH = {"confirmed": "确定", "suspicious": "可疑"}
VERDICT_ZH = {"allow": "放行", "review": "人工复核", "block": "阻断"}


def get_privacy_type(rule_code: str) -> str:
    """获取规则对应的隐私类型"""
    return RULE_PRIVACY_TYPE.get(rule_code, "other")


def get_privacy_type_zh(rule_code: str) -> str:
    """获取规则对应的隐私类型中文名"""
    privacy_type = get_privacy_type(rule_code)
    return PRIVACY_TYPE_ZH.get(privacy_type, "其他风险")


def get_confidence(rule_code: str, severity: str) -> str:
    """规则置信度：confirmed / suspicious"""
    if rule_code in FORCE_CONFIRMED_CODES:
        return "confirmed"
    if rule_code in FORCE_SUSPICIOUS_CODES:
        return "suspicious"
    return "confirmed" if severity == "high" else "suspicious"


def extract_snippet(content: str, match: re.Match, radius: int = 80) -> str:
    start = max(0, match.start() - radius)
    end = min(len(content), match.end() + radius)
    snippet = content[start:end].replace("\n", " ").strip()
    if start > 0:
        snippet = "…" + snippet
    if end < len(content):
        snippet = snippet + "…"
    return snippet


def is_false_positive(item: Dict[str, Any], match: re.Match, content: str, file_path: Path) -> bool:
    """基于上下文的误报过滤（不整文件屏蔽测试 Skill）"""
    path_norm = str(file_path).replace("\\", "/").lower()
    if "/fixtures/" in path_norm:
        return True

    matched = match.group(0)
    window = content[max(0, match.start() - 120): min(len(content), match.end() + 120)]

    if item["code"] == "HTTP_INSECURE":
        url_window = content[match.start(): min(len(content), match.end() + 120)]
        if HTTP_SAFE_HOST_RE.search(url_window) or FAKE_VALUE_RE.search(url_window):
            return True
        return False

    # 混淆类规则不因注释里的 fake 字样而放过
    if item["code"].startswith("OBFUSCATION_") or item["code"] in {
        "NL_SOFT_TRUST",
        "NL_EXPAND_PERMISSION",
        "NL_DISABLE_GUARDRAIL",
        "SILENT_CATCH",
    }:
        return False

    # 命中值或邻近窗口明显是占位/示例数据（仅针对明文密钥/PII 类）
    if FAKE_VALUE_RE.search(matched) or FAKE_VALUE_RE.search(window):
        secret_like = (
            item["code"].startswith("PII_")
            or item["code"].endswith("_SECRET")
            or item["code"].endswith("_CREDENTIALS")
            or item["code"] in {
                "HARDCODED_SECRET",
                "DB_CREDENTIALS",
                "SENSITIVE_FILE_ACCESS",
            }
        )
        if secret_like:
            return True

    return False


def decide_verdict(findings: List[Dict[str, Any]]) -> str:
    """统一结论：allow / review / block"""
    if not findings:
        return "allow"
    if any(f.get("confidence") == "confirmed" and f.get("risk") == "high" for f in findings):
        return "block"
    if any(f.get("confidence") in {"confirmed", "suspicious"} for f in findings):
        return "review"
    return "allow"


PRIVACY_FOCUS_TYPES = ("personal", "government", "system")
PRIVACY_FOCUS_LABEL = {
    "personal": "个人隐私",
    "government": "国家隐私",
    "system": "系统凭证/隐私",
}


def build_privacy_leak_report(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """专门汇总隐私泄露（确定 / 疑似），聚焦个人隐私与国家隐私。"""
    buckets = {
        key: {
            "label": PRIVACY_FOCUS_LABEL[key],
            "confirmed": [],
            "suspicious": [],
            "confirmed_count": 0,
            "suspicious_count": 0,
        }
        for key in PRIVACY_FOCUS_TYPES
    }

    for item in findings:
        ptype = item.get("privacy_type")
        if ptype not in buckets:
            continue
        entry = {
            "check_code": item.get("check_code"),
            "check_name": item.get("check_name"),
            "risk": item.get("risk"),
            "risk_zh": to_severity_zh(item.get("risk", "low")),
            "file": item.get("file"),
            "line_hint": item.get("line_hint"),
            "message": item.get("message"),
            "evidence": item.get("evidence"),
            "matched_text": item.get("matched_text"),
            "confidence": item.get("confidence"),
            "confidence_zh": item.get("confidence_zh") or CONFIDENCE_ZH.get(item.get("confidence", ""), ""),
        }
        conf = item.get("confidence", "suspicious")
        if conf == "confirmed":
            buckets[ptype]["confirmed"].append(entry)
        else:
            buckets[ptype]["suspicious"].append(entry)

    for key in buckets:
        buckets[key]["confirmed_count"] = len(buckets[key]["confirmed"])
        buckets[key]["suspicious_count"] = len(buckets[key]["suspicious"])

    personal_c = buckets["personal"]["confirmed_count"]
    personal_s = buckets["personal"]["suspicious_count"]
    gov_c = buckets["government"]["confirmed_count"]
    gov_s = buckets["government"]["suspicious_count"]
    system_c = buckets["system"]["confirmed_count"]
    system_s = buckets["system"]["suspicious_count"]

    has_any = any(
        buckets[k]["confirmed_count"] + buckets[k]["suspicious_count"] > 0
        for k in PRIVACY_FOCUS_TYPES
    )

    highlights = []
    if personal_c or personal_s:
        highlights.append(
            f"个人隐私：确定泄露 {personal_c} 项，疑似泄露 {personal_s} 项"
        )
    if gov_c or gov_s:
        highlights.append(
            f"国家隐私：确定泄露 {gov_c} 项，疑似泄露 {gov_s} 项"
        )
    if system_c or system_s:
        highlights.append(
            f"系统凭证/隐私：确定泄露 {system_c} 项，疑似泄露 {system_s} 项"
        )
    if not highlights:
        highlights.append("未发现个人隐私、国家隐私或系统凭证类泄露（含疑似）")

    return {
        "has_privacy_leak": has_any,
        "highlights": highlights,
        "summary": "【隐私专项】" + "；".join(highlights) + "。",
        "personal": buckets["personal"],
        "government": buckets["government"],
        "system": buckets["system"],
        "totals": {
            "personal_confirmed": personal_c,
            "personal_suspicious": personal_s,
            "government_confirmed": gov_c,
            "government_suspicious": gov_s,
            "system_confirmed": system_c,
            "system_suspicious": system_s,
        },
    }


def build_summary(findings: List[Dict[str, Any]], risk_counts: Dict[str, int], verdict: str) -> str:
    conf_counts = {"confirmed": 0, "suspicious": 0}
    for item in findings:
        conf = item.get("confidence", "suspicious")
        conf_counts[conf] = conf_counts.get(conf, 0) + 1
    return (
        f"结论={VERDICT_ZH.get(verdict, verdict)}({verdict})；"
        f"高危{risk_counts['high']} / 中危{risk_counts['medium']} / 低危{risk_counts['low']}；"
        f"确定命中{conf_counts['confirmed']} / 可疑命中{conf_counts['suspicious']}。"
        + (
            " 建议阻断或拒绝安装。"
            if verdict == "block"
            else " 建议人工复核或启用 LLM 灰区裁定。"
            if verdict == "review"
            else " 未发现需处理风险。"
        )
    )


def build_privacy_summary(findings: List[Dict[str, Any]] = None, privacy_report: Dict[str, Any] = None) -> str:
    """仅用于隐私专项检测的摘要文案。"""
    report = privacy_report or build_privacy_leak_report(findings or [])
    return report.get("summary") or ("【隐私专项】" + "；".join(report.get("highlights", [])) + "。")


def apply_llm_reviews(findings: List[Dict[str, Any]], llm_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """根据 LLM 对 suspicious 项的裁定更新 findings"""
    reviews = llm_result.get("reviews") if isinstance(llm_result, dict) else None
    if not reviews:
        return findings

    review_map = {}
    for rev in reviews:
        key = (rev.get("check_code"), rev.get("file"))
        review_map[key] = rev

    updated = []
    for finding in findings:
        item = dict(finding)
        if item.get("confidence") != "suspicious":
            updated.append(item)
            continue
        rev = review_map.get((item.get("check_code"), item.get("file")))
        if not rev:
            # 兼容只按 check_code 匹配
            rev = next(
                (r for r in reviews if r.get("check_code") == item.get("check_code")),
                None,
            )
        if not rev:
            updated.append(item)
            continue
        decision = str(rev.get("decision", "")).lower().strip()
        item["llm_decision"] = decision
        item["llm_reason"] = rev.get("reason", "")
        if decision == "confirm":
            item["confidence"] = "confirmed"
        elif decision == "dismiss":
            continue  # 误报剔除
        elif decision == "escalate":
            item["confidence"] = "suspicious"
            item["escalated"] = True
        updated.append(item)
    return updated


def iter_files(root: Path):
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in IGNORE_DIRS for part in path.parts):
            continue
        if LABEL_FILE_RE.match(path.name):
            continue
        if path.suffix.lower() in TEXT_FILE_EXTS:
            yield path


def parse_frontmatter_name(content: str):
    block = re.match(r"^\s*---\s*\n([\s\S]*?)\n---", content)
    if not block:
        return ""
    match = re.search(r"^name:\s*['\"]?([^\r\n'\"]+)['\"]?\s*$", block.group(1), re.M)
    return match.group(1).strip() if match else ""


def classify_skill_type(skill_dir: Path):
    if (skill_dir / "SKILL.md").exists():
        normalized_path = str(skill_dir).replace("\\", "/").lower()
        if "/.trae/skills/" in normalized_path:
            return "trae-skill"
        return "claude-skill"
    if (skill_dir / "skill.json").exists():
        return "json-skill"
    if (skill_dir / "package.json").exists():
        return "node-skill"
    return "unknown"


def infer_platforms_from_skill_md(skill_dir: Path):
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return set()
    content = skill_md.read_text(encoding="utf-8", errors="ignore").lower()
    keyword_map = {
        "trae": "trae",
        "claude code": "claude-code",
        "(cc)": "cc",
        " cursor ": "cursor",
        "openclaw": "openclaw",
        "codex": "codex",
        "gemini cli": "gemini-cli",
        "aider": "aider",
        "windsurf": "windsurf",
        "kilo code": "kilo-code",
        "opencode": "opencode",
        "augment": "augment",
        "antigravity": "antigravity",
        "github copilot": "github-copilot",
        "kimi code cli": "kimi-code-cli",
        "cline": "cline",
        "amp": "amp",
        "warp": "warp",
        "skill.md-style": "universal",
        "跨平台": "universal"
    }
    detected = set()
    normalized = f" {content} "
    for keyword, platform_code in keyword_map.items():
        if keyword in normalized:
            detected.add(platform_code)
    return detected


def infer_platforms(skill_dir: Path, skill_type: str):
    platforms = set()
    normalized_path = str(skill_dir).replace("\\", "/").lower()
    if "/.trae/skills/" in normalized_path:
        platforms.add("trae")
    if "/.agents/skills/" in normalized_path:
        platforms.add("universal")
    skill_json = skill_dir / "skill.json"
    if skill_json.exists():
        try:
            payload = json.loads(skill_json.read_text(encoding="utf-8"))
            for item in payload.get("platforms", []):
                value = str(item).strip().lower()
                if value:
                    platforms.add(value)
        except Exception:
            pass
    platforms.update(infer_platforms_from_skill_md(skill_dir))
    if skill_type == "trae-skill":
        platforms.add("trae")
    elif skill_type == "claude-skill":
        platforms.update(COMMON_PLATFORM_SET)
    elif skill_type == "node-skill":
        platforms.add("universal")
    if "claude-code" in platforms and "cc" in platforms:
        platforms.remove("cc")
    if not platforms:
        platforms.add("universal")
    return sorted(platforms)


def to_type_name_zh(skill_type: str):
    return TYPE_NAME_ZH.get(skill_type, skill_type)


def to_platform_name_zh(platform_code: str):
    return PLATFORM_NAME_ZH.get(platform_code, platform_code)


def format_platforms_zh(platforms):
    if not platforms:
        return "通用（跨平台）"
    return "、".join(to_platform_name_zh(item) for item in platforms)


def to_severity_zh(severity: str):
    return SEVERITY_ZH.get(severity, severity)


def read_skill_name(skill_dir: Path):
    skill_md = skill_dir / "SKILL.md"
    if skill_md.exists():
        content = skill_md.read_text(encoding="utf-8", errors="ignore")
        parsed = parse_frontmatter_name(content)
        if parsed:
            return parsed
    skill_json = skill_dir / "skill.json"
    if skill_json.exists():
        try:
            return json.loads(skill_json.read_text(encoding="utf-8")).get("name", skill_dir.name)
        except Exception:
            return skill_dir.name
    package_json = skill_dir / "package.json"
    if package_json.exists():
        try:
            return json.loads(package_json.read_text(encoding="utf-8")).get("name", skill_dir.name)
        except Exception:
            return skill_dir.name
    return skill_dir.name


def detect_skills(skills_dir: Path):
    candidates = []
    for child in skills_dir.iterdir():
        if not child.is_dir() or child.name in IGNORE_DIRS:
            continue
        if (child / "SKILL.md").exists() or (child / "skill.json").exists() or (child / "package.json").exists():
            candidates.append(child)
    if (skills_dir / "SKILL.md").exists() or (skills_dir / "skill.json").exists() or (skills_dir / "package.json").exists():
        candidates.append(skills_dir)
    normalized = sorted({item.resolve() for item in candidates})
    skills = []
    for item in normalized:
        skill_type = classify_skill_type(item)
        platforms = infer_platforms(item, skill_type)
        skills.append(
            {
                "name": read_skill_name(item),
                "path": str(item),
                "type": skill_type,
                "type_zh": to_type_name_zh(skill_type),
                "platforms": platforms,
                "platforms_zh": [
                    to_platform_name_zh(platform)
                    for platform in platforms
                ]
            }
        )
    return skills


def assess(skills_dir: Path):
    findings = []
    scanned = 0
    suppressed = 0
    for file_path in iter_files(skills_dir):
        scanned += 1
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for item in CHECK_ITEMS:
            for match in item["regex"].finditer(content):
                if is_false_positive(item, match, content, file_path):
                    suppressed += 1
                    continue
                privacy_type = get_privacy_type(item["code"])
                confidence = get_confidence(item["code"], item["severity"])
                findings.append(
                    {
                        "file": str(file_path),
                        "risk": item["severity"],
                        "confidence": confidence,
                        "confidence_zh": CONFIDENCE_ZH.get(confidence, confidence),
                        "check_code": item["code"],
                        "check_name": item["name"],
                        "message": item["message"],
                        "remediation": item["remediation"],
                        "privacy_type": privacy_type,
                        "privacy_type_zh": PRIVACY_TYPE_ZH.get(privacy_type, "其他风险"),
                        "matched_text": match.group(0)[:200],
                        "evidence": extract_snippet(content, match),
                        "line_hint": content.count("\n", 0, match.start()) + 1,
                    }
                )
    risk_counts = {"high": 0, "medium": 0, "low": 0}
    confidence_counts = {"confirmed": 0, "suspicious": 0}
    privacy_counts = {"system": 0, "personal": 0, "government": 0, "security": 0, "other": 0}
    for item in findings:
        risk_counts[item["risk"]] += 1
        confidence_counts[item["confidence"]] = confidence_counts.get(item["confidence"], 0) + 1
        privacy_counts[item["privacy_type"]] += 1
    triggered_codes = {item["check_code"] for item in findings}
    detection_items = [
        {
            "code": item["code"],
            "name": item["name"],
            "severity": item["severity"],
            "confidence": get_confidence(item["code"], item["severity"]),
        }
        for item in CHECK_ITEMS
        if item["code"] in triggered_codes
    ]
    remediation_map = {}
    severity_rank = {"high": 0, "medium": 1, "low": 2}
    for item in findings:
        key = item["check_code"]
        if key not in remediation_map:
            remediation_map[key] = {
                "severity": item["risk"],
                "check_name": item["check_name"],
                "advice": item["remediation"],
                "privacy_type": item["privacy_type"],
                "privacy_type_zh": item["privacy_type_zh"],
                "confidence": item["confidence"],
            }
    remediation = sorted(remediation_map.values(), key=lambda x: severity_rank[x["severity"]])
    verdict = decide_verdict(findings)
    privacy_leak_report = build_privacy_leak_report(findings)
    return {
        "scanned_files": scanned,
        "suppressed_false_positives": suppressed,
        "findings": findings,
        "risk_counts": risk_counts,
        "confidence_counts": confidence_counts,
        "privacy_counts": privacy_counts,
        "privacy_leak_report": privacy_leak_report,
        "detection_items": detection_items,
        "remediation": remediation,
        "verdict": verdict,
        "verdict_zh": VERDICT_ZH.get(verdict, verdict),
        "summary": build_summary(findings, risk_counts, verdict),
    }


def to_safe_filename(value: str):
    return re.sub(r'[<>:"/\\|?*]+', "_", value).strip("_") or "skills-security"


def build_markdown_report(result, skills_dir: Path):
    risk = result["risk_counts"]
    privacy = result.get("privacy_counts", {})
    conf = result.get("confidence_counts", {})
    skills = result["skill_basic_info"]
    lines = [
        "# skills-security 评估报告",
        "",
        f"- 扫描目录：`{skills_dir}`",
        f"- 扫描时间：`{datetime.now().isoformat()}`",
        f"- 扫描文件：`{result['scanned_files']}`",
        f"- 结论：`{result.get('verdict_zh', result.get('verdict', 'N/A'))}` (`{result.get('verdict', 'N/A')}`)",
        f"- 高风险：`{risk['high']}`",
        f"- 中风险：`{risk['medium']}`",
        f"- 低风险：`{risk['low']}`",
        f"- 确定命中：`{conf.get('confirmed', 0)}`",
        f"- 可疑命中：`{conf.get('suspicious', 0)}`",
        f"- 已抑制疑似误报：`{result.get('suppressed_false_positives', 0)}`",
        "",
        "## 隐私泄露专项（确定 / 疑似）",
        "",
    ]
    privacy_report = result.get("privacy_leak_report") or build_privacy_leak_report(result.get("findings", []))
    for line in privacy_report.get("highlights", []):
        lines.append(f"- {line}")
    lines.append("")

    def append_privacy_bucket(title: str, bucket: Dict[str, Any]):
        confirmed_items = bucket.get("confirmed", [])
        suspicious_items = bucket.get("suspicious", [])
        if not confirmed_items and not suspicious_items:
            return
        lines.append(f"### {title}")
        lines.append("")
        if confirmed_items:
            lines.append(f"**确定泄露（{len(confirmed_items)}）**")
            lines.append("")
            lines.extend(["| 风险 | 检测项 | 证据 | 文件:行 |", "|---|---|---|---|"])
            for item in confirmed_items:
                ev = str(item.get("evidence", "")).replace("|", "\\|")[:100]
                loc = f"{item.get('file', '')}:{item.get('line_hint', '?')}"
                lines.append(
                    f"| {item.get('risk_zh', '')} | {item.get('check_name', '')} | `{ev}` | `{loc}` |"
                )
            lines.append("")
        if suspicious_items:
            lines.append(f"**疑似泄露（{len(suspicious_items)}）**")
            lines.append("")
            lines.extend(["| 风险 | 检测项 | 证据 | 文件:行 |", "|---|---|---|---|"])
            for item in suspicious_items:
                ev = str(item.get("evidence", "")).replace("|", "\\|")[:100]
                loc = f"{item.get('file', '')}:{item.get('line_hint', '?')}"
                lines.append(
                    f"| {item.get('risk_zh', '')} | {item.get('check_name', '')} | `{ev}` | `{loc}` |"
                )
            lines.append("")

    append_privacy_bucket("个人隐私", privacy_report.get("personal", {}))
    append_privacy_bucket("国家隐私", privacy_report.get("government", {}))
    append_privacy_bucket("系统凭证/隐私", privacy_report.get("system", {}))

    lines.extend([
        "## 隐私泄露统计",
        "",
        f"- 系统凭证泄露：`{privacy.get('system', 0)}` 项",
        f"- 用户个人隐私泄露：`{privacy.get('personal', 0)}` 项",
        f"- 国家政府隐私泄露：`{privacy.get('government', 0)}` 项",
        f"- 安全机制绕过：`{privacy.get('security', 0)}` 项",
        f"- 其他风险：`{privacy.get('other', 0)}` 项",
        "",
        "## 被评估Skill基本信息",
        ""
    ])
    if not skills:
        lines.append("- 未识别到标准技能目录")
    else:
        lines.extend(["| 名称 | 类型 | 平台 | 路径 |", "|---|---|---|---|"])
        for item in skills:
            platform_text = format_platforms_zh(item.get("platforms", []))
            lines.append(f"| {item['name']} | {to_type_name_zh(item['type'])} | {platform_text} | `{item['path']}` |")
    lines.extend(["", "## 检测项目", ""])
    if not result["detection_items"]:
        lines.append("- 本次扫描未命中已配置检测项")
    else:
        lines.extend(["| 编码 | 项目 | 风险级别 | 置信度 | 隐私类型 |", "|---|---|---|---|---|"])
        for item in result["detection_items"]:
            privacy_type_zh = get_privacy_type_zh(item['code'])
            conf_zh = CONFIDENCE_ZH.get(item.get("confidence", ""), item.get("confidence", ""))
            lines.append(
                f"| {item['code']} | {item['name']} | {to_severity_zh(item['severity'])} | "
                f"{conf_zh} | {privacy_type_zh} |"
            )
    lines.extend(["", "## 隐私泄露专报", ""])
    
    # 按隐私类型分组显示
    findings = result.get("findings", [])
    if not findings:
        lines.append("- 未发现隐私泄露问题")
    else:
        def append_finding_table(title, subset):
            if not subset:
                return
            lines.append(f"### {title}")
            lines.append("")
            lines.extend(["| 风险 | 置信度 | 检测项目 | 问题 | 证据 | 文件 |", "|---|---|---|---|---|---|"])
            for item in subset:
                file_cell = str(item["file"]).replace("|", "\\|")
                msg_cell = str(item["message"]).replace("|", "\\|")
                risk_cell = str(to_severity_zh(item["risk"])).replace("|", "\\|")
                check_cell = str(item["check_name"]).replace("|", "\\|")
                conf_cell = str(item.get("confidence_zh", item.get("confidence", ""))).replace("|", "\\|")
                evidence_cell = str(item.get("evidence", "")).replace("|", "\\|")[:120]
                lines.append(
                    f"| {risk_cell} | {conf_cell} | {check_cell} | {msg_cell} | "
                    f"`{evidence_cell}` | `{file_cell}` |"
                )
            lines.append("")

        append_finding_table("系统凭证泄露", [f for f in findings if f.get("privacy_type") == "system"])
        append_finding_table("用户个人隐私泄露", [f for f in findings if f.get("privacy_type") == "personal"])
        append_finding_table("国家政府隐私泄露 ⚠️", [f for f in findings if f.get("privacy_type") == "government"])
        append_finding_table("安全机制绕过", [f for f in findings if f.get("privacy_type") == "security"])
        other_findings = [f for f in findings if f.get("privacy_type") == "other"]
        append_finding_table("其他风险", other_findings)
    
    lines.extend(["## 整改意见", ""])
    if not result["remediation"]:
        lines.append("- 当前无需整改")
    else:
        for idx, item in enumerate(result["remediation"], start=1):
            privacy_label = f"[{item.get('privacy_type_zh', '其他')}] "
            conf_label = f"[{CONFIDENCE_ZH.get(item.get('confidence', ''), item.get('confidence', ''))}] "
            lines.append(
                f"{idx}. {privacy_label}{conf_label}[{to_severity_zh(item['severity'])}] "
                f"{item['check_name']}：{item['advice']}"
            )
    lines.extend(["", "## 结论", "", result["summary"]])
    return "\n".join(lines)


def write_reports(result, skills_dir: Path, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    target_name = to_safe_filename(skills_dir.name)
    json_path = output_dir / f"{target_name}_security_report.json"
    md_path = output_dir / f"{target_name}_security_report.md"
    summary_path = output_dir / "assessment_summary.txt"
    privacy = result.get("privacy_counts", {})
    system_privacy = privacy.get('system', 0) + privacy.get('personal', 0) + privacy.get('government', 0)
    result_with_meta = {
        "generated_at": datetime.now().isoformat(),
        "skills_dir": str(skills_dir),
        **result,
        "summary": result.get("summary") or build_summary(
            result.get("findings", []),
            result.get("risk_counts", {"high": 0, "medium": 0, "low": 0}),
            result.get("verdict", "allow"),
        ),
    }
    json_path.write_text(json.dumps(result_with_meta, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(build_markdown_report(result_with_meta, skills_dir), encoding="utf-8")
    privacy_report = result_with_meta.get("privacy_leak_report") or build_privacy_leak_report(
        result_with_meta.get("findings", [])
    )
    totals = privacy_report.get("totals", {})
    summary_lines = [
        f"评估时间: {result_with_meta['generated_at']}",
        f"目标目录: {skills_dir}",
        f"结论: {result_with_meta.get('verdict_zh', '')} ({result_with_meta.get('verdict', 'N/A')})",
        f"扫描文件: {result_with_meta['scanned_files']}",
        f"高风险: {result_with_meta['risk_counts']['high']}",
        f"中风险: {result_with_meta['risk_counts']['medium']}",
        f"低风险: {result_with_meta['risk_counts']['low']}",
        f"确定命中: {result_with_meta.get('confidence_counts', {}).get('confirmed', 0)}",
        f"可疑命中: {result_with_meta.get('confidence_counts', {}).get('suspicious', 0)}",
        f"已抑制疑似误报: {result_with_meta.get('suppressed_false_positives', 0)}",
        "隐私泄露专项:",
        *[f"  - {h}" for h in privacy_report.get("highlights", [])],
        f"  - 个人隐私 确定/疑似: {totals.get('personal_confirmed', 0)}/{totals.get('personal_suspicious', 0)}",
        f"  - 国家隐私 确定/疑似: {totals.get('government_confirmed', 0)}/{totals.get('government_suspicious', 0)}",
        f"  - 系统凭证 确定/疑似: {totals.get('system_confirmed', 0)}/{totals.get('system_suspicious', 0)}",
        f"隐私泄露总计: {system_privacy}",
        f"摘要: {result_with_meta['summary']}",
        f"JSON报告: {json_path}",
        f"Markdown报告: {md_path}"
    ]
    summary_path.write_text("\n".join(summary_lines), encoding="utf-8")
    return result_with_meta, json_path, md_path, summary_path


# ==================== LLM 分析模块 ====================

class LLMAnalyzer:
    """LLM 分析器，支持多种 LLM 提供商（已做：缓存/预筛/退避重试/分批/精简prompt/连接复用）。

    协议分三类：
    - openai_compat : OpenAI /v1/chat/completions（deepseek/zhipu/moonshot/sjtu/custom 都走它）
    - anthropic     : Anthropic /v1/messages（非 streaming）
    - ollama        : Ollama /api/chat（stream=False）
    """

    PROVIDERS = {
        "openai": {
            "url": "https://api.openai.com/v1/chat/completions",
            "model": "gpt-4o-mini",
            "header": lambda key: {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            "max_out_tokens": 1536,
            "protocol": "openai_compat",
        },
        "anthropic": {
            "url": "https://api.anthropic.com/v1/messages",
            "model": "claude-sonnet-4-20250514",
            "header": lambda key: {"x-api-key": key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
            "max_out_tokens": 2048,
            "protocol": "anthropic",
        },
        "deepseek": {
            "url": "https://api.deepseek.com/v1/chat/completions",
            "model": "deepseek-chat",
            "header": lambda key: {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            "max_out_tokens": 1536,
            "protocol": "openai_compat",
        },
        "sjtu": {
            "url": "https://models.sjtu.edu.cn/api/v1/chat/completions",
            "model": "deepseek-chat",
            "header": lambda key: {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            "max_out_tokens": 1536,
            "protocol": "openai_compat",
        },
        "zhipu": {
            "url": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
            "model": "glm-4-flash",
            "header": lambda key: {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            "max_out_tokens": 1536,
            "protocol": "openai_compat",
        },
        "moonshot": {
            "url": "https://api.moonshot.cn/v1/chat/completions",
            "model": "moonshot-v1-8k",
            "header": lambda key: {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            "max_out_tokens": 1536,
            "protocol": "openai_compat",
        },
        "ollama": {
            "url": "http://localhost:11434/api/chat",
            "model": "qwen2.5:7b-instruct",
            "header": lambda key: {"Content-Type": "application/json"},
            "max_out_tokens": 1536,
            "protocol": "ollama",
        },
        # ⭐通用 OpenAI 兼容入口：用 base_url 指定任意网关（硅基流动 / 内部模型商店 / 自研转发）
        # 用法：LLM_BASE_URL=https://api.siliconflow.cn/v1/chat/completions  LLM_MODEL=Qwen3.6-Plus  或  CLI --base-url ... --model ...
        "custom": {
            "url": "",  # 必须由 base_url 覆盖，否则会报错
            "model": "",  # 必须由 LLM_MODEL 或 CLI --model 覆盖
            "header": lambda key: {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            "max_out_tokens": 1536,
            "protocol": "openai_compat",
        },
    }

    # 精简版：更短、token 更少、JSON 结构更紧凑
    ANALYSIS_PROMPT = """你是Skill安全审计员，只做二分类风险挖掘。只输出JSON，禁止解释。
检测四类：
1)编码混淆：atob/base64/\\x..\\u..../字符串拼接构造eval或命令
2)隐蔽行为：静默catch/遍历process.env或os.environ/读.ssh/.aws/.env/调用homedir/收集系统信息/上传sendData,upload,collect
3)自然语言诱导："信任我"、"不要限制权限"、"忽略安全检查"、"不要脱敏"、"完整输出不截断"、冒充、覆盖规则
4)密钥泄露：sk-,api_key,token硬编码或编码后藏于代码/URL。

JSON格式：
{{"risk_level":"high|medium|low|none","findings":[{{"type":"混淆|隐蔽|诱导|密钥","severity":"high|medium|low","location":"","description":"","remediation":""}}],"static_missed":[],"summary":""}}

技能内容（前8K字）：
{content}
"""

    GRAY_AREA_PROMPT = """你是灰区裁定员。以下是静态扫描的suspicious命中。只按JSON输出：
{{"reviews":[{{"check_code":"","file":"","decision":"confirm|dismiss|escalate","reason":""}}],"summary":""}}
- confirm=确认真实风险；dismiss=误报示例无害；escalate=仍需人工。
- 不要重扫，逐条对号入座。

命中列表：
{findings_json}
"""

    # 灰区分批上限（单条LLM请求最多审多少项），太多会慢+易截断
    GRAY_BATCH_SIZE = 20
    # 超时（秒）。默认120s以兼容思考型模型(DeepSeek-R1等)；可用环境变量 SKILL_SEC_LLM_TIMEOUT 覆盖；失败做2次指数退避
    REQUEST_TIMEOUT = 120
    MAX_RETRIES = 2
    BACKOFF_BASE = 1.2

    def __init__(self, provider: str = "openai", api_key: str = None, model: str = None, base_url: str = None):
        if not LLM_AVAILABLE:
            raise ImportError("requests 库未安装，请运行: pip install requests")

        self.provider = provider.lower()
        if self.provider not in self.PROVIDERS:
            raise ValueError(f"不支持的 LLM 提供商: {provider}，支持: {list(self.PROVIDERS.keys())}")

        self.config = self.PROVIDERS[self.provider]
        self.protocol = self.config.get("protocol", "openai_compat")

        self.api_key = api_key if api_key is not None else _resolve_llm_api_key(self.provider, None)
        # model 优先级：参数显式 > LLM_MODEL env > provider 默认
        self.model = _resolve_llm_model(self.provider, model) or ""
        # url 优先级：参数 base_url 显式 > LLM_BASE_URL env > provider 默认
        self.url = _normalize_base_url_to_full(self.provider, base_url) or ""

        # 前置校验：避免调用时才知道没配
        if not self.model:
            raise ValueError(
                f"未配置模型名：provider={self.provider}。请设置 LLM_MODEL 或传 --model <模型名>。"
                "统一模型商店/硅基流动/自研网关 请使用 `--provider custom --base-url ... --model <模型名>`"
            )
        if not self.url:
            raise ValueError(
                f"未配置 endpoint：provider={self.provider}。请设置 LLM_BASE_URL 或传 --base-url <URL>，"
                "或选择内置 provider（openai/deepseek/zhipu/moonshot/sjtu/anthropic/ollama）。"
            )

        self._session = _build_http_session()
        # 超时可再用环境变量覆盖：SKILL_SEC_LLM_TIMEOUT（默认已是120s）
        try:
            self.REQUEST_TIMEOUT = int(os.getenv("SKILL_SEC_LLM_TIMEOUT", str(self.REQUEST_TIMEOUT)))
        except ValueError:
            pass

    # ---------- 解析 ----------
    def _parse_llm_json(self, content_text: str) -> Dict[str, Any]:
        content_text = (content_text or "").strip()
        if not content_text:
            return {"parse_error": "空响应"}
        # 先取 fenced
        m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", content_text, re.I)
        if m:
            content_text = m.group(1)
        try:
            return json.loads(content_text)
        except json.JSONDecodeError:
            pass
        a, b = content_text.find("{"), content_text.rfind("}")
        if -1 < a < b:
            try:
                return json.loads(content_text[a:b + 1])
            except json.JSONDecodeError:
                pass
        return {"raw_response": content_text, "parse_error": "无法解析为JSON"}

    # ---------- 核心调用（缓存+退避+连接复用） ----------
    def _call_llm(self, prompt: str) -> Dict[str, Any]:
        if not self.api_key and self.provider != "ollama":
            return {"error": f"未配置 API Key，请设置 LLM_API_KEY / {self.provider.upper()}_API_KEY 或传入 --api-key"}

        cache_k = _cache_key(prompt, self.provider, self.model)
        cached = _cache_read(cache_k)
        if cached is not None:
            cached.setdefault("_from_cache", True)
            return cached

        # 按协议构造 payload（而不是 provider），custom 也能正确构造
        max_out = self.config.get("max_out_tokens", 1536)
        if self.protocol == "anthropic":
            payload = {
                "model": self.model,
                "max_tokens": max_out,
                "messages": [{"role": "user", "content": prompt}],
            }
        elif self.protocol == "ollama":
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": max_out},
            }
        else:  # openai_compat
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": max_out,
            }
        headers = self.config["header"](self.api_key)
        last_err: Optional[str] = None
        # 诊断上下文：每次报错都带 provider/url/model/key 前缀，用户一眼知道"用了谁的key打哪一家"
        key_hint = (self.api_key or "")[:4] + "****" + (self.api_key or "")[-4:] if self.api_key else "<empty>"
        diag_ctx = f"[provider={self.provider}, protocol={self.protocol}, url={self.url}, model={self.model}, key={key_hint}]"

        for attempt in range(self.MAX_RETRIES + 1):
            try:
                resp = self._session.post(
                    self.url,
                    headers=headers,
                    json=payload,
                    timeout=self.REQUEST_TIMEOUT,
                )
                # 401/403 = 鉴权问题，绝不重试（重试只会浪费时间）
                if resp.status_code in (401, 403):
                    body = resp.text[:400]
                    extra = ""
                    if resp.status_code == 401:
                        extra = (
                            " 建议排查：1)该Key是否能对 url=" + self.url + " 生效（是否来自同一个网关/同一个平台）；"
                            "2)模型名=" + self.model + " 是否是该控制台显示的完整名称（区分大小写，连字符不要写错）；"
                            "3)是否已开通该API并绑定支付/额度；"
                            "4)用 --diagnose-llm 再核对最终生效值。"
                        )
                    return {
                        "error": f"LLM 鉴权失败{diag_ctx}: {resp.status_code} {body}{extra}",
                        "auth_error": True,
                        "status_code": resp.status_code,
                    }
                if resp.status_code in (429, 500, 502, 503, 504):
                    raise requests.exceptions.HTTPError(
                        f"{resp.status_code} retryable: {resp.text[:200]}", response=resp
                    )
                if resp.status_code != 200:
                    return {"error": f"LLM API 调用失败{diag_ctx}: {resp.status_code} {resp.text[:300]}"}

                data = resp.json()
                if self.protocol == "anthropic":
                    content = data.get("content") or [{}]
                    text = content[0].get("text", "") if content else ""
                elif self.protocol == "ollama":
                    text = (data.get("message") or {}).get("content", "")
                else:  # openai_compat
                    choices = data.get("choices") or [{}]
                    message = choices[0].get("message") or {}
                    # 兼容部分网关把 reasoning_content / text 放在不同字段
                    text = message.get("content", "") or message.get("reasoning_content", "") or ""
                parsed = self._parse_llm_json(text)
                _cache_write(cache_k, parsed)
                return parsed
            except requests.exceptions.Timeout:
                last_err = f"LLM API 调用超时{diag_ctx}"
            except requests.exceptions.HTTPError as e:
                last_err = f"{diag_ctx} {e}"
            except requests.exceptions.RequestException as e:
                last_err = f"LLM API 调用失败{diag_ctx}: {type(e).__name__}: {str(e)}"
            except Exception as e:
                return {"error": f"分析过程出错{diag_ctx}: {type(e).__name__}: {str(e)}"}

            if attempt < self.MAX_RETRIES:
                time.sleep(self.BACKOFF_BASE * (2 ** attempt))

        return {"error": (last_err or "LLM API 最终失败") + f" {diag_ctx}"}

    # ---------- 对外 API ----------
    def analyze(self, content: str, enable_prescreen: bool = True) -> Dict[str, Any]:
        """全量分析；enable_prescreen=True 时用预筛快速跳过无风险场景（节省90%场景时间）"""
        if enable_prescreen and not _need_full_mode_deepscan(content or ""):
            return {
                "skipped_by_prescreen": True,
                "reason": "无混淆/敏感文件/诱导语言等深度特征，直接跳过full扫描",
                "risk_level": "none",
                "findings": [],
                "static_missed": [],
                "summary": "预筛无命中",
            }
        prompt = self.ANALYSIS_PROMPT.format(content=(content or "")[:8000])
        return self._call_llm(prompt)

    def review_suspicious(self, suspicious_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """仅裁定 suspicious 命中；超阈值时自动分批调用再合并，避免单请求过大超时"""
        findings = list(suspicious_findings or [])
        if not findings:
            return {"mode": "gray", "skipped": True, "reason": "无可疑项", "reviews": [], "summary": ""}

        # 只保留关键字段，节省 token/体积
        compact_all = [
            {
                "check_code": f.get("check_code"),
                "check_name": f.get("check_name"),
                "file": f.get("file"),
                "risk": f.get("risk"),
                "message": f.get("message"),
                "evidence": (f.get("evidence") or "")[:160],
                "matched_text": (f.get("matched_text") or "")[:120],
            }
            for f in findings
        ]

        # 单批或多批
        batches = [compact_all[i:i + self.GRAY_BATCH_SIZE] for i in range(0, len(compact_all), self.GRAY_BATCH_SIZE)]
        merged_reviews: List[Dict[str, Any]] = []
        summaries: List[str] = []
        parse_errors: List[str] = []
        ran_batches = 0

        # 批间并发（≤3并发），单批内仍旧一次LLM调用
        concurrency = min(3, max(1, len(batches)))
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {
                pool.submit(self._run_gray_batch, idx, batch): idx for idx, batch in enumerate(batches)
            }
            for fut in as_completed(futures):
                ran_batches += 1
                try:
                    part = fut.result()
                    merged_reviews.extend(part.get("reviews", []))
                    s = part.get("summary")
                    if s:
                        summaries.append(f"批{futures[fut]}: {s}")
                    if part.get("error"):
                        parse_errors.append(f"批{futures[fut]}: {part['error']}")
                except Exception as e:
                    parse_errors.append(f"批{futures[fut]} 异常: {type(e).__name__}: {e}")

        result: Dict[str, Any] = {
            "reviews": merged_reviews,
            "summary": "；".join(summaries) or "灰区裁定完成",
            "batches": ran_batches,
            "batch_size": self.GRAY_BATCH_SIZE,
            "total_suspicious": len(compact_all),
        }
        if parse_errors:
            result["batch_errors"] = parse_errors
        return result

    # ---------- 内部 ----------
    def _run_gray_batch(self, batch_idx: int, batch: List[Dict[str, Any]]) -> Dict[str, Any]:
        """执行单个灰区批次的LLM调用，并防止JSON截断超出8K"""
        # 先尝试整批；如果超限则递归对半
        text = json.dumps(batch, ensure_ascii=False, separators=(",", ":"))
        # 预估 prompt 总长度：模板约 280 字 + JSON 数据，安全上限 7500
        if len(text) > 7500 and len(batch) > 1:
            mid = len(batch) // 2
            a = self._run_gray_batch(batch_idx * 2, batch[:mid])
            b = self._run_gray_batch(batch_idx * 2 + 1, batch[mid:])
            return {
                "reviews": a.get("reviews", []) + b.get("reviews", []),
                "summary": (a.get("summary") or "") + " | " + (b.get("summary") or ""),
            }
        prompt = self.GRAY_AREA_PROMPT.format(findings_json=text)
        res = self._call_llm(prompt)
        if isinstance(res, dict) and "error" in res:
            return {"reviews": [], "summary": "", "error": res["error"]}
        return res if isinstance(res, dict) else {"reviews": [], "summary": str(res)}


def _resolve_llm_provider(provider: str = None) -> str:
    if provider:
        return provider
    # 支持通用变量 LLM_PROVIDER（优先级最高，仅次于 CLI 显式传）
    universal = (os.getenv("LLM_PROVIDER") or "").strip().lower()
    if universal:
        return universal
    for p in ["openai", "anthropic", "deepseek", "zhipu", "moonshot", "sjtu", "ollama"]:
        if os.getenv(f"{p.upper()}_API_KEY"):
            return p
    # 通用 LLM_API_KEY 存在但没指定 provider 时，默认按 deepseek 的兼容协议（用户可通过 LLM_PROVIDER 覆盖）
    if os.getenv("LLM_API_KEY"):
        return "deepseek"
    return "ollama"


def _resolve_llm_api_key(provider: str, explicit: Optional[str] = None) -> str:
    """解析LLM API Key：显式 > LLM_API_KEY 通用变量 > 对应 provider 的 *_API_KEY"""
    if explicit:
        return explicit
    universal = os.getenv("LLM_API_KEY")
    if universal:
        return universal
    return os.getenv(f"{provider.upper()}_API_KEY") or ""


def _resolve_llm_model(provider: str, explicit: Optional[str] = None) -> Optional[str]:
    """解析模型名：显式 > LLM_MODEL 通用 > PROVIDERS 默认"""
    if explicit:
        return explicit
    universal = (os.getenv("LLM_MODEL") or "").strip()
    if universal:
        return universal
    default_cfg = LLMAnalyzer.PROVIDERS.get(provider) or {}
    default_model = default_cfg.get("model")
    return default_model or None


def _resolve_llm_base_url(provider: str, explicit: Optional[str] = None) -> Optional[str]:
    """解析 endpoint URL。显式 CLI/参数 > LLM_BASE_URL > PROVIDERS 内默认。
    注意 LLM_BASE_URL 一般配到 /v1 即可，本函数会自动判断是否补 /chat/completions：
    - 如果 URL 以 /chat/completions 结尾：直接用；
    - 否则自动补上；anthropic 协议会补 /v1/messages；ollama 协议补 /api/chat。
    """
    url: Optional[str] = None
    if explicit:
        url = explicit
    else:
        env_url = (os.getenv("LLM_BASE_URL") or "").strip()
        if env_url:
            url = env_url
        else:
            default_cfg = LLMAnalyzer.PROVIDERS.get(provider) or {}
            url = default_cfg.get("url") or None
    if not url:
        return None

    # 标准化：去掉末尾斜杠
    url = url.rstrip("/")
    # 按 provider 拿到协议类型（anthropic/ollama/openai_compat）
    cfg = LLMAnalyzer.PROVIDERS.get(provider) or {}
    protocol = cfg.get("protocol", "openai_compat")
    # 已到具体接口路径就直接保留（按协议拆三种：openai_compat / anthropic / ollama）
    if url.endswith("/chat/completions") or url.endswith("/messages") or url.endswith("/api/chat"):
        return url
    # 命中 API 根端点（/v1 /v2 /v3 ... 结尾），直接补具体 path（避免拼出 /v1/v1/chat/completions 的 double-v1 bug）
    if re.search(r"/v\d+$", url):
        if protocol == "anthropic":
            return url + "/messages"
        if protocol == "ollama":
            # ollama 根域名下 /api/chat 不是 /v1 路径
            return url.rsplit("/", 1)[0] + "/api/chat"
        return url + "/chat/completions"
    # 其他情况：按协议补完整路径（补 /v1 或 /api/chat 前缀）
    if protocol == "anthropic":
        return url + "/v1/messages"
    if protocol == "ollama":
        return url + "/api/chat"
    # openai_compat 及默认
    return url + "/v1/chat/completions"


def _normalize_base_url_to_full(provider: str, base_url: Optional[str]) -> Optional[str]:
    """兼容：老代码里 PROVIDERS[provider]['url'] 是完整接口路径，这里再包一次 _resolve 返回"""
    return _resolve_llm_base_url(provider, base_url)


def diagnose_llm_config(cli_provider: Optional[str], cli_api_key: Optional[str],
                        cli_model: Optional[str] = None, cli_base_url: Optional[str] = None
                        ) -> Dict[str, Any]:
    """返回当前生效的LLM配置快照（不含完整key），给 --diagnose-llm 用。"""
    import os as _os

    provider = _resolve_llm_provider(cli_provider)
    api_key = _resolve_llm_api_key(provider, cli_api_key)
    model = _resolve_llm_model(provider, cli_model)
    effective_url = _normalize_base_url_to_full(provider, cli_base_url)
    sources: Dict[str, Any] = {}
    for p in ["openai", "anthropic", "deepseek", "zhipu", "moonshot", "sjtu"]:
        v = _os.getenv(f"{p.upper()}_API_KEY")
        sources[f"{p.upper()}_API_KEY"] = (
            None if not v else (v[:4] + "****" + v[-4:])
        )
    for name in ["LLM_PROVIDER", "LLM_API_KEY", "LLM_MODEL", "LLM_BASE_URL"]:
        v = _os.getenv(name)
        if name.endswith("API_KEY") and v:
            v = v[:4] + "****" + v[-4:]
        sources[name] = v

    # CLI 显式覆盖
    if cli_provider:
        sources["CLI_arg_--provider"] = cli_provider
    if cli_api_key:
        sources["CLI_arg_--api-key"] = cli_api_key[:4] + "****" + cli_api_key[-4:]
    if cli_model:
        sources["CLI_arg_--model"] = cli_model
    if cli_base_url:
        sources["CLI_arg_--base-url"] = cli_base_url

    cfg = LLMAnalyzer.PROVIDERS.get(provider, {})
    return {
        "effective": {
            "provider": provider,
            "supported": provider in LLMAnalyzer.PROVIDERS,
            "protocol": cfg.get("protocol"),
            "model": model,
            "model_empty": not bool(model),
            "url": effective_url,
            "url_empty": not bool(effective_url),
            "api_key": None if not api_key else (api_key[:4] + "****" + api_key[-4:]),
            "api_key_empty": not bool(api_key),
        },
        "sources": sources,
        "hint": (
            "若 401：① key 归属平台是否 = provider 且该 url；② 是否开通并绑定支付/额度；"
            "③ 用 --diagnose-llm 核对 sources；④ 统一模型商店请用 --provider custom --base-url ... --model <完整名>。"
            " Ollama 本地模式不需要 key，但模型必须先 pull。"
        ),
    }


def _collect_skill_text(skills_dir: Path, total_cap: int = 12000) -> str:
    """收集skill目录内文本文件，先SKILL.md/skill.json，再其余TEXT_FILE_EXTS。按优先级+大小上限截断。"""
    prio_files: List[Tuple[int, Path]] = []
    other_files: List[Path] = []
    for p in iter_files(skills_dir):
        name = p.name.lower()
        if name in ("skill.md",):
            prio_files.append((0, p))
        elif name in ("skill.json", "package.json"):
            prio_files.append((1, p))
        elif name in ("index.js", "index.ts", "main.py"):
            prio_files.append((2, p))
        else:
            other_files.append(p)
    ordered: List[Path] = [p for _, p in sorted(prio_files, key=lambda x: x[0])]
    ordered.extend(other_files)

    parts: List[str] = []
    used = 0
    for fp in ordered:
        try:
            raw = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(fp.relative_to(skills_dir)) if fp.is_absolute() and skills_dir in fp.parents else fp.name
        # 单文件配额：剩余空间的 80% 上限，避免一个大文件把后面文件全挤掉
        remain = max(0, total_cap - used)
        if remain <= 0:
            break
        cap = max(800, int(remain * 0.9))
        if len(raw) > cap:
            raw = raw[:cap] + "\n…<truncated>"
        header = f"=== {rel} ===\n"
        parts.append(header + raw)
        used += len(header) + len(raw)
        if used >= total_cap:
            break
    return "\n\n".join(parts)


def analyze_with_llm(
    skills_dir: Path,
    provider: str = None,
    api_key: str = None,
    model: str = None,
    base_url: str = None,
    mode: str = "gray",
    suspicious_findings: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """使用 LLM 分析。mode=gray 仅审可疑项；mode=full 全量深挖（含预筛跳过+多文件聚合）。"""
    if not LLM_AVAILABLE:
        return {"error": "requests 库未安装，请运行: pip install requests"}

    provider = _resolve_llm_provider(provider)
    try:
        analyzer = LLMAnalyzer(provider=provider, api_key=api_key, model=model, base_url=base_url)
        if mode == "gray":
            findings = suspicious_findings or []
            if not findings:
                return {
                    "mode": "gray",
                    "skipped": True,
                    "reason": "无 suspicious 命中，跳过 LLM",
                    "reviews": [],
                    "summary": "无需灰区裁定",
                    "llm": {"provider": analyzer.provider, "model": analyzer.model, "url": analyzer.url},
                }
            result = analyzer.review_suspicious(findings)
            if isinstance(result, dict):
                result["mode"] = "gray"
                result.setdefault("llm", {})
                result["llm"].update({"provider": analyzer.provider, "model": analyzer.model, "url": analyzer.url})
            return result

        # full 模式：聚合多文件内容 + 预筛（默认开，可用 env 关闭）
        merged = _collect_skill_text(skills_dir)
        if not merged.strip():
            return {"error": "未找到可分析的 Skill 文件"}
        prescreen = os.getenv("SKILL_SEC_LLM_NO_PRESCREEN") not in ("1", "true", "yes")
        result = analyzer.analyze(merged, enable_prescreen=prescreen)
        if isinstance(result, dict):
            result["mode"] = "full"
            result.setdefault("llm", {})
            result["llm"].update({"provider": analyzer.provider, "model": analyzer.model, "url": analyzer.url})
            if "skipped_by_prescreen" in result:
                result["prescreen_enabled"] = True
        return result
    except ValueError as e:
        return {"error": f"LLM 配置错误: {e}", "mode": mode}
    except ImportError as e:
        return {"error": f"依赖缺失: {str(e)}", "mode": mode}
    except Exception as e:
        return {"error": f"分析异常: {type(e).__name__}: {str(e)}", "mode": mode}


def refresh_static_after_llm(static_result: Dict[str, Any]) -> Dict[str, Any]:
    """LLM 裁定后重算计数与结论"""
    findings = static_result.get("findings", [])
    risk_counts = {"high": 0, "medium": 0, "low": 0}
    confidence_counts = {"confirmed": 0, "suspicious": 0}
    privacy_counts = {"system": 0, "personal": 0, "government": 0, "security": 0, "other": 0}
    for item in findings:
        risk_counts[item["risk"]] += 1
        confidence_counts[item.get("confidence", "suspicious")] = (
            confidence_counts.get(item.get("confidence", "suspicious"), 0) + 1
        )
        privacy_counts[item.get("privacy_type", "other")] += 1
    verdict = decide_verdict(findings)
    static_result["findings"] = findings
    static_result["risk_counts"] = risk_counts
    static_result["confidence_counts"] = confidence_counts
    static_result["privacy_counts"] = privacy_counts
    static_result["privacy_leak_report"] = build_privacy_leak_report(findings)
    static_result["verdict"] = verdict
    static_result["verdict_zh"] = VERDICT_ZH.get(verdict, verdict)
    static_result["summary"] = build_summary(findings, risk_counts, verdict)
    return static_result


def assess_with_llm(skills_dir: Path, provider: str = None, api_key: str = None,
                    model: str = None, base_url: str = None) -> Dict[str, Any]:
    """结合静态分析和 LLM 灰区裁定"""
    static_result = assess(skills_dir)
    suspicious = [f for f in static_result.get("findings", []) if f.get("confidence") == "suspicious"]
    llm_result = analyze_with_llm(
        skills_dir, provider, api_key, model=model, base_url=base_url,
        mode="gray", suspicious_findings=suspicious,
    )
    if isinstance(llm_result, dict) and "reviews" in llm_result and "error" not in llm_result:
        static_result["findings"] = apply_llm_reviews(static_result.get("findings", []), llm_result)
        static_result = refresh_static_after_llm(static_result)
    return {
        "static_analysis": static_result,
        "llm_analysis": llm_result,
        "combined": True,
        "verdict": static_result.get("verdict"),
        "verdict_zh": static_result.get("verdict_zh"),
    }


def _run_one(
    skills_dir: Path,
    output_dir: Path,
    *,
    llm: bool,
    llm_full: bool,
    provider: Optional[str],
    api_key: Optional[str],
    model: Optional[str],
    base_url: Optional[str],
    no_static: bool,
) -> Dict[str, Any]:
    """单目录评估核心逻辑，被 CLI 与并发调度器共用。"""
    if not skills_dir.exists() or not skills_dir.is_dir():
        return {"error": f"Invalid skills_dir: {skills_dir}", "skills_dir": str(skills_dir)}

    result: Dict[str, Any] = {"skills_dir": str(skills_dir)}

    # 静态分析
    if not no_static:
        static_result = assess(skills_dir)
        static_result["skill_basic_info"] = detect_skills(skills_dir)
        result["static_analysis"] = static_result

    # LLM 分析
    if llm or llm_full:
        if not LLM_AVAILABLE:
            result["llm_analysis"] = {"error": "requests 库未安装，请运行: pip install requests"}
        else:
            mode = "full" if llm_full else "gray"
            suspicious: List[Dict[str, Any]] = []
            if mode == "gray" and "static_analysis" in result:
                suspicious = [
                    f for f in result["static_analysis"].get("findings", [])
                    if f.get("confidence") == "suspicious"
                ]
            llm_result = analyze_with_llm(
                skills_dir, provider, api_key,
                model=model, base_url=base_url,
                mode=mode, suspicious_findings=suspicious,
            )
            result["llm_analysis"] = llm_result

            # 灰区裁定回写静态结果并重算结论
            if (
                mode == "gray"
                and "static_analysis" in result
                and isinstance(llm_result, dict)
                and "reviews" in llm_result
                and "error" not in llm_result
            ):
                result["static_analysis"]["findings"] = apply_llm_reviews(
                    result["static_analysis"].get("findings", []), llm_result,
                )
                result["static_analysis"] = refresh_static_after_llm(result["static_analysis"])
                if "skill_basic_info" not in result["static_analysis"]:
                    result["static_analysis"]["skill_basic_info"] = detect_skills(skills_dir)

    # 生成报告
    if "static_analysis" in result:
        result_with_meta, json_path, md_path, summary_path = write_reports(
            result["static_analysis"], skills_dir, output_dir,
        )
        result["report_files"] = {
            "json": str(json_path),
            "md": str(md_path),
            "summary": str(summary_path),
        }
        result["summary"] = result_with_meta["summary"]
        result["verdict"] = result_with_meta.get("verdict")
        result["verdict_zh"] = result_with_meta.get("verdict_zh")
        result["privacy_leak_report"] = result_with_meta.get("privacy_leak_report")
    else:
        result["generated_at"] = datetime.now().isoformat()

    return result


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Skill 安全评估工具（含LLM性能优化：缓存/预筛/分批/并发/退避重试）")
    parser.add_argument("skills_dirs", nargs="*", help="Skill 目录路径（可多个，支持批处理）")
    parser.add_argument("-o", "--output", dest="output_dir", default=None, help="报告输出目录（默认 ./auto_reports）")
    parser.add_argument("--llm", action="store_true", help="启用 LLM 灰区裁定（仅审 suspicious）")
    parser.add_argument("--llm-full", action="store_true", help="启用 LLM 全量深挖（启用预筛，命中才调LLM）")
    provider_choices = list(LLMAnalyzer.PROVIDERS.keys()) if LLM_AVAILABLE else []
    parser.add_argument("--provider", choices=provider_choices if provider_choices else None,
                        help="LLM 提供商（custom=统一模型商店/硅基流动/任意OpenAI兼容网关，需配合--base-url/--model）")
    parser.add_argument("--api-key", help="LLM API Key（优先级最高，覆盖环境变量）")
    parser.add_argument("--model", help="模型名（完整名，区分大小写和连字符）。优先级>LLM_MODEL env>provider默认")
    parser.add_argument("--base-url", dest="base_url",
                        help="网关基地址或完整接口地址。支持两种写法：① https://xxx/v1 （自动补 /chat/completions）② https://xxx/v1/chat/completions （原样使用）")
    parser.add_argument("--no-static", action="store_true", help="禁用静态分析")
    parser.add_argument("--jobs", type=int, default=1, help="批并发数（多目录时并行跑LLM），默认 1，建议 2~4")
    parser.add_argument("--clear-llm-cache", action="store_true", help="清空LLM磁盘缓存后退出")
    parser.add_argument("--no-llm-cache", action="store_true", help="本次运行不读也不写LLM缓存")
    parser.add_argument("--diagnose-llm", action="store_true", help="打印当前生效的LLM配置快照并退出（解决401定位神器）")

    args = parser.parse_args()

    # 快捷动作：清空LLM缓存
    if args.clear_llm_cache:
        cache_dir = _get_cache_dir()
        removed = 0
        for fp in cache_dir.glob("*.json"):
            try:
                fp.unlink()
                removed += 1
            except OSError:
                pass
        print(json.dumps({"cleared_cache_dir": str(cache_dir), "removed_files": removed}, ensure_ascii=False))
        return

    # 快捷动作：诊断LLM配置（无需指定目录）
    if args.diagnose_llm:
        diag = diagnose_llm_config(args.provider, args.api_key, args.model, args.base_url)
        print(json.dumps(diag, ensure_ascii=False, indent=2))
        return

    if not args.skills_dirs:
        parser.print_help()
        print("\n[提示] 请至少传入一个 skill 目录；或使用 --diagnose-llm / --clear-llm-cache 单独运行。")
        sys.exit(2)

    # 运行时禁用缓存：把读写函数替换为空（monkey-patch 级别最简实现）
    if args.no_llm_cache:
        global _cache_read, _cache_write
        def _cache_read(key, ttl_seconds=0):  # type: ignore[no-redef]
            return None
        def _cache_write(key, payload):  # type: ignore[no-redef]
            return None

    output_dir = Path(args.output_dir).resolve() if args.output_dir else (Path.cwd() / "auto_reports")

    jobs = max(1, int(args.jobs or 1))
    target_dirs = [Path(p).resolve() for p in args.skills_dirs]

    # 单目录仍然按旧结构输出JSON，避免破坏兼容
    if len(target_dirs) == 1:
        result = _run_one(
            target_dirs[0], output_dir,
            llm=args.llm, llm_full=args.llm_full,
            provider=args.provider, api_key=args.api_key,
            model=args.model, base_url=args.base_url,
            no_static=args.no_static,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        risk_summary = result.get("summary") or ((result.get("static_analysis") or {}).get("summary") or "")
        pr = result.get("privacy_leak_report") or ((result.get("static_analysis") or {}).get("privacy_leak_report"))
        privacy_summary = (
            (pr.get("summary") if pr else None)
            or build_privacy_summary(
                privacy_report=pr if pr else None,
                findings=(result.get("static_analysis") or {}).get("findings", []),
            )
        )
        if risk_summary or privacy_summary:
            print(f"{risk_summary}{privacy_summary}".strip())
        if result.get("verdict") == "block":
            sys.exit(1)
        return

    # 多目录 → 并发
    results: List[Dict[str, Any]] = []
    block_count = 0
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        future_map = {
            pool.submit(
                _run_one, d, output_dir,
                llm=args.llm, llm_full=args.llm_full,
                provider=args.provider, api_key=args.api_key,
                model=args.model, base_url=args.base_url,
                no_static=args.no_static,
            ): d for d in target_dirs
        }
        for fut in as_completed(future_map):
            r = fut.result()
            results.append(r)
            if r.get("verdict") == "block":
                block_count += 1

    multi_out = {
        "generated_at": datetime.now().isoformat(),
        "jobs": jobs,
        "total": len(results),
        "blocked": block_count,
        "results": results,
    }
    print(json.dumps(multi_out, ensure_ascii=False, indent=2))
    sys.exit(1 if block_count > 0 else 0)


if __name__ == "__main__":
    main()
