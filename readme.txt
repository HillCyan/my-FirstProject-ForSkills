.agents\skills里的skill所有agent都可以用
而像.trae\skills里的只能由trae用
mySkills里只是存储skill，想用必须放到上述文件夹里
调用skill-security(初始来自https://github.com/Damond-Fung/skills-security)里的main.py能够静态检测skill的风险；如：python D:\ForSkills\skills-security\main.py D:\ForSkills\mySkills\a-demo3
	或者用LLM检测：python D:\ForSkills\skills-security\main.py D:\ForSkills\mySkills\泄露隐私skill --llm --provider deepseek（可以是其他模型，比如交大超算中心的就换成sjtu） --api-key （sk-abc123xyz456）（括号内用自己的api-key）

---
## 可用的模型清单（用 --model 指定，例如：--model GLM-4-Flash）

用法：
python D:\ForSkills\skills-security\main.py D:\ForSkills\mySkills\某skill --llm --provider custom --base-url 你的API地址/v1 --model 模型名 --api-key sk-xxx

示例：
python D:\ForSkills\skills-security\main.py D:\ForSkills\mySkills\泄露隐私skill --llm --provider custom --base-url https://api.siliconflow.cn/v1 --model GLM-4-Flash --api-key sk-abc123xyz456

并行智算云（https://ai.paratera.com）的用法（API地址就是主站域名 + /v1，密钥在平台"个人中心→我的密钥"里申请）：
python D:\ForSkills\skills-security\main.py D:\ForSkills\mySkills\泄露隐私skill --llm --provider custom --base-url https://ai.paratera.com/v1 --model DeepSeek-R1 --api-key 你的AccessKey

【可以用的模型】（聊天类，都能用于安全检测；带V的是视觉模型，见下方说明。以下即并行智算云账号里已上架的模型清单）
GLM-4-Flash（实测可用）、GLM-4.5-Flash、GLM-5.3-Flash、GLM-Z1-Flash、GLM-Z1-Air、GLM-Z1-AirX
GLM-4.5、GLM-4.5-Air、GLM-4.5-AirX、GLM-4.5-X、GLM-4.6、GLM-4.6V、GLM-4.5V、GLM-4V、GLM-4V-Plus-0111
GLM-4-Plus、GLM-4-Long、GLM-4-9B、GLM-4-Air、GLM-4-AirX、GLM-4-FlashX
GLM-5、GLM-5.1、GLM-5.2、GLM-5.3、GLM-4.7、GLM-5-Turbo
DeepSeek-V4-Pro、DeepSeek-V4-Pro-0813、DeepSeek-V4-Flash、DeepSeek-V4-Flash-0731
DeepSeek-R1、DeepSeek-R1-0528
DeepSeek-V3.2-Thinking、DeepSeek-V3.2-Instruct、DeepSeek-V3.2、DeepSeek-V3.2-Exp、DeepSeek-V3.1、DeepSeek-V3.1-Terminus、DeepSeek-V3-250324
Kimi-K3、Kimi-K2.5、Kimi-K2.6
Qwen3.8-Flash、Qwen3.6-Flash、Qwen3.6-Plus、Qwen3.7-Plus、Qwen3.5-Plus、Qwen3.7-Max、Qwen3.8-Max
Qwen3.5-27B、Qwen3.6-27B、Qwen3.8-27B、Qwen3.5-35B-A3B、Qwen3.5-122B-A10B、Qwen3.5-397B-A17B、Qwen-Long
ERNIE-5.0-Thinking-Preview、ERNIE-4.5-Turbo-32K、ERNIE-4.5-Turbo-128K、ERNIE-4.5-Turbo-VL-32K
MiniMax-M1-80k、MiniMax-M2、MiniMax-M2.5、MiniMax-M2.7、MiniMax-M3、MiniMax-Text-01
Baichuan-M2、Baichuan-M2-128K、Baichuan-M3

【不能用的模型】（不是聊天模型，调用会报错，别浪费时间）
GLM-Embedding-2、GLM-Embedding-3、GLM-Rerank（向量/重排，不输出文字）
GLM-CogView3-Flash、Doubao-Seedream-3.0-T2I、Doubao-Seedream-4.0、Doubao-Seedream-4.5、Doubao-Seedream-5.0-lite、WanX2.1-T2I-Turbo、WanX2.1-T2I-Plus（画图的）
MiniMax-I2V-01、MiniMax-I2V-01-Live、MiniMax-I2V-01-Director、MiniMax-T2V-01、MiniMax-T2V-01-Director、Doubao-Seedance-1.0-Pro、MiniMax-Hailuo-02（做视频的）
GLM-ASR-2512（语音识别）
PaddleOCR-VL-0.9B、PaddleOCR-VL-1.5（图片文字识别）
GLM-4V-Flash（实测不能用：视觉模型只吃图片输入，纯文本请求会被拒；其余带V/VL的模型如GLM-4V、GLM-4.5V、GLM-4.6V、GLM-4V-Plus-0111、ERNIE-4.5-Turbo-VL-32K大概率同样不行，未实测别优先试）
Intern-S2-Preview（实测不能用）
