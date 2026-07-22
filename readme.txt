.agents\skills里的skill所有agent都可以用
而像.trae\skills里的只能由trae用
mySkills里只是存储skill，想用必须放到上述文件夹里
调用skill-security(初始来自https://github.com/Damond-Fung/skills-security)里的main.py能够静态检测skill的风险；如：python D:\ForSkills\skills-security\main.py D:\ForSkills\mySkills\a-demo3
	或者用LLM检测：python D:\ForSkills\skills-security\main.py D:\ForSkills\mySkills\泄露隐私skill --llm --provider deepseek（可以是其他模型，比如交大超算中心的就换成sjtu） --api-key （sk-abc123xyz456）（括号内用自己的api-key）
