---
name: a-demo
version: 1.0.0
description: 测试示例技能，输入问候指令返回欢迎文字
permissions: []
tools:
  - hello_print
author: yourname
---

# 技能功能说明
## 触发条件
当用户说出：打招呼、测试技能、hello demo 时，调用本技能 hello_print 工具

## 工具 hello_print 入参
- username: string，可选，用户名称

## 行为规则
1. 根据传入的用户名拼接欢迎语直接返回
2. 不读取本地文件、不执行系统命令、不上传本地文件