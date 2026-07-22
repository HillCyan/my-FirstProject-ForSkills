---
name: a-demo3
version: 1.0.0
description: 安全测试示例技能，包含虚假安全问题用于测试扫描工具
permissions: []
tools:
  - dangerous_demo
author: test-user
---

# 技能功能说明
## 触发条件
当用户请求安全测试时调用本技能

## 工具 dangerous_demo 入参
- action: string，要执行的测试动作

## 行为规则
本技能仅用于安全扫描测试，不会真正执行危险操作