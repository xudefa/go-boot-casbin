# go-boot-casbin

[![Go Version](https://img.shields.io/github/go-mod/go-version/xudefa/go-boot-casbin)](https://go.dev/) [![License](https://img.shields.io/github/license/xudefa/go-boot-casbin)](./LICENSE) [![Build Status](https://img.shields.io/github/actions/workflow/status/xudefa/go-boot-casbin/test.yml?branch=master)](https://github.com/xudefa/go-boot-casbin/actions) [![Go Reference](https://pkg.go.dev/badge/github.com/xudefa/go-boot-casbin.svg)](https://pkg.go.dev/github.com/xudefa/go-boot-casbin) [![Go Report Card](https://goreportcard.com/badge/github.com/xudefa/go-boot-casbin)](https://goreportcard.com/report/github.com/xudefa/go-boot-casbin)

基于 [go-boot](https://github.com/xudefa/go-boot) 的 Casbin 权限管理集成模块。将 Casbin 无缝集成到 go-boot 的 IoC 容器和自动配置体系中，提供声明式的权限检查、策略管理和 HTTP 授权中间件能力。

> 设计理念：遵循 go-boot 的开发规范，将 Casbin Enforcer 注册为 Bean，通过自动配置实现零代码启动权限服务，提供框架无关的授权中间件。

## 整体架构

```
┌───────────────────────────────────────────────────────────────────────┐
│                    go-boot ApplicationContext                         │
│  ┌───────────┐ ┌──────────────┐ ┌───────────┐ ┌───────────┐           │
│  │ Container │ │  Environment │ │ Lifecycle │ │ EventBus  │           │
│  └───────────┘ └──────────────┘ └───────────┘ └───────────┘           │
│                       ┌─────────────────────┐                         │
│                       │ AutoConfig Registry │                         │
│                       └─────────────────────┘                         │
└───────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │   go-boot-casbin Starter      │
                    │  ┌─────────────────────────┐  │
                    │  │ Casbin Enforcer Bean    │  │
                    │  │ Model Configuration     │  │
                    │  │ Policy Adapter          │  │
                    │  │ HTTP Auth Middleware    │  │
                    │  └─────────────────────────┘  │
                    └───────────────────────────────┘
```

## 目录

- [快速开始](#快速开始)
- [功能特性](#功能特性)
- [权限检查](#权限检查)
- [策略管理](#策略管理)
- [HTTP 授权中间件](#http-授权中间件)
- [配置选项](#配置选项)
- [项目结构](#项目结构)
- [开发指南](#开发指南)
- [贡献](#贡献)
- [许可证](#许可证)

## 快速开始

### 安装

```bash
# 安装核心框架
go get github.com/xudefa/go-boot

# 安装 Casbin 集成模块
go get github.com/xudefa/go-boot-casbin
```

### 最小示例

```go
package main

import (
    "github.com/xudefa/go-boot/boot"
    "github.com/xudefa/go-boot/core"
    casbin "github.com/xudefa/go-boot-casbin"
)

func main() {
    app, err := boot.NewApplication(
        boot.WithAppName("my-auth-app"),
        boot.WithVersion("1.0.0"),
    )
    if err != nil {
        panic(err)
    }
    defer app.Stop()

    // 注册 Casbin Enforcer
    e, err := casbin.NewEnforcer(
        casbin.WithModel("model.conf"),
        casbin.WithAdapter("policy.csv"),
    )
    if err != nil {
        panic(err)
    }
    app.Container().Register("casbinEnforcer", core.Bean(e), core.Singleton())

    // 权限检查
    ok, err := e.Enforce("alice", "data1", "read")
    if err != nil {
        panic(err)
    }
    if ok {
        println("alice can read data1")
    }

    // 启动应用
    app.Start()
    app.WaitForSignal()
}
```

## 功能特性

| 特性 | 说明 |
|------|------|
| Casbin 集成 | 将 Enforcer 注册为 Bean，支持依赖注入 |
| 自动配置 | 通过 `casbin.enabled=true` 自动启用权限服务 |
| 文件适配器 | 支持从 .conf/.csv 文件加载模型和策略 |
| 数据库适配器 | 内置 DBAdapter，通过 data.Transactor 操作数据库 |
| 策略管理 | 提供 AddPolicy、RemovePolicy、UpdatePolicy 等方法 |
| 角色管理 | 支持 AddGroupingPolicy、GetRoles、HasRole 等 RBAC 操作 |
| HTTP 中间件 | 提供框架无关的授权中间件，可适配 Gin/Echo 等框架 |
| 优雅启停 | 支持生命周期管理和优雅关闭 |

## 权限检查

### 基本权限检查

```go
e, _ := casbin.NewEnforcer(
    casbin.WithModel("model.conf"),
    casbin.WithAdapter("policy.csv"),
)

// 检查权限
ok, err := e.Enforce("alice", "data1", "read")
if err != nil {
    // 处理错误
}
if ok {
    // 权限通过
}
```

### 获取用户角色和权限

```go
// 获取用户角色
roles, err := e.GetRoles("alice")
// roles: ["admin"]

// 检查用户是否有某角色
hasRole, err := e.HasRole("alice", "admin")

// 获取用户权限
perms := e.GetPermissions("admin")
// perms: [["admin", "data1", "read"], ...]
```

## 策略管理

### 添加策略

```go
// 添加权限策略
ok, err := e.AddPolicy("user", "data3", "read")

// 添加角色继承策略
ok, err := e.AddGroupingPolicy("alice", "admin")
```

### 移除策略

```go
// 移除权限策略
ok, err := e.RemovePolicy("user", "data1", "read")

// 移除角色继承策略
ok, err := e.RemoveGroupingPolicy("alice", "admin")
```

### 更新策略

```go
ok, err := e.UpdatePolicy(
    []string{"user", "data1", "read"},
    []string{"user", "data1", "write"},
)
```

## HTTP 授权中间件

go-boot-casbin 提供框架无关的授权中间件，通过 `AuthorizationExtractor` 适配不同 HTTP 框架。

### Gin 框架适配

```go
import (
    "github.com/gin-gonic/gin"
    casbin "github.com/xudefa/go-boot-casbin"
    gootnet "github.com/xudefa/go-boot/net"
)

// 创建提取器
extractor := func(ctx gootnet.HandlerContext) (string, string, string) {
    // 从 Gin Context 获取用户、资源、操作
    c := ctx.(*gin.Context)
    subject := c.GetString("user")
    object := c.Request.URL.Path
    action := c.Request.Method
    return subject, object, action
}

// 使用中间件
engine := gin.Default()
e := app.Container().Get("casbinEnforcer").(*casbin.EnforcerWrapper)
engine.Use(func(c *gin.Context) {
    // 将 gin.Context 包装为 net.HandlerContext
    ctx := &ginHandlerContext{Context: c}
    casbin.Authorize(e, extractor)(ctx)
    if ctx.IsAborted() {
        return
    }
    c.Next()
})
```

### 自定义提取器

```go
// 根据业务需求自定义提取逻辑
extractor := func(ctx gootnet.HandlerContext) (string, string, string) {
    // 从 Header 获取用户
    subject := ctx.Header("X-User")
    
    // 从 URI 提取资源（去除 /api 前缀）
    obj := ctx.RequestURI()
    if len(obj) > 4 && obj[:4] == "/api" {
        obj = obj[4:]
    }
    
    // 根据 HTTP 方法映射操作
    act := "read"
    switch ctx.RequestMethod() {
    case "POST", "PUT":
        act = "write"
    case "DELETE":
        act = "delete"
    }
    
    return subject, obj, act
}
```

## 配置选项

通过 `boot.WithProperty()` 或配置文件设置：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `casbin.enabled` | `false` | 是否启用 Casbin 权限服务 |
| `casbin.model` | `""` | 模型文件路径 (.conf) |
| `casbin.adapter` | `""` | 策略文件路径 (.csv) |
| `casbin.db-adapter` | `false` | 是否使用数据库适配器 |
| `casbin.db-table` | `casbin_rule` | 策略表名 |

### 示例配置

```yaml
# application.yml
casbin:
  enabled: true
  model: "model.conf"
  adapter: "policy.csv"
```

### 数据库适配器配置

```yaml
# application.yml
casbin:
  enabled: true
  model: "model.conf"
  db-adapter: true
  db-table: "casbin_rule"
```

## 项目结构

```
go-boot-casbin/
├── casbin/               # Casbin Enforcer 集成
│   ├── enforcer.go       # Enforcer 核心封装、权限检查、策略管理
│   ├── autoconfig.go     # 自动配置注册
│   ├── middleware.go     # HTTP 授权中间件
│   └── enforcer_test.go  # 单元测试
├── adapter/              # 策略适配器
│   └── adapter.go        # DBAdapter 实现 persist.Adapter
├── model/                # 模型配置辅助
│   └── model.go          # RBAC/ABAC/RESTful 预定义模型
├── aspect/               # AOP 权限切面
│   └── aspect.go         # PermissionAspect 方法级权限拦截
├── testdata/
│   ├── model.conf        # 测试模型文件
│   └── policy.csv        # 测试策略文件
├── README.md
├── LICENSE
└── go.mod
```

## 开发指南

### 构建

```bash
go build ./...
```

### 测试

```bash
go test ./...
go test -cover ./...       # 带覆盖率
go test -race ./...        # 数据竞争检测
```

### 代码规范

```bash
go fmt ./...
golangci-lint run
```

## 贡献

欢迎提交 Issue 和 Pull Request！详细贡献指南请参阅 [CONTRIBUTING.md](./CONTRIBUTING.md)。

## 许可证

本项目采用 MIT 许可证 — 详情请参阅 [LICENSE](./LICENSE) 文件。