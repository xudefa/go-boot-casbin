# 贡献指南

感谢你对 go-boot-casbin 项目的关注！本文档将帮助你快速了解如何参与项目开发。

## 前提条件

- Go 1.21 或更高版本
- Git
- 熟悉的代码编辑器（推荐 VS Code 或 GoLand）

## 快速开始

### 1. 克隆仓库

```bash
git clone https://github.com/xudefa/go-boot-casbin.git
cd go-boot-casbin
```

### 2. 安装依赖

```bash
go mod download
```

### 3. 运行测试

```bash
# 运行所有测试
go test ./...

# 运行测试并生成覆盖率报告
go test -cover ./...

# 运行测试并检测数据竞争
go test -race ./...
```

### 4. 代码格式化

```bash
# 格式化代码
go fmt ./...

# 运行 lint 检查（需安装 golangci-lint）
golangci-lint run
```

## 开发流程

### 分支策略

- `master` — 主分支，保持稳定
- `feature/*` — 功能开发分支
- `fix/*` — 修复分支
- `docs/*` — 文档更新分支

### 提交规范

提交信息应遵循 conventional commits 规范：

```
<type>(<scope>): <description>

[optional body]
```

常用 type：

- `feat` — 新功能
- `fix` — 修复 bug
- `docs` — 文档更新
- `refactor` — 代码重构
- `test` — 测试相关
- `chore` — 构建/工具相关

示例：

```
feat(casbin): add RBAC model support

fix(adapter): resolve DBAdapter policy loading issue

docs(readme): add installation instructions and usage examples
```

### 提交 Pull Request

1. Fork 本仓库
2. 创建功能分支：`git checkout -b feature/my-feature`
3. 提交更改：`git commit -m 'feat(casbin): add my feature'`
4. 推送分支：`git push origin feature/my-feature`
5. 在 GitHub 上创建 Pull Request

### PR 要求

- [ ] 代码通过所有测试（`go test ./...`）
- [ ] 代码已格式化（`go fmt ./...`）
- [ ] 新增功能包含相应的测试
- [ ] 更新相关文档（如适用）
- [ ] 提交信息遵循规范

## 代码规范

详细的代码规范请参阅 [AGENTS.md](./AGENTS.md) 和 [CODING_STYLE.md](./CODING_STYLE.md)。

### 核心原则

- **包名**：小写，与目录名一致（如 `casbin`, `adapter`, `model`, `aspect`）
- **导出标识符**：大驼峰（如 `Enforcer`, `NewEnforcer`）
- **非导出标识符**：小驼峰（如 `enforcer`, `newEnforcer`）
- **错误变量**：以 `Err` 前缀（如 `ErrEnforcerNotFound`）
- **接口**：以 `er` 结尾（如 `Adapter`）或功能描述（如 `Model`）

### 注释规范

- 使用中文注释，保持国际化友好
- 导出函数/类型必须有 godoc 注释
- 注释应说明"为什么"而非"做什么"

### 错误处理

- 不忽略任何错误
- 使用 `%w` 包装错误以保留错误链
- 使用哨兵错误表示框架级错误

```go
var ErrEnforcerNotFound = errors.New("casbin: enforcer not found in container")

if err := find(id); err != nil {
    return fmt.Errorf("lookup failed: %w", err)
}
```

## 测试要求

### 测试命名

```
TestFunctionName_Condition_ExpectedBehavior
```

示例：

```go
func TestEnforcer_Enforce_Success(t *testing.T)
func TestEnforcer_Enforce_PermissionDenied_ReturnsFalse(t *testing.T)
```

### 覆盖率目标

- casbin 核心包：80%+
- adapter/model/aspect 包：70%+

### 运行特定测试

```bash
# 运行特定包的测试
go test ./casbin/... -v

# 运行特定测试函数
go test ./casbin/... -run TestEnforcer_Enforce -v

# 生成覆盖率报告
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## 架构设计原则

### 依赖 go-boot 核心

go-boot-casbin 依赖 go-boot 核心框架（IoC 容器、AOP、自动配置），不引入其他外部依赖（除 Casbin 本身）。

### 接口优先

优先定义接口，再提供默认实现。这使得用户可以轻松替换实现。

### 函数式选项

使用函数式选项模式提供灵活的配置：

```go
e, err := casbin.NewEnforcer(
    casbin.WithModel("model.conf"),
    casbin.WithAdapter("policy.csv"),
)
```

## 项目结构

```
go-boot-casbin/
├── casbin/               # Casbin Enforcer 集成
│   ├── enforcer.go       # Enforcer 核心封装
│   ├── autoconfig.go     # 自动配置注册
│   ├── middleware.go     # HTTP 授权中间件
│   └── enforcer_test.go  # 单元测试
├── adapter/              # 策略适配器
│   └── adapter.go        # DBAdapter 实现
├── model/                # 模型配置辅助
│   └── model.go          # RBAC/ABAC/RESTful 预定义模型
├── aspect/               # AOP 权限切面
│   └── aspect.go         # PermissionAspect
├── testdata/             # 测试数据
├── README.md
├── LICENSE
└── go.mod
```

## 问题反馈

- **Bug 报告**：创建 Issue 并添加 `bug` 标签
- **功能请求**：创建 Issue 并添加 `enhancement` 标签
- **问题咨询**：创建 Issue 并添加 `question` 标签

## 行为准则

- 尊重所有贡献者
- 接受建设性批评
- 关注问题而非个人
- 欢迎新贡献者

感谢你的贡献！