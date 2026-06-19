// Package casbin 提供基于 Casbin 的权限控制核心。
//
// 该包将 Casbin 权限控制库与 go-boot 容器系统集成，
// 不依赖任何 HTTP 框架，提供框架无关的泛用中间件：
//
// 快速开始:
//
//	e, err := casbin.NewEnforcer(
//	    casbin.WithModel("path/to/model.conf"),
//	    casbin.WithAdapter("path/to/policy.csv"),
//	)
//	if err != nil {
//	    return err
//	}
//	ok, err := e.Enforce("alice", "data1", "read")
package casbin

import (
	"errors"

	casbin "github.com/casbin/casbin/v2"
	"github.com/xudefa/go-boot-casbin/adapter"
	"github.com/xudefa/go-boot/data"
)

// EnforcerBeanID 是 Casbin Enforcer 在 IoC 容器中注册的 Bean ID。
const EnforcerBeanID = "casbinEnforcer"

var (
	// ErrEnforcerNotFound 表示容器中未找到 Enforcer 实例。
	ErrEnforcerNotFound = errors.New("casbin: enforcer not found in container")
	// ErrInvalidEnforcer 表示 Enforcer 类型无效。
	ErrInvalidEnforcer = errors.New("casbin: invalid enforcer type")
)

// Enforcer 是 Casbin 强制执行器的包装类型。
type Enforcer struct {
	enforcer *casbin.Enforcer
}

// RawEnforcer 返回内部的 Casbin Enforcer 实例。
func (e *Enforcer) RawEnforcer() *casbin.Enforcer {
	return e.enforcer
}

// Option 是 Enforcer 配置选项函数。
type Option func(*options)

type options struct {
	model       string
	adapter     string
	adapterImpl adapter.Adapter
}

// WithModel 设置 Casbin 模型文件路径 (.conf)。
func WithModel(model string) Option {
	return func(o *options) {
		o.model = model
	}
}

// WithAdapter 设置 Casbin 策略文件适配器路径。
func WithAdapter(adapterPath string) Option {
	return func(o *options) {
		o.adapter = adapterPath
	}
}

// WithDBAdapter 设置基于数据库的 Casbin 策略适配器。
//
// 参数:
//   - tx: 数据库事务操作器（实现了 data.Transactor 接口）
//   - tableName: 可选，策略表名（默认 "casbin_rule"）
//
// 示例:
//
//	e, err := casbin.NewEnforcer(
//	    casbin.WithModel("model.conf"),
//	    casbin.WithDBAdapter(transactor),
//	)
func WithDBAdapter(tx data.Transactor, tableName ...string) Option {
	return func(o *options) {
		o.adapterImpl = adapter.NewDBAdapter(tx, tableName...)
	}
}

// NewEnforcer 创建新的 Casbin Enforcer。
//
// 支持三种适配器模式：
//  1. 文件适配器：WithModel + WithAdapter
//  2. 数据库适配器：WithModel + WithDBAdapter
//  3. 仅模型：WithModel（无持久化）
func NewEnforcer(opts ...Option) (*Enforcer, error) {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	if o.model == "" {
		return nil, errors.New("casbin: model must be provided")
	}

	var rawEnforcer *casbin.Enforcer
	var err error

	switch {
	case o.adapterImpl != nil:
		rawEnforcer, err = casbin.NewEnforcer(o.model, o.adapterImpl)
	case o.adapter != "":
		rawEnforcer, err = casbin.NewEnforcer(o.model, o.adapter)
	default:
		rawEnforcer, err = casbin.NewEnforcer(o.model)
	}

	if err != nil {
		return nil, err
	}

	return &Enforcer{enforcer: rawEnforcer}, nil
}

// Enforce 执行权限检查。
func (e *Enforcer) Enforce(args ...any) (bool, error) {
	if e.enforcer == nil {
		return false, ErrEnforcerNotFound
	}
	return e.enforcer.Enforce(args...)
}

// AddPolicy 添加策略规则。
func (e *Enforcer) AddPolicy(params ...string) (bool, error) {
	if e.enforcer == nil {
		return false, ErrEnforcerNotFound
	}
	vals := make([]interface{}, len(params))
	for i, p := range params {
		vals[i] = p
	}
	return e.enforcer.AddPolicy(vals...)
}

// RemovePolicy 移除策略规则。
func (e *Enforcer) RemovePolicy(params ...string) (bool, error) {
	if e.enforcer == nil {
		return false, ErrEnforcerNotFound
	}
	vals := make([]interface{}, len(params))
	for i, p := range params {
		vals[i] = p
	}
	return e.enforcer.RemovePolicy(vals...)
}

// AddGroupingPolicy 添加角色继承规则（g 类型）。
//
// 示例:
//
//	e.AddGroupingPolicy("alice", "admin")
func (e *Enforcer) AddGroupingPolicy(params ...string) (bool, error) {
	if e.enforcer == nil {
		return false, ErrEnforcerNotFound
	}
	vals := make([]any, len(params))
	for i, p := range params {
		vals[i] = p
	}
	return e.enforcer.AddGroupingPolicy(vals...)
}

// RemoveGroupingPolicy 移除角色继承规则（g 类型）。
//
// 示例:
//
//	e.RemoveGroupingPolicy("alice", "admin")
func (e *Enforcer) RemoveGroupingPolicy(params ...string) (bool, error) {
	if e.enforcer == nil {
		return false, ErrEnforcerNotFound
	}
	vals := make([]any, len(params))
	for i, p := range params {
		vals[i] = p
	}
	return e.enforcer.RemoveGroupingPolicy(vals...)
}

// UpdatePolicy 更新策略规则。
func (e *Enforcer) UpdatePolicy(oldParams, newParams []string) (bool, error) {
	if e.enforcer == nil {
		return false, ErrEnforcerNotFound
	}
	return e.enforcer.UpdatePolicy(oldParams, newParams)
}

// GetRoles 获取用户的所有角色。
func (e *Enforcer) GetRoles(name string) ([]string, error) {
	if e.enforcer == nil {
		return nil, ErrEnforcerNotFound
	}
	return e.enforcer.GetRolesForUser(name)
}

// GetPermissions 获取用户的所有权限。
func (e *Enforcer) GetPermissions(name string) [][]string {
	if e.enforcer == nil {
		return nil
	}
	return e.enforcer.GetPermissionsForUser(name)
}

// HasRole 检查用户是否具有角色。
func (e *Enforcer) HasRole(name, role string) (bool, error) {
	if e.enforcer == nil {
		return false, ErrEnforcerNotFound
	}
	roles, err := e.enforcer.GetRolesForUser(name)
	if err != nil {
		return false, err
	}
	for _, r := range roles {
		if r == role {
			return true, nil
		}
	}
	return false, nil
}
