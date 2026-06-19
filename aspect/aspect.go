// Package aspect 提供基于 AOP 的 Casbin 权限切面。
//
// 该包将 Casbin 权限检查与 go-boot 的 AOP 框架集成，
// 实现方法级的权限拦截，支持声明式权限注解。
package aspect

import (
	"fmt"

	"github.com/xudefa/go-boot-casbin/casbin"
	"github.com/xudefa/go-boot/aop"
)

// PermissionAspect 是 Casbin 权限检查的 AOP 切面。
//
// 该切面在方法执行前进行权限校验，
// 权限校验通过则继续执行，否则返回权限拒绝错误。
type PermissionAspect struct {
	enforcer *casbin.Enforcer
	extract  func(args []any) (subject, object, action string)
}

// NewPermissionAspect 创建权限检查切面。
//
// 参数:
//   - enforcer: Casbin Enforcer 实例
//   - extract: 从方法参数中提取授权信息的函数
//
// 示例:
//
//	aspect := aspect.NewPermissionAspect(enforcer, func(args []any) (string, string, string) {
//	    return args[0].(string), args[1].(string), args[2].(string)
//	})
func NewPermissionAspect(enforcer *casbin.Enforcer, extract func(args []any) (string, string, string)) *PermissionAspect {
	return &PermissionAspect{
		enforcer: enforcer,
		extract:  extract,
	}
}

// Advice 返回 AOP 通知（Before 类型）。
func (p *PermissionAspect) Advice() aop.Advice {
	return aop.Before(func(jp aop.JoinPoint) {
		args := jp.Args()
		sub, obj, act := p.extract(args)
		ok, err := p.enforcer.Enforce(sub, obj, act)
		if err != nil {
			panic(fmt.Errorf("casbin: enforce error: %w", err))
		}
		if !ok {
			panic(fmt.Errorf("casbin: permission denied for %s on %s with action %s", sub, obj, act))
		}
	})
}

// PointCut 返回切点匹配器（匹配所有方法）。
func (p *PermissionAspect) PointCut() aop.PointCut {
	return aop.MatchAll()
}

// Meta 返回切面元数据。
func (p *PermissionAspect) Meta() aop.AspectMeta {
	return aop.AspectMeta{
		Instance: p,
		PointCut: p.PointCut(),
		Advice:   p.Advice(),
		Order:    1,
	}
}
