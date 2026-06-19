// Package casbin 提供基于 Casbin 的 HTTP 授权中间件。
//
// 该包提供框架无关的授权中间件，通过 AuthorizationExtractor 从请求上下文中
// 提取授权信息（主体、资源、操作），然后使用 Casbin Enforcer 进行权限检查。
package casbin

import (
	"github.com/xudefa/go-boot/net"
)

// AuthorizationExtractor 从请求上下文中提取授权信息。
//
// 返回主体(subject)、资源(object)和操作(action)三个字符串，
// 用于 Casbin 权限检查。
type AuthorizationExtractor func(ctx net.HandlerContext) (subject, object, action string)

// Authorize 创建基于 Casbin 的授权中间件。
//
// 该中间件使用指定的提取器从请求中获取主体、资源和操作信息，
// 然后通过 Enforcer 进行权限检查。
// 权限校验通过则调用 ctx.Next() 继续处理，否则返回 403 状态码。
//
// 参数:
//   - enforcer: Casbin Enforcer 实例
//   - extract: 授权信息提取函数
//
// 返回值:
//   - net.MiddlewareFunc: 中间件函数
func Authorize(enforcer *Enforcer, extract AuthorizationExtractor) net.MiddlewareFunc {
	return func(ctx net.HandlerContext) {
		sub, obj, act := extract(ctx)
		ok, err := enforcer.Enforce(sub, obj, act)
		if err != nil {
			ctx.AbortWithStatus(500)
			return
		}
		if !ok {
			ctx.AbortWithStatus(403)
			return
		}
		ctx.Next()
	}
}
