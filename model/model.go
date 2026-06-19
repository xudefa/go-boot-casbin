// Package model 提供 Casbin 模型配置辅助。
//
// 该包提供 RBAC、ABAC 等常见权限模型的预定义配置，
// 简化 Casbin 模型文件的创建和使用。
package model

import (
	"github.com/casbin/casbin/v2/model"
)

// Model 是 Casbin 模型接口。
type Model interface {
	model.Model
}

// RBACModel 创建基于角色的访问控制（RBAC）模型。
//
// 该模型支持：
//   - 主体（subject）、资源（object）、操作（action）三元组
//   - 角色继承关系（g = _, _）
//   - 允许策略效果（some(where (p.eft == allow))）
//
// 示例:
//
//	m := model.RBACModel()
//	e, err := casbin.NewEnforcer(casbin.WithModel(m))
func RBACModel() model.Model {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("g", "g", "_, _")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")
	return m
}

// ABACModel 创建基于属性的访问控制（ABAC）模型。
//
// 该模型支持：
//   - 主体属性、资源属性、操作属性的匹配
//   - 无角色继承
//   - 允许策略效果
//
// 示例:
//
//	m := model.ABACModel()
//	e, err := casbin.NewEnforcer(casbin.WithModel(m))
func ABACModel() model.Model {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
	return m
}

// RESTfulModel 创建 RESTful 风格的 RBAC 模型。
//
// 该模型将 HTTP 方法和 URL 路径作为资源和操作：
//   - 资源：URL 路径（如 /api/users）
//   - 操作：HTTP 方法（GET、POST、PUT、DELETE）
//
// 示例:
//
//	m := model.RESTfulModel()
//	e, err := casbin.NewEnforcer(casbin.WithModel(m))
func RESTfulModel() model.Model {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("g", "g", "_, _")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "g(r.sub, p.sub) && keyMatch2(r.obj, p.obj) && r.act == p.act")
	return m
}
