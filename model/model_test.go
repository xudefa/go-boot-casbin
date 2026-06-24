package model

import (
	"testing"

	"github.com/casbin/casbin/v2/model"
)

// TestRBACModel 测试 RBAC 模型创建
func TestRBACModel(t *testing.T) {
	t.Parallel()

	m := RBACModel()
	if m == nil {
		t.Fatal("RBACModel() returned nil")
	}

	// 验证模型定义存在
	if _, ok := m["r"]; !ok {
		t.Error("RBACModel should have request definition 'r'")
	}
	if _, ok := m["p"]; !ok {
		t.Error("RBACModel should have policy definition 'p'")
	}
	if _, ok := m["g"]; !ok {
		t.Error("RBACModel should have role definition 'g'")
	}
	if _, ok := m["e"]; !ok {
		t.Error("RBACModel should have effect definition 'e'")
	}
	if _, ok := m["m"]; !ok {
		t.Error("RBACModel should have matcher definition 'm'")
	}
}

// TestRBACModel_Definitions 测试 RBAC 模型定义内容
func TestRBACModel_Definitions(t *testing.T) {
	t.Parallel()

	m := RBACModel()

	// 验证请求定义
	rDef, ok := m["r"]
	if !ok {
		t.Fatal("request definition 'r' not found")
	}
	if len(rDef) == 0 {
		t.Error("request definition 'r' is empty")
	}

	// 验证角色定义
	gDef, ok := m["g"]
	if !ok {
		t.Fatal("role definition 'g' not found")
	}
	if len(gDef) == 0 {
		t.Error("role definition 'g' is empty")
	}

	// 验证策略定义
	pDef, ok := m["p"]
	if !ok {
		t.Fatal("policy definition 'p' not found")
	}
	if len(pDef) == 0 {
		t.Error("policy definition 'p' is empty")
	}
}

// TestABACModel 测试 ABAC 模型创建
func TestABACModel(t *testing.T) {
	t.Parallel()

	m := ABACModel()
	if m == nil {
		t.Fatal("ABACModel() returned nil")
	}

	// 验证模型定义
	if _, ok := m["r"]; !ok {
		t.Error("ABACModel should have request definition 'r'")
	}
	if _, ok := m["p"]; !ok {
		t.Error("ABACModel should have policy definition 'p'")
	}
	if _, ok := m["e"]; !ok {
		t.Error("ABACModel should have effect definition 'e'")
	}
	if _, ok := m["m"]; !ok {
		t.Error("ABACModel should have matcher definition 'm'")
	}

	// ABAC 模型不应该有角色定义
	if _, ok := m["g"]; ok {
		t.Error("ABACModel should NOT have role definition 'g'")
	}
}

// TestABACModel_Definitions 测试 ABAC 模型定义内容
func TestABACModel_Definitions(t *testing.T) {
	t.Parallel()

	m := ABACModel()

	// 验证请求定义
	rDef, ok := m["r"]
	if !ok {
		t.Fatal("request definition 'r' not found")
	}
	if len(rDef) == 0 {
		t.Error("request definition 'r' is empty")
	}

	// 验证策略定义
	pDef, ok := m["p"]
	if !ok {
		t.Fatal("policy definition 'p' not found")
	}
	if len(pDef) == 0 {
		t.Error("policy definition 'p' is empty")
	}
}

// TestRESTfulModel 测试 RESTful 模型创建
func TestRESTfulModel(t *testing.T) {
	t.Parallel()

	m := RESTfulModel()
	if m == nil {
		t.Fatal("RESTfulModel() returned nil")
	}

	// 验证模型定义
	if _, ok := m["r"]; !ok {
		t.Error("RESTfulModel should have request definition 'r'")
	}
	if _, ok := m["p"]; !ok {
		t.Error("RESTfulModel should have policy definition 'p'")
	}
	if _, ok := m["g"]; !ok {
		t.Error("RESTfulModel should have role definition 'g'")
	}
	if _, ok := m["e"]; !ok {
		t.Error("RESTfulModel should have effect definition 'e'")
	}
	if _, ok := m["m"]; !ok {
		t.Error("RESTfulModel should have matcher definition 'm'")
	}
}

// TestRESTfulModel_Definitions 测试 RESTful 模型定义内容
func TestRESTfulModel_Definitions(t *testing.T) {
	t.Parallel()

	m := RESTfulModel()

	// 验证请求定义
	rDef, ok := m["r"]
	if !ok {
		t.Fatal("request definition 'r' not found")
	}
	if len(rDef) == 0 {
		t.Error("request definition 'r' is empty")
	}

	// 验证角色定义
	gDef, ok := m["g"]
	if !ok {
		t.Fatal("role definition 'g' not found")
	}
	if len(gDef) == 0 {
		t.Error("role definition 'g' is empty")
	}
}

// TestModelComparison 测试不同模型之间的差异
func TestModelComparison(t *testing.T) {
	t.Parallel()

	rbacModel := RBACModel()
	abacModel := ABACModel()
	restfulModel := RESTfulModel()

	// RBAC 和 RESTful 应该有角色定义
	if _, ok := rbacModel["g"]; !ok {
		t.Error("RBAC model should have role definition")
	}
	if _, ok := restfulModel["g"]; !ok {
		t.Error("RESTful model should have role definition")
	}

	// ABAC 不应该有角色定义
	if _, ok := abacModel["g"]; ok {
		t.Error("ABAC model should NOT have role definition")
	}

	// 所有模型都应该有基本的 r, p, e, m 定义
	models := map[string]model.Model{
		"RBAC":    rbacModel,
		"ABAC":    abacModel,
		"RESTful": restfulModel,
	}

	for name, m := range models {
		for _, def := range []string{"r", "p", "e", "m"} {
			if _, ok := m[def]; !ok {
				t.Errorf("%s model should have definition '%s'", name, def)
			}
		}
	}
}

// TestRBACModel_AddDef 测试 AddDef 返回值
func TestRBACModel_AddDef(t *testing.T) {
	t.Parallel()

	m := RBACModel()

	// 尝试添加已存在的定义
	result := m.AddDef("r", "r", "sub, obj, act")
	if !result {
		t.Error("AddDef should return true for valid definition")
	}
}

// TestModel_ClearPolicy 测试清空策略
func TestModel_ClearPolicy(t *testing.T) {
	t.Parallel()

	m := RBACModel()

	// 添加一些策略
	m.AddPolicy("p", "p", []string{"alice", "data1", "read"})
	m.AddPolicy("p", "p", []string{"bob", "data2", "write"})

	// 验证策略已添加
	policies := m.GetPolicy("p", "p")
	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}

	// 清空策略
	m.ClearPolicy()

	// 验证策略已清空
	policies = m.GetPolicy("p", "p")
	if len(policies) != 0 {
		t.Errorf("expected 0 policies after clear, got %d", len(policies))
	}
}

// TestModel_Copy 测试模型复制
func TestModel_Copy(t *testing.T) {
	t.Parallel()

	m := RBACModel()
	copy := m.Copy()

	if copy == nil {
		t.Fatal("Copy() returned nil")
	}

	// 验证复制的模型有相同的定义
	if _, ok := copy["r"]; !ok {
		t.Error("copied model should have request definition 'r'")
	}
	if _, ok := copy["g"]; !ok {
		t.Error("copied model should have role definition 'g'")
	}
}
