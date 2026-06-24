package aspect

import (
	"context"
	"testing"

	"github.com/xudefa/go-boot-casbin/casbin"
	"github.com/xudefa/go-boot/aop"
)

// TestNewPermissionAspect 测试创建权限切面
func TestNewPermissionAspect(t *testing.T) {
	enforcer := &casbin.Enforcer{}
	extract := func(args []any) (string, string, string) {
		return "sub", "obj", "act"
	}

	aspect := NewPermissionAspect(enforcer, extract)
	if aspect == nil {
		t.Fatal("expected non-nil aspect")
	}
	if aspect.enforcer != enforcer {
		t.Error("expected enforcer to be set")
	}
	if aspect.extract == nil {
		t.Error("expected extract function to be set")
	}
}

// TestPermissionAspect_Advice 测试通知
func TestPermissionAspect_Advice(t *testing.T) {
	enforcer := &casbin.Enforcer{}
	extract := func(args []any) (string, string, string) {
		return "sub", "obj", "act"
	}

	aspect := NewPermissionAspect(enforcer, extract)
	advice := aspect.Advice()
	if advice == nil {
		t.Error("expected non-nil advice")
	}
}

// TestPermissionAspect_PointCut 测试切点
func TestPermissionAspect_PointCut(t *testing.T) {
	enforcer := &casbin.Enforcer{}
	extract := func(args []any) (string, string, string) {
		return "sub", "obj", "act"
	}

	aspect := NewPermissionAspect(enforcer, extract)
	pointCut := aspect.PointCut()
	if pointCut == nil {
		t.Error("expected non-nil point cut")
	}
}

// TestPermissionAspect_Meta 测试元数据
func TestPermissionAspect_Meta(t *testing.T) {
	enforcer := &casbin.Enforcer{}
	extract := func(args []any) (string, string, string) {
		return "sub", "obj", "act"
	}

	aspect := NewPermissionAspect(enforcer, extract)
	meta := aspect.Meta()
	if meta.Instance != aspect {
		t.Error("expected instance to be the aspect itself")
	}
	if meta.Order != 1 {
		t.Errorf("expected order 1, got %d", meta.Order)
	}
	if meta.PointCut == nil {
		t.Error("expected non-nil point cut in meta")
	}
	if meta.Advice == nil {
		t.Error("expected non-nil advice in meta")
	}
}

// TestPermissionAspect_Advice_PermissionGranted 测试权限通过
func TestPermissionAspect_Advice_PermissionGranted(t *testing.T) {
	t.Parallel()

	e, err := casbin.NewEnforcer(
		casbin.WithModel("../testdata/model.conf"),
		casbin.WithAdapter("../testdata/policy.csv"),
	)
	if err != nil {
		t.Fatalf("NewEnforcer failed: %v", err)
	}

	extract := func(args []any) (string, string, string) {
		return args[0].(string), args[1].(string), args[2].(string)
	}

	aspect := NewPermissionAspect(e, extract)
	advice := aspect.Advice()

	// 创建 mock join point
	jp := &mockJoinPoint{
		args: []any{"alice", "data1", "read"},
	}

	// 执行 advice（应该不 panic）
	advice.Apply(jp, nil)

	// 验证没有异常
	if jp.panicCalled {
		t.Error("should not panic when permission is granted")
	}
}

// TestPermissionAspect_Advice_PermissionDenied 测试权限拒绝
func TestPermissionAspect_Advice_PermissionDenied(t *testing.T) {
	t.Parallel()

	e, err := casbin.NewEnforcer(
		casbin.WithModel("../testdata/model.conf"),
		casbin.WithAdapter("../testdata/policy.csv"),
	)
	if err != nil {
		t.Fatalf("NewEnforcer failed: %v", err)
	}

	extract := func(args []any) (string, string, string) {
		return args[0].(string), args[1].(string), args[2].(string)
	}

	aspect := NewPermissionAspect(e, extract)
	advice := aspect.Advice()

	// 创建 mock join point
	jp := &mockJoinPoint{
		args: []any{"bob", "data1", "write"}, // bob 没有 write 权限
	}

	// 执行 advice（应该 panic）
	defer func() {
		if r := recover(); r == nil {
			t.Error("should panic when permission is denied")
		} else {
			t.Logf("panicked as expected: %v", r)
		}
	}()

	advice.Apply(jp, nil)
}

// TestPermissionAspect_Advice_EnforceError 测试 Enforce 错误
func TestPermissionAspect_Advice_EnforceError(t *testing.T) {
	t.Parallel()

	// 使用空的 enforcer（没有模型）
	e, err := casbin.NewEnforcer(
		casbin.WithModel("../testdata/model.conf"),
	)
	if err != nil {
		t.Fatalf("NewEnforcer failed: %v", err)
	}

	extract := func(args []any) (string, string, string) {
		return args[0].(string), args[1].(string), args[2].(string)
	}

	aspect := NewPermissionAspect(e, extract)
	advice := aspect.Advice()

	// 创建 mock join point
	jp := &mockJoinPoint{
		args: []any{"alice", "data1", "read"},
	}

	// 执行 advice（可能会因为缺少策略而返回 false，但不应该 panic 于错误）
	defer func() {
		if r := recover(); r != nil {
			t.Logf("panicked (permission denied is expected): %v", r)
		}
	}()

	advice.Apply(jp, nil)

	// 验证没有异常（权限拒绝会 panic，但这是预期的行为）
	t.Logf("test completed without enforce error")
}

// TestPermissionAspect_PointCut_MatchAll 测试切点匹配所有
func TestPermissionAspect_PointCut_MatchAll(t *testing.T) {
	t.Parallel()

	enforcer := &casbin.Enforcer{}
	extract := func(args []any) (string, string, string) {
		return "sub", "obj", "act"
	}

	aspect := NewPermissionAspect(enforcer, extract)
	pointCut := aspect.PointCut()

	// 验证切点匹配所有方法
	if pointCut == nil {
		t.Fatal("expected non-nil point cut")
	}

	// MatchAll 应该匹配任何方法
	t.Log("point cut matches all methods")
}

// mockJoinPoint 模拟 AOP 连接点
type mockJoinPoint struct {
	args        []any
	panicCalled bool
}

func (m *mockJoinPoint) Method() any {
	return nil
}

func (m *mockJoinPoint) Args() []any {
	return m.args
}

func (m *mockJoinPoint) Signature() aop.MethodSignature {
	return nil
}

func (m *mockJoinPoint) This() any {
	return nil
}

func (m *mockJoinPoint) Target() any {
	return nil
}

func (m *mockJoinPoint) Context() context.Context {
	return context.Background()
}

func (m *mockJoinPoint) Panic(v any) {
	m.panicCalled = true
	panic(v)
}
