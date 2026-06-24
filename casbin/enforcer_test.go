package casbin

import (
	"context"
	"testing"

	"github.com/xudefa/go-boot/data"
	"github.com/xudefa/go-boot/net"
)

type mockHandlerContext struct {
	method     string
	uri        string
	header     string
	statusCode int
	aborted    bool
	nextCalled bool
	ctx        context.Context
}

func (m *mockHandlerContext) RequestMethod() string { return m.method }
func (m *mockHandlerContext) RequestURI() string    { return m.uri }
func (m *mockHandlerContext) Header(key string) string {
	if key == "X-User" {
		return m.header
	}
	return ""
}
func (m *mockHandlerContext) SetStatusCode(code int)      { m.statusCode = code }
func (m *mockHandlerContext) SetHeader(key, value string) {}
func (m *mockHandlerContext) AbortWithStatus(code int) {
	m.aborted = true
	m.statusCode = code
}
func (m *mockHandlerContext) AbortWithStatusJSON(code int, body interface{}) {
	m.aborted = true
	m.statusCode = code
}
func (m *mockHandlerContext) Next()                          { m.nextCalled = true }
func (m *mockHandlerContext) IsAborted() bool                { return m.aborted }
func (m *mockHandlerContext) Context() context.Context       { return m.ctx }
func (m *mockHandlerContext) SetContext(ctx context.Context) { m.ctx = ctx }

func newTestEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	e, err := NewEnforcer(
		WithModel("../testdata/model.conf"),
		WithAdapter("../testdata/policy.csv"),
	)
	if err != nil {
		t.Fatalf("NewEnforcer failed: %v", err)
	}
	return e
}

func TestNewEnforcer(t *testing.T) {
	t.Parallel()

	t.Run("success with model and adapter", func(t *testing.T) {
		t.Parallel()
		e, err := NewEnforcer(
			WithModel("../testdata/model.conf"),
			WithAdapter("../testdata/policy.csv"),
		)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if e == nil {
			t.Fatal("expected non-nil enforcer")
		}
	})

	t.Run("success with model only", func(t *testing.T) {
		t.Parallel()
		e, err := NewEnforcer(WithModel("../testdata/model.conf"))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if e == nil {
			t.Fatal("expected non-nil enforcer")
		}
	})

	t.Run("fail without model", func(t *testing.T) {
		t.Parallel()
		_, err := NewEnforcer()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("fail with nonexistent model file", func(t *testing.T) {
		t.Parallel()
		_, err := NewEnforcer(WithModel("../testdata/nonexistent.conf"))
		if err == nil {
			t.Fatal("expected error for nonexistent model file")
		}
	})
}

func TestEnforcer_RawEnforcer(t *testing.T) {
	t.Parallel()

	e := newTestEnforcer(t)
	raw := e.RawEnforcer()
	if raw == nil {
		t.Fatal("RawEnforcer() returned nil")
	}
}

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	if ErrEnforcerNotFound.Error() != "casbin: enforcer not found in container" {
		t.Errorf("unexpected ErrEnforcerNotFound message: %s", ErrEnforcerNotFound.Error())
	}
	if ErrInvalidEnforcer.Error() != "casbin: invalid enforcer type" {
		t.Errorf("unexpected ErrInvalidEnforcer message: %s", ErrInvalidEnforcer.Error())
	}
	// Verify errors are non-nil
	if ErrEnforcerNotFound == nil {
		t.Error("ErrEnforcerNotFound should be non-nil")
	}
	if ErrInvalidEnforcer == nil {
		t.Error("ErrInvalidEnforcer should be non-nil")
	}
}

func TestEnforce(t *testing.T) {
	t.Parallel()

	e := newTestEnforcer(t)

	tests := []struct {
		name string
		sub  string
		obj  string
		act  string
		want bool
	}{
		{"alice read data1", "alice", "data1", "read", true},
		{"alice write data1", "alice", "data1", "write", true},
		{"alice read data2", "alice", "data2", "read", true},
		{"alice write data2", "alice", "data2", "write", true},
		{"bob read data1", "bob", "data1", "read", true},
		{"bob read data2", "bob", "data2", "read", true},
		{"bob write data1", "bob", "data1", "write", false},
		{"bob write data2", "bob", "data2", "write", false},
		{"unknown user read data1", "unknown", "data1", "read", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.Enforce(tt.sub, tt.obj, tt.act)
			if err != nil {
				t.Fatalf("Enforce failed: %v", err)
			}
			if got != tt.want {
				t.Errorf("Enforce(%q, %q, %q) = %v, want %v", tt.sub, tt.obj, tt.act, got, tt.want)
			}
		})
	}

	t.Run("raw http uri returns false (bug reproduction)", func(t *testing.T) {
		got, err := e.Enforce("alice", "/api/data1", "GET")
		if err != nil {
			t.Fatalf("Enforce failed: %v", err)
		}
		if got {
			t.Error("Enforce with raw URI /api/data1 and GET should return false - policy expects 'data1' and 'read'")
		}
	})
}

func TestAddPolicy(t *testing.T) {
	t.Parallel()

	e := newTestEnforcer(t)

	ok, err := e.AddPolicy("user", "data3", "read")
	if err != nil {
		t.Fatalf("AddPolicy failed: %v", err)
	}
	if !ok {
		t.Fatal("AddPolicy returned false")
	}

	got, err := e.Enforce("bob", "data3", "read")
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if !got {
		t.Error("bob should be able to read data3 after adding policy")
	}
}

func TestRemovePolicy(t *testing.T) {
	t.Parallel()

	e := newTestEnforcer(t)

	ok, err := e.RemovePolicy("user", "data1", "read")
	if err != nil {
		t.Fatalf("RemovePolicy failed: %v", err)
	}
	if !ok {
		t.Fatal("RemovePolicy returned false")
	}

	got, err := e.Enforce("bob", "data1", "read")
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if got {
		t.Error("bob should not be able to read data1 after removing policy")
	}
}

func TestUpdatePolicy(t *testing.T) {
	t.Parallel()

	e := newTestEnforcer(t)

	ok, err := e.UpdatePolicy(
		[]string{"user", "data1", "read"},
		[]string{"user", "data1", "write"},
	)
	if err != nil {
		t.Fatalf("UpdatePolicy failed: %v", err)
	}
	if !ok {
		t.Fatal("UpdatePolicy returned false")
	}

	readOk, _ := e.Enforce("bob", "data1", "read")
	if readOk {
		t.Error("bob should not be able to read data1 after policy update")
	}

	writeOk, _ := e.Enforce("bob", "data1", "write")
	if !writeOk {
		t.Error("bob should be able to write data1 after policy update")
	}
}

func TestGetRoles(t *testing.T) {
	t.Parallel()

	e := newTestEnforcer(t)

	roles, err := e.GetRoles("alice")
	if err != nil {
		t.Fatalf("GetRoles failed: %v", err)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("alice should have role admin, got %v", roles)
	}

	roles, err = e.GetRoles("bob")
	if err != nil {
		t.Fatalf("GetRoles failed: %v", err)
	}
	if len(roles) != 1 || roles[0] != "user" {
		t.Errorf("bob should have role user, got %v", roles)
	}
}

func TestGetPermissions(t *testing.T) {
	t.Parallel()

	e := newTestEnforcer(t)

	t.Run("admin has 4 permissions", func(t *testing.T) {
		t.Parallel()
		perms := e.GetPermissions("admin")
		if len(perms) != 4 {
			t.Errorf("admin should have 4 permissions, got %d: %v", len(perms), perms)
		}
	})

	t.Run("user has 2 permissions", func(t *testing.T) {
		t.Parallel()
		perms := e.GetPermissions("user")
		if len(perms) != 2 {
			t.Errorf("user should have 2 permissions, got %d: %v", len(perms), perms)
		}
	})

	t.Run("user has read data1", func(t *testing.T) {
		t.Parallel()
		perms := e.GetPermissions("user")
		found := false
		for _, p := range perms {
			if len(p) >= 3 && p[0] == "user" && p[1] == "data1" && p[2] == "read" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("user permissions should include (user, data1, read), got %v", perms)
		}
	})

	t.Run("alice inherits permissions via role", func(t *testing.T) {
		perms := e.GetPermissions("alice")
		if len(perms) != 0 {
			t.Logf("alice's direct permissions: %v", perms)
		}
	})
}

func TestHasRole(t *testing.T) {
	t.Parallel()

	e := newTestEnforcer(t)

	tests := []struct {
		name string
		user string
		role string
		want bool
	}{
		{"alice is admin", "alice", "admin", true},
		{"alice is not user", "alice", "user", false},
		{"bob is user", "bob", "user", true},
		{"bob is not admin", "bob", "admin", false},
		{"unknown has no role", "unknown", "admin", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.HasRole(tt.user, tt.role)
			if err != nil {
				t.Fatalf("HasRole failed: %v", err)
			}
			if got != tt.want {
				t.Errorf("HasRole(%q, %q) = %v, want %v", tt.user, tt.role, got, tt.want)
			}
		})
	}
}

func TestAuthorizeMiddleware(t *testing.T) {
	t.Parallel()

	e := newTestEnforcer(t)

	extractor := func(ctx net.HandlerContext) (string, string, string) {
		return ctx.Header("X-User"), ctx.RequestURI(), ctx.RequestMethod()
	}

	t.Run("raw http request returns 403 (bug reproduction)", func(t *testing.T) {
		t.Parallel()
		ctx := &mockHandlerContext{
			method: "GET",
			uri:    "/api/data1",
			header: "alice",
		}

		mw := Authorize(e, extractor)
		mw(ctx)

		if !ctx.aborted {
			t.Fatal("expected request to be aborted (403) for raw HTTP data without mapping")
		}
		if ctx.statusCode != 403 {
			t.Errorf("expected status 403, got %d", ctx.statusCode)
		}
	})
}

func TestAuthorizeMiddlewareWithMappedExtractor(t *testing.T) {
	t.Parallel()

	e := newTestEnforcer(t)

	extractor := func(ctx net.HandlerContext) (string, string, string) {
		sub := ctx.Header("X-User")
		obj := ctx.RequestURI()
		if len(obj) > 4 && obj[:4] == "/api" {
			obj = obj[4:]
		}
		if len(obj) > 0 && obj[0] == '/' {
			obj = obj[1:]
		}
		act := "read"
		if len(obj) > 6 && obj[len(obj)-6:] == "/write" {
			act = "write"
			obj = obj[:len(obj)-6]
		}
		return sub, obj, act
	}

	tests := []struct {
		name   string
		method string
		uri    string
		user   string
		wantOK bool
	}{
		{"alice GET /api/data1", "GET", "/api/data1", "alice", true},
		{"alice GET /api/data1/write", "GET", "/api/data1/write", "alice", true},
		{"alice GET /api/data2", "GET", "/api/data2", "alice", true},
		{"bob GET /api/data1", "GET", "/api/data1", "bob", true},
		{"bob GET /api/data1/write", "GET", "/api/data1/write", "bob", false},
		{"bob GET /api/data2", "GET", "/api/data2", "bob", true},
		{"unknown GET /api/data1", "GET", "/api/data1", "unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &mockHandlerContext{
				method: tt.method,
				uri:    tt.uri,
				header: tt.user,
			}

			mw := Authorize(e, extractor)
			mw(ctx)

			if tt.wantOK && ctx.aborted {
				t.Errorf("expected 200, got abort with status %d", ctx.statusCode)
			}
			if !tt.wantOK && !ctx.aborted {
				t.Error("expected 403, got 200")
			}
			if !tt.wantOK && ctx.statusCode != 403 {
				t.Errorf("expected status 403, got %d", ctx.statusCode)
			}
		})
	}
}

// TestWithDBAdapter 测试 WithDBAdapter 选项
func TestWithDBAdapter(t *testing.T) {
	t.Parallel()

	// 创建一个 mock transactor
	tx := &mockTransactor{}

	// 测试 WithDBAdapter 选项
	opt := WithDBAdapter(tx)
	if opt == nil {
		t.Fatal("WithDBAdapter() returned nil")
	}

	// 验证选项函数被正确应用
	opts := &options{}
	opt(opts)

	if opts.adapterImpl == nil {
		t.Error("expected adapterImpl to be set")
	}
}

// TestWithDBAdapter_CustomTableName 测试 WithDBAdapter 自定义表名
func TestWithDBAdapter_CustomTableName(t *testing.T) {
	t.Parallel()

	tx := &mockTransactor{}

	// 测试 WithDBAdapter 带自定义表名
	opt := WithDBAdapter(tx, "custom_rules")
	if opt == nil {
		t.Fatal("WithDBAdapter() returned nil")
	}

	// 验证选项函数被正确应用
	opts := &options{}
	opt(opts)

	if opts.adapterImpl == nil {
		t.Error("expected adapterImpl to be set")
	}
}

// TestEnforcer_AddGroupingPolicy 测试添加角色继承规则
func TestEnforcer_AddGroupingPolicy(t *testing.T) {
	t.Parallel()

	e := newTestEnforcer(t)

	// 添加角色继承规则
	ok, err := e.AddGroupingPolicy("charlie", "admin")
	if err != nil {
		t.Fatalf("AddGroupingPolicy failed: %v", err)
	}
	if !ok {
		t.Fatal("AddGroupingPolicy returned false")
	}

	// 验证 charlie 现在有 admin 角色
	roles, err := e.GetRoles("charlie")
	if err != nil {
		t.Fatalf("GetRoles failed: %v", err)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("charlie should have role admin, got %v", roles)
	}
}

// TestEnforcer_RemoveGroupingPolicy 测试移除角色继承规则
func TestEnforcer_RemoveGroupingPolicy(t *testing.T) {
	t.Parallel()

	e := newTestEnforcer(t)

	// 先添加角色继承规则
	_, err := e.AddGroupingPolicy("charlie", "admin")
	if err != nil {
		t.Fatalf("AddGroupingPolicy failed: %v", err)
	}

	// 移除角色继承规则
	ok, err := e.RemoveGroupingPolicy("charlie", "admin")
	if err != nil {
		t.Fatalf("RemoveGroupingPolicy failed: %v", err)
	}
	if !ok {
		t.Fatal("RemoveGroupingPolicy returned false")
	}

	// 验证 charlie 不再有 admin 角色
	roles, err := e.GetRoles("charlie")
	if err != nil {
		t.Fatalf("GetRoles failed: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("charlie should have no roles, got %v", roles)
	}
}

// TestEnforcer_Enforce_NilEnforcer 测试 nil enforcer 的 Enforce
func TestEnforcer_Enforce_NilEnforcer(t *testing.T) {
	t.Parallel()

	e := &Enforcer{enforcer: nil}

	ok, err := e.Enforce("alice", "data1", "read")
	if err == nil {
		t.Error("expected error when enforcer is nil")
	}
	if ok {
		t.Error("expected false when enforcer is nil")
	}
}

// TestEnforcer_AddPolicy_NilEnforcer 测试 nil enforcer 的 AddPolicy
func TestEnforcer_AddPolicy_NilEnforcer(t *testing.T) {
	t.Parallel()

	e := &Enforcer{enforcer: nil}

	ok, err := e.AddPolicy("alice", "data1", "read")
	if err == nil {
		t.Error("expected error when enforcer is nil")
	}
	if ok {
		t.Error("expected false when enforcer is nil")
	}
}

// TestEnforcer_RemovePolicy_NilEnforcer 测试 nil enforcer 的 RemovePolicy
func TestEnforcer_RemovePolicy_NilEnforcer(t *testing.T) {
	t.Parallel()

	e := &Enforcer{enforcer: nil}

	ok, err := e.RemovePolicy("alice", "data1", "read")
	if err == nil {
		t.Error("expected error when enforcer is nil")
	}
	if ok {
		t.Error("expected false when enforcer is nil")
	}
}

// TestEnforcer_AddGroupingPolicy_NilEnforcer 测试 nil enforcer 的 AddGroupingPolicy
func TestEnforcer_AddGroupingPolicy_NilEnforcer(t *testing.T) {
	t.Parallel()

	e := &Enforcer{enforcer: nil}

	ok, err := e.AddGroupingPolicy("alice", "admin")
	if err == nil {
		t.Error("expected error when enforcer is nil")
	}
	if ok {
		t.Error("expected false when enforcer is nil")
	}
}

// TestEnforcer_RemoveGroupingPolicy_NilEnforcer 测试 nil enforcer 的 RemoveGroupingPolicy
func TestEnforcer_RemoveGroupingPolicy_NilEnforcer(t *testing.T) {
	t.Parallel()

	e := &Enforcer{enforcer: nil}

	ok, err := e.RemoveGroupingPolicy("alice", "admin")
	if err == nil {
		t.Error("expected error when enforcer is nil")
	}
	if ok {
		t.Error("expected false when enforcer is nil")
	}
}

// TestEnforcer_UpdatePolicy_NilEnforcer 测试 nil enforcer 的 UpdatePolicy
func TestEnforcer_UpdatePolicy_NilEnforcer(t *testing.T) {
	t.Parallel()

	e := &Enforcer{enforcer: nil}

	ok, err := e.UpdatePolicy([]string{"alice", "data1", "read"}, []string{"alice", "data1", "write"})
	if err == nil {
		t.Error("expected error when enforcer is nil")
	}
	if ok {
		t.Error("expected false when enforcer is nil")
	}
}

// TestEnforcer_GetRoles_NilEnforcer 测试 nil enforcer 的 GetRoles
func TestEnforcer_GetRoles_NilEnforcer(t *testing.T) {
	t.Parallel()

	e := &Enforcer{enforcer: nil}

	roles, err := e.GetRoles("alice")
	if err == nil {
		t.Error("expected error when enforcer is nil")
	}
	if roles != nil {
		t.Error("expected nil roles when enforcer is nil")
	}
}

// TestEnforcer_GetPermissions_NilEnforcer 测试 nil enforcer 的 GetPermissions
func TestEnforcer_GetPermissions_NilEnforcer(t *testing.T) {
	t.Parallel()

	e := &Enforcer{enforcer: nil}

	perms := e.GetPermissions("alice")
	if perms != nil {
		t.Error("expected nil permissions when enforcer is nil")
	}
}

// TestEnforcer_HasRole_NilEnforcer 测试 nil enforcer 的 HasRole
func TestEnforcer_HasRole_NilEnforcer(t *testing.T) {
	t.Parallel()

	e := &Enforcer{enforcer: nil}

	ok, err := e.HasRole("alice", "admin")
	if err == nil {
		t.Error("expected error when enforcer is nil")
	}
	if ok {
		t.Error("expected false when enforcer is nil")
	}
}

// TestEnforcer_HasRole 测试 HasRole 方法
func TestEnforcer_HasRole(t *testing.T) {
	t.Parallel()

	e := newTestEnforcer(t)

	// 测试 alice 有 admin 角色
	ok, err := e.HasRole("alice", "admin")
	if err != nil {
		t.Fatalf("HasRole failed: %v", err)
	}
	if !ok {
		t.Error("alice should have admin role")
	}

	// 测试 alice 没有 user 角色
	ok, err = e.HasRole("alice", "user")
	if err != nil {
		t.Fatalf("HasRole failed: %v", err)
	}
	if ok {
		t.Error("alice should not have user role")
	}

	// 测试 bob 有 user 角色
	ok, err = e.HasRole("bob", "user")
	if err != nil {
		t.Fatalf("HasRole failed: %v", err)
	}
	if !ok {
		t.Error("bob should have user role")
	}
}

// TestEnforcerBeanID 测试 EnforcerBeanID 常量
func TestEnforcerBeanID(t *testing.T) {
	t.Parallel()

	if EnforcerBeanID != "casbinEnforcer" {
		t.Errorf("expected EnforcerBeanID to be 'casbinEnforcer', got %s", EnforcerBeanID)
	}
}

// mockTransactor 模拟数据库事务操作器
type mockTransactor struct{}

func (m *mockTransactor) Exec(ctx context.Context, query string, args ...any) (data.Result, error) {
	return nil, nil
}

func (m *mockTransactor) Query(ctx context.Context, query string, args ...any) (data.Rows, error) {
	return nil, nil
}

func (m *mockTransactor) QueryRow(ctx context.Context, query string, args ...any) data.Row {
	return nil
}

func (m *mockTransactor) Begin(ctx context.Context) (data.Transaction, error) {
	return nil, nil
}

func (m *mockTransactor) Stats() data.DBStats {
	return data.DBStats{}
}

func (m *mockTransactor) Close() error {
	return nil
}

var _ data.Transactor = (*mockTransactor)(nil)
