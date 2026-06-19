package casbin

import (
	"context"
	"testing"

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
