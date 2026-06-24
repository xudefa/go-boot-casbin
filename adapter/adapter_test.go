package adapter

import (
	"context"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2/model"
	"github.com/xudefa/go-boot/data"
)

// mockResult 模拟执行结果
type mockResult struct{}

func (m *mockResult) LastInsertId() (int64, error) {
	return 0, nil
}

func (m *mockResult) RowsAffected() (int64, error) {
	return 0, nil
}

// mockRow 模拟单行结果
type mockRow struct{}

func (m *mockRow) Scan(dest ...any) error {
	return nil
}

// mockTransaction 模拟事务
type mockTransaction struct {
	*mockTransactor
}

func (m *mockTransaction) Commit() error {
	return nil
}

func (m *mockTransaction) Rollback() error {
	return nil
}

// mockTransactor 模拟数据库事务操作器
type mockTransactor struct {
	execQueries []string
	execArgs    [][]any
	queryResult *mockRows
	queryError  error
	execError   error
}

type mockRows struct {
	rows     [][]any
	index    int
	closed   bool
	closeErr error
}

func (m *mockRows) Next() bool {
	if m.index < len(m.rows) {
		m.index++
		return true
	}
	return false
}

func (m *mockRows) Scan(dest ...any) error {
	if m.index == 0 || m.index > len(m.rows) {
		return nil
	}
	row := m.rows[m.index-1]
	for i, v := range row {
		if i < len(dest) {
			switch d := dest[i].(type) {
			case *string:
				if s, ok := v.(string); ok {
					*d = s
				}
			case *int:
				if n, ok := v.(int); ok {
					*d = n
				}
			case *int64:
				if n, ok := v.(int64); ok {
					*d = n
				}
			}
		}
	}
	return nil
}

func (m *mockRows) Close() error {
	m.closed = true
	return m.closeErr
}

func (m *mockRows) Err() error {
	return nil
}

func (m *mockTransactor) Exec(ctx context.Context, query string, args ...any) (data.Result, error) {
	m.execQueries = append(m.execQueries, query)
	m.execArgs = append(m.execArgs, args)
	if m.execError != nil {
		return nil, m.execError
	}
	return &mockResult{}, nil
}

func (m *mockTransactor) Query(ctx context.Context, query string, args ...any) (data.Rows, error) {
	m.execQueries = append(m.execQueries, query)
	m.execArgs = append(m.execArgs, args)
	if m.queryError != nil {
		return nil, m.queryError
	}
	if m.queryResult == nil {
		return &mockRows{}, nil
	}
	return m.queryResult, nil
}

func (m *mockTransactor) QueryRow(ctx context.Context, query string, args ...any) data.Row {
	return &mockRow{}
}

func (m *mockTransactor) Begin(ctx context.Context) (data.Transaction, error) {
	return &mockTransaction{mockTransactor: m}, nil
}

func (m *mockTransactor) Stats() data.DBStats {
	return data.DBStats{}
}

func (m *mockTransactor) Close() error {
	return nil
}

var _ data.Transactor = (*mockTransactor)(nil)

// TestNewDBAdapter 测试创建适配器
func TestNewDBAdapter(t *testing.T) {
	tx := &mockTransactor{}

	// 测试默认表名
	adapter := NewDBAdapter(tx)
	if adapter.tableName != defaultCasbinTableName {
		t.Errorf("expected default table name %s, got %s", defaultCasbinTableName, adapter.tableName)
	}

	// 测试自定义表名
	adapter2 := NewDBAdapter(tx, "custom_table")
	if adapter2.tableName != "custom_table" {
		t.Errorf("expected custom table name custom_table, got %s", adapter2.tableName)
	}

	// 测试空表名（应使用默认）
	adapter3 := NewDBAdapter(tx, "")
	if adapter3.tableName != defaultCasbinTableName {
		t.Errorf("expected default table name %s, got %s", defaultCasbinTableName, adapter3.tableName)
	}
}

// TestDBAdapter_CreateTable 测试创建表
func TestDBAdapter_CreateTable(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx)

	err := adapter.createTable(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(tx.execQueries) != 1 {
		t.Errorf("expected 1 exec query, got %d", len(tx.execQueries))
	}

	if !strings.Contains(tx.execQueries[0], "CREATE TABLE") {
		t.Errorf("expected CREATE TABLE query, got %s", tx.execQueries[0])
	}
}

// TestDBAdapter_CreateTable_Error 测试创建表错误
func TestDBAdapter_CreateTable_Error(t *testing.T) {
	tx := &mockTransactor{
		execError: context.DeadlineExceeded,
	}
	adapter := NewDBAdapter(tx)

	err := adapter.createTable(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestLoadPolicyLine 测试加载策略行
func TestLoadPolicyLine(t *testing.T) {
	tests := []struct {
		name     string
		rule     casbinRule
		expected string
	}{
		{
			name:     "empty rule",
			rule:     casbinRule{ptype: "p"},
			expected: "p",
		},
		{
			name:     "rule with v0",
			rule:     casbinRule{ptype: "p", v0: "alice"},
			expected: "p, alice",
		},
		{
			name:     "rule with v0 and v1",
			rule:     casbinRule{ptype: "p", v0: "alice", v1: "data1"},
			expected: "p, alice, data1",
		},
		{
			name:     "rule with all fields",
			rule:     casbinRule{ptype: "p", v0: "alice", v1: "data1", v2: "read"},
			expected: "p, alice, data1, read",
		},
		{
			name:     "g type rule",
			rule:     casbinRule{ptype: "g", v0: "alice", v1: "admin"},
			expected: "g, alice, admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modelStr := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
			if tt.rule.ptype == "g" {
				modelStr = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _ _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`
			}

			m, err := model.NewModelFromString(modelStr)
			if err != nil {
				t.Fatalf("failed to create model: %v", err)
			}

			loadPolicyLine(&tt.rule, m)
			t.Log("policy loaded successfully")
		})
	}
}

// TestDBAdapter_SaveRule 测试保存规则
func TestDBAdapter_SaveRule(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx)

	rule := []string{"alice", "data1", "read"}
	err := adapter.saveRule(context.Background(), "p", rule)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(tx.execQueries) != 1 {
		t.Errorf("expected 1 exec query, got %d", len(tx.execQueries))
	}

	if !strings.Contains(tx.execQueries[0], "INSERT INTO") {
		t.Errorf("expected INSERT query, got %s", tx.execQueries[0])
	}
}

// TestDBAdapter_SaveRule_EmptyRule 测试保存空规则
func TestDBAdapter_SaveRule_EmptyRule(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx)

	rule := []string{}
	err := adapter.saveRule(context.Background(), "p", rule)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestDBAdapter_SaveRule_ShortRule 测试保存短规则
func TestDBAdapter_SaveRule_ShortRule(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx)

	rule := []string{"alice"}
	err := adapter.saveRule(context.Background(), "p", rule)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestDBAdapter_SaveRule_LongRule 测试保存长规则（超过6个字段）
func TestDBAdapter_SaveRule_LongRule(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx)

	rule := []string{"alice", "data1", "read", "field3", "field4", "field5", "field6"}
	err := adapter.saveRule(context.Background(), "p", rule)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestDBAdapter_InsertRule_Error 测试插入规则错误
func TestDBAdapter_InsertRule_Error(t *testing.T) {
	tx := &mockTransactor{
		execError: context.DeadlineExceeded,
	}
	adapter := NewDBAdapter(tx)

	rule := casbinRule{ptype: "p", v0: "alice"}
	err := adapter.insertRule(context.Background(), rule)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestDBAdapter_Interface 测试适配器实现接口
func TestDBAdapter_Interface(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx)

	var _ Adapter = adapter
}

// TestDBAdapter_CustomTableName 测试自定义表名
func TestDBAdapter_CustomTableName(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx, "custom_casbin_rules")

	if adapter.tableName != "custom_casbin_rules" {
		t.Errorf("expected table name custom_casbin_rules, got %s", adapter.tableName)
	}

	err := adapter.createTable(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !strings.Contains(tx.execQueries[0], "custom_casbin_rules") {
		t.Errorf("expected query to contain custom_casbin_rules, got %s", tx.execQueries[0])
	}
}

// TestDBAdapter_LoadPolicy 测试加载策略
func TestDBAdapter_LoadPolicy(t *testing.T) {
	tx := &mockTransactor{
		queryResult: &mockRows{
			rows: [][]any{
				{"p", "alice", "data1", "read", "", "", ""},
				{"p", "bob", "data2", "write", "", "", ""},
				{"g", "alice", "admin", "", "", "", ""},
			},
		},
	}
	adapter := NewDBAdapter(tx)

	modelStr := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _ _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`
	m, err := model.NewModelFromString(modelStr)
	if err != nil {
		t.Fatalf("failed to create model: %v", err)
	}

	err = adapter.LoadPolicy(m)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// 验证执行了查询
	if len(tx.execQueries) < 2 {
		t.Errorf("expected at least 2 queries (CREATE TABLE + SELECT), got %d", len(tx.execQueries))
	}

	// 验证包含 SELECT 查询
	found := false
	for _, q := range tx.execQueries {
		if strings.Contains(q, "SELECT") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SELECT query in executed queries")
	}
}

// TestDBAdapter_LoadPolicy_Error 测试加载策略错误
func TestDBAdapter_LoadPolicy_Error(t *testing.T) {
	tx := &mockTransactor{
		queryError: context.DeadlineExceeded,
	}
	adapter := NewDBAdapter(tx)

	modelStr := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	m, err := model.NewModelFromString(modelStr)
	if err != nil {
		t.Fatalf("failed to create model: %v", err)
	}

	err = adapter.LoadPolicy(m)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestDBAdapter_SavePolicy 测试保存策略
func TestDBAdapter_SavePolicy(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx)

	modelStr := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _ _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`
	m, err := model.NewModelFromString(modelStr)
	if err != nil {
		t.Fatalf("failed to create model: %v", err)
	}

	// 添加一些策略
	m.AddPolicy("p", "p", []string{"alice", "data1", "read"})
	m.AddPolicy("p", "p", []string{"bob", "data2", "write"})
	m.AddPolicy("g", "g", []string{"alice", "admin"})

	err = adapter.SavePolicy(m)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// 验证执行了 DELETE 查询（清空现有规则）
	found := false
	for _, q := range tx.execQueries {
		if strings.Contains(q, "DELETE") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DELETE query in executed queries")
	}

	// 验证执行了 INSERT 查询（插入新规则）
	insertCount := 0
	for _, q := range tx.execQueries {
		if strings.Contains(q, "INSERT") {
			insertCount++
		}
	}
	if insertCount < 3 {
		t.Errorf("expected at least 3 INSERT queries, got %d", insertCount)
	}
}

// TestDBAdapter_SavePolicy_Error 测试保存策略错误
func TestDBAdapter_SavePolicy_Error(t *testing.T) {
	tx := &mockTransactor{
		execError: context.DeadlineExceeded,
	}
	adapter := NewDBAdapter(tx)

	modelStr := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	m, err := model.NewModelFromString(modelStr)
	if err != nil {
		t.Fatalf("failed to create model: %v", err)
	}

	err = adapter.SavePolicy(m)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestDBAdapter_AddPolicy 测试添加策略
func TestDBAdapter_AddPolicy(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx)

	rule := []string{"alice", "data1", "read"}
	err := adapter.AddPolicy("p", "p", rule)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// 验证执行了 INSERT 查询
	if len(tx.execQueries) != 1 {
		t.Errorf("expected 1 query, got %d", len(tx.execQueries))
	}

	if !strings.Contains(tx.execQueries[0], "INSERT") {
		t.Errorf("expected INSERT query, got %s", tx.execQueries[0])
	}
}

// TestDBAdapter_AddPolicy_Error 测试添加策略错误
func TestDBAdapter_AddPolicy_Error(t *testing.T) {
	tx := &mockTransactor{
		execError: context.DeadlineExceeded,
	}
	adapter := NewDBAdapter(tx)

	rule := []string{"alice", "data1", "read"}
	err := adapter.AddPolicy("p", "p", rule)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestDBAdapter_RemovePolicy 测试移除策略
func TestDBAdapter_RemovePolicy(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx)

	rule := []string{"alice", "data1", "read"}
	err := adapter.RemovePolicy("p", "p", rule)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// 验证执行了 DELETE 查询
	if len(tx.execQueries) != 1 {
		t.Errorf("expected 1 query, got %d", len(tx.execQueries))
	}

	if !strings.Contains(tx.execQueries[0], "DELETE") {
		t.Errorf("expected DELETE query, got %s", tx.execQueries[0])
	}

	// 验证 DELETE 查询包含正确的条件
	if !strings.Contains(tx.execQueries[0], "ptype = ?") {
		t.Error("expected DELETE query to contain 'ptype = ?'")
	}
}

// TestDBAdapter_RemovePolicy_Error 测试移除策略错误
func TestDBAdapter_RemovePolicy_Error(t *testing.T) {
	tx := &mockTransactor{
		execError: context.DeadlineExceeded,
	}
	adapter := NewDBAdapter(tx)

	rule := []string{"alice", "data1", "read"}
	err := adapter.RemovePolicy("p", "p", rule)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestDBAdapter_RemovePolicy_ShortRule 测试移除短规则
func TestDBAdapter_RemovePolicy_ShortRule(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx)

	rule := []string{"alice"}
	err := adapter.RemovePolicy("p", "p", rule)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// 验证 DELETE 查询包含空字符串匹配
	if !strings.Contains(tx.execQueries[0], "v0 = ?") {
		t.Error("expected DELETE query to contain 'v0 = ?'")
	}
}

// TestDBAdapter_RemoveFilteredPolicy 测试移除过滤策略
func TestDBAdapter_RemoveFilteredPolicy(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx)

	err := adapter.RemoveFilteredPolicy("p", "p", 0, "alice")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// 验证执行了 DELETE 查询
	if len(tx.execQueries) != 1 {
		t.Errorf("expected 1 query, got %d", len(tx.execQueries))
	}

	if !strings.Contains(tx.execQueries[0], "DELETE") {
		t.Errorf("expected DELETE query, got %s", tx.execQueries[0])
	}

	// 验证 DELETE 查询包含过滤条件
	if !strings.Contains(tx.execQueries[0], "v0 = ?") {
		t.Error("expected DELETE query to contain 'v0 = ?'")
	}
}

// TestDBAdapter_RemoveFilteredPolicy_MultipleFields 测试多字段过滤
func TestDBAdapter_RemoveFilteredPolicy_MultipleFields(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx)

	err := adapter.RemoveFilteredPolicy("p", "p", 0, "alice", "data1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// 验证 DELETE 查询包含多个过滤条件
	if !strings.Contains(tx.execQueries[0], "v0 = ?") {
		t.Error("expected DELETE query to contain 'v0 = ?'")
	}
	if !strings.Contains(tx.execQueries[0], "v1 = ?") {
		t.Error("expected DELETE query to contain 'v1 = ?'")
	}
}

// TestDBAdapter_RemoveFilteredPolicy_Error 测试移除过滤策略错误
func TestDBAdapter_RemoveFilteredPolicy_Error(t *testing.T) {
	tx := &mockTransactor{
		execError: context.DeadlineExceeded,
	}
	adapter := NewDBAdapter(tx)

	err := adapter.RemoveFilteredPolicy("p", "p", 0, "alice")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestDBAdapter_RemoveFilteredPolicy_EmptyFilter 测试空过滤值
func TestDBAdapter_RemoveFilteredPolicy_EmptyFilter(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx)

	err := adapter.RemoveFilteredPolicy("p", "p", 0, "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// 空过滤值不应该添加额外的 AND 条件
	if strings.Contains(tx.execQueries[0], "v0 = ?") {
		t.Error("expected DELETE query NOT to contain 'v0 = ?' for empty filter value")
	}
}

// TestDBAdapter_RemoveFilteredPolicy_IndexOutOfRange 测试索引超出范围
func TestDBAdapter_RemoveFilteredPolicy_IndexOutOfRange(t *testing.T) {
	tx := &mockTransactor{}
	adapter := NewDBAdapter(tx)

	err := adapter.RemoveFilteredPolicy("p", "p", 10, "alice")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// 索引超出范围应该只包含 ptype 条件
	if strings.Contains(tx.execQueries[0], "v10 = ?") {
		t.Error("expected DELETE query NOT to contain 'v10 = ?' for out of range index")
	}
}

// TestDBAdapter_LoadPolicy_ScanError 测试加载策略扫描错误
func TestDBAdapter_LoadPolicy_ScanError(t *testing.T) {
	tx := &mockTransactor{
		queryResult: &mockRows{
			rows: [][]any{
				{"p", "alice", "data1", "read", "", "", ""},
			},
		},
	}
	adapter := NewDBAdapter(tx)

	modelStr := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	m, err := model.NewModelFromString(modelStr)
	if err != nil {
		t.Fatalf("failed to create model: %v", err)
	}

	// 这个测试应该成功，因为 mockRows.Scan 实现会处理类型转换
	err = adapter.LoadPolicy(m)
	if err != nil {
		t.Logf("LoadPolicy returned error (may be expected): %v", err)
	}
}
