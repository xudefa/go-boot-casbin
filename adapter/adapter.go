// Package adapter 提供基于数据库的 Casbin 策略适配器。
//
// 该包实现了 persist.Adapter 接口，通过 data.Transactor 操作数据库，
// 不依赖特定数据库类型（MySQL、PostgreSQL、SQLite 等均可）。
package adapter

import (
	"context"
	"fmt"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/xudefa/go-boot/data"
)

const defaultCasbinTableName = "casbin_rule"

// Adapter 是 Casbin 策略适配器接口。
type Adapter interface {
	persist.Adapter
}

// DBAdapter 是基于数据库的 Casbin 策略适配器。
//
// 通过 data.Transactor 接口操作数据库，不依赖特定数据库类型。
// 适配器会自动创建策略表用于存储规则（默认表名 casbin_rule）。
//
// 用法:
//
//	adapter := adapter.NewDBAdapter(transactor)
//	e, _ := casbin.NewEnforcer(
//	    casbin.WithModel("model.conf"),
//	    casbin.WithDBAdapter(transactor),
//	)
type DBAdapter struct {
	tx        data.Transactor
	tableName string
}

// NewDBAdapter 创建数据库策略适配器。
//
// 参数:
//   - tx: 数据库事务操作器（由具体集成模块如 gorm、xorm 提供）
//   - tableName: 可选，策略表名（默认 "casbin_rule"）
func NewDBAdapter(tx data.Transactor, tableName ...string) *DBAdapter {
	name := defaultCasbinTableName
	if len(tableName) > 0 && tableName[0] != "" {
		name = tableName[0]
	}
	return &DBAdapter{tx: tx, tableName: name}
}

func (a *DBAdapter) createTable(ctx context.Context) error {
	q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		id    BIGINT AUTO_INCREMENT PRIMARY KEY,
		ptype VARCHAR(100) NOT NULL DEFAULT '',
		v0    VARCHAR(255) NOT NULL DEFAULT '',
		v1    VARCHAR(255) NOT NULL DEFAULT '',
		v2    VARCHAR(255) NOT NULL DEFAULT '',
		v3    VARCHAR(255) NOT NULL DEFAULT '',
		v4    VARCHAR(255) NOT NULL DEFAULT '',
		v5    VARCHAR(255) NOT NULL DEFAULT ''
	)`, a.tableName)
	_, err := a.tx.Exec(ctx, q)
	return err
}

// casbinRule 表示数据库中的一条策略规则行。
//
// ptype 存储规则类型（p 或 g），v0~v5 存储策略参数。
// 最多支持 6 个参数，对应 Casbin 策略模型的最大列数。
type casbinRule struct {
	ptype string
	v0    string
	v1    string
	v2    string
	v3    string
	v4    string
	v5    string
}

func loadPolicyLine(r *casbinRule, m model.Model) {
	s := r.ptype
	if r.v0 != "" {
		s += ", " + r.v0
	}
	if r.v1 != "" {
		s += ", " + r.v1
	}
	if r.v2 != "" {
		s += ", " + r.v2
	}
	if r.v3 != "" {
		s += ", " + r.v3
	}
	if r.v4 != "" {
		s += ", " + r.v4
	}
	if r.v5 != "" {
		s += ", " + r.v5
	}
	persist.LoadPolicyLine(s, m)
}

// LoadPolicy 从数据库加载所有策略规则到模型。
//
// 加载流程：
//  1. 确保策略表已创建
//  2. 查询所有规则
//  3. 逐行通过 persist.LoadPolicyLine 加载到模型
func (a *DBAdapter) LoadPolicy(m model.Model) error {
	ctx := context.Background()
	if err := a.createTable(ctx); err != nil {
		return err
	}
	q := fmt.Sprintf("SELECT ptype, v0, v1, v2, v3, v4, v5 FROM %s", a.tableName)
	rows, err := a.tx.Query(ctx, q)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			fmt.Printf("[go-boot] failed to close rows: %v\n", cerr)
		}
	}()
	for rows.Next() {
		var r casbinRule
		if err := rows.Scan(&r.ptype, &r.v0, &r.v1, &r.v2, &r.v3, &r.v4, &r.v5); err != nil {
			return err
		}
		loadPolicyLine(&r, m)
	}
	return rows.Err()
}

// SavePolicy 保存模型中的所有策略规则到数据库。
//
// 保存流程：
//  1. 确保策略表已创建
//  2. 清空现有规则
//  3. 逐条插入 p 和 g 类型的规则
func (a *DBAdapter) SavePolicy(m model.Model) error {
	ctx := context.Background()
	if err := a.createTable(ctx); err != nil {
		return err
	}
	if _, err := a.tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s", a.tableName)); err != nil {
		return err
	}
	for ptype, ast := range m["p"] {
		for _, rule := range ast.Policy {
			if err := a.saveRule(ctx, ptype, rule); err != nil {
				return err
			}
		}
	}
	for ptype, ast := range m["g"] {
		for _, rule := range ast.Policy {
			if err := a.saveRule(ctx, ptype, rule); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *DBAdapter) saveRule(ctx context.Context, ptype string, rule []string) error {
	r := casbinRule{ptype: ptype}
	for i, v := range rule {
		switch i {
		case 0:
			r.v0 = v
		case 1:
			r.v1 = v
		case 2:
			r.v2 = v
		case 3:
			r.v3 = v
		case 4:
			r.v4 = v
		case 5:
			r.v5 = v
		}
	}
	return a.insertRule(ctx, r)
}

// AddPolicy 添加一条策略规则到数据库。
//
// 参数:
//   - sec: 策略节（"p" 或 "g"）
//   - ptype: 策略类型
//   - rule: 策略规则（最多6个字段）
func (a *DBAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.saveRule(context.Background(), ptype, rule)
}

// RemovePolicy 从数据库移除一条策略规则。
//
// 根据 ptype + 所有字段的精确匹配删除。
// 如果 rule 长度不足6，剩余字段按空字符串匹配。
func (a *DBAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	ctx := context.Background()
	q := fmt.Sprintf("DELETE FROM %s WHERE ptype = ? AND v0 = ? AND v1 = ? AND v2 = ? AND v3 = ? AND v4 = ? AND v5 = ?", a.tableName)
	args := make([]any, 7)
	args[0] = ptype
	for i := 0; i < 6; i++ {
		if i < len(rule) {
			args[i+1] = rule[i]
		} else {
			args[i+1] = ""
		}
	}
	_, err := a.tx.Exec(ctx, q, args...)
	return err
}

// RemoveFilteredPolicy 从数据库移除匹配过滤条件的策略规则。
func (a *DBAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	ctx := context.Background()
	q := fmt.Sprintf("DELETE FROM %s WHERE ptype = ?", a.tableName)
	args := []any{ptype}
	cols := []string{"v0", "v1", "v2", "v3", "v4", "v5"}
	for i, v := range fieldValues {
		idx := fieldIndex + i
		if idx >= len(cols) {
			break
		}
		if v != "" {
			q += fmt.Sprintf(" AND %s = ?", cols[idx])
			args = append(args, v)
		}
	}
	_, err := a.tx.Exec(ctx, q, args...)
	return err
}

func (a *DBAdapter) insertRule(ctx context.Context, r casbinRule) error {
	q := fmt.Sprintf("INSERT INTO %s (ptype, v0, v1, v2, v3, v4, v5) VALUES (?, ?, ?, ?, ?, ?, ?)", a.tableName)
	_, err := a.tx.Exec(ctx, q, r.ptype, r.v0, r.v1, r.v2, r.v3, r.v4, r.v5)
	return err
}

var _ Adapter = (*DBAdapter)(nil)
