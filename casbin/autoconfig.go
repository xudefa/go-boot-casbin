// Package casbin 提供 Casbin 权限管理的自动配置。
//
// 当 casbin.enabled=true 时自动启用，从 Environment 中读取 casbin.model、casbin.adapter 配置项，
// 创建并注册 Casbin Enforcer Bean 到 IoC 容器中（Bean ID: casbinEnforcer）。
package casbin

import (
	"errors"

	"github.com/xudefa/go-boot/boot"
	"github.com/xudefa/go-boot/condition"
	"github.com/xudefa/go-boot/constants"
	"github.com/xudefa/go-boot/core"
	"github.com/xudefa/go-boot/data"
)

// CasbinAutoConfiguration Casbin 权限管理的自动配置
//
// 从 Environment 中读取 casbin.model、casbin.adapter 配置项，
// 创建 Casbin Enforcer 实例并注册到 IoC 容器中。
// 启用条件：casbin.enabled=true
type CasbinAutoConfiguration struct{}

// init 注册 Casbin 自动配置，由 casbin.enabled=true 条件控制
func init() {
	boot.RegisterAutoConfig(&CasbinAutoConfiguration{},
		condition.OnProperty(constants.CasbinEnabled, constants.ConditionTrue),
	)
}

// Configure 执行自动配置逻辑，创建 Casbin Enforcer 并注册为 Bean
//
// 支持三种策略源：
//  1. 文件适配器（通过 casbin.model + casbin.adapter 配置）
//  2. 数据库适配器（通过 casbin.model + casbin.db-adapter=true 配置，自动从容器获取 data.Transactor）
//  3. 仅模型模式（仅 casbin.model，无持久化策略）
func (c *CasbinAutoConfiguration) Configure(ctx boot.ApplicationContext) error {
	env := ctx.Environment()

	// 读取配置
	modelPath := env.GetString(constants.CasbinModel, "")
	adapterPath := env.GetString(constants.CasbinAdapter, "")
	useDBAdapter := env.GetBool(constants.CasbinDBAdapter, false)

	if modelPath == "" {
		return nil
	}

	opts := []Option{WithModel(modelPath)}

	// 使用数据库适配器
	if useDBAdapter {
		txList, err := ctx.Container().GetAll((*data.Transactor)(nil))
		if err != nil || len(txList) == 0 {
			return errors.New("casbin: no data.Transactor found in container for db adapter, ensure a database module (e.g. gorm) is enabled")
		}
		tx, ok := txList[0].(data.Transactor)
		if !ok {
			return errors.New("casbin: invalid data.Transactor type in container")
		}
		tableName := env.GetString(constants.CasbinDBTable, constants.DefaultCasbinDBTable)
		opts = append(opts, WithDBAdapter(tx, tableName))
	} else if adapterPath != "" {
		// 使用文件适配器
		opts = append(opts, WithAdapter(adapterPath))
	}

	enforcer, err := NewEnforcer(opts...)
	if err != nil {
		return err
	}

	if err := ctx.Register(constants.CasbinEnforcerBeanID,
		core.Bean(enforcer),
		core.Singleton(),
	); err != nil {
		return err
	}

	return nil
}
