package standard

import (
	"context"
	"fmt"
	"strings"

	"github.com/golangid/candi/candihelper"
	"github.com/golangid/candi/config/env"
	"github.com/golangid/candi/tracer"
	"gorm.io/gorm"
)

const (
	spanContext       = "spanContext"
	parentSpanGormKey = "opentracingParentSpan"
	spanGormKey       = "opentracingSpan"
)

// SetSpanToGorm sets span to gorm settings, returns cloned DB
func SetSpanToGorm(ctx context.Context, db *gorm.DB) *gorm.DB {
	if ctx == nil {
		return db
	}
	return db.Set(spanContext, ctx)
}

// AddGormCallbacks adds callbacks for tracing, you should call SetSpanToGorm to make them work
func AddGormCallbacks(db *gorm.DB) {
	callbacks := newCallbacks()
	registerCallbacks(db, "create", callbacks)
	registerCallbacks(db, "query", callbacks)
	registerCallbacks(db, "update", callbacks)
	registerCallbacks(db, "delete", callbacks)
	registerCallbacks(db, "row", callbacks)
	registerCallbacks(db, "raw", callbacks)
}

type callbacks struct{}

func newCallbacks() *callbacks {
	return &callbacks{}
}

func (c *callbacks) beforeCreate(db *gorm.DB)   { c.before(db) }
func (c *callbacks) afterCreate(db *gorm.DB)    { c.after(db, "INSERT") }
func (c *callbacks) beforeQuery(db *gorm.DB)    { c.before(db) }
func (c *callbacks) afterQuery(db *gorm.DB)     { c.after(db, "SELECT") }
func (c *callbacks) beforeUpdate(db *gorm.DB)   { c.before(db) }
func (c *callbacks) afterUpdate(db *gorm.DB)    { c.after(db, "UPDATE") }
func (c *callbacks) beforeDelete(db *gorm.DB)   { c.before(db) }
func (c *callbacks) afterDelete(db *gorm.DB)    { c.after(db, "DELETE") }
func (c *callbacks) beforeRowQuery(db *gorm.DB) { c.before(db) }
func (c *callbacks) afterRowQuery(db *gorm.DB)  { c.after(db, "") }
func (c *callbacks) beforeRawQuery(db *gorm.DB) { c.before(db) }
func (c *callbacks) afterRawQuery(db *gorm.DB)  { c.after(db, "") }
func (c *callbacks) before(db *gorm.DB) {
	spanCtx, ok := db.Get(spanContext)
	if !ok {
		return
	}
	ctx, ok := spanCtx.(context.Context)
	if !ok {
		return
	}
	trace := tracer.StartTrace(ctx, "gorm.sql")
	db.Set(spanGormKey, trace)
}

func (c *callbacks) after(db *gorm.DB, operation string) {
	val, ok := db.Get(spanGormKey)
	if !ok {
		return
	}
	trace := val.(tracer.Tracer)
	defer trace.Finish()
	if operation == "" {
		operation = strings.ToUpper(strings.Split(db.Statement.SQL.String(), " ")[0])
	}

	trace.Log("db.query", db.Dialector.Explain(db.Statement.SQL.String(), db.Statement.Vars...))
	trace.Log("db.rows_affected", db.RowsAffected)
	trace.SetTag("db.table", db.Statement.Table)
	trace.SetTag("db.method", operation)
	if operation == "SELECT" {
		trace.SetTag("db.connection", candihelper.MaskingPasswordURL(env.BaseEnv().DbSQLReadDSN))
	} else {
		trace.SetTag("db.connection", candihelper.MaskingPasswordURL(env.BaseEnv().DbSQLWriteDSN))
	}
	if db.Statement.Error != nil {
		if db.Statement.Error == gorm.ErrRecordNotFound {
			trace.Log("message", db.Statement.Error.Error())
			return
		}
		trace.SetError(db.Statement.Error)
		logParam := LogParam{
			Error:         db.Statement.Error,
			OperationName: operation,
			Message:       fmt.Sprintf("query : %s | variables : %v", db.Statement.SQL.String(), db.Statement.Vars),
			Scope:         fmt.Sprintf("table : %s | operation : %s", db.Statement.Table, operation),
		}
		if !strings.Contains(db.Statement.Error.Error(), "context") && !strings.Contains(db.Statement.Error.Error(), "duplicate") {
			logParam.IsSentry = true
		}
		trace.SetError(db.Statement.Error)
		Log(trace.Context(), logParam)
	}
}

func registerCallbacks(db *gorm.DB, name string, c *callbacks) {
	beforeName := fmt.Sprintf("tracing:before_%v", name)
	afterName := fmt.Sprintf("tracing:after_%v", name)
	gormCallbackName := fmt.Sprintf("gorm:%v", name)
	// gorm does some magic, if you pass CallbackProcessor here - nothing works
	switch name {
	case "create":
		db.Callback().Create().Before(gormCallbackName).Register(beforeName, c.beforeCreate)
		db.Callback().Create().After(gormCallbackName).Register(afterName, c.afterCreate)
	case "query":
		db.Callback().Query().Before(gormCallbackName).Register(beforeName, c.beforeQuery)
		db.Callback().Query().After(gormCallbackName).Register(afterName, c.afterQuery)
	case "update":
		db.Callback().Update().Before(gormCallbackName).Register(beforeName, c.beforeUpdate)
		db.Callback().Update().After(gormCallbackName).Register(afterName, c.afterUpdate)
	case "delete":
		db.Callback().Delete().Before(gormCallbackName).Register(beforeName, c.beforeDelete)
		db.Callback().Delete().After(gormCallbackName).Register(afterName, c.afterDelete)
	case "row":
		db.Callback().Row().Before(gormCallbackName).Register(beforeName, c.beforeRowQuery)
		db.Callback().Row().After(gormCallbackName).Register(afterName, c.afterRowQuery)
	case "raw":
		db.Callback().Raw().Before(gormCallbackName).Register(beforeName, c.beforeRawQuery)
		db.Callback().Raw().After(gormCallbackName).Register(afterName, c.afterRawQuery)
	}
}
