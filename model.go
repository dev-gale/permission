package permission

type SystemPermission struct {
	Id     int64  `gorm:"primary_key"`
	Route  string `gorm:"column:route"`  // 权限路由
	Sign   string `gorm:"column:sign"`   // 权限标识
	Role   string `gorm:"column:role"`   // 权限角色名
	Method string `gorm:"column:method"` // Request Method GET|POST|PUT|DELETE ...
}

func (SystemPermission) TableName() string {
	return "system_permission"
}
