package permission

import (
	"gorm.io/gorm"
	"slices"
	"strings"
)

type Permission struct {
	db    *gorm.DB
	rules []SystemPermission
}

var permission = new(Permission)

func New(db *gorm.DB) *Permission {
	if permission.db == nil || len(permission.rules) == 0 {
		permission.db = db
	}
	return permission
}

func (p *Permission) LoadRules() error {
	var rules []SystemPermission
	if err := p.db.Find(&rules).Error; err != nil {
		return err
	}

	p.rules = rules
	return nil
}

func (p *Permission) WithSign(sign string) []SystemPermission {
	var withSign []SystemPermission
	for _, rule := range p.rules {
		if rule.Sign == sign {
			withSign = append(withSign, rule)
		}
	}
	return withSign
}

func (p *Permission) WithRoute(route string) []SystemPermission {
	var withRoute []SystemPermission
	for _, rule := range p.rules {
		if strings.Contains(rule.Route, ParameterTpl) {
			rs := strings.Split(rule.Route, "/")
			inRs := strings.Split(route, "/")
			for i, s := range rs {
				if s == ParameterTpl {
					rs[i] = inRs[i]
				}
			}
			rule.Route = strings.Join(rs, "/")
		}

		if rule.Route == route {
			withRoute = append(withRoute, rule)
		}
	}
	return withRoute
}

func (p *Permission) WithRole(role string) []SystemPermission {
	var withRole []SystemPermission
	for _, rule := range p.rules {
		if rule.Role == role {
			withRole = append(withRole, rule)
		}
	}
	return withRole
}

func (p *Permission) Update(role string, rules []SystemPermission) error {
	var withRoleMap = make(map[string]SystemPermission)
	for _, rule := range p.rules {
		if rule.Role == role {
			withRoleMap[rule.Route+rule.Sign+rule.Method] = rule
		}
	}

	var inserts []SystemPermission
	for _, rule := range rules {
		if _, ok := withRoleMap[rule.Route]; !ok {
			inserts = append(inserts, rule)
		} else {
			delete(withRoleMap, rule.Route)
		}
	}

	var deletes []int64
	if len(withRoleMap) > 0 {
		for _, rule := range withRoleMap {
			deletes = append(deletes, rule.Id)

			slices.DeleteFunc(p.rules, func(systemPermission SystemPermission) bool {
				return systemPermission.Id == rule.Id
			})
		}
	}

	err := p.db.Transaction(func(tx *gorm.DB) error {
		if len(deletes) > 0 {
			if err := tx.Delete(&SystemPermission{}, "id in ?", deletes).Error; err != nil {
				return err
			}
		}

		return tx.Create(&inserts).Error
	})
	return err
}

func (p *Permission) HasPermission(role, route, method string) bool {
	for _, rule := range p.rules {
		if rule.Role == role && rule.Route == route && rule.Method == method {
			return true
		}
	}
	return false
}

func (p *Permission) HasPermissionWithSign(role, sign, method string) bool {
	for _, rule := range p.rules {
		if rule.Role == role && rule.Sign == sign && rule.Method == method {
			return true
		}
	}
	return false
}
