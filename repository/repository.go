package repository

import (
	"Firewall/models"
	"sync"
)

type RuleRepository interface {
    AddRule(rule models.Rule) error
    RemoveRule(id string) error
    GetRule(id string) (*models.Rule, error)
    GetAllRules() ([]models.Rule, error)
    GetRulesByPort(port int) ([]models.Rule, error)
    ClearRules() error
}

type InMemoryRuleRepository struct {
    rules map[string]models.Rule
    mu    sync.RWMutex
}

func NewInMemoryRuleRepository() *InMemoryRuleRepository {
    return &InMemoryRuleRepository{
        rules: make(map[string]models.Rule),
    }
}

func (r *InMemoryRuleRepository) AddRule(rule models.Rule) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.rules[rule.ID] = rule
    return nil
}

func (r *InMemoryRuleRepository) RemoveRule(id string) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    delete(r.rules, id)
    return nil
}

func (r *InMemoryRuleRepository) GetRule(id string) (*models.Rule, error) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    rule, exists := r.rules[id]
    if !exists {
        return nil, nil
    }
    return &rule, nil
}

func (r *InMemoryRuleRepository) GetAllRules() ([]models.Rule, error) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    rules := make([]models.Rule, 0, len(r.rules))
    for _, rule := range r.rules {
        rules = append(rules, rule)
    }
    return rules, nil
}

func (r *InMemoryRuleRepository) GetRulesByPort(port int) ([]models.Rule, error) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    var result []models.Rule
    for _, rule := range r.rules {
        if rule.Port == port {
            result = append(result, rule)
        }
    }
    return result, nil
}

func (r *InMemoryRuleRepository) ClearRules() error {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.rules = make(map[string]models.Rule)
    return nil
}