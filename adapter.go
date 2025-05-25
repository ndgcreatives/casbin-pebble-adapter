package pebbleadapter

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/goccy/go-json"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/cockroachdb/pebble/v2"
)

var _ persist.Adapter = (*adapter)(nil)
var _ persist.UpdatableAdapter = (*adapter)(nil)

// var _ persist.FilteredAdapter = (*adapter)(nil)

// CasbinRule represents a Casbin rule line.
type CasbinRule struct {
	Key   string `json:"key"`
	PType string `json:"p_type"`
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

func (cr *CasbinRule) Rule() []string {
	return strings.Split(cr.Key, "::")[1:]
}

type adapter struct {
	db     *pebble.DB
	prefix []byte
}

// NewAdapter creates a new adapter. It assumes that the Pebble DB is already open. A prefix is used if given and
// represents the Pebble prefix to save the under.
func NewAdapter(db *pebble.DB, prefix string) (persist.BatchAdapter, error) {
	if prefix == "" {
		return nil, errors.New("must provide a prefix")
	}

	adapter := &adapter{
		db:     db,
		prefix: []byte(prefix),
	}

	return adapter, nil
}

func (a *adapter) IsFiltered() bool {
	return false
}

// LoadPolicy performs a scan on the bucket and individually loads every line into the Casbin model.
// Not particularity efficient but should only be required on when you application starts up as this adapter can
// leverage auto-save functionality.
func (a *adapter) LoadPolicy(model model.Model) error {
	iter, err := a.db.NewIter(&pebble.IterOptions{
		LowerBound: a.prefix,
		UpperBound: append(a.prefix, 0xff),
	})
	if err != nil {
		return fmt.Errorf("creating db iterator: %w", err)
	}
	defer iter.Close()
	for iter.First(); iter.Valid(); iter.Next() {
		var line CasbinRule
		if err := json.Unmarshal(iter.Value(), &line); err != nil {
			return err
		}
		loadPolicy(line, model)
	}
	return nil
}

// SavePolicy is not supported for this adapter. Auto-save should be used.
func (a *adapter) SavePolicy(model model.Model) error {
	return errors.New("not supported: must use auto-save with this adapter")
}

// AddPolicy inserts or updates a rule.
func (a *adapter) AddPolicy(_ string, ptype string, rule []string) error {
	line := convertRule(ptype, rule)
	bts, err := json.Marshal(line)
	if err != nil {
		return err
	}
	return a.db.Set(a.withPrefix(line.Key), bts, pebble.Sync)
}

// AddPolicies inserts or updates multiple rules by iterating over each one and inserting it into the bucket.
func (a *adapter) AddPolicies(_ string, ptype string, rules [][]string) error {
	batch := a.db.NewBatch()
	for _, r := range rules {
		line := convertRule(ptype, r)
		bts, err := json.Marshal(line)
		if err != nil {
			return err
		}
		if err := batch.Set(a.withPrefix(line.Key), bts, nil); err != nil {
			return err
		}
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return err
	}
	return nil
}

// RemoveFilteredPolicy has an implementation that is slightly limited in that we can only find and remove elements
// using a policy line prefix.
//
// For example, if you have the following policy:
//
//	p, subject-a, action-a, get
//	p, subject-a, action-a, write
//	p, subject-b, action-a, get
//	p, subject-b, action-a, write
//
// The following would remove all subject-a rules:
//
//	enforcer.RemoveFilteredPolicy(0, "subject-a")
//
// The following would remove all subject-a rules that contain action-a:
//
//	enforcer.RemoveFilteredPolicy(0, "subject-a", "action-a")
//
// The following does not work and will return an error:
//
//	enforcer.RemoveFilteredPolicy(1, "action-a")
//
// This is because we use leverage Pebble's prefix scan to find an item.
// Once these keys are found we can iterate over and remove them.
// Each policy rule is stored as a row in Pebble: p::subject-a::action-a::get
func (a *adapter) RemoveFilteredPolicy(_ string, ptype string, fieldIndex int, fieldValues ...string) error {
	rule := CasbinRule{}

	rule.PType = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		rule.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		rule.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		rule.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		rule.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		rule.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		rule.V5 = fieldValues[5-fieldIndex]
	}

	filterPrefix := a.buildFilter(rule)
	iter, err := a.db.NewIter(&pebble.IterOptions{
		LowerBound: a.prefix,
		UpperBound: append(a.prefix, 0xff),
		SkipPoint: func(userKey []byte) bool {
			userKey = bytes.TrimPrefix(userKey, a.prefix)
			if !bytes.HasPrefix(userKey, []byte(rule.PType)) {
				return false
			}
			for range fieldIndex + 1 {
				i := bytes.Index(userKey, []byte("::"))
				if i < 0 {
					return false // no more fields to check
				}
				userKey = userKey[i+2:]
			}
			return !bytes.Contains(userKey, []byte(filterPrefix))
		},
	})
	if err != nil {
		return fmt.Errorf("creating db iterator: %w", err)
	}
	defer iter.Close()
	batch := a.db.NewBatch()
	for iter.First(); iter.Valid(); iter.Next() {
		if err := batch.Delete(bytes.Clone(iter.Key()), nil); err != nil {
			return err
		}
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return err
	}
	return nil
}

func (a *adapter) buildFilter(rule CasbinRule) string {
	filter := "" // rule.PType
	if rule.V0 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V0)
	}
	if rule.V1 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V1)
	}
	if rule.V2 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V2)
	}
	if rule.V3 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V3)
	}
	if rule.V4 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V4)
	}
	if rule.V5 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V5)
	}
	return strings.Trim(filter, ":")
}

func (a *adapter) withPrefix(key string) []byte {
	return fmt.Append(a.prefix, key)
}

// RemovePolicy removes a policy line that matches key.
func (a *adapter) RemovePolicy(_ string, ptype string, line []string) error {
	rule := convertRule(ptype, line)
	return a.db.Delete(a.withPrefix(rule.Key), pebble.Sync)
}

// RemovePolicies removes multiple policies.
func (a *adapter) RemovePolicies(_ string, ptype string, rules [][]string) error {
	batch := a.db.NewBatch()
	for _, r := range rules {
		rule := convertRule(ptype, r)
		if err := batch.Delete(a.withPrefix(rule.Key), nil); err != nil {
			return err
		}
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return err
	}
	return nil
}

func (a *adapter) UpdatePolicy(_ string, ptype string, oldRule, newRule []string) error {
	old := convertRule(ptype, oldRule)
	new := convertRule(ptype, newRule)
	batch := a.db.NewBatch()
	if err := batch.Delete(a.withPrefix(old.Key), nil); err != nil {
		return err
	}
	bts, err := json.Marshal(new)
	if err != nil {
		return err
	}

	if err := batch.Set(a.withPrefix(new.Key), bts, nil); err != nil {
		return err
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return err
	}

	return nil
}

func (a *adapter) UpdatePolicies(_ string, ptype string, oldRules, newRules [][]string) error {
	batch := a.db.NewBatch()
	for _, r := range oldRules {
		old := convertRule(ptype, r)

		if err := batch.Delete(a.withPrefix(old.Key), nil); err != nil {
			return err
		}
	}

	for _, r := range newRules {
		new := convertRule(ptype, r)

		bts, err := json.Marshal(new)
		if err != nil {
			return err
		}

		if err := batch.Set(a.withPrefix(new.Key), bts, nil); err != nil {
			return err
		}
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return err
	}
	return nil
}

func (a *adapter) UpdateFilteredPolicies(_ string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	rule := CasbinRule{}

	rule.PType = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		rule.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		rule.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		rule.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		rule.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		rule.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		rule.V5 = fieldValues[5-fieldIndex]
	}

	filterPrefix := a.buildFilter(rule)
	matched := []CasbinRule{}
	iter, err := a.db.NewIter(&pebble.IterOptions{
		LowerBound: a.prefix,
		UpperBound: append(a.prefix, 0xff),
		SkipPoint: func(userKey []byte) bool {
			userKey = bytes.TrimPrefix(userKey, a.prefix)
			if !bytes.HasPrefix(userKey, []byte(rule.PType)) {
				return false
			}
			for range fieldIndex + 1 {
				i := bytes.Index(userKey, []byte("::"))
				if i < 0 {
					return false // no more fields to check
				}
				userKey = userKey[i+2:]
			}
			return !bytes.Contains(userKey, []byte(filterPrefix))
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating db iterator: %w", err)
	}
	defer iter.Close()
	batch := a.db.NewBatch()
	oldRules := make([][]string, 0, len(matched))
	for iter.First(); iter.Valid(); iter.Next() {
		r := CasbinRule{}
		if err := json.Unmarshal(iter.Value(), &r); err != nil {
			return nil, err
		}
		oldRules = append(oldRules, r.Rule())
		if err := batch.Delete(a.withPrefix(r.Key), nil); err != nil {
			return nil, err
		}
	}
	for _, r := range newPolicies {
		new := convertRule(ptype, r)

		bts, err := json.Marshal(new)
		if err != nil {
			return nil, err
		}

		if err := batch.Set(a.withPrefix(new.Key), bts, nil); err != nil {
			return nil, err
		}
	}

	return oldRules, nil
}

func loadPolicy(rule CasbinRule, model model.Model) {
	lineText := rule.PType

	if rule.V0 != "" {
		lineText += ", " + rule.V0
	}
	if rule.V1 != "" {
		lineText += ", " + rule.V1
	}
	if rule.V2 != "" {
		lineText += ", " + rule.V2
	}
	if rule.V3 != "" {
		lineText += ", " + rule.V3
	}
	if rule.V4 != "" {
		lineText += ", " + rule.V4
	}
	if rule.V5 != "" {
		lineText += ", " + rule.V5
	}

	persist.LoadPolicyLine(lineText, model)
}

func convertRule(ptype string, line []string) CasbinRule {
	rule := CasbinRule{PType: ptype}

	keySlice := []string{ptype}

	l := len(line)
	if l > 0 {
		rule.V0 = line[0]
		keySlice = append(keySlice, line[0])
	}
	if l > 1 {
		rule.V1 = line[1]
		keySlice = append(keySlice, line[1])
	}
	if l > 2 {
		rule.V2 = line[2]
		keySlice = append(keySlice, line[2])
	}
	if l > 3 {
		rule.V3 = line[3]
		keySlice = append(keySlice, line[3])
	}
	if l > 4 {
		rule.V4 = line[4]
		keySlice = append(keySlice, line[4])
	}
	if l > 5 {
		rule.V5 = line[5]
		keySlice = append(keySlice, line[5])
	}

	rule.Key = strings.Join(keySlice, "::")

	return rule
}
