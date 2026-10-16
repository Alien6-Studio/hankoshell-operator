package contract

import "time"

type Value struct {
	Deadline time.Time `json:"deadline"`
}

func (value *Value) Ready() bool { return !value.Deadline.IsZero() }

// Export capture must compile packages without running their initializers.
func init() { panic("API capture must not execute package initializers") }
