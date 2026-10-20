package controller

import (
	"errors"
	"unicode/utf8"
)

// Reserve enough room for every old checkpoint plus every desired write before
// starting a batch. A later write/cleanup failure must never force us to forget
// an accepted provider identity or credential projection to fit the CRD.
const statusInventoryLimit = 128

var errStatusInventoryCapacity = errors.New("status checkpoint capacity exhausted; complete retained inventory cleanup before adding a new batch")

func checkStatusInventoryCapacity(previous, desired int) error {
	if previous < 0 || desired < 0 || previous > statusInventoryLimit || desired > statusInventoryLimit-previous {
		return errStatusInventoryCapacity
	}
	return nil
}

func boundedOperationStepMessage(message string) string {
	if utf8.RuneCountInString(message) > 4096 {
		return "operation diagnostic exceeds the public status size budget"
	}
	return message
}
