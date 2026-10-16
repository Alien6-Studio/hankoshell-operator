package controller

import (
	"errors"
	"os"
	"strconv"

	runtimecontroller "sigs.k8s.io/controller-runtime/pkg/controller"
)

// Only the four IAM controllers with request-local reconciliation state opt in.
// Infrastructure, transactions, imports, Fleet and shared trust stay serial.
// Controller-runtime continues to serialize each individual workqueue key.
func iamControllerOptions() (runtimecontroller.Options, error) {
	workers := 1
	if value, present := os.LookupEnv("HANKO_IAM_MAX_CONCURRENT_RECONCILES"); present {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 8 || strconv.Itoa(parsed) != value {
			return runtimecontroller.Options{}, errors.New("HANKO_IAM_MAX_CONCURRENT_RECONCILES must be an integer from 1 to 8")
		}
		workers = parsed
	}
	return runtimecontroller.Options{MaxConcurrentReconciles: workers}, nil
}
