package authorization

// OrganizationError contains only a stable locally authored code. It never
// renders provider bodies, group inventory, credentials or membership data.
type OrganizationError struct{ Code string }

func (e OrganizationError) Error() string   { return "organizational authorization refused: " + e.Code }
func OrganizationFailure(code string) error { return OrganizationError{Code: code} }
