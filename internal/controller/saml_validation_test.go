package controller_test

import (
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const samlProtocolNS = "urn:oasis:names:tc:SAML:2.0:protocol"
const samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
const samlDSigNS = "http://www.w3.org/2000/09/xmldsig#"
const samlRSA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
const samlSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
const samlExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"

type samlExpectation struct {
	Issuer, Audience, ACS, RequestID, NameIDFormat string
	Now                                            time.Time
}

// This synthetic SP validates only the qualified two-signature POST subset.
// It is test-only: the operator manages IdP configuration, not SP sessions.
// Cryptographic verification/canonicalization is delegated to pinned goxmldsig.
func validateSAMLResponse(data []byte, certificates []*x509.Certificate, want samlExpectation) (string, error) {
	if err := applications.CheckXMLBounds(data); err != nil {
		return "", err
	}
	doc := etree.NewDocument()
	doc.ReadSettings.ValidateInput = true
	doc.ReadSettings.MaxDepth = 32
	if err := doc.ReadFromBytes(data); err != nil {
		return "", fmt.Errorf("invalid bounded SAML XML")
	}
	root := doc.Root()
	if root == nil || root.Tag != "Response" || root.NamespaceURI() != samlProtocolNS {
		return "", fmt.Errorf("unexpected SAML root")
	}
	assertions, responses, signatures := 0, 0, 0
	var walk func(*etree.Element)
	walk = func(e *etree.Element) {
		if e.Tag == "Assertion" {
			assertions++
		}
		if e.Tag == "Response" {
			responses++
		}
		if e.Tag == "Signature" {
			signatures++
		}
		for _, child := range e.ChildElements() {
			walk(child)
		}
	}
	walk(root)
	if assertions != 1 || responses != 1 || signatures != 2 {
		return "", fmt.Errorf("ambiguous SAML signed structure")
	}
	assertion, err := singleSAMLChild(root, samlAssertionNS, "Assertion")
	if err != nil {
		return "", err
	}
	if root.SelectAttrValue("ID", "") == "" || assertion.SelectAttrValue("ID", "") == "" {
		return "", fmt.Errorf("missing signed ID")
	}
	if err := checkSAMLSignature(root); err != nil {
		return "", err
	}
	if err := checkSAMLSignature(assertion); err != nil {
		return "", err
	}
	verification := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certificates})
	verification.IdAttribute = "ID"
	verifiedResponse, err := verification.Validate(root)
	if err != nil {
		return "", fmt.Errorf("SAML response signature rejected")
	}
	signedAssertion, err := singleSAMLChild(verifiedResponse, samlAssertionNS, "Assertion")
	if err != nil {
		return "", err
	}
	verifiedAssertion, err := verification.Validate(signedAssertion)
	if err != nil {
		return "", fmt.Errorf("SAML assertion signature rejected")
	}
	// Consume only the elements returned by cryptographic verification.
	if verifiedResponse.SelectAttrValue("Destination", "") != want.ACS || verifiedResponse.SelectAttrValue("InResponseTo", "") != want.RequestID || verifiedResponse.SelectAttrValue("Version", "") != "2.0" {
		return "", fmt.Errorf("SAML response destination/request mismatch")
	}
	for _, element := range []*etree.Element{verifiedResponse, verifiedAssertion} {
		issuer, err := singleSAMLChild(element, samlAssertionNS, "Issuer")
		if err != nil || issuer.Text() != want.Issuer {
			return "", fmt.Errorf("SAML issuer mismatch")
		}
		issued, err := time.Parse(time.RFC3339Nano, element.SelectAttrValue("IssueInstant", ""))
		if err != nil || issued.After(want.Now.Add(time.Minute)) || issued.Before(want.Now.Add(-5*time.Minute)) {
			return "", fmt.Errorf("invalid SAML issue instant")
		}
	}
	status, err := singleSAMLChild(verifiedResponse, samlProtocolNS, "Status")
	if err != nil {
		return "", err
	}
	code, err := singleSAMLChild(status, samlProtocolNS, "StatusCode")
	if err != nil || code.SelectAttrValue("Value", "") != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return "", fmt.Errorf("SAML status unsuccessful")
	}
	conditions, err := singleSAMLChild(verifiedAssertion, samlAssertionNS, "Conditions")
	if err != nil {
		return "", err
	}
	if err := samlValidity(conditions, want.Now, true); err != nil {
		return "", err
	}
	restriction, err := singleSAMLChild(conditions, samlAssertionNS, "AudienceRestriction")
	if err != nil {
		return "", err
	}
	audience, err := singleSAMLChild(restriction, samlAssertionNS, "Audience")
	if err != nil || audience.Text() != want.Audience {
		return "", fmt.Errorf("SAML audience mismatch")
	}
	subject, err := singleSAMLChild(verifiedAssertion, samlAssertionNS, "Subject")
	if err != nil {
		return "", err
	}
	name, err := singleSAMLChild(subject, samlAssertionNS, "NameID")
	if err != nil || name.Text() == "" || name.SelectAttrValue("Format", "") != want.NameIDFormat {
		return "", fmt.Errorf("SAML NameID format mismatch")
	}
	confirmation, err := singleSAMLChild(subject, samlAssertionNS, "SubjectConfirmation")
	if err != nil || confirmation.SelectAttrValue("Method", "") != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return "", fmt.Errorf("unexpected SAML confirmation")
	}
	confirmationData, err := singleSAMLChild(confirmation, samlAssertionNS, "SubjectConfirmationData")
	if err != nil || confirmationData.SelectAttrValue("Recipient", "") != want.ACS || confirmationData.SelectAttrValue("InResponseTo", "") != want.RequestID {
		return "", fmt.Errorf("SAML confirmation destination/request mismatch")
	}
	if err := samlValidity(confirmationData, want.Now, false); err != nil {
		return "", err
	}
	return name.Text(), nil
}
func samlValidity(e *etree.Element, now time.Time, requireBefore bool) error {
	after, err := time.Parse(time.RFC3339Nano, e.SelectAttrValue("NotOnOrAfter", ""))
	if err != nil || !now.Before(after) || after.After(now.Add(10*time.Minute)) {
		return fmt.Errorf("invalid SAML expiry")
	}
	if requireBefore {
		before, err := time.Parse(time.RFC3339Nano, e.SelectAttrValue("NotBefore", ""))
		if err != nil || before.After(now.Add(time.Minute)) || !before.Before(after) {
			return fmt.Errorf("invalid SAML validity interval")
		}
	}
	return nil
}
func singleSAMLChild(parent *etree.Element, namespace, tag string) (*etree.Element, error) {
	var result *etree.Element
	for _, child := range parent.ChildElements() {
		if child.Tag == tag {
			if result != nil || child.NamespaceURI() != namespace {
				return nil, fmt.Errorf("ambiguous SAML element")
			}
			result = child
		}
	}
	if result == nil {
		return nil, fmt.Errorf("missing SAML element")
	}
	return result, nil
}
func checkSAMLSignature(element *etree.Element) error {
	sig, err := singleSAMLChild(element, samlDSigNS, "Signature")
	if err != nil {
		return err
	}
	info, err := singleSAMLChild(sig, samlDSigNS, "SignedInfo")
	if err != nil {
		return err
	}
	canonical, err := singleSAMLChild(info, samlDSigNS, "CanonicalizationMethod")
	if err != nil || canonical.SelectAttrValue("Algorithm", "") != samlExclusiveC14N {
		return fmt.Errorf("SAML canonicalization rejected")
	}
	algorithm, err := singleSAMLChild(info, samlDSigNS, "SignatureMethod")
	if err != nil || algorithm.SelectAttrValue("Algorithm", "") != samlRSA256 {
		return fmt.Errorf("SAML signature algorithm rejected")
	}
	reference, err := singleSAMLChild(info, samlDSigNS, "Reference")
	if err != nil || reference.SelectAttrValue("URI", "") != "#"+element.SelectAttrValue("ID", "") {
		return fmt.Errorf("SAML signature reference rejected")
	}
	digest, err := singleSAMLChild(reference, samlDSigNS, "DigestMethod")
	if err != nil || digest.SelectAttrValue("Algorithm", "") != samlSHA256 {
		return fmt.Errorf("SAML digest algorithm rejected")
	}
	transforms, err := singleSAMLChild(reference, samlDSigNS, "Transforms")
	if err != nil {
		return err
	}
	children := transforms.ChildElements()
	if len(children) != 2 || children[0].Tag != "Transform" || children[1].Tag != "Transform" || children[0].NamespaceURI() != samlDSigNS || children[1].NamespaceURI() != samlDSigNS || children[0].SelectAttrValue("Algorithm", "") != samlDSigNS+"enveloped-signature" || children[1].SelectAttrValue("Algorithm", "") != samlExclusiveC14N {
		return fmt.Errorf("SAML transforms rejected")
	}
	return nil
}

func TestSAMLXMLRejectsAmbiguousAndUnboundedInput(t *testing.T) {
	for name, data := range map[string]string{
		"XXE":                    `<!DOCTYPE Response [<!ENTITY ext SYSTEM "file:///etc/passwd">]><Response>&ext;</Response>`,
		"duplicate ID":           `<Response ID="same"><Assertion ID="same"/></Response>`,
		"ambiguous lowercase id": `<Response ID="a" id="b"/>`,
		"multiple roots":         `<Response/><Response/>`,
		"duplicate attributes":   `<Response ID="a" ID="b"/>`,
		"unknown entity":         `<Response>&external;</Response>`,
		"deep":                   strings.Repeat("<a>", 40) + strings.Repeat("</a>", 40),
		"oversize":               `<Response>` + strings.Repeat("x", (1<<20)) + `</Response>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateSAMLResponse([]byte(data), nil, samlExpectation{}); err == nil {
				t.Fatal("unsafe XML accepted")
			}
		})
	}
}
