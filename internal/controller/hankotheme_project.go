package controller

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const themeProjectLabel = "hanko.sh/theme-project"

func validateThemeProject(spec api.HankoThemeSpec) ([]byte, error) {
	if spec.ProjectGzip == "" && spec.ProjectSHA256 == "" {
		return nil, nil
	}
	if spec.ProjectGzip == "" || len(spec.ProjectGzip) > 900000 || len(spec.ProjectSHA256) != 64 || strings.ToLower(spec.ProjectSHA256) != spec.ProjectSHA256 {
		return nil, fmt.Errorf("project snapshot and SHA-256 are required and must satisfy size bounds")
	}
	if spec.ArtifactSHA256 != "" || spec.PrimaryColor != "" || spec.BackgroundColor != "" || spec.ForegroundColor != "" || spec.LogoURL != "" || spec.FontFamily != "" || spec.Headline != "" || spec.Subline != "" {
		return nil, fmt.Errorf("a Studio project cannot be combined with artifact installation or legacy design tokens")
	}
	compressed, err := base64.StdEncoding.Strict().DecodeString(spec.ProjectGzip)
	if err != nil {
		return nil, fmt.Errorf("invalid compressed project encoding")
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("invalid project gzip")
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, 40*1024*1024+1))
	if err != nil || len(raw) > 40*1024*1024 {
		return nil, fmt.Errorf("invalid project gzip or project exceeds 40 MiB")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != spec.ProjectSHA256 {
		return nil, fmt.Errorf("project snapshot digest mismatch")
	}
	var envelope struct {
		Format string `json:"format"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Format != "hanko.theme-studio.project/v1" {
		return nil, fmt.Errorf("unsupported Studio project format")
	}
	return compressed, nil
}

func themeProjectName(theme *api.HankoTheme) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", theme.UID, theme.Generation, themeSpecHash(theme.Spec))))
	prefix := theme.Name
	if len(prefix) > 34 {
		prefix = strings.TrimRight(prefix[:34], "-")
	}
	return prefix + "-source-" + hex.EncodeToString(digest[:8])
}

func (r *HankoThemeReconciler) ensureThemeProject(ctx context.Context, theme *api.HankoTheme) error {
	if theme.Spec.ProjectGzip == "" {
		return nil
	}
	compressed, err := validateThemeProject(theme.Spec)
	if err != nil {
		return err
	}
	name := themeProjectName(theme)
	var existing corev1.ConfigMap
	err = r.Get(ctx, types.NamespacedName{Namespace: theme.Namespace, Name: name}, &existing)
	if err == nil {
		if !metav1.IsControlledBy(&existing, theme) || existing.Immutable == nil || !*existing.Immutable || len(existing.Data) != 0 || len(existing.BinaryData) != 1 || !bytes.Equal(existing.BinaryData["project.json.gz"], compressed) {
			return fmt.Errorf("project ConfigMap conflicts with its immutable source contract")
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	} else {
		input := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: theme.Namespace, Labels: map[string]string{themeLabel: theme.Name, themeProjectLabel: "true"}}, Immutable: boolPtr(true), BinaryData: map[string][]byte{"project.json.gz": compressed}}
		if err := controllerutil.SetControllerReference(theme, input, r.Scheme); err != nil {
			return err
		}
		if err := r.Create(ctx, input); err != nil {
			return err
		}
	}
	return nil
}

func (r *HankoThemeReconciler) bindThemeProject(ctx context.Context, theme *api.HankoTheme, job *batchv1.Job) error {
	if theme.Spec.ProjectGzip == "" {
		return nil
	}
	var input corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: theme.Namespace, Name: themeProjectName(theme)}, &input); err != nil {
		return err
	}
	expected, err := validateThemeProject(theme.Spec)
	if err != nil {
		return err
	}
	if input.Immutable == nil || !*input.Immutable || len(input.Data) != 0 || len(input.BinaryData) != 1 || !bytes.Equal(input.BinaryData["project.json.gz"], expected) {
		return fmt.Errorf("project source differs from its immutable contract")
	}
	if metav1.IsControlledBy(&input, job) {
		return nil
	}
	if !metav1.IsControlledBy(&input, theme) {
		return fmt.Errorf("project source has a foreign owner")
	}
	patch := client.MergeFrom(input.DeepCopy())
	if err := controllerutil.RemoveControllerReference(theme, &input, r.Scheme); err != nil {
		return err
	}
	if err := controllerutil.SetControllerReference(job, &input, r.Scheme); err != nil {
		return err
	}
	// Job TTL and owner garbage collection clean up the source without delete privileges.
	return r.Patch(ctx, &input, patch)
}
