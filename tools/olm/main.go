// Command olm derives OperatorHub packaging and administrator installation
// prerequisites from the reviewed Helm chart.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const (
	packageName       = "hankoshell-operator"
	deploymentName    = "hankoshell-operator-olm"
	configurationName = "hankoshell-operator-installation"
	defaultNamespace  = "hankoshell-system"
	imageRepository   = "ghcr.io/alien6-studio/hankoshell-operator"
)

type options struct {
	chart, helm, output, namespace, kubernetes, values, image, replaces string
	catalog, catalogNamespace                                           string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || (args[0] != "bundle" && args[0] != "install") {
		return errors.New("usage: go run ./tools/olm bundle|install --output DIRECTORY [options]")
	}
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	chart, err := render(ctx, opts)
	if err != nil {
		return err
	}
	if err := validateProfile(chart); err != nil {
		return err
	}
	return generate(args[0], chart, opts)
}

func parseOptions(args []string) (options, error) {
	var opts options
	flags := flag.NewFlagSet("olm "+args[0], flag.ContinueOnError)
	flags.StringVar(&opts.chart, "chart", "charts/hankoshell-operator", "Reviewed chart source directory.")
	flags.StringVar(&opts.helm, "helm", "helm", "Helm executable.")
	flags.StringVar(&opts.output, "output", "", "New output directory; existing files are not overwritten.")
	flags.StringVar(&opts.namespace, "namespace", defaultNamespace, "Own namespace for administrator installation output.")
	flags.StringVar(&opts.kubernetes, "kube-version", "1.37.0", "Actual stable Kubernetes version for installation rendering.")
	flags.StringVar(&opts.values, "values", "", "Administrator values file; accepted only by install.")
	flags.StringVar(&opts.image, "image", "", "Published operator image pinned by SHA-256; required by bundle.")
	flags.StringVar(&opts.replaces, "replaces", "", "Previous CSV in the same package, for an existing channel.")
	flags.StringVar(&opts.catalog, "catalog", "operatorhubio-catalog", "CatalogSource used by installation output.")
	flags.StringVar(&opts.catalogNamespace, "catalog-namespace", "olm", "Namespace containing the CatalogSource.")
	if err := flags.Parse(args[1:]); err != nil {
		return opts, fmt.Errorf("parse packaging options: %w", err)
	}
	if opts.output == "" || flags.NArg() != 0 {
		return opts, errors.New("a fresh --output directory is required")
	}
	if _, err := os.Lstat(opts.output); !os.IsNotExist(err) {
		return opts, errors.New("output already exists or cannot be inspected")
	}
	if args[0] == "bundle" {
		if opts.values != "" || opts.namespace != defaultNamespace {
			return opts, errors.New("public bundles use reviewed defaults; site values belong to install output")
		}
		if !regexp.MustCompile(`^ghcr\.io/alien6-studio/hankoshell-operator@sha256:[a-f0-9]{64}$`).MatchString(opts.image) {
			return opts, errors.New("bundle requires the public operator image pinned by SHA-256")
		}
	}
	return opts, nil
}

func generate(mode string, chart *chartSource, opts options) error {
	// Generate into a sibling directory and expose the result only on success.
	parent := filepath.Dir(opts.output)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create output parent: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".olm-")
	if err != nil {
		return fmt.Errorf("create generation directory: %w", err)
	}
	defer os.RemoveAll(staging)
	if mode == "bundle" {
		err = writeBundle(staging, chart, opts)
	} else {
		err = writeInstallation(staging, chart, opts)
	}
	if err != nil {
		return err
	}
	if err := os.Rename(staging, opts.output); err != nil {
		return fmt.Errorf("publish generated output: %w", err)
	}
	return nil
}
