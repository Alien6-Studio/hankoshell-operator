package main

import (
	"context"
	"errors"
	corev1 "k8s.io/api/core/v1"
	"time"

	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Alien6-Studio/hankoshell-operator/internal/installation"
)

func verifyInstallation(config runtimeConfig) error {
	if !config.hasInstallationVerification() {
		return nil
	}
	if err := config.validateInstallationVerification(); err != nil {
		return err
	}
	restConfig, err := ctrl.GetConfig()
	if err != nil {
		return errors.New("installation verification requires Kubernetes API access")
	}
	restConfig.Timeout = 10 * time.Second
	reader, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		return errors.New("cannot construct installation verification reader")
	}
	contract, err := readInstallation(config, reader)
	if err != nil {
		return err
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(restConfig)
	if err != nil {
		return errors.New("cannot construct Kubernetes version reader")
	}
	server, err := discoveryClient.ServerVersion()
	if err != nil {
		return errors.New("cannot verify Kubernetes version")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	for {
		err = contract.Verify(ctx, reader, config.watchNamespace, server.GitVersion)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(2 * time.Second):
		}
	}
}

func (config runtimeConfig) hasInstallationVerification() bool {
	return config.installationContract != "" || config.installationConfigMap != "" || config.installationDigest != "" || config.installationCheckOnly || config.installationRequired
}

func (config runtimeConfig) validateInstallationVerification() error {
	if config.installationDigest == "" || (config.installationContract == "" && config.installationConfigMap == "") {
		return errors.New("installation requires a contract and an independently approved SHA-256")
	}
	if config.installationContract != "" && config.installationConfigMap != "" {
		return errors.New("choose either an installation file or ConfigMap")
	}
	return nil
}

func readInstallation(config runtimeConfig, reader client.Reader) (*installation.Contract, error) {
	if config.installationContract != "" {
		return installation.Load(config.installationContract, config.installationDigest)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var object corev1.ConfigMap
	if err := reader.Get(ctx, client.ObjectKey{Name: config.installationConfigMap, Namespace: config.watchNamespace}, &object); err != nil {
		return nil, errors.New("cannot read the installation contract ConfigMap")
	}
	if object.Immutable == nil || !*object.Immutable {
		return nil, errors.New("installation contract ConfigMap must be immutable")
	}
	return installation.Decode([]byte(object.Data["contract.json"]), config.installationDigest)
}
