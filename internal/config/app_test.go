package config_test

import (
	"os"
	"testing"

	"github.com/nckslvrmn/whisper/internal/config"
)

func TestLoadAppConfig_Defaults(t *testing.T) {
	os.Unsetenv("PROJECT_NAME")
	os.Unsetenv("ADVANCED_FEATURES")
	os.Unsetenv("PORT")

	if err := config.LoadAppConfig(); err != nil {
		t.Fatalf("LoadAppConfig: %v", err)
	}

	if config.ProjectName != "Whisper" {
		t.Errorf("ProjectName = %q, want %q", config.ProjectName, "Whisper")
	}
	if config.AdvancedFeatures {
		t.Error("AdvancedFeatures should default to false")
	}
	if config.Port != "8081" {
		t.Errorf("Port = %q, want %q", config.Port, "8081")
	}
}

func TestLoadAppConfig_ProjectNameOverride(t *testing.T) {
	os.Setenv("PROJECT_NAME", "TestVault")
	defer os.Unsetenv("PROJECT_NAME")

	config.LoadAppConfig()
	if config.ProjectName != "TestVault" {
		t.Errorf("ProjectName = %q, want TestVault", config.ProjectName)
	}
}

func TestLoadAppConfig_AdvancedFeaturesTrue(t *testing.T) {
	os.Setenv("ADVANCED_FEATURES", "true")
	defer os.Unsetenv("ADVANCED_FEATURES")

	config.LoadAppConfig()
	if !config.AdvancedFeatures {
		t.Error("AdvancedFeatures should be true when env var is 'true'")
	}
}

func TestLoadAppConfig_AdvancedFeatures_1(t *testing.T) {
	os.Setenv("ADVANCED_FEATURES", "1")
	defer os.Unsetenv("ADVANCED_FEATURES")

	config.LoadAppConfig()
	if !config.AdvancedFeatures {
		t.Error("AdvancedFeatures should be true when env var is '1'")
	}
}

func TestLoadAppConfig_AdvancedFeaturesFalse(t *testing.T) {
	os.Setenv("ADVANCED_FEATURES", "false")
	defer os.Unsetenv("ADVANCED_FEATURES")

	config.LoadAppConfig()
	if config.AdvancedFeatures {
		t.Error("AdvancedFeatures should be false when env var is 'false'")
	}
}

func TestLoadAppConfig_AdvancedFeaturesInvalid(t *testing.T) {
	os.Setenv("ADVANCED_FEATURES", "notabool")
	defer os.Unsetenv("ADVANCED_FEATURES")

	config.LoadAppConfig()
	if config.AdvancedFeatures {
		t.Error("AdvancedFeatures should remain false for invalid value")
	}
}

func TestLoadAppConfig_PortOverride(t *testing.T) {
	os.Setenv("PORT", "9090")
	defer os.Unsetenv("PORT")

	config.LoadAppConfig()
	if config.Port != "9090" {
		t.Errorf("Port = %q, want 9090", config.Port)
	}
}

func TestLoadAppConfig_ReturnsNilError(t *testing.T) {
	err := config.LoadAppConfig()
	if err != nil {
		t.Errorf("LoadAppConfig returned non-nil error: %v", err)
	}
}
