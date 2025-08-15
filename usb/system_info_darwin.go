package main

import (
	"os/exec"
	"strings"
)

// GetHardDriveID returns a unique identifier for the primary hard drive on macOS
func GetHardDriveID() string {
	cmd := exec.Command("diskutil", "info", "/")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Parse the output to find the Volume UUID
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Volume UUID:") {
			parts := strings.Fields(line)
			if len(parts) > 2 {
				return parts[len(parts)-1]
			}
		}
	}
	return "unknown"
}

// GetInstalledApps returns a list of installed applications on macOS
func GetInstalledApps() []string {
	var apps []string

	// Check Applications directory
	cmd := exec.Command("ls", "/Applications")
	output, err := cmd.Output()
	if err != nil {
		return apps
	}

	// Process the output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasSuffix(line, ".app") {
			apps = append(apps, strings.TrimSuffix(line, ".app"))
		}
	}

	return apps
}
