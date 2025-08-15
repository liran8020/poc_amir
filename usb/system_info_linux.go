//go:build linux

package main

import (
	"os/exec"
	"strings"
)

func GetHardDriveID() string {
	cmd := exec.Command("sh", "-c", "lsblk -ndo serial /dev/sda || lsblk -ndo serial /dev/vda || echo 'not_found'")
	output, err := cmd.Output()
	if err != nil {
		return "unknown_linux"
	}
	return strings.TrimSpace(string(output))
}

func GetInstalledApps() []string {
	cmd := exec.Command("dpkg-query", "-W", "-f=${Package}\\n")
	output, err := cmd.Output()
	if err != nil { // Fallback for RPM-based systems
		cmd = exec.Command("rpm", "-qa")
		output, err = cmd.Output()
		if err != nil {
			return []string{"error_retrieving_apps"}
		}
	}
	apps := strings.Split(string(output), "\n")
	if len(apps) > 0 && apps[len(apps)-1] == "" {
		return apps[:len(apps)-1]
	}
	return apps
}
