package main

import (
	"os/exec"
	"strings"
)

// GetHardDriveID returns a unique identifier for the primary hard drive on Windows
func GetHardDriveID() string {
	// Using wmic to get the disk serial number
	cmd := exec.Command("wmic", "diskdrive", "get", "serialnumber")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Parse the output to get the serial number
	lines := strings.Split(string(output), "\n")
	if len(lines) >= 2 {
		// The first line is the header, second line should be the serial number
		serialNumber := strings.TrimSpace(lines[1])
		if serialNumber != "" {
			return serialNumber
		}
	}
	return "unknown"
}

// GetInstalledApps returns a list of installed applications on Windows
func GetInstalledApps() []string {
	var apps []string

	// Using powershell to get installed applications from registry
	cmd := exec.Command("powershell", "-Command", `Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Where-Object {$_.DisplayName -ne $null} | ForEach-Object {$_.DisplayName}`)
	output, err := cmd.Output()
	if err != nil {
		return apps
	}

	// Split output by newlines and add non-empty lines to apps list
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		app := strings.TrimSpace(line)
		if app != "" {
			apps = append(apps, app)
		}
	}

	// Also check 32-bit applications on 64-bit systems
	cmd = exec.Command("powershell", "-Command", `Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Where-Object {$_.DisplayName -ne $null} | ForEach-Object {$_.DisplayName}`)
	output, err = cmd.Output()
	if err == nil {
		lines = strings.Split(string(output), "\n")
		for _, line := range lines {
			app := strings.TrimSpace(line)
			if app != "" {
				apps = append(apps, app)
			}
		}
	}

	return apps
}
