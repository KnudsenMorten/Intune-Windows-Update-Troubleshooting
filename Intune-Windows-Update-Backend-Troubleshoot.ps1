<#
    .NAME
    Intune/AutoPatch/WHfB Troubleshooting (

    .SYNOPSIS

    .NOTES
    
    .VERSION
    1.0
    
    .AUTHOR
    Morten Knudsen, Microsoft MVP - https://mortenknudsen.net

    .LICENSE
    Licensed under the MIT license.

    .PROJECTURI
    https://github.com/KnudsenMorten/Intune-Windows-Update-Troubleshooting


    .WARRANTY
    Use at your own risk, no warranty given!
#>

# First, ensure you're connected to Graph with the right scopes:
Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All", "WindowsUpdates.ReadWrite.All"


###################################################################################
# Get Status about Windows Client devices from WUfB AutoPatch
###################################################################################
function Get-WUfBEnrollmentStatus {
    <#
    .SYNOPSIS
        Retrieves the WUfB AutoPatch enrollment status for Windows client devices managed by Intune (MDM).
    
    .PARAMETER ShowStatus
        Optional. If specified, displays output during processing using Write-Host.

    .OUTPUTS
        [PSCustomObject] array with DeviceName, DeviceId, EnrollmentStateFeature, EnrollmentStateQuality, EnrollmentStateDriver
    #>

    param (
        [switch]$ShowStatus = $false
    )

    $StatusEnrollmentWUfB = @()

    if ($ShowStatus) {
        Write-Host ""
        Write-Host "📥 Retrieving all devices from Intune..."
    }

    $devices = @()
    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $devices += $response.value
        $uri = $response.'@odata.nextLink'
    } while ($uri)

    $ScopedDevices = $devices | Where-Object {
        $_.managementAgent -eq "mdm" -and $_.operatingSystem -like "Windows*"
    }

    if ($ShowStatus) {
        Write-Host ""
        Write-Host "✅ Scoped devices found: $($ScopedDevices.Count)"
    }

    foreach ($device in $ScopedDevices) {
        $deviceName = $device.deviceName
        $deviceId = $device.azureADDeviceId

        if ($ShowStatus) {
            Write-Host ""
            Write-Host "🔍 Processing device: $deviceName ($deviceId)"
        }

        $enrollmentStateFeature = $null
        $enrollmentStateQuality = $null
        $enrollmentStateDriver = $null
        $errorsWUfB = 0

        try {
            $wuAsset = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/$deviceId"
            $enrollmentStateFeature = $wuAsset.enrollment.feature.enrollmentState
            $enrollmentStateQuality = $wuAsset.enrollment.quality.enrollmentState
            $enrollmentStateDriver  = $wuAsset.enrollment.driver.enrollmentState
            $errorsWUfB = if ($wuAsset.errors) { $wuAsset.errors.Count } else { 0 }

            if ($ShowStatus) {
                Write-Host "📋 Enrollment State Feature: $enrollmentStateFeature"
                Write-Host "📋 Enrollment State Quality: $enrollmentStateQuality"
                Write-Host "📋 Enrollment State Driver : $enrollmentStateDriver"
                Write-Host "📋 Errors (WUfB)           : $errorsWUfB"
            }

            $StatusObj = [PSCustomObject]@{
                DeviceName             = $deviceName
                DeviceId               = $deviceId
                EnrollmentStateFeature = $enrollmentStateFeature
                EnrollmentStateQuality = $enrollmentStateQuality
                EnrollmentStateDriver  = $enrollmentStateDriver
                ErrorsWUfB             = $errorsWUfB
            }

            $StatusEnrollmentWUfB += $StatusObj
        }
        catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 404) {
                if ($ShowOut) {
                    Write-Host "ℹ️ Device not found in WUfB AutoPatch"
                }
            } else {
                if ($ShowStatus) {
                    Write-Host "❌ Failed to process $deviceName ($deviceId): $($_.Exception.Message)"
                }
            }
            continue
        }
    }

    return $StatusEnrollmentWUfB
}

# Call the function and save results
$WUStatus = Get-WUfBEnrollmentStatus -ShowStatus

# Optionally view as a table
$WUStatus | Format-Table -AutoSize

function Get-WUfBUpdatePolicies {
    <#
    .SYNOPSIS
        Retrieves all Windows Update for Business (WUfB) update policies from Microsoft Graph.

    .DESCRIPTION
        Uses Microsoft Graph beta endpoint to list all update policies configured in Windows Update for Business.

    .OUTPUTS
        Array of update policy objects with ID, display name, settings, assignments, etc.
    #>

    $uri = "https://graph.microsoft.com/beta/admin/windows/updates/updatePolicies"
    $allPolicies = @()

    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $allPolicies += $response.value
        $uri = $response.'@odata.nextLink'
    } while ($uri)

    return $allPolicies
}

# Call the function
$policies = Get-WUfBUpdatePolicies

foreach ($policy in $policies) {
    Write-Host "`n📄 Policy: $($policy.displayName)"
    Write-Host "🆔 ID: $($policy.id)"

    if ($policy) {
        # Assuming $policy contains the policy object

        Write-Host "`n📄 Policy ID: $($policy.id)"
        Write-Host "🕒 Created: $($policy.createdDateTime)"
        Write-Host "📦 Auto Enrollment Categories: $($policy.autoEnrollmentUpdateCategories -join ', ')"
        Write-Host "👥 Audience Group ID: $($policy.audience.id)"

        # Deployment Settings
        if ($policy.deploymentSettings) {
            Write-Host "`n⚙️ Deployment Settings:"
            if ($policy.deploymentSettings.userExperience) {
                $ux = $policy.deploymentSettings.userExperience
                Write-Host "   Offer As Optional: $($ux.offerAsOptional)"
                Write-Host "   Hotpatch Enabled:   $($ux.isHotpatchEnabled)"
                Write-Host "   Days Until Forced Reboot: $($ux.daysUntilForcedReboot)"
            }
        }

        # Compliance Change Rules
        if ($policy.complianceChangeRules) {
            Write-Host "`n📏 Compliance Change Rules:"
            foreach ($rule in $policy.complianceChangeRules) {
                Write-Host "   Rule Type: $($rule.'@odata.type')"
                Write-Host "   Classification: $($rule.contentFilter.classification)"
                Write-Host "   Cadence:        $($rule.contentFilter.cadence)"
                Write-Host "   Delay:          $($rule.durationBeforeDeploymentStart)"
                Write-Host "   Created:        $($rule.createdDateTime)"
            }
        }
    } else {
        Write-Host "⚠️  No settings defined."
    }
}

function Get-WUfBPolicyComplianceChanges {
    <#
    .SYNOPSIS
        Retrieves compliance change records for a given WUfB update policy.
    
    .PARAMETER PolicyId
        The ID of the update policy to query.
    
    .OUTPUTS
        Array of compliance change objects, including compliance state, affected devices, timestamps, etc.
    
    .EXAMPLE
        Get-WUfBPolicyComplianceChanges -PolicyId "a688f89c-930c-4652-bc5d-daf3a63fbf56"
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$PolicyId
    )

    $uri = "https://graph.microsoft.com/beta/admin/windows/updates/updatePolicies/$PolicyId/complianceChanges"
    $allChanges = @()

    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $allChanges += $response.value
        $uri = $response.'@odata.nextLink'
    } while ($uri)

    return $allChanges
}

# Get compliance changes for a specific update policy
$policyId = "a688f89c-930c-4652-bc5d-daf3a63fbf56"
$changes = Get-WUfBPolicyComplianceChanges -PolicyId $policyId

# Show the results
$changes | Select-Object id, complianceState, deviceId, createdDateTime | Format-Table -AutoSize


function Get-WUfBDeviceErrors {
    <#
    .SYNOPSIS
        Retrieves WUfB deployment service errors for a specific device.

    .PARAMETER DeviceId
        Azure AD Device ID of the updatable asset.

    .OUTPUTS
        Array of error records related to WUfB updatable asset operations.

    .EXAMPLE
        Get-WUfBDeviceErrors -DeviceId "52d3a1f4-aefc-4fac-b0c3-0e49e655acd0"
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$DeviceId
    )

    $uri = "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/$DeviceId/errors"
    $errors = @()

    try {
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri
            $errors += $response.value
            $uri = $response.'@odata.nextLink'
        } while ($uri)
    }
    catch {
        Write-Host "❌ Failed to retrieve errors for device $($DeviceId): $($_.Exception.Message)"
        return @()
    }

    return $errors
}


# Get WUfB errors for a device
$devices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $devices += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

$device = $devices | Where-Object {$_.deviceName -eq "STRV-ACW-DT-01"}

$errors = Get-WUfBDeviceErrors -DeviceId ($device.azureADDeviceId)

# View output
$errors | Select-Object code, message, createdDateTime | Format-Table -AutoSize

function Get-AllWUfBUpdatableAssetsByGroup {
    <#
    .SYNOPSIS
        Retrieves all updatable asset groups and lists all updatable assets in each group from Windows Update for Business Deployment Service.
    
    .OUTPUTS
        [PSCustomObject] array containing GroupId, GroupName, and list of Updatable Assets.
    
    .REQUIRES
        Microsoft Graph Beta PowerShell SDK and "WindowsUpdates.Read.All" permission.
    #>

    $groupsUri = "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssetGroups"
    $groupList = @()

    try {
        do {
            $groupResponse = Invoke-MgGraphRequest -Method GET -Uri $groupsUri
            $groupList += $groupResponse.value
            $groupsUri = $groupResponse.'@odata.nextLink'
        } while ($groupsUri)
    }
    catch {
        Write-Host "❌ Failed to retrieve updatable asset groups: $($_.Exception.Message)"
        return @()
    }

    $results = foreach ($group in $groupList) {
        $groupId = $group.id
        $groupName = $group.displayName
        $assetsUri = "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssetGroups/$groupId/updatableAssets"
        $assets = @()

        try {
            do {
                $assetResponse = Invoke-MgGraphRequest -Method GET -Uri $assetsUri
                $assets += $assetResponse.value
                $assetsUri = $assetResponse.'@odata.nextLink'
            } while ($assetsUri)
        }
        catch {
            Write-Host "⚠️  Failed to retrieve assets for group '$groupName' ($groupId): $($_.Exception.Message)"
            continue
        }

        [PSCustomObject]@{
            GroupId   = $groupId
            GroupName = $groupName
            AssetCount = $assets.Count
            Assets    = $assets
        }
    }

    return $results
}

function Get-WUfBDeploymentAudienceMembersWithNames {
    <#
    .SYNOPSIS
        Retrieves all WUfB Deployment Audiences and members, resolving Azure AD device names
        and labeling asset groups appropriately.

    .OUTPUTS
        [PSCustomObject] with AudienceName, DeviceId, DeviceName, Type
    #>

    $audienceUri = "https://graph.microsoft.com/beta/admin/windows/updates/deploymentAudiences"
    $audiences = @()

    try {
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $audienceUri
            $audiences += $response.value
            $audienceUri = $response.'@odata.nextLink'
        } while ($audienceUri)
    } catch {
        Write-Host "❌ Failed to get audiences: $($_.Exception.Message)"
        return
    }

    $results = @()

    foreach ($audience in $audiences) {
        $audienceName = $audience.displayName
        $audienceId = $audience.id
        $memberUri = "https://graph.microsoft.com/beta/admin/windows/updates/deploymentAudiences/$audienceId/members"
        $members = @()

        try {
            do {
                $memberResponse = Invoke-MgGraphRequest -Method GET -Uri $memberUri
                $members += $memberResponse.value
                $memberUri = $memberResponse.'@odata.nextLink'
            } while ($memberUri)
        } catch {
            Write-Host "⚠️ Failed to get members for audience $audienceName"
            continue
        }

        foreach ($member in $members) {
            $deviceId = $member.id
            $odataType = $member.'@odata.type'
            $deviceName = "<not resolved>"

            switch ($odataType) {
                "#microsoft.graph.windowsUpdates.azureADDevice" {
                    try {
                        $aadDevice = Get-MgDevice -Filter "id eq '$deviceId'" -ErrorAction Stop
                        if ($aadDevice) {
                            $deviceName = $aadDevice.displayName
                        } else {
                            $deviceName = "<not found or deleted>"
                        }
                    } catch {
                        $deviceName = "<not found or deleted>"
                    }
                }
                "#microsoft.graph.windowsUpdates.updatableAssetGroup" {
                    $deviceName = "<updatable asset group>"
                }
                default {
                    $deviceName = "<unknown member type>"
                }
            }

            $results += [PSCustomObject]@{
                AudienceName = $audienceName
                DeviceId     = $deviceId
                DeviceName   = $deviceName
                Type         = $odataType
            }
        }
    }

    return $results
}

$devicesPerAudience = Get-WUfBDeploymentAudienceMembersWithNames

# Show results
$devicesPerAudience | Format-Table -AutoSize

# Run the function
$allGroupAssets = Get-AllWUfBUpdatableAssetsByGroup

 $audiences = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/admin/windows/updates/deploymentAudiences" 
 $deploymentAudience = $audiences.value

 $audienceId = "36ecbdc0-5b90-44f8-b00c-2588ad942337"

Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/admin/windows/updates/deploymentAudiences/$audienceId/members"

 
# Show summary
$allGroupAssets | Select-Object GroupName, AssetCount | Format-Table -AutoSize

# Show details for one group
$allGroupAssets[0].Assets | Select-Object id, "@odata.type"

pause

###################################################################################
# Force Un-enroll Windows Client devices from WUfB AutoPatch (Feature Updates only)
###################################################################################
# https://learn.microsoft.com/en-us/graph/api/windowsupdates-updatableasset-unenrollassets?view=graph-rest-beta&tabs=http

Write-Host ""
Write-Host "📥 Retrieving all devices from Intune..."

$devices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $devices += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

# Filter only Windows client devices managed by Intune
$ScopedDevices = $devices | Where-Object { $_.managementAgent -eq "mdm" -and $_.operatingSystem -like "Windows*"}
Write-Host ""
Write-Host "✅ Scoped devices found: $($ScopedDevices.Count)"

# === LOOP THROUGH DEVICES ===
foreach ($device in $ScopedDevices) {
    $deviceName = $device.deviceName
    $deviceId = $device.azureADDeviceId

    Write-Host ""
    Write-Host "🔍 Processing device: $deviceName ($deviceId)"

    # Build JSON body for (un)enrollment
    $body = @{
        updateCategory = "feature"
        assets = @(
            @{
                "@odata.type" = "#microsoft.graph.windowsUpdates.azureADDevice"
                id = $deviceId
            }
        )
    }
    $jsonBody = $body | ConvertTo-Json -Depth 5

    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/unenrollAssets" `
        -Body $jsonBody `
        -ContentType "application/json"
}

#########################################################################################################################
# Force Un-enroll Windows Client devices from WUfB AutoPatch, where state is NOT 'Enrolled' (Feature Updates only)
#########################################################################################################################
# https://learn.microsoft.com/en-us/graph/api/windowsupdates-updatableasset-unenrollassets?view=graph-rest-beta&tabs=http

Write-Host ""
Write-Host "📥 Retrieving all devices from Intune..."

$devices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $devices += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

write-host "Get enrollment status for devices ... Pleae Wait !"
$StatusEnrollmentWUfB = Get-WUfBEnrollmentStatus

# Build a lookup dictionary from enrollment status for fast access
$StatusLookup = @{}
foreach ($entry in $StatusEnrollmentWUfB) {
    $StatusLookup[$entry.DeviceId] = $entry
}

# Filter: MDM-managed Windows devices that are NOT enrolled for 'feature' updates
$ScopedDevices = $devices | Where-Object {
    $_.managementAgent -eq "mdm" -and
    $_.operatingSystem -like "Windows*" -and
    $StatusLookup.ContainsKey($_.azureADDeviceId) -and
    $StatusLookup[$_.azureADDeviceId].EnrollmentStateFeature -ne "enrolled"
}

Write-Host ""
Write-Host "✅ Scoped devices found: $($ScopedDevices.Count)"

# === LOOP THROUGH DEVICES ===
foreach ($device in $ScopedDevices) {
    $deviceName = $device.deviceName
    $deviceId = $device.azureADDeviceId

    Write-Host ""
    Write-Host "🔍 Processing device: $deviceName ($deviceId)"

    # Build JSON body for (un)enrollment
    $body = @{
        updateCategory = "feature"
        assets = @(
            @{
                "@odata.type" = "#microsoft.graph.windowsUpdates.azureADDevice"
                id = $deviceId
            }
        )
    }
    $jsonBody = $body | ConvertTo-Json -Depth 5

    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/unenrollAssets" `
        -Body $jsonBody `
        -ContentType "application/json"
}

################################################################################################################################################
# Force Delete All Windows Client devices from WUfB AutoPatch, where Feature Update enrollment state is stuck in 'enrolling' or 'unenrolling'
################################################################################################################################################
# https://learn.microsoft.com/en-us/graph/api/windowsupdates-updatableasset-delete?view=graph-rest-beta&tabs=http

Write-Host ""
Write-Host "📥 Retrieving all devices from Intune..."

$devices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $devices += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

# Filter only Windows client devices managed by Intune
write-host "Get enrollment status for devices ... Please Wait !"
$StatusEnrollmentWUfB = Get-WUfBEnrollmentStatus

# Build a lookup dictionary from enrollment status for fast access
$StatusLookup = @{}
foreach ($entry in $StatusEnrollmentWUfB) {
    $StatusLookup[$entry.DeviceId] = $entry
}

# Filter: MDM-managed Windows devices that are NOT enrolled for 'feature' updates
$ScopedDevices = $devices | Where-Object {
    $_.managementAgent -eq "mdm" -and
    $_.operatingSystem -like "Windows*" -and
    $StatusLookup.ContainsKey($_.azureADDeviceId) -and
    $StatusLookup[$_.azureADDeviceId].EnrollmentStateFeature -eq "enrolling" -or $StatusLookup[$_.azureADDeviceId].EnrollmentStateFeature -eq "unenrolling"
}
Write-Host ""
Write-Host "✅ Scoped devices found: $($ScopedDevices.Count)"

# === LOOP THROUGH DEVICES ===
foreach ($device in $ScopedDevices) {
    $deviceName = $device.deviceName
    $deviceId = $device.azureADDeviceId

    Write-Host ""
    Write-Host "🔍 Processing device: $deviceName ($deviceId)"

    Invoke-MgGraphRequest -Method DELETE `
        -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/$deviceId"
}

###################################################################################################################################################
# Enroll Windows Client devices into WUfB AutoPatch (Feature Updates only) - will also include devices, that was deleted before (catch-up)
###################################################################################################################################################
# https://learn.microsoft.com/en-us/graph/api/windowsupdates-updatableasset-enrollassets?view=graph-rest-beta&tabs=http

Write-Host ""
Write-Host "📥 Retrieving all devices from Intune..."

$devices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $devices += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

# Filter only Windows client devices managed by Intune
$ScopedDevices = $devices | Where-Object { $_.managementAgent -eq "mdm" -and $_.operatingSystem -like "Windows*"}
Write-Host ""
Write-Host "✅ Scoped devices found: $($ScopedDevices.Count)"

# === LOOP THROUGH DEVICES ===
foreach ($device in $ScopedDevices) {
    $deviceName = $device.deviceName
    $deviceId = $device.azureADDeviceId

    Write-Host ""
    Write-Host "🔍 Processing device: $deviceName ($deviceId)"

    # Build JSON body for enrollment
    $body = @{
        updateCategory = "feature"
        assets = @(
            @{
                "@odata.type" = "#microsoft.graph.windowsUpdates.azureADDevice"
                id = $deviceId
            }
        )
    }
    $jsonBody = $body | ConvertTo-Json -Depth 5

    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/enrollAssets" `
        -Body $jsonBody `
        -ContentType "application/json"
}


#######################################################################################################
# Enroll Windows Client devices into WUfB AutoPatch with 'NotEnrolled' state (Feature Updates only)
#######################################################################################################
# https://learn.microsoft.com/en-us/graph/api/windowsupdates-updatableasset-enrollassets?view=graph-rest-beta&tabs=http

Write-Host ""
Write-Host "📥 Retrieving all devices from Intune..."

$devices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $devices += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

write-host "Get enrollment status for devices ... Please Wait !"
$StatusEnrollmentWUfB = Get-WUfBEnrollmentStatus

# Build a lookup dictionary from enrollment status for fast access
$StatusLookup = @{}
foreach ($entry in $StatusEnrollmentWUfB) {
    $StatusLookup[$entry.DeviceId] = $entry
}

# Filter: MDM-managed Windows devices that are NOT enrolled for 'feature' updates
$ScopedDevices = $devices | Where-Object {
    $_.managementAgent -eq "mdm" -and
    $_.operatingSystem -like "Windows*" -and
    $StatusLookup.ContainsKey($_.azureADDeviceId) -and
    $StatusLookup[$_.azureADDeviceId].EnrollmentStateFeature -eq "notEnrolled"   # filter for 'NotEnrolled' state. We don't want to include 'unenrolling', but let them finish first
}
Write-Host ""
Write-Host "✅ Scoped devices found: $($ScopedDevices.Count)"

# === LOOP THROUGH DEVICES ===
foreach ($device in $ScopedDevices) {
    $deviceName = $device.deviceName
    $deviceId = $device.azureADDeviceId

    Write-Host ""
    Write-Host "🔍 Processing device: $deviceName ($deviceId)"

    #####################
    # Feature Updates
    #####################
        # Build JSON body for enrollment
        $body = @{
            updateCategory = "feature"
            assets = @(
                @{
                    "@odata.type" = "#microsoft.graph.windowsUpdates.azureADDevice"
                    id = $deviceId
                }
            )
        }
        $jsonBody = $body | ConvertTo-Json -Depth 5

        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/enrollAssets" `
            -Body $jsonBody `
            -ContentType "application/json"
}


##################################################################################################################
# Force Delete All Windows Client devices from WUfB AutoPatch (Only use, if you want complete reset !!!)
##################################################################################################################
# https://learn.microsoft.com/en-us/graph/api/windowsupdates-updatableasset-delete?view=graph-rest-beta&tabs=http

Write-Host ""
Write-Host "📥 Retrieving all devices from Intune..."

$devices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $devices += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

# Filter only Windows client devices managed by Intune
$ScopedDevices = $devices | Where-Object { $_.managementAgent -eq "mdm" -and $_.operatingSystem -like "Windows*"}
Write-Host ""
Write-Host "✅ Scoped devices found: $($ScopedDevices.Count)"

# === LOOP THROUGH DEVICES ===
foreach ($device in $ScopedDevices) {
    $deviceName = $device.deviceName
    $deviceId = $device.azureADDeviceId

    Write-Host ""
    Write-Host "🔍 Processing device: $deviceName ($deviceId)"

    Invoke-MgGraphRequest -Method DELETE `
        -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/$deviceId"
}


###################################################################################
# Enroll All Windows Client devices into WUfB AutoPatch (Quality Updates only)
###################################################################################
# https://learn.microsoft.com/en-us/graph/api/windowsupdates-updatableasset-enrollassets?view=graph-rest-beta&tabs=http

Write-Host ""
Write-Host "📥 Retrieving all devices from Intune..."

$devices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $devices += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

# Filter only Windows client devices managed by Intune
$ScopedDevices = $devices | Where-Object { $_.managementAgent -eq "mdm" -and $_.operatingSystem -like "Windows*"}
Write-Host ""
Write-Host "✅ Scoped devices found: $($ScopedDevices.Count)"

# === LOOP THROUGH DEVICES ===
foreach ($device in $ScopedDevices) {
    $deviceName = $device.deviceName
    $deviceId = $device.azureADDeviceId

    Write-Host ""
    Write-Host "🔍 Processing device: $deviceName ($deviceId)"

    #####################
    # Quality Updates
    #####################
    # Build JSON body for enrollment
    $body = @{
        updateCategory = "quality"
        assets = @(
            @{
                "@odata.type" = "#microsoft.graph.windowsUpdates.azureADDevice"
                id = $deviceId
            }
        )
    }
    $jsonBody = $body | ConvertTo-Json -Depth 5

    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/enrollAssets" `
        -Body $jsonBody `
        -ContentType "application/json"
}


###################################################################################
# Enroll All Windows Client devices into WUfB AutoPatch (Driver Updates only)
###################################################################################
# https://learn.microsoft.com/en-us/graph/api/windowsupdates-updatableasset-enrollassets?view=graph-rest-beta&tabs=http

Write-Host ""
Write-Host "📥 Retrieving all devices from Intune..."

$devices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $devices += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

# Filter only Windows client devices managed by Intune
$ScopedDevices = $devices | Where-Object { $_.managementAgent -eq "mdm" -and $_.operatingSystem -like "Windows*"}
Write-Host ""
Write-Host "✅ Scoped devices found: $($ScopedDevices.Count)"

# === LOOP THROUGH DEVICES ===
foreach ($device in $ScopedDevices) {
    $deviceName = $device.deviceName
    $deviceId = $device.azureADDeviceId

    Write-Host ""
    Write-Host "🔍 Processing device: $deviceName ($deviceId)"

    #####################
    # Driver Updates
    #####################
        # Build JSON body for enrollment
        $body = @{
            updateCategory = "driver"
            assets = @(
                @{
                    "@odata.type" = "#microsoft.graph.windowsUpdates.azureADDevice"
                    id = $deviceId
                }
            )
        }
        $jsonBody = $body | ConvertTo-Json -Depth 5

        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/enrollAssets" `
            -Body $jsonBody `
            -ContentType "application/json"
}

#######################################################################################################
# Enroll Windows Client devices into WUfB AutoPatch with 'NotEnrolled' state (Quality Updates only)
#######################################################################################################
# https://learn.microsoft.com/en-us/graph/api/windowsupdates-updatableasset-enrollassets?view=graph-rest-beta&tabs=http

Write-Host ""
Write-Host "📥 Retrieving all devices from Intune..."

$devices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $devices += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

write-host "Get enrollment status for devices ... Please Wait !"
$StatusEnrollmentWUfB = Get-WUfBEnrollmentStatus

# Build a lookup dictionary from enrollment status for fast access
$StatusLookup = @{}
foreach ($entry in $StatusEnrollmentWUfB) {
    $StatusLookup[$entry.DeviceId] = $entry
}

# Filter: MDM-managed Windows devices that are NOT enrolled for 'feature' updates
$ScopedDevices = $devices | Where-Object {
    $_.managementAgent -eq "mdm" -and
    $_.operatingSystem -like "Windows*" -and
    $StatusLookup.ContainsKey($_.azureADDeviceId) -and
    $StatusLookup[$_.azureADDeviceId].EnrollmentStateQuality -eq "notEnrolled"   # filter for 'NotEnrolled' state. We don't want to include 'unenrolling', but let them finish first
}
Write-Host ""
Write-Host "✅ Scoped devices found: $($ScopedDevices.Count)"

# === LOOP THROUGH DEVICES ===
foreach ($device in $ScopedDevices) {
    $deviceName = $device.deviceName
    $deviceId = $device.azureADDeviceId

    Write-Host ""
    Write-Host "🔍 Processing device: $deviceName ($deviceId)"

    #####################
    # Quality Updates
    #####################
        # Build JSON body for enrollment
        $body = @{
            updateCategory = "quality"
            assets = @(
                @{
                    "@odata.type" = "#microsoft.graph.windowsUpdates.azureADDevice"
                    id = $deviceId
                }
            )
        }
        $jsonBody = $body | ConvertTo-Json -Depth 5

        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/enrollAssets" `
            -Body $jsonBody `
            -ContentType "application/json"
}

###################################################################################
# Enroll Windows Client devices into WUfB AutoPatch with 'NotEnrolled' state (Driver Updates only)
###################################################################################
# https://learn.microsoft.com/en-us/graph/api/windowsupdates-updatableasset-enrollassets?view=graph-rest-beta&tabs=http

Write-Host ""
Write-Host "📥 Retrieving all devices from Intune..."

$devices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $devices += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

write-host "Get enrollment status for devices ... Please Wait !"
$StatusEnrollmentWUfB = Get-WUfBEnrollmentStatus

# Build a lookup dictionary from enrollment status for fast access
$StatusLookup = @{}
foreach ($entry in $StatusEnrollmentWUfB) {
    $StatusLookup[$entry.DeviceId] = $entry
}

# Filter: MDM-managed Windows devices that are NOT enrolled for 'feature' updates
$ScopedDevices = $devices | Where-Object {
    $_.managementAgent -eq "mdm" -and
    $_.operatingSystem -like "Windows*" -and
    $StatusLookup.ContainsKey($_.azureADDeviceId) -and
    $StatusLookup[$_.azureADDeviceId].EnrollmentStateDriver -eq "notEnrolled"   # filter for 'NotEnrolled' state. We don't want to include 'unenrolling', but let them finish first
}
Write-Host ""
Write-Host "✅ Scoped devices found: $($ScopedDevices.Count)"

# === LOOP THROUGH DEVICES ===
foreach ($device in $ScopedDevices) {
    $deviceName = $device.deviceName
    $deviceId = $device.azureADDeviceId

    Write-Host ""
    Write-Host "🔍 Processing device: $deviceName ($deviceId)"

    #####################
    # Driver Updates
    #####################
        # Build JSON body for enrollment
        $body = @{
            updateCategory = "driver"
            assets = @(
                @{
                    "@odata.type" = "#microsoft.graph.windowsUpdates.azureADDevice"
                    id = $deviceId
                }
            )
        }
        $jsonBody = $body | ConvertTo-Json -Depth 5

        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/enrollAssets" `
            -Body $jsonBody `
            -ContentType "application/json"
}

###################################################################################
# Force Un-enroll Windows Servers from WUfB AutoPatch (Feature Updates, Quality, Drivers)
###################################################################################
# https://learn.microsoft.com/en-us/graph/api/windowsupdates-updatableasset-unenrollassets?view=graph-rest-beta&tabs=http

Write-Host ""
Write-Host "📥 Retrieving all devices from Intune..."

$devices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $devices += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

# Filter only Windows Servers devices (onboarded using MDE)
$ScopedDevices = $devices | Where-Object { $_.managementAgent -like "msSense" }
Write-Host ""
Write-Host "✅ Scoped devices found: $($ScopedDevices.Count)"

# === LOOP THROUGH DEVICES ===
foreach ($device in $ScopedDevices) {
    $deviceName = $device.deviceName
    $deviceId = $device.azureADDeviceId

    Write-Host ""
    Write-Host "🔍 Processing device: $deviceName ($deviceId)"

    # Build JSON body for (un)enrollment
    $body = @{
        updateCategory = "feature"
        assets = @(
            @{
                "@odata.type" = "#microsoft.graph.windowsUpdates.azureADDevice"
                id = $deviceId
            }
        )
    }
    $jsonBody = $body | ConvertTo-Json -Depth 5

    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/unenrollAssets" `
        -Body $jsonBody `
        -ContentType "application/json"

    # Build JSON body for (un)enrollment
    $body = @{
        updateCategory = "quality"
        assets = @(
            @{
                "@odata.type" = "#microsoft.graph.windowsUpdates.azureADDevice"
                id = $deviceId
            }
        )
    }
    $jsonBody = $body | ConvertTo-Json -Depth 5

    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/unenrollAssets" `
        -Body $jsonBody `
        -ContentType "application/json"

    # Build JSON body for (un)enrollment
    $body = @{
        updateCategory = "driver"
        assets = @(
            @{
                "@odata.type" = "#microsoft.graph.windowsUpdates.azureADDevice"
                id = $deviceId
            }
        )
    }
    $jsonBody = $body | ConvertTo-Json -Depth 5

    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/unenrollAssets" `
        -Body $jsonBody `
        -ContentType "application/json"
}


###################################################################################
# Force Delete ALL Windows Servers from WUfB AutoPatch
###################################################################################
# https://learn.microsoft.com/en-us/graph/api/windowsupdates-updatableasset-delete?view=graph-rest-beta&tabs=http

Write-Host ""
Write-Host "📥 Retrieving all devices from Intune..."

$devices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $devices += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

# Filter only Windows Servers devices (onboarded using MDE)
$ScopedDevices = $devices | Where-Object { $_.managementAgent -like "msSense" }
Write-Host ""
Write-Host "✅ Scoped devices found: $($ScopedDevices.Count)"

# === LOOP THROUGH DEVICES ===
foreach ($device in $ScopedDevices) {
    $deviceName = $device.deviceName
    $deviceId = $device.azureADDeviceId

    Write-Host ""
    Write-Host "🔍 Processing device: $deviceName ($deviceId)"

    Invoke-MgGraphRequest -Method DELETE `
        -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/$deviceId"
}
