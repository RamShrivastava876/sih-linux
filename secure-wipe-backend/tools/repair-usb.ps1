param(
    [Parameter(Mandatory=$true)]
    [int]$DiskNumber,
    [ValidateSet('exFAT','NTFS')]
    [string]$FileSystem = 'exFAT',
    [string]$Label = 'USB'
)

# Safety: require elevation
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Error 'Run this script in an elevated PowerShell (Run as Administrator).'
    exit 1
}

# Show target info
$disk = Get-Disk -Number $DiskNumber -ErrorAction SilentlyContinue
if (-not $disk) { Write-Error "Disk $DiskNumber not found"; exit 1 }
Write-Host "Target Disk: $($disk.Number)  Size: $([math]::Round($disk.Size/1MB,2)) MB  BusType: $($disk.BusType)  IsSystem: $($disk.IsSystem)" -ForegroundColor Cyan
if ($disk.IsSystem -or $disk.IsBoot) {
    Write-Error 'Refusing to operate on a System/Boot disk.'
    exit 1
}

# Helper: small test format block
function New-UsbVolume {
    param([Microsoft.Management.Infrastructure.CimInstance]$d, [string]$fs, [string]$label)
    # Try MBR first
    try {
        Write-Host 'Attempting MBR path...' -ForegroundColor Yellow
        $null = $d | Set-Disk -IsReadOnly $false -IsOffline $false -ErrorAction SilentlyContinue
        $null = $d | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false -ErrorAction SilentlyContinue
        $null = $d | Initialize-Disk -PartitionStyle MBR -ErrorAction Stop
        $part = New-Partition -DiskNumber $d.Number -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
        $letter = ($part | Get-Partition).DriveLetter
        $vol = Format-Volume -DriveLetter $letter -FileSystem $fs -NewFileSystemLabel $label -Quick -Force -Confirm:$false -ErrorAction Stop
        return $true
    } catch {
        Write-Warning ("MBR path failed: " + $_.Exception.Message)
    }
    # GPT fallback
    try {
        Write-Host 'Attempting GPT fallback...' -ForegroundColor Yellow
        $null = $d | Set-Disk -IsReadOnly $false -IsOffline $false -ErrorAction SilentlyContinue
        $null = $d | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false -ErrorAction SilentlyContinue
        $null = $d | Initialize-Disk -PartitionStyle GPT -ErrorAction Stop
        $part = New-Partition -DiskNumber $d.Number -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
        $letter = ($part | Get-Partition).DriveLetter
        $vol = Format-Volume -DriveLetter $letter -FileSystem $fs -NewFileSystemLabel $label -Quick -Force -Confirm:$false -ErrorAction Stop
        return $true
    } catch {
        Write-Warning ("GPT path failed: " + $_.Exception.Message)
    }
    return $false
}

# Try requested FS, then fallback FS
if (-not (New-UsbVolume -d $disk -fs $FileSystem -label $Label)) {
    $fallback = if ($FileSystem -eq 'exFAT') { 'NTFS' } else { 'exFAT' }
    Write-Host "Trying filesystem fallback: $fallback" -ForegroundColor Yellow
    if (-not (New-UsbVolume -d $disk -fs $fallback -label $Label)) {
        Write-Error 'Both MBR and GPT paths failed.'
        # Show disk details to aid diagnosis
        Get-Disk -Number $DiskNumber | Format-List -Property *
        Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue | Format-List -Property *
        exit 2
    }
}

# Final report
$final = Get-Disk -Number $DiskNumber
$sizeMB = [math]::Round($final.Size/1MB,2)
Write-Host "Success. Disk now shows: $sizeMB MB" -ForegroundColor Green
Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue | Get-Volume | Select-Object DriveLetter,FileSystemLabel,FileSystem,AllocationUnitSize,Size,SizeRemaining | Format-Table -AutoSize