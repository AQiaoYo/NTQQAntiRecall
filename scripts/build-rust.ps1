$ErrorActionPreference = "Stop"

$target = "x86_64-pc-windows-msvc"
$sysroot = (rustc --print sysroot).Trim()
$rustLld = Join-Path $sysroot "lib\rustlib\$target\bin\rust-lld.exe"

if (-not (Test-Path $rustLld)) {
    throw "rust-lld.exe not found: $rustLld"
}

$env:RUSTFLAGS = "-Clinker=$rustLld"
cargo build --release

Write-Host ""
Write-Host "Built:"
Write-Host "  target\release\NapCatWinBootMain.exe"
Write-Host "  target\release\NapCatWinBootHook.dll"

