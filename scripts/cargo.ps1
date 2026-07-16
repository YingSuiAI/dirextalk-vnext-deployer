$ErrorActionPreference = 'Stop'
$cargoArguments = @($args)
if ($cargoArguments.Count -eq 0) {
    throw 'Pass a Cargo command and its arguments.'
}

$pathEntries = @()
foreach ($pathSource in @(
    $env:Path,
    [Environment]::GetEnvironmentVariable('Path', 'User'),
    [Environment]::GetEnvironmentVariable('Path', 'Machine')
)) {
    foreach ($pathEntry in ($pathSource -split ';')) {
        $pathEntry = $pathEntry.Trim()
        if (-not [string]::IsNullOrWhiteSpace($pathEntry) -and $pathEntries -notcontains $pathEntry) {
            $pathEntries += $pathEntry
        }
    }
}
$env:Path = $pathEntries -join ';'

if (Get-Command link.exe -ErrorAction SilentlyContinue) {
    & cargo @cargoArguments
    exit $LASTEXITCODE
}

$gnuLinker = Get-Command x86_64-w64-mingw32-clang.exe -ErrorAction SilentlyContinue
if (-not $gnuLinker) {
    throw 'No supported Rust linker was found. Install Visual C++ Build Tools or user-scoped LLVM-MinGW.'
}

$gnuToolchain = '1.97.0-x86_64-pc-windows-gnu'
$installedToolchains = & rustup toolchain list
if (($installedToolchains -join "`n") -notmatch [regex]::Escape($gnuToolchain)) {
    throw "Rust toolchain $gnuToolchain is not installed."
}

$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = $gnuLinker.Source
$linkSelfContained = '-Clink-self-contained=yes'
if ([string]::IsNullOrWhiteSpace($env:RUSTFLAGS)) {
    $env:RUSTFLAGS = $linkSelfContained
} elseif ($env:RUSTFLAGS -notmatch [regex]::Escape($linkSelfContained)) {
    $env:RUSTFLAGS = "$($env:RUSTFLAGS) $linkSelfContained"
}

& rustup run $gnuToolchain cargo @cargoArguments
exit $LASTEXITCODE
