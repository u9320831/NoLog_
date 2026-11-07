use std::env;
use std::io::Read;
use std::path::Path;
use std::process::Command;

const PROGRAM_FILES_X86: &str = "ProgramFiles(x86)";
const VCTOOLS_DEFAULT_PATH: &str = "VC\\Auxiliary\\Build\\Microsoft.VCToolsVersion.default.txt";
const MSVC_PATH: &str = "VC\\Tools\\MSVC";
const ENCLAVE_LIB_PATH: &str = "lib\\x64\\enclave";
const UCRT_LIB_PATH: &str = "ucrt_enclave\\x64\\ucrt.lib";

const SDK_SCRIPT: &str = r#"& {
    $kits_root_10 = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows Kits\Installed Roots\" -Name KitsRoot10).KitsRoot10
    $sdk = Get-ChildItem -Path "$($kits_root_10)Lib" -Directory |
        Where-Object { Test-Path (Join-Path $_.FullName "ucrt_enclave\x64\ucrt.lib") } |
        Sort-Object Name -Descending |
        Select-Object -First 1
    if (-not $sdk) { throw "Aucun SDK Windows avec ucrt_enclave.lib n'a ete trouve" }
    Write-Output $sdk.FullName
}"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-arg=/OPT:REF,ICF");
    println!("cargo:rustc-link-arg=/ENTRY:dllmain");
    println!("cargo:rustc-link-arg=/MERGE:.edata=.rdata");
    println!("cargo:rustc-link-arg=/MERGE:.rustc=.data");
    println!("cargo:rustc-link-arg=/INTEGRITYCHECK");
    println!("cargo:rustc-link-arg=/enclave");
    println!("cargo:rustc-link-arg=/GUARD:MIXED");
    println!("cargo:rustc-link-arg=/include:__enclave_config");

    let program_files_x86 = env::var(PROGRAM_FILES_X86)?;

    let sdk_output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", SDK_SCRIPT])
        .output()?;

    if !sdk_output.status.success() {
        return Err(format!(
            "impossible de trouver le SDK Windows: {}",
            String::from_utf8_lossy(&sdk_output.stderr)
        )
        .into());
    }

    let sdk_path = String::from_utf8(sdk_output.stdout)?.trim().to_owned();

    let vswhere =
        Path::new(&program_files_x86).join("Microsoft Visual Studio\\Installer\\vswhere.exe");

    let vswhere_output = Command::new(vswhere)
        .args([
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ])
        .output()?;

    let install_path = String::from_utf8(vswhere_output.stdout)?.trim().to_owned();
    let install_path = Path::new(&install_path);

    let mut default_path = String::new();
    std::fs::File::open(install_path.join(VCTOOLS_DEFAULT_PATH))?
        .read_to_string(&mut default_path)?;

    let enclave_lib_path = install_path
        .join(MSVC_PATH)
        .join(default_path.trim())
        .join(ENCLAVE_LIB_PATH);

    println!(
        "cargo:rustc-link-arg={}",
        Path::new(&sdk_path).join(UCRT_LIB_PATH).display()
    );
    println!(
        "cargo:rustc-link-arg={}",
        enclave_lib_path.join("libvcruntime.lib").display()
    );
    println!(
        "cargo:rustc-link-arg={}",
        enclave_lib_path.join("libcmt.lib").display()
    );
    println!("cargo:rustc-link-arg=vertdll.lib");
    println!("cargo:rustc-link-arg=bcrypt.lib");

    Ok(())
}
