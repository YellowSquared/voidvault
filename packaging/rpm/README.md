# VoidVault RPM Packaging

This directory contains the RPM packaging specifications and build automation for `voidvault` on Red Hat Enterprise Linux (RHEL), Fedora, CentOS Stream, Rocky Linux, AlmaLinux, and openSUSE.

---

## 1. Directory Layout

- [`voidvault.spec`](./voidvault.spec): Canonical RPM spec file defining package metadata, architecture, dependencies, and file layout.
- [`build-rpm.sh`](./build-rpm.sh): Automated one-shot build script that compiles, strips, packages, and verifies the `.rpm` in `dist/`.

---

## 2. Building the RPM Locally

### Prerequisites
- Rust & Cargo (`rustc >= 1.75`)
- RPM build tools:
  - Fedora / RHEL / CentOS: `sudo dnf install -y rpm-build`
  - Debian / Ubuntu: `sudo apt-get install -y rpm`
  - openSUSE: `sudo zypper install -y rpm-build`

### Build Command
Run the build script from anywhere in the repository:
```bash
./packaging/rpm/build-rpm.sh
```

The resulting package will be output to:
```text
dist/voidvault-0.2.0-1.x86_64.rpm
```

---

## 3. Installing the Package

### Fedora / RHEL / CentOS / Rocky Linux / AlmaLinux:
```bash
sudo dnf install ./dist/voidvault-0.2.0-1.x86_64.rpm
```

### openSUSE:
```bash
sudo zypper install ./dist/voidvault-0.2.0-1.x86_64.rpm
```

### Direct RPM verification:
```bash
rpm -qip ./dist/voidvault-0.2.0-1.x86_64.rpm
voidvault --version
```

---

## 4. Alternative: CI / `cargo-generate-rpm`

`cli/Cargo.toml` is also preconfigured for `cargo-generate-rpm`:
```bash
cargo install cargo-generate-rpm
cargo build --release --manifest-path cli/Cargo.toml
cargo generate-rpm --manifest-path cli/Cargo.toml
```

---

## 5. Fedora Copr Repository (Optional Continuous Delivery)

To distribute automated updates to Fedora and EPEL users:
1. Initialize a project on [Fedora Copr](https://copr.fedorainfracloud.org/) named `voidvault`.
2. Configure Copr webhook pointing to GitHub repository releases.
3. Users can enable and install via:
   ```bash
   sudo dnf copr enable yellowsquared/voidvault
   sudo dnf install voidvault
   ```
