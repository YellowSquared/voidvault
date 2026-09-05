Name:           voidvault
Version:        0.2.0
Release:        1%{?dist}
Summary:        Zero-knowledge FIDO2 hardware attestation password vault CLI
Group:          Applications/System
License:        MIT
URL:            https://github.com/YellowSquared/voidvault
Source0:        https://github.com/YellowSquared/voidvault/archive/v%{version}/voidvault-%{version}.tar.gz

# Architectures supported
ExclusiveArch:  x86_64 aarch64

# Disable debuginfo package generation for pre-stripped Rust binary
%define debug_package %{nil}

%description
VoidVault is a minimalist, blind zero-knowledge password vault CLI with full
WebAuthn PRF parity. It stores encrypted credentials locally in unified
.voidvault capsules and optionally synchronizes blindly with self-hosted
VoidVault relay instances.

Features:
- Full WebAuthn PRF & AES-256-GCM authenticated encryption.
- Multi-keyslot envelope with simulated PRF for headless automation and dev workflows.
- Blind server relay synchronization with optimistic locking (409 conflict detection).
- Unified .voidvault cross-platform capsule interoperability (Firefox, Linux, Windows, macOS).
- Strict manual password ingress with active guards against shell history leaks.

%prep
# Binary packaging prep

%build
# Build step handled prior to packaging

%install
mkdir -p %{buildroot}%{_bindir}
install -p -m 0755 %{_sourcedir}/voidvault %{buildroot}%{_bindir}/voidvault

%files
%{_bindir}/voidvault

%changelog
* Sat Sep 05 2026 Andrey Bezrukavyi <yesq2@tutamail.com> - 0.2.0-1
- Initial RPM package release for VoidVault CLI
- Multi-keyslot capsule envelope and strict manual password ingress guard
