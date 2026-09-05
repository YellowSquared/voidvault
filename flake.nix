{
  description = "VoidVault: Zero-knowledge, blind password vault backed by WebAuthn PRF hardware attestation";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        voidvault-server = pkgs.rustPlatform.buildRustPackage {
          pname = "voidvault-server";
          version = "0.2.0";

          src = ./server;

          cargoLock = {
            lockFile = ./server/Cargo.lock;
          };

          meta = with pkgs.lib; {
            description = "VoidVault zero-knowledge password vault server daemon";
            homepage = "https://github.com/YellowSquared/voidvault";
            license = licenses.mit;
            mainProgram = "voidvault-server";
          };
        };

        default = voidvault-server;
      });

      apps = forAllSystems (pkgs: rec {
        voidvault-server = {
          type = "app";
          program = "${self.packages.${pkgs.system}.voidvault-server}/bin/voidvault-server";
        };
        default = voidvault-server;
      });

      nixosModules = rec {
        voidvault = { config, lib, pkgs, ... }:
          let
            cfg = config.services.voidvault;
          in
          {
            options.services.voidvault = {
              enable = lib.mkEnableOption "VoidVault zero-knowledge password vault server";

              package = lib.mkOption {
                type = lib.types.package;
                default = self.packages.${pkgs.stdenv.hostPlatform.system}.voidvault-server;
                description = "VoidVault server package to execute.";
              };

              port = lib.mkOption {
                type = lib.types.port;
                default = 8080;
                description = "Port the VoidVault server listens on.";
              };

              bindAddr = lib.mkOption {
                type = lib.types.str;
                default = "127.0.0.1";
                description = "IP address to bind the server to.";
              };

              dataDir = lib.mkOption {
                type = lib.types.path;
                default = "/var/lib/voidvault";
                description = "Directory for storing the encrypted SQLite database.";
              };

              logLevel = lib.mkOption {
                type = lib.types.str;
                default = "info,tower_http=info";
                description = "Log filter level (RUST_LOG syntax).";
              };
            };

            config = lib.mkIf cfg.enable {
              systemd.services.voidvault = {
                description = "VoidVault Zero-Knowledge Hardware Password Vault Server";
                wantedBy = [ "multi-user.target" ];
                after = [ "network-online.target" ];
                wants = [ "network-online.target" ];

                environment = {
                  PORT = toString cfg.port;
                  BIND_ADDR = "${cfg.bindAddr}:${toString cfg.port}";
                  DATABASE_PATH = "${cfg.dataDir}/voidvault.db";
                  RUST_LOG = cfg.logLevel;
                };

                serviceConfig = {
                  ExecStart = "${cfg.package}/bin/voidvault-server";
                  Restart = "always";
                  RestartSec = "5s";

                  StateDirectory = "voidvault";
                  WorkingDirectory = cfg.dataDir;

                  # Systemd Security Hardening
                  DynamicUser = true;
                  ProtectSystem = "strict";
                  ProtectHome = true;
                  PrivateTmp = true;
                  ProtectKernelTunables = true;
                  ProtectKernelModules = true;
                  ProtectControlGroups = true;
                  NoNewPrivileges = true;
                  CapabilityBoundingSet = "";
                };
              };
            };
          };

        default = voidvault;
      };
    };
}
