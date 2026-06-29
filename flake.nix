# SPDX-FileCopyrightText: 2021 Serokell <https://serokell.io/>
#
# SPDX-License-Identifier: CC0-1.0
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          # ecdsa is a transitive dependency (via bip-utils / ecpy) and is
          # flagged insecure in nixpkgs due to a known timing side-channel.
          config.permittedInsecurePackages = [ "python3.13-ecdsa-0.19.2" ];
        };
        python = pkgs.python3;

        # xrpl-py is not packaged in nixpkgs, so build it from PyPI.
        # All of its runtime dependencies are available in nixpkgs.
        xrpl-py = python.pkgs.buildPythonPackage rec {
          pname = "xrpl-py";
          version = "4.5.0";
          pyproject = true;

          src = pkgs.fetchPypi {
            pname = "xrpl_py";
            inherit version;
            hash = "sha256-PuJfy3SL32r+GKrY90unH/ojv2gUCf2jqesCnkOB/HQ=";
          };

          build-system = [ python.pkgs.poetry-core ];

          dependencies = with python.pkgs; [
            deprecated
            ecpy
            base58
            httpx
            pycryptodome
            types-deprecated
            typing-extensions
            websockets
          ];

          pythonImportsCheck = [ "xrpl" ];
          doCheck = false;
        };

        pythonEnv = python.withPackages (ps: [
          xrpl-py
          ps.bip-utils
          ps.mnemonic
          ps.base58
        ]);
      in {
        devShells.default = pkgs.mkShell {
          packages = [
            pythonEnv
            pkgs.nodejs
            # Rust toolchain for the xrp-key-to-address crate.
            pkgs.cargo
            pkgs.rustc
          ];

          # `xrpl-rust` pulls in `openssl-sys`, which needs pkg-config to
          # locate a system OpenSSL at build time.
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.openssl ];
        };
      });
}
