{
  description = "komodo-ops dev environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            python3
            bc
          ];

          shellHook = ''
            git config core.hooksPath .githooks

            if [ ! -f .githooks/secrets-patterns ]; then
              cp .githooks/secrets-patterns.example .githooks/secrets-patterns
              echo "Created .githooks/secrets-patterns from example. Edit it to add your private patterns."
            fi
          '';
        };
      });
    };
}
