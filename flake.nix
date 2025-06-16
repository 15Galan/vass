{
  description = "Tenable API and Python 3.13.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }: 
    let
      system = "x86_64-linux";

      pkgs = import nixpkgs {
        inherit system;
      # config.allowUnfree = true;   # Uncomment if private software is added
      };

      envPython = pkgs.python313.withPackages (
        ps: with ps;
        [
          matplotlib
          pip
          pytenable
          python-dotenv      # 'dotenv'
        ]
      );
    in {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = [
          envPython
          pkgs.git
        ];

        shellHook = ''
          echo "Entorno de desarrollo para la entrevista técnica de VASS."
	  '';
      };
    };
}
