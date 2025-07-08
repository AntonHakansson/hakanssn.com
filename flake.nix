{
  description = "hakanssn webserver";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }: {
    packages.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.callPackage ./default.nix {};
    nixosModules.hakanssn-webserver = import ./modules/hakanssn-webserver.nix;
    nixosModules.default = self.nixosModules.hakanssn-webserver;
  };
}
