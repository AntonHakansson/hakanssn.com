{ stdenv, autoPatchelfHook, python3, pandoc }:

stdenv.mkDerivation {
  pname = "hakanssn.com";
  version = "0.0.1";
  src = ./.;

  buildInputs = [ ];
  nativeBuildInputs = [ autoPatchelfHook python3 pandoc ];

  preConfigure = ''
    patchShebangs ./build.sh
  '';
  buildPhase = ''
    runHook preBuild
    python3 generate.py
    gcc main.c -o hakanssn.com -O2 -fsanitize=undefined
    runHook postBuild
  '';
  installPhase = ''
    runHook preInstall
    install -D hakanssn.com $out/bin/hakanssn.com
    runHook postInstall
  '';
}
