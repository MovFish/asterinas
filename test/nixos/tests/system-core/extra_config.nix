{
  lib,
  pkgs,
  ...
}:

{
  services.udev.enable = lib.mkForce true;
  services.udev.extraHwdb = ''
    # Asterinas NixOS hwdb placeholder
  '';

  environment.systemPackages = with pkgs; [
    fish
    zsh
    busybox
    fastfetch
    lsof
    ncdu
    procps
    coreutils
    diffutils
    findutils
    gnugrep
    net-tools
    less
    man-pages
    util-linux
    which
    (pkgs.writeShellScriptBin "asterinas-udev-mem-test" (
      builtins.readFile ../../../initramfs/src/regression/udev/run_test.sh
    ))
    (pkgs.writeShellScriptBin "asterinas-udev-mem-processed-test" (
      builtins.readFile ../../../initramfs/src/regression/udev/processed_test.sh
    ))
  ];
}
