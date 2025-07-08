{ config, lib, pkgs, ... }:

let
  cfg = config.services.hakanssn-webserver;
  hakanssn-webserver = pkgs.callPackage ../default.nix {};
in
{
  options.services.hakanssn-webserver = {
    enable = lib.mkEnableOption "hakanssn personal webserver";

    port = lib.mkOption {
      type = lib.types.port;
      default = 8000;
      description = "Port to listen on";
      readOnly = true;
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "hakanssn-web";
      description = "User to run the service as";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "hakanssn-web";
      description = "Group to run the service as";
    };

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/hakanssn-webserver";
      description = "Directory to store data";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to open the firewall for the webserver port";
    };
  };

  config = lib.mkIf cfg.enable {
    # Create user and group
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = cfg.dataDir;
      createHome = true;
    };

    users.groups.${cfg.group} = {};

    # Open firewall
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

    # Systemd service
    systemd.services.hakanssn-webserver = {
      description = "hakanssn personal webserver";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        Restart = "always";
        RestartSec = "10s";

        # Security hardening
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadWritePaths = [ cfg.dataDir ];

        # Network restrictions
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];

        # Capabilities
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        AmbientCapabilities = lib.mkIf (cfg.port < 1024) [ "CAP_NET_BIND_SERVICE" ];

        ExecStart = "${hakanssn-webserver}/bin/hakanssn.com";
        WorkingDirectory = cfg.dataDir;
      };

      environment = {
        PORT = toString cfg.port;
      };
    };
  };
}
