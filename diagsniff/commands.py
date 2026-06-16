from __future__ import annotations
from .models import CaptureConfig, DeviceType



def build_fortigate_sniffer(cfg: CaptureConfig) -> str:
    count = 0 if cfg.interactive else cfg.count
    return (
        f"diagnose sniffer packet {cfg.interface} "
        f"'{cfg.filter_expr}' {cfg.verbosity} {count}"
    )



def build_fortiweb_sniffer(cfg: CaptureConfig) -> str:
    count = 0 if cfg.interactive else cfg.count
    return (
        f"diagnose network sniffer {cfg.interface} "
        f"'{cfg.filter_expr}' {cfg.verbosity} {count}"
    )


from typing import Optional


def build_fortiweb_tls_debug_enable(
    ssl_debug_level: int = 255,
    client_ip: Optional[str] = None,
    server_ip: Optional[str] = None,
    pserver_ip: Optional[str] = None,
) -> list[str]:
 
    cmds = [
        "diagnose debug reset",
        "diagnose debug flow filter flow-detail 4",
    ]
    
    if client_ip:
        cmds.append(f"diagnose debug flow filter client-ip {client_ip}")
    if server_ip:
        cmds.append(f"diagnose debug flow filter server-ip {server_ip}")
    if pserver_ip:
        cmds.append(f"diagnose debug flow filter pserver-ip {pserver_ip}")
    
    cmds.append("diagnose debug flow trace start")
    
    cmds.append("diagnose debug enable")
    
    return cmds


def build_fortiweb_tls_debug_disable() -> list[str]:

    return [
        "diagnose debug flow trace stop",
        "diagnose debug flow filter reset",
        "diagnose debug disable",
        "diagnose debug reset",
    ]



def build_sniffer_command(device_type: DeviceType, cfg: CaptureConfig) -> str:
    """Return the correct sniffer command string for the given device type."""
    builders = {
        "fortigate": build_fortigate_sniffer,
        "fortiweb":  build_fortiweb_sniffer,
    }
    builder = builders.get(device_type)
    if builder is None:
        raise ValueError(f"Unknown device type: {device_type!r}")
    return builder(cfg)
