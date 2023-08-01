signature dpd_njrat {
    ip-proto == tcp
    payload /^[0-9]+\x00(ll|proc|rss|rs|rsc|kl|inf|prof|rn|inv|ret|CAP|P|un|up|RG|nwpr|site|fun|IEhome|shutdowncomputer|restartcomputer|logoff|ErrorMsg|peech|BepX|piano|OpenCD|CloseCD|EnableKM|DisableKM|TurnOnMonitor|TurnOffMonitor|NormalMouse|ReverseMouse|EnableCMD|DisableCMD|EnableRegistry|DisableRegistry|EnableRestore|DisableRestore|CursorShow|CursorHide|sendmusicplay|OpenSite|dos|udp|udpstp|pingstop|pas)\|/
    enable "spicy_NJRAT"
}