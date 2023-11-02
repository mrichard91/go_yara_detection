rule network_detect_partial_GET {
    strings:
        $a = "GET /foo"
    condition:
        $a
}

rule network_detect_full_GET {
    strings:
        $a = "GET /foo HTTP/1.1"
    condition:
        $a
}

rule network_detect_full_GET_fullword {
    strings:
        $a = "GET /foo" fullword
    condition:
        $a
}

rule network_detect_c2_domain {
    strings:
        $a = "doesthispersonexist.com"
    condition:
        $a
}

rule network_detect_c2_ipv6 {
    strings:
        $a = "2606:4700:3035::ac43:cf7b"
    condition:
        $a
}

rule network_detect_magic {
    strings:
        // little endian
        $a = {19 80 14 06}
    condition:
        any of them
}

rule network_detect_error_message_string {
    strings:
        $a = "Error connecting baz:"
    condition:
        $a
}

rule detect_go_binary_buildid {
    strings:
        // https://cs.opensource.google/go/go/+/refs/tags/go1.21.1:src/cmd/internal/buildid/buildid.go;l=240
        $a = "\xff Go build ID: "
        $elf = "Go\x00\x00"
    condition:
        (uint16(0) == 0x5a4d and $a in (0x400..0x1200)) or 
        ($elf in (0..0x1000)) or
        ($a in (0..0x2000)) or
        (uint32(0) == 0x6d736100) and $a in (0..1024)
}