import "pe"
import "console"

// these rules attempt to use the console.log to print the pe section for the match
// credit to wxs for the rules

rule network_detect_string {
  strings:
    $a1 = "Error connecting baz:"
  condition:
    for all of ($a*): (
      $ and (console.log(pe.sections[pe.section_index(@)].name))
    )
}

rule network_detect_magic_bytes {
  strings:
    // little endian
    $a0 = {19 80 14 06}
  condition:
    for all of ($a*): (
      $ and (console.log(pe.sections[pe.section_index(@)].name))
    )
}
