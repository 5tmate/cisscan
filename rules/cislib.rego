package cislib

import rego.v1

name(resource) := object.get(resource, "_name", "<unnamed>")

collected(t) if t in object.get(object.get(input, "meta", {}), "collected_types", [])

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)

now_ns := time.parse_rfc3339_ns(input.meta.scanned_at)

days_ns(d) := d * 86400000000000

known_timestamp(ts) if {
	is_string(ts)
	not ts in {"N/A", "not_supported", "no_information", ""}
}

older_than(ts, d) if {
	known_timestamp(ts)
	time.parse_rfc3339_ns(ts) < now_ns - days_ns(d)
}
