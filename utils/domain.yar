




rule domain {
strings:
        $domain_regex = /([\w\.-]+)/ wide ascii
    condition:
        $domain_regex
}
