




rule with_urls : mail {
	meta:
		reference = "http://laboratorio.blogs.hispasec.com/"
		description = "Rule to detect the presence of an or several urls"
	strings:
                $eml_01 = "From:"
                $eml_02 = "To:"
                $eml_03 = "Subject:"

		$url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/
	condition:
		all of them
}

rule without_urls : mail {
	meta:
		reference = "http://laboratorio.blogs.hispasec.com/"
		description = "Rule to detect the no presence of any url"
	strings:
                $eml_01 = "From:"
                $eml_02 = "To:"
                $eml_03 = "Subject:"

		$url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/
	condition:
                all of ( $eml_* ) and
		not $url_regex
}
