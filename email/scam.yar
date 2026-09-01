




rule content : mail {
	meta:
		description = "Detects scam emails with phishing attachment."

	strings:
		$subject = "Asunto: Justificante de transferencia" nocase
		$body = "Adjunto justificante de transferencia"
	condition:
		all of them
}

rule attachment : mail {
	meta:
		description = "Detects scam emails with phishing attachment."
		test1 = "email/eml/transferencia1.eml"
		test2 = "email/eml/transferencia2.eml"

	strings:
		$filename = "filename=\"scan001.pdf.html\""
		$pleaseEnter = "NTAlNkMlNjUlNjElNzMlNjUlMjAlNjUlNkUlNzQlNjUlNzIlMjAlN"
		$emailReq = "NkQlNjUlNkUlNzQlMkUlNjklNkUlNjQlNjUlNzglMzIlMkUlNDUlNkQlNjElNjklNkMlM0I"
		$pAssign = "NzAlMjAlM0QlMjAlNjQlNkYlNjMlNzUlNkQlNjUlNkUlNzQlMkUlNjklNkUlNjQlNjUl"

	condition:
		all of them
}
