




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

	strings:
		$filename = "filename=\"scan001.pdf.html\""
		$pleaseEnter = "NTAlNkMlNjUlNjElNzMlNjUlMjAlNjUlNkUlNzQlNjUlNzIlMjAlN"
		$emailReq = "NkQlNjUlNkUlNzQlMkUlNjklNkUlNjQlNjUlNzglMzIlMkUlNDUlNkQlNjElNjklNkMlM0I"
		$pAssign = "NzAlMjAlM0QlMjAlNjQlNkYlNjMlNzUlNkQlNjUlNkUlNzQlMkUlNjklNkUlNjQlNjUl"

	condition:
		all of them
}
