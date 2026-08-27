









import "androguard"

rule backdoor: dropper
{
	meta:
		description = "This rule detects fake samples with a backdoor/dropper"
		sample = "0c3bc51952c71e5bb05c35346005da3baa098faf3911b9b45c3487844de9f539"
		source = "https://koodous.com/rulesets/1765"

	condition:
		androguard.url("http://sys.wksnkys7.com")
		or androguard.url("http://sys.hdyfhpoi.com")
		or androguard.url("http://sys.syllyq1n.com")
		or androguard.url("http://sys.aedxdrcb.com")
		or androguard.url("http://sys.aedxdrcb.com")
}