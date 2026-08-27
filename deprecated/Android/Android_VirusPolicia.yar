









import "androguard"

rule BaDoink : official android
{
		meta:
		reference = "https://koodous.com/"
		description = "Virus de la Policia - android"
		sample = "9bc0fb0f05bbf25507104a4eb74e8066b194a8e6a57670957c0ad1af92189921"

	strings:




		$type_a_1 ="6589y459gj4058rt"

		$type_b_1 = "Q,hu4P#hT;U!XO7T,uD"
		$type_b_2 = "+Gkwg#M!lf>Laq&+J{lg"






	condition:
		androguard.app_name("BaDoink") or

		$type_a_1 or
		all of ($type_b*)


}
