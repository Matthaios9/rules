









import "androguard"

rule Trojan_Droidjack
{
condition:
androguard.package_name("net.droidjack.server") or androguard.activity(/net.droidjack.server/i)
}
