






rule chinese_spam_spreader : webshell
{
    meta:
        date        = "2016/07/18"
        description = "Catches chinese PHP spam files (autospreaders)"
    strings:
        $a = "User-Agent: aQ0O010O"
        $b = "<font color='red'><b>Connection Error!</b></font>"
        $c = /if ?\(\$_POST\[Submit\]\) ?{/
    condition:
        all of them
}

rule chinese_spam_echoer : webshell
{
    meta:
        date        = "2016/07/18"
        description = "Catches chinese PHP spam files (printers)"
    strings:
        $a = "set_time_limit(0)"
        $b = "date_default_timezone_set('PRC');"
        $c = "$Content_mb;"
        $d = "/index.php?host="
    condition:
        all of them
}
