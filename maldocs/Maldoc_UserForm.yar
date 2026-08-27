





rule Contains_UserForm_Object
{
	meta:
		description = "Detect UserForm object in MS Office document"
		reference = "https://msdn.microsoft.com/en-us/library/office/gg264663.aspx"
		date = "2016-03-05"
		filetype = "Office documents"

	strings:
		$a = "UserForm1"
		$b = "TextBox1"
		$c = "Microsoft Forms 2.0"

	condition:
		all of them
}
