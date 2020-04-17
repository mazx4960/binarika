rule Cmd_detected
{
	meta:
		author = "Desmond"
		description = "Oh no, it's cmd!"
	strings:
		$a = "AUAVAWH"

	condition:
		$a
}
