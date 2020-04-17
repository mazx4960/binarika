rule Oh_No_Its_Meterpreter
{
	meta:
		author = "0316"
		description = "Oh no, it's meterpreter!"
	strings:
		$a = "stdapi_"
		$b = { 6D 65 74 73 72 76 2E 64 6C 6C 00 00 52 65 66 6C 65 63 74 69 76 65 4C 6F 61 64 65 72 }

	condition:
		$a and $b
}