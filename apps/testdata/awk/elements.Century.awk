BEGIN { FS = OFS = "\t" }
$5 ~ /^17/ { $5 = "18th century" }
$5 ~ /^18/ { $5 = "19th century" }
{ print }
