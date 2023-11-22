BEGIN { FS = "\t" }
{ type[$6]++ }
END { for (name in type)
        print name ":" type[name] }
