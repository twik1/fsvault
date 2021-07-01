# fsvault
Live forensic filesystem vault

This is a tool to help collecting files and directories during live forensics.
It will automatically help with things like checksum calculation, full path information, system information
and filesystem information.

To aid a sqlite db is created for each vault which is added to the archive.
The db will contain information about the system the files are collected from, 'there can be only one'.
It also contain the full path for each file including the drive letter or the root slash.

Filesystem information for the files added to the fsvault is also collected and stored in the db.
For filesystem with extended file attributes this is also collected.

Finally also MD5 and SHA256 checksums are calculated for each file added to the fsvault archive.

This is all done automatically, all you need to do is to add a file or directory to the vault.
The tool is cross-platform and works for Linux, Windows and Mac OS.

```
#fsvault -a <dir> or <file> <vault.zip>
#fsvault -l <vault.zip>
#fsvault -h
```
