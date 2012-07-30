# DV - Verify file hashes in the DNS

An experiment.

## Examples

### Normal operation

	$ ./example reference.file
		filename....: reference.file
		sha1........: 557db03de997c86a4a028e1ebd3a1ceb225be238
		ttl.........: 70900
		rdata.......: reference.file
		reason......: NOERROR
	file `reference.file' is valid

### Modify input file

	$ echo h >> reference.file
	$ ./example reference.file
		filename....: reference.file
		sha1........: c9477886d6d694b1b6dc17bfa04e4d81af0a1d6d
		ttl.........: 0
		rdata.......: 
		reason......: NXDOMAIN
	file `reference.file' is NOT valid: NXDOMAIN

### Same data, different name

	$ cp reference.file reference.bad
	$ ./example reference.bad 
		filename....: reference.bad
		sha1........: 557db03de997c86a4a028e1ebd3a1ceb225be238
		ttl.........: 70856
		rdata.......: reference.file
		reason......: NOERROR
	file `reference.bad' signature-state BAD (githash in DNS but filename not in rdata)

### Modify program

	$ echo 'hello foo' >> example
	$ strings - example | tail -1
	hello foo

	$ ./example reference.file
	Program file ./example has been modified. ABORT

