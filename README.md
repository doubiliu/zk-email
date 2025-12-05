# ZK-email Toolkit



## MPC usage process
Stage 1:
1) `go run mpccmd.go phase1 init --output <phase1 file path>`, this command is used to generate the phase1 initial file;
2) `go run mpccmd.go phase1 contribute --input <prev phase1 file path> --output <curr phase1 file path>`, this command is used by participants in this round to calculate phase1 data;
3) `go run mpccmd.go phase1 verify --input <prev phase1 file path> --output <curr phase1 file path>`, this command is used by other participants to verify phase1 data.

Repeat steps 2-3 in a loop until all participants complete the calculation and verification work of phase1.

Stage 1.5:
- `go run mpccmd.go phase1 seal --input <filepath>  --output <filepath>`, this command is used to output SRS parameters for Stage 2 initialization.

Stage 2:
1) `go run mpccmd.go phase2 init --srs <srs file path> --output <phase2 file path> --mailType <type> --ccs <filepath>`, this command is used to generate the phase2 initial file,and we support four types of email addresses("gmail","icloud","outlook","foxmail");
2) `go run mpccmd.go phase2 contribute --input <prev phase2 file path> --output <curr phase2 file path>`, this command is used by participants in this round to calculate phase2 data;
3) `go run mpccmd.go phase2 verify --input <prev phase2 file path> --output <curr phase2 file path>`, this command is used by other participants to verify phase2 data.

Repeat steps 2-3 in a loop until all participants complete the calculation and verification work of phase2.

Export contract:
- `go run mpccmd.go seal --srs <filepath> --input <phase2 file path> --contract <filepath> --pk <filepath> --vk <filepath> --ccs <filepath>`, this command is used to export verification contracts after mpc has completed.

## Calculate a zk-proof
`go run mpccmd.go proof --pk <filepath> --vk <filepath> --mailType <type> --ccs <filepath> --rsaPuKey <filepath> --dkimData <filepath> `,This command can be used to calculate the zkp certificate of zk-email. 

## Use Case
1) The user uses his registered email address to send any email to his other email addresses and obtains the source file of the email (which needs to contain a DKIM signature)
2) The user constructs a new string according to the template corresponding to the email service provider in the 'template.go' file and replaces its relevant fields and DKIM signature.
3) The user sends the string to the following website (https://www.appmaildev.com/site/testfile/dkim?lang=en) to verify whether the data format is normal. If the DKIM detection item is displayed (or DKIM-Result: fail (signature verified) appears), it means the verification is passed.
4) The user writes the verified string into a separate txt file
5) The user uses the 'dig TXT selector.domainkey.domain' command to query the DKIM public key, and the query results are written into a separate text file
6) The user uses the proof command to calculate the final proof, and the proof is sent to the chain.