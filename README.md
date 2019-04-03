# A-file-transfer-tool-based-on-TFTP-protocol-over-TCP-with-Encryption-enhancement
In this project, I realize a file transfer tool based on TFTP protocol over TCP with encryption enhancement. T
hough the TFTP protocol is mainly for UDP, the TFTP itself doesn’t rely on any network protocol specifically. 
We put it on TCP to get better stability in network transfer, so we don’t have to do the housekeeping in TFTP when realized over UDP.
   
The tool has a FileServer ,a FileClient and a KeyTool. 
The file transfer protocol is almost the same as in TFTP as described in RFC1350, except for the packet length and the encryption operation. 
And also we only handle one error condition that is file can’t be created or found for the sake of simplicity.   
First we don’t have to worry about packet lost in the transfer, because TCP will do the retransmit work for us. 
So no timeout and retransmit is done in our code. And second, we enlarge the package length from 512 to 4096 bytes, so that we can transmit more data in every send. And also, we only use 1 byte to record the serial number of the package, so it will wrap around when getting to 256. And last, we use RSA and RC4 algorithm to protect the communication between client and server. The usage of the tool is as below:
We use the keyTool to generate a pair of RSA 1024 keys. And save the private kets and public kets separately in pr.txt and pk.txt. 
Place pk.txt with FileClient and pri.tx with FileServer
Start FileSErver Use FileClient just as some TFTP client with the following command line arguments:
./FileClient <ipaddress>  -get|-put  <filename>
Here ‘-get’ means download file from server, while ‘ –put’  means upload file to server. And the ‘ipaddress’  is the ip of the server. The ‘filename’ is the name of the file to be transferred.
