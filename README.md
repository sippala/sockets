# sockets 
Parts of code have been taken from Internet and modified, I don't take complete ownership of this code, credit to those who did. 

Client and Server socket programs to replicate Telnet/SSH sessions. After succesful Authentication, Client sends a command (like pwd, cp etc) that server receives, executes it and replies back so you aren't SSHing into the machine actually but getting things done as SSH does. 

There are two folders/directories 
1) without_encryption - This has client and server files without the use of key based encryption but uses password hashing.

To compile client and server, use:  gcc -o client client.c -lssl -lcrypto (same for server)

Usage-   ./server port password.txt  

         ./client localhost port username password 
 
 username and password here are Silva and ManCity respectively (case sensitive)
             
•	Silva and the sha1 hash of ManCity are specified in the password.txt file, if the client sends any other username/password combination, server will not start a connection. 
•	5 simultaneous connections can be done i.e server can connect to multiple clients this number can be increased by changing the value in msock() function in server.c
•	If multiple connections are made with the server, all clients will be talking to same server port.
•	There is a file in each of these directories named encrypted and unencrypted, they are the tcpdump files for respective connections. 

2) with_encryption - This use basic key based encryption/decryption and  password hashing.

usage - ./en_server port password.txt 

        ./en_client localhost port username password
        
• password.txt file has the same combination as above but client takes the username and encrypts it before sending whereas the server decrypts the username received from client before comparing it with the one that is present in password.txt file 
• If username and password combination has to be changed, specify a new username and find the sha1 hash of the new password, change the values accordingly in password.txt

There is room for imporvement in this, as of now this code ust encrypts the username but sends other info in clear text, I'm working on ssl to do end to end encryption. 
