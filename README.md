# Homework3

1.
-k <key file> : A valid RSA key file matching the format you used for assignment two. For
rsa-sign this should be a private key file, for rsa-validate it will be a public key.
 -m <message file> : A file that you will hash using SHA256 and then sign the resulting
hash. You may assume that the key size of the RSA key is at least as large to contain a
SHA256 hash.
 -s <signature file> : The file where the output if rsa-sign is stored. For rsa-validate
this file will instead be an input, containing a signature to validate.
  
 2.
 
 -k <key file> : required, specifies a file storing a valid AES key as a hex encoded string
 -m <message file> : required, specifies the path of the message file is being store
 -t <output file> : required, specifies the path of the tag file, either as output for cbcmactag
or as an input for cbcmac-validate.
  
3. for generation the tag:
  -n <bit you want the key >: required, specifies the bit of the key
  -p <publickey>: required, specifies the public key u generate
  -s <secretKey>: required, specifies the secret key u generate
  -c <capublickey>: optional, when there exist a capublickey, you may use that
  
  for validation:
  -k <key file> : A valid RSA key file matching the format you used for assignment two. For
rsa-sign this should be a private key file, for rsa-validate it will be a public key.
 -m <message file> : A file that you will hash using SHA256 and then sign the resulting
hash. You may assume that the key size of the RSA key is at least as large to contain a
SHA256 hash.
 -s <signature file> : The file where the output if rsa-sign is stored. For rsa-validate
this file will instead be an input, containing a signature to validate.
  
4. 
lock.py -d newone -p unlockpublic -r lockprivate -vk capublic 


unlock.py -d newone -p lockpublic -r unlockprivate -vk capublic
