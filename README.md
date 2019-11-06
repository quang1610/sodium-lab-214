# sodium-lab-CSC214
Experiment with sodium library

Some comment on the layout of message:

1. Session message:

notice that the session message has fixed length = SESSION_MESSAGE_LEN defined in utility.c

  a. encrypted session message: |encrypted message||nonce|
  
  b. decrypted session message (original): |padding|%|principal 1|%|principal 2|%|time_stamp|%|Kab|
  
2. Normal message (messages that are sent between Alice and Bob:

  encrypted message: |nonce||8 bytes for length of message||encrypted message|
  
3. time_stamp:

  layout of timestamp is: YYYYMMDDHHMinMinSS
  
