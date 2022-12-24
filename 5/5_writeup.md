# Task 5

Prompt:
![](../img/prompts/task_5.png)

Files:

- [Core dump of ssh-agent from the attacker's computer (core)](../orig_files/5/core)

- [ssh-agent binary from the attacker's computer. The computer was running Ubuntu 20.04. (ssh-agent)](../orig_files/5/ssh-agent)

- [Encrypted data file from the attacker's computer (data.enc)](../orig_files/5/data.enc)

This one was a pain.

Before we get diving into all of the files, I looked up how `ssh-agent` actually stored its private keys using Ubuntu 20.04 on google. You have to know what you're looking for before diving head-first, right?

I found these interesting links online that describe `ssh-agent`'s process of storing private keys in use:

[1] https://xorhash.gitlab.io/xhblog/0010.html

[2] https://github.com/openssh/openssh-portable/blob/master/sshkey.h

[3] https://github.com/openssh/openssh-portable/blob/master/ssh-rsa.c

The first link talk about using AES-256-CTR to encrypt and decrypt the key whenever it is needed. It is also stored in memory and has a length of `0x4000`.

The second link shows us the key struct that `ssh-agent` stores in memory. Now we know what format to look for in memory:

```c
struct sshkey {
	int	 type;
	int	 flags;
	/* KEY_RSA */
	RSA	*rsa;
	/* KEY_DSA */
	DSA	*dsa;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	int	 ecdsa_nid;	/* NID of curve */
	EC_KEY	*ecdsa;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_XMSS */
	char	*xmss_name;
	char	*xmss_filename;	/* for state file updates */
	void	*xmss_state;	/* depends on xmss_name, opaque */
	u_char	*xmss_sk;
	u_char	*xmss_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	char	*sk_application;
	uint8_t	sk_flags;
	struct sshbuf *sk_key_handle;
	struct sshbuf *sk_reserved;
	/* Certificates */
	struct sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	size_t	shielded_len;
	u_char	*shield_prekey;
	size_t	shield_prekey_len;
};
```

---

## Reversing

Let's start looking at the artifacts.

Taking a look at the core dump in Ghidra, we see this:
![](../img/5/ghidra_overview.png)

There's a few functions and a whole lot of hex.

From the links, we know that the key is encrypted with a randomly-generated prekey. This prekey, along with the encrypted private key, is stored in a struct within memory. Since we know the prekey's size is guaranteed to be 0x4000we can look for the value `00 40 00 00 00 00 00 00` in memory (8 bit value and also minding little endianness) and see if it looks to be in a struct-like section of memory:


![](../img/5/ghidra_hex_search_1.png)

Note: I used the "Bytes" viewing window for easier viewing.

Going through each occurrence, we see only one that looks like a struct and is 8 byte aligned:

![](../img/5/ghidra_hex_search_2.png)

The struct says that a pointer to the shield prekey is right before the prekey's length, so we can check address `0x55e1b79a4c00` and check that there is data there:

![](../img/5/ghidra_hex_search_4.png)

This non-zero part of memory does in fact go on for 0x4000 bytes, so there's a pretty good likelihood that this is what we are looking for!

We can also view the shielded private key by going to its pointer `0x55e1b79a3ab0`. When we go to that address in memory, we see this:

![](../img/5/ghidra_hex_search_3.png)

With these values, we can go ahead and start the process for decrypting the key.

---

## Unshielding the private key

The first article linked above tells us the exact procedure used to shield the private key. All we have to do is reverse the process. 

The first step is to calculate our key and IV to use. This is done by taking the SHA-512 hash of the entire prekey. The key is the first 32 bytes and the IV is the next 16.

Next, we have to decrypt the private key. After plugging the hardcoded values of the prekey (`prekey`) and encrypted private key (`private`) and some python code, we get our unencrypted private key:

Code:
```py
prekey_hash = hashlib.sha512(prekey).digest()

key = prekey_hash[:32]
iv = prekey_hash[32:48]

ctr = Counter.new(16*8, initial_value=bytes_to_long(iv))
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
final_key = cipher.decrypt(private)

print(final_key)
```

Result:
![](../img/5/unencrypted_private_key.png)

I was pretty confident that it worked because I could see the string "ssh-rsa" at the start, which is how the keys are normally formatted. This was the first time I had ever seen data like this, so it took me a long time to realize that it was serialized like the article said... *facepalm*

Anyways, after having that revelation, I manually parsed the data in python.

From the source code link (the third link above), we know the format of the private key from the `ssh_rsa_deserialize_private` function: `n`, `e`, `d`, `iqmp`, `p`, and `q`. With this, we can manually parse the serialized data and reconstruct the private key!

Code:
```py
key_format = ['type', 'n', 'e', 'd', 'iqmp', 'p', 'q']
key_dict = dict()
curr_label = 0
curr_byte = 0
while curr_byte < len(final_key):
    if final_key[curr_byte:] == b"\x01\x02\x03\x04\x05\x06\x07":
        curr_byte += 7
        break
    next_len = bytes_to_long(final_key[curr_byte: curr_byte+4])
    print(f"Reading next {next_len} bytes")
    curr_byte += 4
    data_read = final_key[curr_byte: curr_byte+next_len]
    curr_byte += next_len
    if key_format[curr_label] == 'type':
        key_dict[key_format[curr_label]] = data_read.decode()
    else:
        key_dict[key_format[curr_label]] = bytes_to_long(data_read)
    curr_label += 1

print(key_dict)
```

Result:
![](../img/5/key_dictionary.png)

Great, we have all the values sorted. Now we can use python's crypto library to generate an rsa private key with these values!

Code:
```py
key = RSA.construct((key_dict['n'], key_dict['e'], key_dict['d'], key_dict['p'], key_dict['q']))

print(key.exportKey().decode())

with open("privatekey.pem", "w") as f:
    f.write(key.exportKey().decode())
```

Result:
![](../img/5/rsa_private_key.png)

Awesome! We have the private key! Now we can decrypt the encrypted data file with the given command: `openssl pkeyutl -decrypt -inkey privatekey.pem -in data.enc`

![](../img/5/decrypted_file.png)

Perfect! We have a cookie used for a website! We can submit the `tok` cookie's value as the flag and move on!

Flag: `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTM1NzgxMjcsImV4cCI6MTY1NjE3MDEyNywic2VjIjoibTVlaEN5SmlZcFJSU0kyRE1RV2hOTTFqSUlFMUhpdVciLCJ1aWQiOjM2ODI4fQ.OtaP0CW65Wz565OeWHJxj7YIj1AKcSI9EkG3F2kBgfc`
![](../img/submissions/task_5_solve.png)

Final script:
```py
# Hardcoded bytestring values
prekey = <snip>
private = <snip>

prekey_hash = hashlib.sha512(prekey).digest()

key = prekey_hash[:32]
iv = prekey_hash[32:48]

ctr = Counter.new(16*8, initial_value=bytes_to_long(iv))
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
final_key = cipher.decrypt(private)

print(final_key)

key_format = ['type', 'n', 'e', 'd', 'iqmp', 'p', 'q']
key_dict = dict()
curr_label = 0
curr_byte = 0
while curr_byte < len(final_key):
    if final_key[curr_byte:] == b"\x01\x02\x03\x04\x05\x06\x07":
        curr_byte += 7
        break
    next_len = bytes_to_long(final_key[curr_byte: curr_byte+4])
    print(f"Reading next {next_len} bytes")
    curr_byte += 4
    data_read = final_key[curr_byte: curr_byte+next_len]
    curr_byte += next_len
    if key_format[curr_label] == 'type':
        key_dict[key_format[curr_label]] = data_read.decode()
    else:
        key_dict[key_format[curr_label]] = bytes_to_long(data_read)
    curr_label += 1

print(key_dict['p'] * key_dict['q'] == key_dict['n'])

print(key_dict)

key = RSA.construct((key_dict['n'], key_dict['e'], key_dict['d'], key_dict['p'], key_dict['q']))

print(key.exportKey().decode())

with open("privatekey.pem", "w") as f:
    f.write(key.exportKey().decode())
```