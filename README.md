# Bitcoin Address Generation Server
1. Generate Bitcoin segwit address with the provided seed and address index
2. Generate Bitcoin multi-sig p2sh address with the provided public keys, n, and m

### Build
```
$ cd hdwallet
$ make build
```

### Create Seed file
```
// To start app, you need to create a seed file(.seed) at the same path as the current running executable
$ ./hdwallet seed

// This password needs to be used for starting app
Please type your seed password:
xxxxx

.seed file was created successfully!
encrypted seed: ...
```

### Quick Start
```
// 1. build
$ cd hdwallet
$ make build

// 2. make seed
$ cd target/release
$ ./hdwallet seed

// 3. type password
Please type your seed password:
xxxxx

// 4. start app
$ ./hdwallet
Please type your seed password:
xxxxx
```

### Test
```
$ cd hdwallet
$ make test
```

### REST API
With basic authentication, you can call the below APIs. `-H 'Authorization: Basic Yml0Y29pbjpuYWthbW90b3NhdG9zaGk='`
needs to be put in command like in example.

*Generate Bitcoin segwit address with the provided seed and address index*

* Path: /hd-segwit-address
* Request Method: POST
* Content-Type: application/json
* JSON Body

| Field          | Type                  | Desc                                    |
|----------------|-----------------------|-----------------------------------------|
| mainnet        | boolean               | mainnet: true, testnet: false           |
| address_index  | number                | Addresses are numbered from index 0 in increasing way which is described in BIP44            |

> BIP44 defines the following 5 levels in BIP32 path:
> m/purpose'/coin_type'/account'/change/address_index
>
> In this app, HD wallet address will be generated using m/44H/0H/0H/0/address_index
> in which address_index is from user input

*Generate Bitcoin multi-sig p2sh address with the provided public keys, n, and m*

* Path: /multi-sig-address
* Request Method: POST
* Content-Type: application/json
* JSON Body

| Field          | Type                  | Desc                                    |
|----------------|-----------------------|-----------------------------------------|
| mainnet        | boolean               | mainnet: true, testnet: false           |
| n              | number                | n in n-of-m multi-sig. This is minimum number of public keys to sign the transaction.             |
| m              | number                | m in n-of-m multi-sig. This number must match the size of public keys.            |
| public_keys    | string[]              | Public keys are used to generate multi-sig p2sh address            |

### Example
```
// get segwit address by specifiyng address index 
$ curl -H 'Content-Type:application/json' -H 'Authorization: Basic Yml0Y29pbjpuYWthbW90b3NhdG9zaGk=' \
-d '{"mainnet": true, "address_index":5}' \
-X POST http://localhost:8000/hd-segwit-address

// get multi sig address by providing threshold and public keys
$ curl -H 'Content-Type:application/json' -H 'Authorization: Basic Yml0Y29pbjpuYWthbW90b3NhdG9zaGk=' \
-d '{"mainnet": true, "n":2, "m":3, "public_keys": ["03b5807b167a4950e883ee383194a1e7ae0804d312b68f303743a9f3a19c3029cf", "032fc4366e9eab6f4a879035e25f4c8b3bf7aece95e6ddd2e325d95fb9660c5fbf", "02ab1d0cf83b59a605add3bb3cff58844271373a56f20eadac93d6ee0723ab516d"]}' \
-X POST http://localhost:8000/multi-sig-address
```

### Build and open Document
```
$ make doc
```

### Topic: What is the best way(s) to provide the seed onto this server?
If you need to load the seed from the file, the .seed file has to have the encrypted seed, considering when stolen.
After creating .seed file, the encrypted seed needs to be stored in the safe hardware disk such as USB.
It would be safer to delete .seed file right after starting application.
For example, encrypted seed can be converted to QR code and printed on the paper which is kept in the safety vault. 
This could be the safest, but it requires offline environment and some manual operations. 

If you use cloud service such as AWS, you could also put the seed onto the secret manager.
In this way, we could keep it safe and avoid some offline manual operations. 