# Bloom-Filter-Hash

Tain a set of Bloom Filters to help reduce the charset needed when brute forcing a password.


## Install

```bash
pip install bloom-filter-hash
```

## Train Filters

Create the set of bloom filters for passwords of length 2 using the charset of lowercase letters. (Default hashing algorithm is sha256, and default location to store the filters is `./pretrained_filters`)

#### Using Command Line

```bash
bloom-hash train "abcdefghijklmnopqrstuvwxyz" 2
```

#### Using Python Package

```python
from bloom_filter_hash import train

train(
    "abcdefghijklmnopqrstuvwxyz",
    password_length=2,
)
```

## Break Hash

Break the hash for the following sha256 hashed password `ab` using our pre-created filters above.

### Using Command Line

```bash
bloom-hash break fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603 --hash-alg sha256
```

### Using Python Package

```python
from bloom_filter_hash import break_hash

password = break_hash(
    'fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603', 
    'sha256', 
)
print(password)
```

## Methodology

### Memory Requirements

Storage of pre-created hash lists can require very large amounts of storage. For example if we wanted to store all alphanumeric passwords of length 6 using sha256.

We have:
* Character set: 62 (lowercase + 26 uppercase + 10 digits = **62 alphanumeric characters**)
* Password length: 6
* One hash is 32 bytes
* One password is 6 bytes (approx 1 byte per char)

Therefore in total you would need $62^6 * (32+6) \approx 2.15*10^{12}\ bytes \approx 2\ Terabytes$

The approximate equivalent for storing all the hashes into a bloom filter (with error rate of 1%) is 

$$
m = -\frac{n\ln p}{(\ln2)^2} = -\frac{62^6\ln 0.01}{(\ln2)^2} \approx 5.44 * 10^{11}\ bits \approx 68\ Gigabytes
$$

Where:
* $n$ = Number of elements in the filter
* $p$ = Desired false-positive rate (1%)

So as we can see the memory requirements is almost 4% of the full pre-computed hash list.

### How it works

Using the efficient storage of bloom filters we can build up a set of filters to try and reduce the amount of work needed to brute force a password hash.

This works by creating a family of filters.
1. Given a charset, password length, and hashing algorithm
2.  Iterate through all password combinations in the charset 
3. For each char in the password, we add that hash to the corresponding bloom filter that stores all hashes that contain that specific char.
    * For example: We has password "aab", so the we add the hash to 2 different bloom filters that store all passwords of length 3:
        * Bloom filter for passwords that contain "a"
        * Bloom filter for passwords that contain "b"

Then to break a hash we check to see if the password has been seen in any of our pre-created filters, therefore leaving us with a massively reduced charset to brute force through.

## TODO:
* Save some pretrained filters in a branch
* Add method to try break multiples hashes at once
* Have option to generate HashCat commands for brute forcing to utilize the efficiencies in HashCat
* Extend to custom hashing algorithms?
