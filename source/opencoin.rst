#################
opencoin protocol
#################


*******************
About this document
*******************


Status of this Memo
===================

This draft is work in heavy progress. Do not consider it's content 
stable in any sense as long as this note is present. Get in touch with 
opencoin.org [1]_ and fetch a recent copy [TBD].


Copyright
=========

Copyright (2012,2013) N. Toedtmann, J. H. Baach, J. K. Muennich, J. Suhr.

Abstract
========

This document describes the OpenCoin protocol which seeks to implement 
David Chaum's concept of digital cash [2]_.


Contents
========

.. contents::
   :depth: 4

************
Introduction
************


Entities
========

Opencoin consists of the following entities:

    * **Currency** is defined by an issuer and it can be used for various 
      use cases (e.g. digital cash, balloting, vouchers)
 
    * **Issuer** defines a currency and provides the following
      services/data:

        * **Certificate Authority (CA)**: masterkey, CDD ("currency description
          document")

        * **Mint** is a service which signs blinded payload hashes and creates 
          blinded signatures
   
        * **Double Spending Data Base (DSDB)** stores the serials (and 
          potentially signatures) of all renewed coins in order to 
          prevent its double spending. WHO IS QUERING THE DSDB? THE 
          MINT, SERVICE OR AUTHORIZER?

        * Issuer services are:
     
            * **Information** provides information of the issuer and 
              currency (e.g. CDDs, mint key certificates, certificate 
              revocation list (CRL))

            * **Validate** is used by clients to request coins without 
              having coins already. Usually the validate service may ask
              the Authorizer whether to approve or reject particular 
              requests. This service is usually used to convert value of
              another payment system to opencoin.

            * **Renew** is used by clients to renew existing coins. The 
              client needs to provide valid coins and blinds of the same 
              total value. The Renew service validates against the DSDB 
              and in the valid case mints the provided blinds. Usually 
              clients who received coins during a transaction are 
              supposed to call this service to ensure the received coins
              are valid (and not spend before).

            * **Invalidate** converts valid coins into a different payment 
              system.
    
        * **Authorizer** verifies validation requests and responds to the 
          mint with an authorization or rejection. This component may 
          interface with other payment/account systems in order to 
          convert value from another payment system to the particular 
          currency.

    * **Client** is the application of a user which interacts with the 
      other entities. It manages the wallet.

    * **Tokens** are payloads, blinds, and coins. Their lifecycle is:

        * Client: creates yet unsigned payload ("blank") 

        * Client: ==[padded hash]==> payload hash
   
        * Client: ==[blind]==> blinded payload hash ("blind")
   
        * Mint: ==[sign]==>       signature of blinded payload hash 
                            a.k.a blind signature of payload hash
                            a.k.a ("blind signature")
                       
        * Client: ==[unblind]==>  signature of payload hash
   
        * Client: ==[combine with unsigned payload]==> signed payload 
                                                       a.k.a. "coin"
  
    * **Payload** is prepared by the client (and while it doesn't have a 
      signature it's called "blank")
  
    * Blind is the blinded padded hash of a payload. It is send from 
      the client to the mint.
  
    * Coin consists of a payload and the mint's signature of the 
      particular payload.
  
    * Wallet is a file which contains tokens (e.g. coins) and is managed
      by the client.



Order of actions/messages
=========================

    * Alice should fetch and verify CDD [revocation check of master key]
    * Alice should fetch and verify current Mintkeys [revocation check]
    * Alice creates new payloads ("blanks")
    * Alice requests validation [authorization might happen here]
    * Mint responds with signatures [or delay]
    * Alice unblinds and verifies signatures
    * Alice attaches signatures to payloads (results in coins)

    * Alice sends coins to Bob
    * (Bob might respond "received" to Alice. Trusted case.)
    * If not cached, Bob fetches and verify CDD. [revocation check of 
                                                  master key]
    * Bob selects preferred denominations for new coins.
    * Bob should fetch and verify mint key certificates associated with 
      selected denominations and received coins, if not cached. 
      [revocation check] To mitigate traffic analysis, client may want 
      to fetch more keys than required.
    * Bob verifies coins using mint key
    * Bob creates new payloads
    * Bob requests renewal
    * Mint signs blinds
    * Mint writes old coins in dsdb
        * Instant response:
            * Mint responds with signatures
            * Bob unblinds and verifies signatures
            * Bob attaches signatures to payloads (->coins)
            * (Bob might respond OK to Alice)
        * Delayed response:
            * Mint responds with 'delayed'
            * (Bob might respond OK to Alice)
            * Bob requests resume
            * Mint responds with signatures
            * Bob unblinds and verifies signatures
            * Bob attaches signatures to payloads (->coins)
            * (Bob might respond OK to Alice)
    * Bob requests invalidate (with authorizer or payment (?) message)
    * Issuer stores old coins in dsdb
    * Issuer responds with OK (and does whatever is required)



The bigger picture
==================


Because a picture says more then 1000 words:

.. seqdiag:: opencoin.diag



************
The protocol
************


Generic container format
========================


struct <name> = {

        type: "<type name>",
            *some explaination*

        <type-dependent field> [, <type-dependent field>[...]]
            *even more explaination*

}


General conventions
===================


Limits
------

The following limits are defined to allow clients handling data more easily.
    
    * Maximum list length = 2^16 entries. Lists are not sorted unless 
      mentioned explicitly. It is used for denominations and service URLs for instance.
    
    * signed (?) integers (weights, denomination, display factor) = 
      4 bytes (32 bit)
      
    * String length = 2^16 bytes
    
    * Date: UTC


Encodings
---------

    * date: ISO8601, extended format, always UTC, 
      e.g. 2009-01-01T12:00:00Z
    
    * URL
    
    * BigInts are encoded as hex 

    * Integer in their decimal presentation
    
    * crypto_random_number: 128 bit, high entropy random number, hexstring


Container signing
-----------------

This is the format for signing the container.
    
struct: SignedContainer = {
    type = string
        we have specific signed container types with individual names
    
    <name> = container
        the actual container is stored under a specific name
        
    signature = signature
        hexstring(padded_hash(bencode_serialized(container)))

}


Container encryption
--------------------

Mandatory: Container encryption DRAFT

SHOULD WE INCLUDE A NONCE RESP. ITS RESPONSE IN ORDER TO PREVENT REPLAY 
ATTACKS?

There are RFC drafts with the same goal. These might be worth 
considering:

    * https://tools.ietf.org/html/draft-jones-json-web-signature-04
    * https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-05
    * https://tools.ietf.org/html/draft-rescorla-jsms-00
    * https://tools.ietf.org/html/draft-jones-json-web-encryption-json-serialization-02
    * OCSP/CRL of mint key certificates. Should be empty in normal case.
    * wallet
    * Glue certificates


Encrypted container structure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

struct encrypted  = {
    
    type = "encrypted" 
        encypt + sign

    reference = string

    cipher = string
        'aes'

    data = ???
        crypt(container)

}


Rules
-----

    * UTF-8 encoding. 

    * exact all fields are required but some may be empty if mentioned 
      in the spec. All field names are unique [[we don't want double 
      fields, or unlimited additional fields. People who want to "abuse"
      the CDD should use additional info field]]


Issuer side containers
======================


Public Keys
-----------

Even though the actual public key definitions are specified somewhere else,
the examples are given using RSA, because thats what we use in the examples below.

Public Key structure
~~~~~~~~~~~~~~~~~~~~

struct: PublicKey = {

    type = "rsa public key"
        ..

    modulus = hexstring
        ..

    public_exponent = hexstring
        ..

}


Public Key JSON Example
~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "modulus": "becac6b3d8c588a2a0601261bb9b9ad82427122dc0fef1053e6d9c74126dff3bf",
        "public_exponent": "10001",
        "type": "rsa public key"
    }



The currency description document (CDD)
---------------------------------------

For simplicity reasons, the terminology defines a CDD as containing a 
signature/certificate.


CDD struct
~~~~~~~~~~

struct: CDD  = {
            
    type = "cdd"
        ..
    
    protocol version = URL
        An URL to the protocol standard being used for the coin.
    
    cdd location = URL
        This is not an identifier. This URL is required to be 
        embedded in payloads. 
        (DOES IT NEED TO BE UNIQUE FOR EACH CDD AND VERSION?)
      
    cdd serial number = positive integer, incremental 
        Purpose is to distinguish different versions of a CDD
      
    cdd signing date = date
        ..

    cdd expiry date = date or None 
        We want to allow a controlled rollover, temporary systems. This is 
        the expiry date of the CDD.
    
    currency name = string
        e.g. Open Cent
    
    currency divisor = positive integer 
        value/display divisor == display value in unit display name; For 
        instance a divisor of 100 to express cent values for Euro or Dollar
      
    info service = weighted_list_of_URLs
        [[weight,URL],...]
        
        Weighted to also allows round-robin, but also proper preference. The 
        info service is for:

            * CDDs
        
            * mint key certificates
        
            * certificate revocation list (CRL)
        
            * icons and other funky shiny stuff
    
    validation_service = weighted_list_of_URLs 
        [[weight,URL],...]

        Where to send the validation messages
    
    renewal_service = weighted_list_of_URLs
        [[weight,URL],...]
    
    invalidation_service = weighted_list_of_URLs
        [[weight,URL],...]
    
    denominations = list_of_integers
        [1, 2, 5, 10, 20, 50, 100...]
        
        negative denominations may be allowed but clients may not be able 
        to handle it and reject the currency
      
    issuer_cipher_suite = string
        HASH-SIGN-BLINDING
    
        example: SHA512-RSA-CHAUM83

    issuer_public_master_key = JSON dict construct
        This depends on used crypto algorithm. 
        
        it seems that the only valid identifier of the currency is 
        the master key. A shorter hash of this key may be displayed to
        allow its manual verification by users. This key MUST be 
        changed if hash or signing algorithm changes.]]
      
    additional info = string or None
        there might be additions
        
}


CDD certificate (CDDC) structure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

struct: CDDC = {

    type =  "cdd certificate"
        ..
 
    cdd = cdd
        ..

    signature = signature
        ..

}


CDD JSON Example
~~~~~~~~~~~~~~~~

A complete CDD serialized into JSON may look like this::

    {
        "type" : "cdd certificate",
        "cdd" : {
            "protocol_version": "http://opencoin.org/1.0",
            "cdd_location": "http://opencent.org",
            "issuer_cipher_suite": "RSA-SHA512-CHAUM86",
            "issuer_public_master_key": {
                "modulus": "becac6b3d8c588a2a0601261bb9b9ad82427122dc0fef1053e6d9c74126dff3bf",
                "public_exponent": "10001",
                "type": "rsa public key"
            },
            "cdd_serial": 1,
            "cdd_signing_date": "2012-12-30T10:46:00Z",
            "cdd_expiry_date": "2014-12-31T22:59:59Z",
            "currency_name": "OpenCent",
            "currency_divisor": 100,
            "info_service": [[10,"http://opencent.org"]],
            "validation_service": [[10,"http://opencent.org"],
                                   [20,"http://opencent.com/validate"]],
            "renewal_service": [[10,"http://opencent.org"]],
            "invalidation_service": [[10,"http://opencent.org"]],
            "denominations": [1,2,5],
            "additional_info": "",
            "type": "cdd"
        },
        "signature" : "8a48179b4666e573a75a9e9cbc5de1d2e0ce5c68f8e869c40160badebc6442cc8"
    }


The minting keys
----------------

For simplicity reasons, the terminology defines a mint key as containing 
a signature/certificate.


Minting Key struct
~~~~~~~~~~~~~~~~~~

struct: mint key = {

    type = "mint key"
        ..

    id = hexstring(hash(public mint key))  
        MUST be verified when receiving a mint_key. 
        [[Why? Isn't the signature sufficient ?]]

    issuer_id  = hexstring
        hexstring(hash(public master key))

    cdd_serial = integer
        Allows unique relation to CDD version but may be ignored by clients
        for now.

    public_mint_key = PublicKey
        depending on used crypto suite.

    denomination = integer 
        The actual denomination is calculated by dividing this denomination
        with the currency_divisor of the CDD.

    sign_coins_not_before = Date
        ..

    sign_coins_not_after  = Date
        ..

    coins_expiry_date     = Date
        ..

}


Minting Key Certificate structure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

struct: mint key certificate = {

    type = "mint key certificate"
        ..

    mint_key = mint key
        ..

    signature = signature
        The mint key is signed with the issuer master key.

}

Minting Key Certificate JSON example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {        
        "mint_key": {
            "id": "ae2f918e6eea72816a3be9709486da22f58e9ec16e40c896ac947a0b976ed452",
            "issuer_id": "6897de0948d16e72556dfe70b21c49ba20e9d334313ab3cc779e5fee676a9c87",
            "cdd_serial": 1,
            "public_mint_key": {
                "modulus": "83f904a772c613a45b611c6e0ccb9cd49325edd5d362491d6f9c951ef6261fd7d",
                "public_exponent": "10001",
                "type": "rsa public key"
            },
            "denomination": 1,
            "sign_coins_not_before": "2013-01-01T00:00:00Z",
            "sign_coins_not_after": "2013-06-30T00:00:00Z",
            "coins_expiry_date": "2013-12-31T00:00:00Z",
            "type": "mint key"
        },
        "signature": "8e04d53fca6fd57c1bf1d7bfdec9996494956511ddda54315827cdbb9b30e5e29",
        "type": "mint key certificate"
    }


Tokens
======


Payload
-------


Payload structure
~~~~~~~~~~~~~~~~~

struct: payload = {
    
    type = "payload"
        ..

    protocol_version    = URL
        http://opencoin.org/OpenCoinProtocol/1.0
    
    issuer_id = string
        hexstring(hash(public master key))

    cdd_location        = URL
        http://opencent.net/OpenCent 
        
        Hint to download the CDD if not available anyway. 
        Useful for clients to "bootstrap" a yet unknown currency.

    denomination = integer
        Only a hint, not verified value. Denomination MUST be verified by 
        checking the mint key's denomination.

    mint_key_id = hexstring
        hexstring(hash(public mint key)) 
        
        The hex encoded hash of the issuer's public key. It may differ 
        depending on denomination, validity period and currency.

    serial = hexstring
        hexstring(128bit random number)
        
        This random value is generated by clients. It is used to 
        identify coins and prevent double spending. Once the coin is spent,
        the serial will be stored in the issuer's DSDB. Because of its 
        sufficient long length it is supposed to be unique for each 
        coin. A high entropy (crypto grade quality) is important.

}


Payload JSON example
~~~~~~~~~~~~~~~~~~~~

::

    {        
        "protocol_version": "http://opencoin.org/1.0",
        "issuer_id": "6897de0948d16e72556dfe70b21c49ba20e9d334313ab3cc779e5fee676a9c87",
        "cdd_location": "http://opencent.org",
        "denomination": 5,
        "mint_key_id": "0ff9bdc16eea8b9ff636b9289962ea95b849fd79c98febacab33170e1f4b038d",
        "serial": "b7204e667d09e176e4f6e3504ec7b465",
        "type": "payload"
    }


Blind
-----

The main element of a blind is the blinded payload hash, which is 
created by:

    * serialize the payload (using bencode [3]_)
    * hash the serialized data
    * apply the rsa blinding operation to the hash.


Blind structure
~~~~~~~~~~~~~~~

struct: blind = {

    type = "blinded payload hash"
        ..

    reference = integer 
        To be chosen by client in order to reference between blinded 
        payload and blind signature. Can be random or incremental but 
        should be unique within one gwop.

        MUST NOT be derived from serial number or blinded factor.

    blinded_payload_hash = hexstring
        hexstring(blind(prepare_signing(hash(serialize(payload)))))

        RSA_blind(BigInt(hash(serialize(payload))))
        ECC_blind(ECC_Point(hash(serialize(payload))))

    mint_key_id  = hexstring
        hexstring(hash(public mint key))  
        
        The client should select a random mint key (for the appropriate 
        denomination) to prevent the issuer from smuggling in tracking
        information by using a particular key.

}


Blind JSON example
~~~~~~~~~~~~~~~~~~

::

    {
        "reference": "r_0",
        "blinded_payload_hash": "2aed4b188576b94f8898909d8e75707dc7a48951579508930a946a4acd5454e87",
        "mint_key_id": "ae2f918e6eea72816a3be9709486da22f58e9ec16e40c896ac947a0b976ed452",
        "type": "blinded payload hash"
    }


Blind signature
---------------


Blind signature structure
~~~~~~~~~~~~~~~~~~~~~~~~~

struct: blind signature = {

    type = "blind signature"
        ..
    
    reference = integer
        ..
    
    blind_signature = hexstring
        hexstring(signature(blinded_payload_hash))

}

Blind signature JSON example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "reference": "r_0",
        "blind_signature": "337c6f69953d91c39fa0913a6fdc8c916d40ddf82a86f733aa501e2b8f2b9519b",
        "type": "blind signature"
    } 

Coin
----

Coin structure
~~~~~~~~~~~~~~

struct: coin = {

    type      = "coin"
        ..

    payload     = payload
        ..

    signature = hexstring
        hexstring(unblind(blind_signature)) 

        A hex encoded RSA signature from the issuer (it's private key) over 
        the SHA-256 hash of the payload.

}


Coin JSON example
~~~~~~~~~~~~~~~~~

::
    
    {
        "payload": {
            "protocol_version": "http://opencoin.org/1.0",
            "issuer_id": "6897de0948d16e72556dfe70b21c49ba20e9d334313ab3cc779e5fee676a9c87",
            "cdd_location": "http://opencent.org",
            "denomination": 5,
            "mint_key_id": "0ff9bdc16eea8b9ff636b9289962ea95b849fd79c98febacab33170e1f4b038d",
            "serial": "b7204e667d09e176e4f6e3504ec7b465",
            "type": "payload"
        },
        "signature": "6f942455e0c154adadbec13873366ce682dd5e3d03540cf05424d33f1e0b95fc0",
        "type": "coin"
    }


Message Types
=============

Request CDD Serial
------------------

Requests the currently active serial number.

Request CDD Serial structure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

struct: request_cdd_serial = {

    type =  "Request cdd serial" 
        Request the serial of latest CDD

    message_reference: integer
        Client internal message reference

}


Request CDD Serial JSON example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "message_reference": 0,
        "type": "request cdd serial"
    }


Response CDD Serial
-------------------

Gives the currently active cdd serial number.

Response CDD serial structure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

struct: response_cdd_serial = {

    type =  "response cdd serial"
        ..

    message_reference = integer
        ..

    status_code = integer
        ..

    status_description = string
        ..

    cdd_serial = integer
        ..

}


Response CDD serial JSON example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "message_reference": 0,
        "status_code": 200,
        "status_description": "ok",
        "cdd_serial": 1,
        "type": "response cdd serial"
    }


Request CDD
-----------

Request a currency description document (CDD).


Request CDD structure
~~~~~~~~~~~~~~~~~~~~~

struct: request_cdd  = {
    
    type = "request cdd"
        ..
    
    message_reference = integer
        ..

    cdd_serial = integer 
        not null to fetch specific cdd version

}


Request CDD JSON example
~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "message_reference": 1,
        "cdd_serial": 1,
        "type": "request cdd"
    }


Response CDD
------------

Returns the Currency Description Document.


Response CDD structure
~~~~~~~~~~~~~~~~~~~~~~


struct: response_cdd = {
    
    type = "response cdd"
        ..

    message_reference = integer
        ..

    status_code = integer
        ..
    
    status_description = string
        ..

    cdd = cddc
        ..

}


Response CDD JSON example
~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "message_reference": 1,
        "status_code": 200,
        "status_description": "ok",
        "cdd": {
            "cdd": {
                "protocol_version": "http://opencoin.org/1.0",
                "cdd_location": "http://opencent.org",
                "issuer_cipher_suite": "RSA-SHA512-CHAUM86",
                "issuer_public_master_key": {
                    "modulus": "becac6b3d8c588a2a0601261bb9b9ad82427122dc0fef1053e6d9c74126dff3bf",
                    "public_exponent": "10001",
                    "type": "rsa public key"
                },
                "cdd_serial": 1,
                "cdd_signing_date": "2012-12-30T10:46:00Z",
                "cdd_expiry_date": "2014-12-31T22:59:59Z",
                "currency_name": "OpenCent",
                "currency_divisor": 100,
                "info_service": [[10,"http://opencent.org"]],
                "validation_service": [[10,"http://opencent.org"],
                                       [20,"http://opencent.com/validate"]],
                "renewal_service": [[10,"http://opencent.org"]],
                "invalidation_service": [[10,"http://opencent.org"]],
                "denominations": [1,2,5],
                "additional_info": "",
                "type": "cdd"
            },
            "signature": "8a48179b4666e573a75a9e9cbc5de1d2e0ce5c68f8e869c40160badebc6442cc8",
            "type": "cdd certificate"
        },
        "type": "response cdd"
    }


Request Mint Keys
-----------------

Request the minting keys.

Request Mint Keys structure
~~~~~~~~~~~~~~~~~~~~~~~~~~~

struct: request_mint_keys = {

    type = 'request mint keys'
        ..

    message_reference = integer
        ..

    mint_key_ids = [mint_key_id,mint_key_id]
        for specific keys

    denominations:[d,d,d]
        for most recent version
        
        If both fields are empty, all latest mint keys will be responded. 
        If both are provided, all current keys for the particular 
        denominations as well as the mint keys with the specific ID will 
        be provided.

}

Request Mint Keys JSON example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "message_reference": 2,
        "mint_key_ids": [
            "ae2f918e6eea72816a3be9709486da22f58e9ec16e40c896ac947a0b976ed452"
        ],
        "denominations": [],
        "type": "request mint keys"
    }

Response Mint Keys
------------------

Return the minting keys.

Response Mint Keys structure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~


struct: response_mint_keys = {
    type = "response mint keys"
        ..

    message_reference = integer
        ..

    status_code = integer
        ..

    status_description = string
        ..

    keys = [mint_key_certificate,mint_key_certificate]
        ..

}


Response Mint Keys JSON example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "message_reference": 2,
        "status_code": 200,
        "status_description": "ok",
        "keys": [
            {
                "mint_key": {
                    "id": "ae2f918e6eea72816a3be9709486da22f58e9ec16e40c896ac947a0b976ed452",
                    "issuer_id": "6897de0948d16e72556dfe70b21c49ba20e9d334313ab3cc779e5fee676a9c87",
                    "cdd_serial": 1,
                    "public_mint_key": {
                        "modulus": "83f904a772c613a45b611c6e0ccb9cd49325edd5d362491d6f9c951ef6261fd7d",
                        "public_exponent": "10001",
                        "type": "rsa public key"
                    },
                    "denomination": 1,
                    "sign_coins_not_before": "2013-01-01T00:00:00Z",
                    "sign_coins_not_after": "2013-06-30T00:00:00Z",
                    "coins_expiry_date": "2013-12-31T00:00:00Z",
                    "type": "mint key"
                },
                "signature": "8e04d53fca6fd57c1bf1d7bfdec9996494956511ddda54315827cdbb9b30e5e29",
                "type": "mint key certificate"
            }
        ],
        "type": "response mint keys"
    }

Request Validation 
------------------

Request the validation of blinds. This is the case of 
withdrawing cash from the atm. The user needs to authenticate 
themselfs, most likely using a method outside the opencoin protocol,
e.g. using ssl client certificates.


Request Validation structure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

struct: request_validation = {

    type = "request validation"
        ..

    message_reference = integer
        ..

    transaction_reference = hexstring
        crypto_random_number

    authorization_info = string
        ...

    blinds = [n blinds]
        ...

}


Request Validation JSON example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "message_reference": 5,
        "transaction_reference": "c6524415dc6a6a29e5906592152986ca",
        "authorization_info": "my secret",
        "blinds": [
            {
                "reference": "r_0",
                "blinded_payload_hash": "2aed4b188576b94f8898909d8e75707dc7a48951579508930a946a4acd5454e87",
                "mint_key_id": "ae2f918e6eea72816a3be9709486da22f58e9ec16e40c896ac947a0b976ed452",
                "type": "blinded payload hash"
            },
            {
                "reference": "r_1",
                "blinded_payload_hash": "607aa7019c620f096ea9baeb5985113b95fb1d1cfd57ae7eb02fee873ee478e95",
                "mint_key_id": "198c351fd446898285f3c6af4e5c85d86ac23cb3dd016f3f2794983d2a1a10c1",
                "type": "blinded payload hash"
            },
            {
                "reference": "r_2",
                "blinded_payload_hash": "8298671d55e63ff31e47a040b990ac14be2909f77c4612e0a58d05f0057812c4f",
                "mint_key_id": "198c351fd446898285f3c6af4e5c85d86ac23cb3dd016f3f2794983d2a1a10c1",
                "type": "blinded payload hash"
            },
            {
                "reference": "r_3",
                "blinded_payload_hash": "862e3ccc95bfe69524b7ee7db720c915fb02faf9b641909ef29c674d6cf044d2",
                "mint_key_id": "0ff9bdc16eea8b9ff636b9289962ea95b849fd79c98febacab33170e1f4b038d",
                "type": "blinded payload hash"
            }
        ],
        "type": "request validation"
    }


Response Minting
----------------

Return the blind signatures for the blinds given in either
a Request Minting or Request Renewal request.


Response Minting structure
~~~~~~~~~~~~~~~~~~~~~~~~~~

struct: response_minting  = {

    type = "response minting"
        ..

    message_reference = integer
        ..

    status_code = integer
        ..

    status_description = string
        ..

    retry_after: Datetime
        not empty if status 3XX / timestamp instead or for asynchronous
        communication

    blind_signatures: [blind_signature,...] 
        not empty if status 2XX

}


Response Minting JSON example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "message_reference": 6,
        "status_code": 200,
        "status_description": "ok",
        "blind_signatures": [
            {
                "reference": "r_0",
                "blind_signature": "337c6f69953d91c39fa0913a6fdc8c916d40ddf82a86f733aa501e2b8f2b9519b",
                "type": "blind signature"
            },
            {
                "reference": "r_1",
                "blind_signature": "23e214c88bcee6c3eb306c7d4022c4f4913be55763d16e822737a8c797b7c1204",
                "type": "blind signature"
            },
            {
                "reference": "r_2",
                "blind_signature": "377299d716822d7209177651d0a5dadf61cc6ec7838b075fbe8bbbf6ed8709881",
                "type": "blind signature"
            },
            {
                "reference": "r_3",
                "blind_signature": "10a00af5e59848a35ffc6458ed327565488f538f8b238a2d204fb33172cc296c2",
                "type": "blind signature"
            }
        ],
        "type": "response minting"
    }


Send Coins
----------

Send coins to someone, most likely between peers.

Send Coins structure
~~~~~~~~~~~~~~~~~~~~

struct: send_coins = {
    
    type = "send coins"
        ..
    
    message_reference = integer 
        Message ID to allow a reference of response message.

    subject = string
        Information for recipient

    coins = [n coins]
        ..

}


Send Coins JSON example
~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "message_reference": 8,
        "subject": "payment 1",
        "coins": [
            {
                "payload": {
                    "protocol_version": "http://opencoin.org/1.0",
                    "issuer_id": "6897de0948d16e72556dfe70b21c49ba20e9d334313ab3cc779e5fee676a9c87",
                    "cdd_location": "http://opencent.org",
                    "denomination": 5,
                    "mint_key_id": "0ff9bdc16eea8b9ff636b9289962ea95b849fd79c98febacab33170e1f4b038d",
                    "serial": "b7204e667d09e176e4f6e3504ec7b465",
                    "type": "payload"
                },
                "signature": "6f942455e0c154adadbec13873366ce682dd5e3d03540cf05424d33f1e0b95fc0",
                "type": "coin"
            }
        ],
        "type": "send coins"
    }


Request Renewal
---------------

Bob has received coins from Alice, and now needs to replace the 'old' coins
by new ones, based on blinds that he creates.

Request Renewal structure
~~~~~~~~~~~~~~~~~~~~~~~~~

struct: request_renewal = {
    
    type = "request renewal"
        ..
    
    message_reference: integer
        ..

    transaction_reference = hexstring
        crypto_random_number

    coins =  [n coins]
        ..

    blinds: [n blinds]
        ..

}


Request Renewal JSON example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "message_reference": 2,
        "transaction_reference": "fa5e6c1ab1bf09ab666321b2c7be2b3d",
        "coins": [
            {
                "payload": {
                    "protocol_version": "http://opencoin.org/1.0",
                    "issuer_id": "6897de0948d16e72556dfe70b21c49ba20e9d334313ab3cc779e5fee676a9c87",
                    "cdd_location": "http://opencent.org",
                    "denomination": 5,
                    "mint_key_id": "0ff9bdc16eea8b9ff636b9289962ea95b849fd79c98febacab33170e1f4b038d",
                    "serial": "b7204e667d09e176e4f6e3504ec7b465",
                    "type": "payload"
                },
                "signature": "6f942455e0c154adadbec13873366ce682dd5e3d03540cf05424d33f1e0b95fc0",
                "type": "coin"
            }
        ],
        "blinds": [
            {
                "reference": "r_0",
                "blinded_payload_hash": "53648eea020c03ed81d64f2f9f0de6eab1307926f86466dfe00b3a9a37f64e9a9",
                "mint_key_id": "198c351fd446898285f3c6af4e5c85d86ac23cb3dd016f3f2794983d2a1a10c1",
                "type": "blinded payload hash"
            },
            {
                "reference": "r_1",
                "blinded_payload_hash": "89fbef47210fd0ae12ec2e13decc12d36d06c2746a383c75ffc4a27136b7acdda",
                "mint_key_id": "198c351fd446898285f3c6af4e5c85d86ac23cb3dd016f3f2794983d2a1a10c1",
                "type": "blinded payload hash"
            },
            {
                "reference": "r_2",
                "blinded_payload_hash": "4c80ddc9edde4913ce70acc4facbd4b8d04fea9a86dac4425fad821244e486c12",
                "mint_key_id": "ae2f918e6eea72816a3be9709486da22f58e9ec16e40c896ac947a0b976ed452",
                "type": "blinded payload hash"
            }
        ],
        "type": "request renewal"
    }


Received Coins
--------------

Confirm that Bob has received the coins. Optional Message.

Received Coins structure
~~~~~~~~~~~~~~~~~~~~~~~~

struct: received_coins = {

    type = 'received coins'
        ..

    message_reference = integer
        This is the id of the original 'Send Coins' message

    status_code = integer
        ..

    status_description: string
        ..

}


Received Coins JSON example
~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "message_reference": 8,
        "status_code": 200,
        "status_description": "ok",
        "type": "received coins"
    }


Request Invalidation
--------------------

'Redeem' some coins. This is used to send coins back to 
the issuer, removing them from circulation. Most likely 
the issuer will credit some form of account of the user. 
The user will have to authenticate herself by e.g. ssl
client certificates. 

Request Invalidation structure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

struct: request_invalidation  = {

    type = "request invalidation"
        ..

    message_reference =  integer
        ..

    authorization_info = string
        ..

    coins = [n coins]
        ..

}


Request Invalidation JSON example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "message_reference": 3,
        "authorization_info": "my account",
        "coins": [
            {
                "payload": {
                    "protocol_version": "http://opencoin.org/1.0",
                    "issuer_id": "6897de0948d16e72556dfe70b21c49ba20e9d334313ab3cc779e5fee676a9c87",
                    "cdd_location": "http://opencent.org",
                    "denomination": 2,
                    "mint_key_id": "198c351fd446898285f3c6af4e5c85d86ac23cb3dd016f3f2794983d2a1a10c1",
                    "serial": "f5732837a4ddea4141c6cbcc1cc39142",
                    "type": "payload"
                },
                "signature": "dc0eb11b62cc3ea42ac83d96c7b28f8fbe58ae1ccb0300da3112db7ae4981778",
                "type": "coin"
            },
            {
                "payload": {
                    "protocol_version": "http://opencoin.org/1.0",
                    "issuer_id": "6897de0948d16e72556dfe70b21c49ba20e9d334313ab3cc779e5fee676a9c87",
                    "cdd_location": "http://opencent.org",
                    "denomination": 1,
                    "mint_key_id": "ae2f918e6eea72816a3be9709486da22f58e9ec16e40c896ac947a0b976ed452",
                    "serial": "a127a84c01a579de35764d0c15338680",
                    "type": "payload"
                },
                "signature": "5408ea882a933c91bb7b890646ee2ee8467f3c9b6115765b5c6a6abbabfb6fb0e",
                "type": "coin"
            }
        ],
        "type": "request invalidation"
    }


Response Invalidation
---------------------

Confirmation that the coins were 'redeemed'

Response Invalidation structure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


struct: response_invalidation = {
    
    type = "response invalidation"
        ..
    
    message_reference = integer
        ..

    status_code: integer
        ..

    status_description: string
        ..

}


Response Invalidation JSON example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "message_reference": 3,
        "status_code": 200,
        "status_description": "ok",
        "type": "response invalidation"
    }

Request Resume
--------------

If one of the Request Minting/Request Renewal messages answered
with a delay, this message will continue the transaction, effectively
asking for the delivery of coins.

Request Resume structure
~~~~~~~~~~~~~~~~~~~~~~~~

struct: request_resume = {
    
    type = "request resume"
        ..
    
    message_reference = integer
        ..

    transaction_reference: hexstring
        crypto_random_number

}


Request Resume JSON example
~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        "message_reference": 6,
        "transaction_reference": "c6524415dc6a6a29e5906592152986ca",
        "type": "request resume"
    }


Error codes
-----------

    * 2XX SUCCESS
    * 3XX DELAY / TEMPORARY ERROR
    * 4XX PERMANENT ERROR


Potential extensions
====================

    * Mandatory: Fees
    * Payment requests
    * "Internet ATM"
    * escrow (trusted third party) (fair exchanges without third party)
    * currency exchanges
    * receipts



******************
Notes and comments
******************


Actions
=======

    * get cdd -> cdd certificate
    * get mintkey -> mint key certificates
    * get crl/ocsp
    * validate: (blinds, + authorizer information) -> delayed/(blind 
      signatures)
    * renew:   (blinds, coins) -> delayed/(blind signatures)
    * invalidate (coins, + authorizer information)
    * resume: transactionid -> delayed / (blind signatures)
    * transaction: (coins A, coins B + optional cdd, messagestring)


Services
========

* info service = weighted_list_of_URLs
    * CDDs
    * mint key certificates
    * certificate revocation list (CRL)
    * fees: A list of fees e.g. {[1-1000, 2, 'coin'],[>1000, 1, 
                                  'percent']}
    * icons and other funky shiny stuff
    * [[Weighted to also allows round-robin, but also proper 
        preference]]
* validation service = weighted_list_of_URLs: 
                        [(10, https://validate.opencent.net:8002), 
                         (1, xmpp://1.2.3.4/opencoin)]
* renewal service = weighted_list_of_URLs
* invalidation service = weighted_list_of_URLs


Open Questions
==============
* Should the Public Key structure contain the cipher suite or should
  the cipher suite remain defined outside, next to the public key?
* Self referencing field names: Change name of cdd_location, 
  cdd_serial, cdd_signing_date, cdd_expiry_date and remove the 
  "cdd" prefix from their names?
* Should we allow negative denominations? -> JS: For the issuer 
  implementation I assume "no".
* Master key rollover. Following options:
    * "Rollover" records in old CDD
        * (rollover CDD info service = weighted_list_of_URLs
        * rollover CDD cipher suite = string
        * rollover CDD public master key = )
    * 2nd signature (by old masterkey) in new CDD
    * Glue certificates
* Protocol rollover?
* Move cdd_location from token to gwop?
* Alice marks token for bob
* How often should the CDD be fetched? Is this security related?
* OCSP or CRL? CRL may be cheaper.
* should the issuer enforce the order in which renewal requests are processed (order or 
  requests = order of responses) regarding competing requests containing same coins
* Shall the "hold-back time" be mentioned into the CDD
* Does the client need the option to say "Do *not* send me a DELAY"?


Other
=====

SHA512-RSA-CHAUM83:
    * hash: sha512
    * padding: ??
    * public key = (bigint: e, bigint: n)
        * 7 bit serialization: HAS TO BE DEFINED
        * Examples:
            * base64(json(list(bigint:e, bigint:n)))
            * json(list(base64(bigint:e),base64(bigint:n)))
    * signature = bigint
        * 7 bit serialization: HAS TO BE DEFINED
    * prepare_signing()

SHA512-ECC-XYZ
    * ECC public key = (5 koordinaten, elements of a binary field)
    * ECC signature = (tupel of field elements)


*********    
Footnotes
*********

.. [1] The OpenCoin project <http://opencoin.org/>
.. [2] David Chaum, "Blind signatures for untraceable payments", Advances in Cryptology - Crypto '82, 
        Springer-Verlag (1983), 199-203.
.. [3] Bencode Wikipedia page <http://en.wikipedia.org/wiki/Bencode>



