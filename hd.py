'''
A very straight forward, no frills bip32/39/44 implementation
leveraging the TREZOR mnemonic library.

This DOES NOT support non-hardened derivation

Also inspired by the Factom Implementation

The bip32 protocol is outlined here:
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

'''
from codecs import encode, decode
from mnemonic import Mnemonic
from bitstring import BitArray

from bip32utils.BIP32Key import *

import ed25519
from pyblake2 import blake2b
import os
import math

COINTYPE = 165
STRENGTH = 256 # Must be a multiple of 32 between 128 and 256

#################################################
# Important functions to be used in retrowallet #
#################################################

def mnemonic_to_keys(mnemonic, passphrase='', account_number=0, cointype=COINTYPE):
    '''
    Primary function to call from RetroWallet to get private and public keys
    '''
    master_key = mnemonic_to_master_key(mnemonic, passphrase)
    private_key = get_private_key(master_key, account_number=account_number, cointype=cointype)
    public_key = private_to_public(private_key)
    return private_key, public_key

def random_mnemonic(strength=256, language='english'):
    '''
    Generates a bip44 compiant mnemonic
    '''
    if strength % 32 != 0:
        raise ValueError("Strength must be a multiple of 32")
    m = Mnemonic(language=language)
    entropy = os.urandom(int(strength//8))
    words = m.to_mnemonic(entropy)
    return words

############
# the rest #
############

def mnemonic_to_seed(mnemonic, passphrase=''):
    '''
    Computes the master seed from mnemonic + passphrase
    '''
    return Mnemonic.to_seed(mnemonic, passphrase)

def seed_to_master_key(seed):
    '''
    Computes the master key from the seed
    '''
    return BIP32Key.fromEntropy(seed, public=False)

def mnemonic_to_master_key(mnemonic, passphrase=''):
    '''
    Helper function that combines:
        1) mnemonic_to_seed
        2) seed_to_master_keys
    Useful because manytimes you don't explicitly care about the seed
    Returns the master_key
    '''
    seed = mnemonic_to_seed(mnemonic, passphrase)
    return seed_to_master_key(seed)

def get_private_key(master_key, account_number=0, cointype=COINTYPE):
    '''
    Derives the specified privatekey from the master_key
    '''
    BIP44_subkey = master_key.ChildKey(BIP32_HARDEN + 44) # 44 path for bip44
    coin_subkey = BIP44_subkey.ChildKey(BIP32_HARDEN + cointype)
    account_subkey = coin_subkey.ChildKey(BIP32_HARDEN + account_number)
    external_subkey = account_subkey.ChildKey(0) # 0 for external facing
    private_key_preimage = external_subkey.ChildKey(0).PrivateKey()

    private_key_preimage = str(encode(private_key_preimage, 'hex'), 'utf8')
    private_key_preimage_data = BitArray(hex=private_key_preimage)

    h = blake2b(digest_size=32)
    h.update(private_key_preimage_data.bytes)
    private_key = BitArray(hex=h.hexdigest())

    return private_key.bytes

def get_private_key_from_mnemonic(mnemonic, passphrase='', account_number=0, cointype=COINTYPE):
    '''
    Helper function that gets a private key
    Combines:
        1) mnemonic_to_master_key
        2) get_private_key
    '''
    master_key = mnemonic_to_master_key(mnemonic, passphrase)
    private_key = get_private_key(master_key, account_number=account_number, cointype=cointype)

    return private_key

def private_to_public(private):
    return ed25519.SigningKey(private).get_verifying_key().to_bytes()

def print_mnemonic(words, cols=3):
    '''
    To be used to print the mnemonic in a pretty fashion
    '''
    if isinstance(words, str):
        # Assume that its space separated and we really wanted
        # to split it
        words = words.split(" ")
    n_words = len(words)
    n_rows = math.ceil(n_words / cols)
    print("BIP44 Compliant Mnemonic (make a copy of this in a safe place!): ")
    print("-" * 20 * cols)
    for r in range(n_rows):
        row_str = ''
        for c in range(cols):
            if c > 0:
                row_str += "   "
            else:
                row_str += "|  "
            index = r*cols + c
            if(index >= n_words):
                break
            row_str += "%2d. %9s   |" % (index+1, words[index])
        print(row_str)
    print("-" * 20 * cols)

def main():
    '''
    Demo on how to generate a RaiBlocks Account
    '''
    mnemonic = random_mnemonic()
    print_mnemonic(mnemonic)
    private_key, public_key =  mnemonic_to_keys(mnemonic, passphrase='', account_number=0, cointype=COINTYPE)
    print("Private key: " + str(encode(private_key, 'hex'), 'utf8'))
    print("Public key:  " + str(encode(public_key,  'hex'), 'utf8'))

if __name__=="__main__":
    main()
