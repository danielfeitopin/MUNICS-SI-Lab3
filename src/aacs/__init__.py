"""
Module aacs

Module for Advanced Access Content System (AACS) operations.

Variables:
    TAG_VALID (bytes): Tag indicating a valid AACS key.
    TAG_SEPARATOR (bytes): Separator tag between keys and encrypted content.

Exceptions:
    KeyNotFound: Raised when a key cannot be found.

Classes:
    AACS: Class representing the AACS system, inheriting from BinaryTree.
"""

from .encryption import (get_random_key, add_padding,
                         remove_padding, AES_encrypt, AES_decrypt)
from .tree import BinaryTree

TAG_VALID: bytes = b'is_valid_aacskey'
TAG_SEPARATOR: bytes = b'END_OF_KEYS'


class KeyNotFound(Exception):
    """Exception raised for key not found."""


class AACS(BinaryTree):
    """
    AACS Class

    Class representing the Advanced Access Content System (AACS).

    Attributes:
        S (set[int]): Set of devices not yet compromised.
        T (set[int]): Set of revoked devices.
        S_cover (tuple[int]): Tuple representing the cover of set S.

    Methods:
        __init__(self, n: int) -> None: Constructor for the AACS class.
        revoke(self, id: int) -> bool: Revoke a device from the set of valid devices.
        encrypt(self, m: bytes) -> bytes: Encrypt a message using AACS.
        decrypt(self, node_id: int, c: bytes) -> bytes: Decrypt a message using AACS.
    """

    def __init__(self, n: int) -> None:
        """
        Constructor for the AACS class.

        Parameters:
            n (int): Number of leaves in the binary tree.

        Returns:
            None
        """
        super().__init__(n)

        # Set of devices not yet compromised
        self.S: set[int] = set(self.get_leaves())

        # Revoked devices
        self.T: set[int] = set()

        self.S_cover: tuple[int] = self.__get_S_cover()

    def __get_S_cover(self) -> tuple[int]:
        """
        Private method to calculate the cover of S.

        Returns:
            tuple[int]: Tuple representing the cover of S.
        """
        cover: set[int] = set()
        if len(self.S) == self.n:
            cover.add(1)
        else:
            for i in self.T:
                for j in self.get_path_to_root(i):
                    if j != 1:  # Exclude root in sibling search
                        cover.add(self.get_sibling(j))
        return tuple(sorted(cover))

    def revoke(self, id: int) -> bool:
        """
        Revoke a device from the set of valid devices.

        Parameters:
            id (int): Identifier of the device to be revoked.

        Returns:
            bool: True if the device was successfully revoked, False otherwise.
        """
        if id in self.S:
            self.S.discard(id)
            self.T.add(id)
            self.S_cover: tuple[int] = self.__get_S_cover()
            return True
        return False

    def __get_known_keys(self, node_id: int) -> tuple[bytes]:
        """
        Private method to retrieve known keys in the path to the root of a node.

        Parameters:
            node_id (int): Identifier of the node.

        Returns:
            tuple[bytes]: Tuple containing known keys.
        """
        return tuple(self.nodes[id] for id in self.get_path_to_root(node_id))

    def encrypt(self, m: bytes) -> bytes:
        """
        Encrypt a message using AACS.

        Parameters:
            m (bytes): Message to be encrypted.

        Returns:
            bytes: Encrypted message.
        """
        # Generate a random key k
        k: bytes = get_random_key()

        # For every node u in a cover of S, compute cu := E(k_u, k)
        encrypted_keys: list[bytes] = []
        for k_u in (self.nodes[u] for u in self.S_cover):
            encrypted_keys.append(
                # 128b IV + 128b encrypted tag + 128b encrypted key (384b)
                b''.join(AES_encrypt(k_u, TAG_VALID + k))
            )

        # Encrypt the content as c := E'(k, m)
        # 128b IV + encrypted message
        c: bytes = b''.join(AES_encrypt(k, add_padding(m)))

        # Output ({c_u}_u∈cover(S), c)
        return b''.join(encrypted_keys) + TAG_SEPARATOR + c

    def decrypt(self, node_id: int, c: bytes) -> bytes:
        """
        Decrypt a message using AACS.

        Parameters:
            node_id (int): Identifier of the node trying to decrypt.
            c (bytes): Encrypted message.

        Returns:
            bytes: Decrypted message.
        """
        # 128b IV + 128b encrypted tag + 128b encrypted key (384b)
        ENCRYPTED_KEY_SIZE: int = 384 // 8  # Encrypted key size in bytes
        IV_SIZE: int = 128 // 8  # IV size in bytes

        # Try to decrypt the random key k from the encrypted key c_u
        keep_searching: bool = True
        separator_found: bool = False
        while not separator_found and c != b'':

            # If the separator is found, break the while
            if c.startswith(TAG_SEPARATOR):
                separator_found: bool = True
                break

            # Keep looking for the key
            if keep_searching:
                c_u: bytes = c[:ENCRYPTED_KEY_SIZE]  # Try next key block
                for k_u in self.__get_known_keys(node_id):
                    k: bytes = AES_decrypt(k_u, c_u[:IV_SIZE], c_u[IV_SIZE:])
                    if k.startswith(TAG_VALID):  # Correct key
                        k: bytes = k[len(TAG_VALID):]  # Remove separator
                        keep_searching: bool = False
                        break

            # Narrow down the byte input
            c: bytes = c[ENCRYPTED_KEY_SIZE:]

        if keep_searching:  # The key couldn't be retrieved
            raise KeyNotFound("The key couldn't be retrieved")

        if not separator_found:  # Can't distinguish keys from message
            raise ValueError('Separator not found')

        c: bytes = c[len(TAG_SEPARATOR):]  # Remove separator

        return remove_padding(AES_decrypt(k, c[:16], c[16:]))
