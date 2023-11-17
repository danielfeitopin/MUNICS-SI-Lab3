"""
Module tree

Module for binary tree operations.
"""

from .encryption import get_random_key
from math import ceil, log2


class BinaryTree:
    """
    Class representing a binary tree.

    Attributes:
        n (int): Number of leaves.
        t (int): Number of levels, excluding root.
        depth (int): Total number of levels.
        nodes (dict): Dictionary containing node IDs as keys and random keys as values.
        first_leaf (int): ID of the first leaf.
        last_leaf (int): ID of the last leaf.

    Methods:
        __init__(self, n: int) -> None: Constructor method to initialize the binary tree.
        get_parent(node_id: int) -> int: Static method to get the parent of a node.
        get_sibling(node_id: int) -> int: Static method to get the sibling of a node.
        get_leaves(self) -> tuple[int]: Method to get the IDs of all leaves.
        get_path_to_root(cls, node_id: int) -> tuple[int]: Class method to get the path from a node to the root.
    """

    def __init__(self, n: int) -> None:
        """
        Constructor method to initialize the binary tree.

        Args:
            n (int): Number of leaves.
        """

        self.n: int = n
        self.t: int = ceil(log2(n))
        self.depth: int = self.t + 1
        self.nodes: dict[int, bytes] = {}
        self.first_leaf: int = 2**self.t
        self.last_leaf: int = 2**(self.t+1)-1

        for i in range(1, self.last_leaf+1):
            self.nodes[i] = get_random_key()

    @staticmethod
    def get_parent(node_id: int) -> int:
        """
        Static method to get the parent of a node.

        Args:
            node_id (int): ID of the node.

        Returns:
            int: ID of the parent.
        """
        return node_id//2

    @staticmethod
    def get_sibling(node_id: int) -> int:
        """
        Static method to get the sibling of a node.

        Args:
            node_id (int): ID of the node.

        Returns:
            int: ID of the sibling.
        """
        return node_id - 1 if node_id % 2 else node_id + 1

    def get_leaves(self) -> tuple[int]:
        """
        Method to get the IDs of all leaves.

        Returns:
            tuple[int]: Tuple containing IDs of leaves.
        """
        return tuple(range(self.first_leaf, self.last_leaf+1))

    @classmethod
    def get_path_to_root(cls, node_id: int) -> tuple[int]:
        """
        Class method to get the path from a node to the root.

        Args:
            node_id (int): ID of the node.

        Returns:
            tuple[int]: Tuple containing IDs of nodes in the path.
        """
        path: list[int] = [node_id]
        id: int = node_id
        while path[-1] != 1:
            id = cls.get_parent(id)
            path.append(id)
        return tuple(path)
