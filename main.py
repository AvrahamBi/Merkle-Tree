from hashlib import sha256

import alg as alg
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509


def function1(input, tree):
    leaf = Node("null", "null", "null", "null", input)
    tree.addNewLeaf(leaf)

def function2(tree):
    print (tree.root.hashValue)

def function3(input, tree):
    result = tree.root.hashValue
    node = tree.leaves[int(input)]
    while node.father != "null":
        if node.father.leftChild.hashValue == node.hashValue:
            result = result + " " + node.father.rightChild.hashValue
        else:
            result = result + " " + node.father.leftChild.hashValue
        node = node.father
    print(result)


def function4(input, tree):
    allOptionsArr = []

    hashesOfNodes = input.split()
    hashesOfNodes.pop(1)
    if len(hashesOfNodes) == 1:
        if hashesOfNodes[0] == tree.root.hashValue:
            print("True")
        else:
            print("False")
        return
    value1 = hashesOfNodes[0] + hashesOfNodes[1]
    hash1 = sha256(value1.encode('UTF-8')).hexdigest()
    allOptionsArr.append(hash1)
    value2 = hashesOfNodes[1] + hashesOfNodes[0]
    hash2 = sha256(value2.encode('UTF-8')).hexdigest()
    allOptionsArr.append(hash2)

    hashesOfNodes.pop(0)
    hashesOfNodes.pop(0)

    for node in hashesOfNodes:
        temp = []
        for option in allOptionsArr:
            value1 = option + node
            hash1 = sha256(value1.encode('UTF-8')).hexdigest()
            temp.append(hash1)
            value2 = node + option
            hash2 = sha256(value2.encode('UTF-8')).hexdigest()
            temp.append(hash2)
        allOptionsArr = temp

    if tree.root.hashValue in allOptionsArr:
        print("True")
    else:
        print("False")


def function5():
    ##### Symmetric crypto #####

    # key = (key1 || key2) where key1 is 128b MAC key and key2 is 128b encryption key.
    # key is a symmetric key.
    key = Fernet.generate_key()

    # MAC with HMAC-SHA256:
    cipher = Fernet(key)

    # Encryption with AES-CBC 128b:
    token = cipher.encrypt(b"Hello")

    # Decryption:
    plaintext = cipher.decrypt(token)

    #### Asymmetric crypto #####

    serialization.NoEncryption()
    # Creating sk, with common exponent and common key size.
    # Backend is the creation library. default_backend() is a common library.
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048,
                                           backend=default_backend()
                                           )

    # Now we want to store the key in the storage so it will be available after system restart.
    # Save sk to pramenter named pem with additional settings and security measures (like password).
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                    encryption_algorithm=alg
                                    )

    # Write pem to sk.pem file.
    with open("sk.pem", "wb") as f:
        f.write(pem)


def function6(input):
    print("function 6")

def function7(input):
    print("function 7")

def function8(input):
    print("function 8")

def function9(input):
    print("function 9")

def function10(input):
    print("function 10")

def function11(input):
    print("function 11")


class Node:
    def __init__(self, father, leftChild, rightChild, value, hashValue):
        self.father = father
        self.leftChild = leftChild
        self.rightChild = rightChild
        self.value = value
        if (hashValue == "null"):
            self.hashValue = sha256(value.encode('UTF-8')).hexdigest()
        else:
            self.hashValue = hashValue

    def setLeftChild(self, node):
        self.leftChild = node

    def setRightChild(self, node):
        self.rightChild = node

    def setParent(self, parent):
        self.father = parent

class MerkleTree:
    def __init__(self, root, leaves):
        self.root = root
        self.leaves = []

    def addNewLeaf(self, leaf):
        self.leaves.append(leaf)
        self.initializeMerkleTree()

    def initializeMerkleTree(self):
        nodes = self.leaves.copy()
        while len(nodes) !=1:
            tempNodes = []
            for i in range(0, len(nodes), 2):
                node1 = nodes[i]
                # if index is in the range
                if i + 1 < len(nodes):
                    node2 = nodes[i + 1]
                else:
                    tempNodes.append(node1)
                    break
                value = node1.hashValue + node2.hashValue
                hashValue = sha256(value.encode('UTF-8')).hexdigest()
                print("hash value:" + hashValue)
                parentNode = Node("null", node1, node2, value, hashValue)
                node1.setParent(parentNode)
                node2.setParent(parentNode)
                tempNodes.append(parentNode)
            nodes = tempNodes
        self.root = nodes[0]







if __name__ == "__main__":
    tree = MerkleTree("null", [])

    while(True):
        inputFromUser = input()
        # case 1
        if inputFromUser[0] == '1' and inputFromUser[1] == ' ':
            function1(inputFromUser[2:], tree)
        if inputFromUser[0] == '2' and len(inputFromUser) == 1:
            function2(tree)
        if inputFromUser[0] == '3' and inputFromUser[1] == ' ':
            function3(inputFromUser[2:], tree)
        if inputFromUser[0] == '4' and inputFromUser[1] == ' ':
            function4(inputFromUser[2:], tree)
        if (inputFromUser[0] == '5' and len(inputFromUser) == 1):
            function5()
        if (inputFromUser[0] == '6' and inputFromUser[1] == ' '):
            function6(inputFromUser)
        if (inputFromUser[0] == '7' and inputFromUser[1] == ' '):
            function7(inputFromUser)
        if (inputFromUser[0] == '8' and inputFromUser[1] == ' '):
            function8(inputFromUser)
        if (inputFromUser[0] == '9' and len(inputFromUser) == 1):
            function9(inputFromUser)
        if (inputFromUser[0] == '1' and inputFromUser[1] == '0' and inputFromUser[2] == ' '):
            function10(inputFromUser)
        if (inputFromUser[0] == '1' and inputFromUser[1] == '1' and inputFromUser[2] == ' '):
            function11(inputFromUser)