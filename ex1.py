import base64
from hashlib import sha256
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
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)
        print(private_pem.decode("UTF-8"))

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)
        print(public_pem.decode("UTF-8"))


def function6(givenKey, tree):
    # convert toe ket to bytes
    givenKey = givenKey.encode()
    # get the private key
    private_key = serialization.load_pem_private_key(givenKey, password=None)
    # convert the tree root to bytes
    message = tree.root.hashValue.encode()
    # signing the root with the given key
    signature = private_key.sign(message,
                                 padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                             salt_length=padding.PSS.MAX_LENGTH
                                             ),
                                 hashes.SHA256()
                                 )
    print(base64.b64encode(signature).decode())

def function7(key, signature, textToVerify):
    signature = base64.decodebytes(signature.encode())
    textToVerify = textToVerify.encode()
    key = key.encode()
    publicKey = serialization.load_pem_public_key(key)
    # Verifying -- with the same mgf (padding), salt and hash.
    try:
        publicKey.verify(signature, textToVerify,
                         padding.PSS(
                             mgf=padding.MGF1(hashes.SHA256()),
                             salt_length=padding.PSS.MAX_LENGTH
                         ),
                         hashes.SHA256()
                         )
        print("True")
    except :
        print("False")

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
                print("hash value:" + hashValue) # todo maybe should remove this print
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
        # case 2
        if inputFromUser[0] == '2' and len(inputFromUser) == 1:
            function2(tree)
        # case 3
        if inputFromUser[0] == '3' and inputFromUser[1] == ' ':
            function3(inputFromUser[2:], tree)
        # case 4
        if inputFromUser[0] == '4' and inputFromUser[1] == ' ':
            function4(inputFromUser[2:], tree)
        # case 5
        if (inputFromUser[0] == '5' and len(inputFromUser) == 1):
            function5()
        # case 6
        if (inputFromUser[0] == '6'):
            inpt = input()
            text = inpt + '\n'
            while inpt != "-----END RSA PRIVATE KEY-----":
                inpt = input()
                text = text + inpt + '\n'
            text = "-----BEGIN RSA PRIVATE KEY-----\n" + text
            text = text[:-1]
            function6(text, tree)

        # case 7
        if (inputFromUser[0] == '7'):
            # get the key from user
            inpt = input()
            text = inpt + '\n'
            while inpt != "-----END PUBLIC KEY-----":
                inpt = input()
                text = text + inpt + '\n'
            text = "-----BEGIN PUBLIC KEY-----\n" + text
            text = text[:-1]
            temp = input()
            signature = input().split()
            function7(text, signature[0], signature[1])
        # case 8
        if (inputFromUser[0] == '8' and inputFromUser[1] == ' '):
            function8(inputFromUser)
        if (inputFromUser[0] == '9' and len(inputFromUser) == 1):
            function9(inputFromUser)
        if (inputFromUser[0] == '1' and inputFromUser[1] == '0' and inputFromUser[2] == ' '):
            function10(inputFromUser)
        if (inputFromUser[0] == '1' and inputFromUser[1] == '1' and inputFromUser[2] == ' '):
            function11(inputFromUser)