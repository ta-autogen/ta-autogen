from pycparser import c_ast
import random

class FunctionObject:
    
    def __init__(self, name):
        self.name = name
        self.node = None
        self.params = []
        self.retval = None
        
    def addParameter(self, parameterObject):
        return self.params.append(parameterObject)
    
    def addRetVal(self, parameterObject):
        self.retval = parameterObject
    
    def addNode(self, node):
        self.node = node

class ParameterObject:
    
    def __init__(self, name, datatype, shared=0, size='', index=None):
        self.name = name
        self.datatype = datatype
        self.shared = shared
        self.size = size
        self.index = index
    
    def addSize(self, size):
        self.size = size
    
    def addDataType(self, datatype):
        self.datatype = datatype
    
    def addIndex(self, index):
        self.index = index

class CryptoFuncCalls(c_ast.NodeVisitor):
    def __init__(self):
        self.rsafuncs = ['RSA_private_encrypt', 'RSA_public_decrypt', 'RSA_public_encrypt', 'RSA_private_decrypt']
        self.keydefs = []
        self.aesID = ''
        self.rsaSize = 2048
        self.rsaID = ''

    def visit_FuncCall(self, node):
        # 0. Keytype 1. Param name 2. Line number 3. Keysize 4. keyID (hmac: 5. Operation mode)
        
        if node.name.name == "HMAC":
            node.name.name = 'TEEC_'+node.name.name
            mode = getDigestMode(node.args.exprs[0].name.name)
            key = node.args.exprs[1].name
            keyID = key+'_ID_'+str(random.randint(1, 1000))
            self.keydefs.append(('HMAC', key, node.name.coord.line, node.args.exprs[2].name, keyID))
            node.args.exprs[1].name = keyID
        
        elif node.name.name == "AES_set_encrypt_key" or node.name.name == "AES_set_decrypt_key":
            key = node.args.exprs[0].name
            keyID = key+'_ID_'+str(random.randint(1, 1000))
            self.keydefs.append(('AES', key, node.name.coord.line, str(128), keyID))
            self.aesID = keyID
        
        elif node.name.name == "RSA_generate_key_ex":
            try:
                self.rsaSize = node.args.exprs[1].name
            except:
                self.rsaSize = node.args.exprs[1].value
            key = node.args.exprs[0].name
            keyID = key+'_ID_'+str(random.randint(1, 1000))
            self.rsaID = keyID
            self.keydefs.append(('RSA', key, node.name.coord.line+1, self.rsaSize, keyID))
        
        elif node.name.name == "AES_ecb_encrypt":
            node.name.name = 'TEEC_'+node.name.name
            node.args.exprs[2].expr.name = self.aesID
        
        elif node.name.name == "AES_ctr128_encrypt":
            node.name.name = 'TEEC_'+node.name.name
            node.args.exprs[3].expr.name = self.aesID
        
        elif node.name.name in self.rsafuncs:
            node.name.name = 'TEEC_'+node.name.name
            node.args.exprs[3].name = self.rsaID


def getDigestMode(indata):
    mode = 0
    try:
        if 'EVP_sha256' in indata:
            mode = "CMD_HMAC_SHA256"
        elif 'EVP_sha384' in indata:
            mode = "CMD_HMAC_SHA384"
        elif 'EVP_sha512' in indata:
            mode = "CMD_HMAC_SHA512"
        else:
            raise Exception()
    except:
        print("Message digest mode not supported\n", indata)
        sys.exit(1)

    return mode
