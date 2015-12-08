from __future__ import print_function
from objectDecl import FunctionObject, ParameterObject, CryptoFuncCalls, getDigestMode
from subprocess import Popen, PIPE
from string import ascii_uppercase
import sys, os, binascii, getopt, shutil
import random

from pycparser import c_parser, c_generator, c_ast

CASource = ['', '', '', '']
TASource = []

protectedFunctions = []
globalVariables = []
sharedVariables = []

path = ''

hasMain = False

"""
Function preprocessFile removes C-includes, defines and comments from
input data. Python library pycparser does not support any of these without
first preprocessing the file with cpp.
"""
def preprocessFile(filename):
    global CASource, protectedFunctions
    
    headerfile = filename.split('/')[-1][:-2]
    
    # Remove comments
    data = Popen(["gcc", "-fpreprocessed", "-dD", "-E", filename], stdout=PIPE).communicate()[0].splitlines(True)
    if not len(data):
        print("Error: Not a valid input file")
        sys.exit(0)
    
    # preprocessor comments
    data.remove(data[0])

    while('#include' in data[0]):
        CASource[0] += data.pop(0)
    CASource[0] += '\n#include "autogen_ca_header.h"\n\n'
    
    data[0] += "typedef struct aes_key_struct {\n\tint dummy;\n} AES_KEY;\ntypedef struct rsa_key_struct {\n\tint dummy;\n} RSA;\ntypedef unsigned long int uint32_t;\ntypedef unsigned long size_t;\n"

    # Search secure annotations
    for line in reversed(data):
        if '#pragma secure' in line:
            name = line.split()[-1]
            if ' function ' in line:
                protectedFunctions.append(FunctionObject(name))
            # Currently appends a name, not an object
            elif ' global ' in line:
                globalVariables.append(name)
            data.remove(line)
    
    for i in range(len(data)-1, -1, -1):
        if '#pragma shared var' in data[i]:
            funcIndex = i
            # Find name of the function
            while '#pragma shared var' in data[funcIndex]:
                funcIndex -= 1
            
            # Determine whether the function is marked as secure
            for func in protectedFunctions:
                if func.name in data[funcIndex]:
                    obj = ParameterObject(data[i].split()[-1], '', 1)
                    sharedVariables.append((func.name, obj))
        
        elif '#pragma shared header' in data[i]:
            TASource.append('\n#include "'+line.split()[-1]+'"\n')
    
    protectedFunctions = protectedFunctions[::-1]
    
    return ''.join(data)

def hasSecureParts(v):
    if (len(protectedFunctions) + len(globalVariables) + len(sharedVariables) + len(v.keydefs)) == 0:
        print("Error: No secure pragmas detected")
        sys.exit(0)

def commandInvokation(command):
    return '\n\tInvokeCommand(CMD_'+command+', NULL);\n\t'\
    'if (result != TEEC_SUCCESS) {\n\t\tprintf("Invoking command failed: 0x%x\\n", result);\n\t\t'\
    'end_3();\n\t}\n'

def generateProtectedFuncCA(generator):
    global CASource
    
    for function in protectedFunctions:
        CASource[1] += '\n'+generator.visit(function.node.decl)+'{\n'
        if (not hasMain): CASource[1] += '\n\tInitializeTEEC();\n'
        
        ree_params = ''
        ree_return = ''
        retval_name = ''
        write_ret = ''
        param_chunk = ('',)
        param_reg = ''
        index = -1
        
        # If function does not take parameters, no shared memory is needed
        if function.params or returnNotNull(function.node):
            
            CASource[1] += '\tuint8_t shared_buffer[BUF_MAX_SIZE];\n\tmemset(shared_buffer, 0, BUF_MAX_SIZE);\n'+\
                            '\tstruct marshal_parameters marshal = {.offset = 0, .b_size = BUF_MAX_SIZE, .list_len = 0};\n'
            
            if function.params:
                for param in function.params:
                    
                    size = ''
                    ptr = ''
                    if param.size != '':
                       # TODO: Fixed value
                        try:
                            if int(param.size) > 2048:
                                # :D
                                if function.chunked:
                                    print("Error: More than one big parameter defined to function", function.name)
                                    sys.exit()
                                param_chunk = '\tchunk_parameter((uint8_t*)'+param.name+', '+param.size+');\n', param.name, param.size
                                function.addChunked()
                                continue
                        except SystemExit:
                            sys.exit(1)
                        except:
                            size = '*'+param.size
                    else:
                        ptr = '&'
                    
                    param_reg += add_param(ptr+param.name, param.datatype, size)
                    index = param.index
                    
                    if param.shared:
                        ree_params += write_param(ptr+param.name, 'shared_buffer+(p['+str(index)+'].value)', index, '')
                    
                    
            if returnNotNull(function.node):
                index += 1
                retval_name = function.retval.name
                write_ret += '\t'+function.retval.datatype+' '+retval_name+';\n'+\
                                add_param('&'+retval_name, function.retval.datatype, '')
                ree_return += write_param('&'+retval_name, 'shared_buffer+(p['+str(index)+'].value)', index,'')
                retval_name = ' '+retval_name
                
            CASource[1] += param_chunk[0]+param_reg+write_ret+'\tAllocateMemory(&marshal, shared_buffer);\n'+commandInvokation(function.name)+\
                        '\tunpack_parameters(&marshal, shared_buffer);\n'+'\tstruct parameter* p = marshal.param_list;\n'+\
                        ree_params+ree_return+'\tReleaseMemory();\n'
            
            ca_shared = []
            for funcName, var in sharedVariables:
                if funcName == function.name:
                    ca_shared.append(var.name)
                
            if param_chunk[0] and param_chunk[1] in ca_shared:
                CASource[1] += '\n\tget_chunked_parameter((void*) '+param_chunk[1]+', '+param_chunk[2]+');\n'
                        
        if (not hasMain): CASource[1] += '\tend_3();\n';
        CASource[1] += '\treturn'+retval_name+';\n}\n\n'
        
# env parameter defines the environment of the function call: TEE or REE        
def write_param(dest, src, i, env):
    return '\t'+env+'write_parameter((uint8_t*)'+dest+', (uint8_t*)'+src+', p['+str(i)+'].len);\n'
    
def add_param(name, datatype, size):
    return '\tadd_parameter(&marshal, (uint8_t*)'+name+', sizeof('+datatype+')'+size+', shared_buffer);\n'

def generateTA(generator):
    global TASource
    with open('autogen_files/auto_ta.c', 'r') as autoTA:
        lines = autoTA.readlines()
        # 0: header includes + global variables
        # 1: secure functions
        # 2: TA-API functions
        # 3: switch-cases
        # 4: default case, param parsing functions
        TASource = ['#include "autogen_ta_header.h"\n\n', '', ''.join(lines[:41]), '', ''.join(lines[41:])]
    
    for var in globalVariables:
        TASource[0] += var
        
    for function in protectedFunctions:
        TASource[1] += '\n'+generator.visit(function.node)
        TASource[3] += '\t\tcase CMD_'+function.name+':\n\t\t{\n'
        
        tee_write = ''
        tee_paramlist = []
        tee_return = ''
        tee_free_chunked = ''
        
        tee_shared = []
        for funcName, var in sharedVariables:
            if funcName == function.name:
                tee_shared.append(var.name)
        
        if len(function.params):
            TASource[3] += '\t\t\tTEE_unpack_parameters(&marshal, params[1].memref.buffer, shared_buffer);\n\t\t\t'+\
                            'struct parameter* p = marshal.param_list;\n'
                         
            for param in function.params:
                tee_paramlist.append(param.name)
                i = (str)(param.index);
                ptr = ''
                param_size = param.size
                if not param_size:
                    ptr = '&'
                else:
                    try:
                        if int(param_size) > 2048:
                            for p in tee_paramlist:
                                if p == param.name:
                                    k = tee_paramlist.index(p)
                                    tee_paramlist[k] = 'chunked_buffer'
                                    if p not in tee_shared:
                                        tee_free_chunked = '\t\t\tTEE_free_chunked();\n'
                                    continue
                            continue
                    except:
                        pass
                    param_size = '['+param_size+']'
                TASource[3] += '\t\t\t'+param.datatype+' '+param.name+param_size+';\n'+write_param(ptr+param.name,'shared_buffer+p['+i+'].value', i, '\t\tTEE_')
                
                # New values are copied only if parameter is marked as shared
                if param.shared:
                    tee_write += write_param('shared_buffer+p['+i+'].value', ptr+param.name, i, '\t\tTEE_')
        
        TASource[3] += '\t\t\t'
                                
        if returnNotNull(function.node):
            TASource[3] += function.retval.datatype+' retval = '
            i = str(len(function.params))
            tee_return += write_param('shared_buffer+p['+i+'].value', '&retval', i, '\t\tTEE_')
        
        TASource[3] += function.name+'('+', '.join(p for p in tee_paramlist)+');\n'+tee_write+tee_return+tee_free_chunked
        
        if len(tee_shared)==1 and len(tee_free_chunked) or len(tee_shared) and 'chunked_buffer' not in tee_paramlist or len(tee_shared)>1 or returnNotNull(function.node):
            TASource[3] += '\t\t\tTEE_pack_parameters(&marshal, params[1].memref.buffer, shared_buffer);\n'
        
        TASource[3] += '\t\t\tbreak;\n\t\t}\n\n'

def generateID():
    timeLow = binascii.b2a_hex(os.urandom(4))
    timeMid = binascii.b2a_hex(os.urandom(2))
    timeHi = binascii.b2a_hex(os.urandom(2))
    appID = ''.join(random.choice(ascii_uppercase) for _ in range(8))
    seq = ', '.join(repr(i) for i in appID)
    
    return '#define ID { 0x'+timeLow+', 0x'+timeMid+', 0x'+timeHi+', { '+seq+' } }\n'

def generateFuncCommands():
    headerSource = ''
    for i in range(len(protectedFunctions)):
        headerSource += '#define\tCMD_'+protectedFunctions[i].name+'\t'+str(i+17)+'\n'
    return headerSource

def writeFile(filename, data):
    with open(filename, 'a+') as fo:
        fo.write(data)

# Set environmental limitations     
def defineBufferSizes(shmem, tamem):
    if shmem == None:
        # Shared memory buffer default size is 4KB
        shmem = str(4096)
    if tamem == None:
        # TA internal memory size 512KB
        tamem = str(524288)
    
    return '\n#define SHMEM_MAX_SIZE\t'+shmem+'\n'\
                '#define TAMEM_MAX_SIZE\t'+tamem+'\n'\
                '#define BUF_MAX_SIZE\t'+shmem+'-100\n\n'

def generateHeader(headDecl, name):
    with open("autogen_files/autogen_shared_header.h", 'r') as f:
        hfile = f.read()
    
    hfile += defineBufferSizes(None, None)+generateID()+generateFuncCommands()
    writeFile(path+'CA/ca_'+name+'/autogen_shared_header.h', hfile+headDecl)
    writeFile(path+'TA/ta_'+name+'/autogen_shared_header.h', hfile+headDecl)

def returnNotNull(node):
    hasBody = (node.body.block_items != None)
    return hasBody and type(node.body.block_items[-1]).__name__ == 'Return' and node.body.block_items[-1].expr

def getParameterDetails(param, func):
    details = ('', '', '')
    paramType = param.type.type
    
    # Assigning tuple values for variables is easier than from lists
    if type(paramType) == c_ast.Struct:
        details = (param.name, 'struct '+paramType.name, '')
        
    elif type(paramType) == c_ast.IdentifierType:
        details = (param.name, paramType.names[0], '')
        
    elif type(paramType) == c_ast.TypeDecl:
        if type(param.type) == c_ast.PtrDecl:
            # Variable sized pointers are supported only for function parameters
            sizeobj = next((p for p in func.params if p.name == paramType.declname+'_size'), None)
            if sizeobj:
                details = (paramType.declname, paramType.type.names[0], sizeobj.name)
            else:
                print('Error: pointer size not defined')
        elif type(param.type) == c_ast.ArrayDecl:
            details = (paramType.declname, paramType.type.names[0], param.type.dim.value)
    
    return details

def isChunkable(size):
    # We assume that a variable cannot be a big parameter (variable value is impossible to determine)
    try:
        if not size or int(size) < 4096:
            return False
    except:
        return False
    return True

def addParamIndex(param, index):
    if isChunkable(param.size):
        return index
    else:
        param.addIndex(index)
        return index+1

def parseOpenSSL(ast, v, g):
    global hasMain
    e = ast.ext
    src = ''
    
    for func in e:
        if type(func) == c_ast.FuncDef and func.decl.name == "main":
            hasMain = True
    
    # Key defs
    for i in range(len(e)):
        
        # Pycparser is incapable of adding semicolons to correct positions...
        if type(e[i]) == c_ast.Typedef or type(e[i]) == c_ast.Decl:
            src += g.visit(e[i]) + ";\n"
        
        # Is the key definition inside this function
        elif len(v.keydefs):
            line = v.keydefs[0][2]
            
            try:
                nextline = e[i+1].coord.line
            except:
                nextline = None

            if line>e[i].coord.line and nextline == None or line<nextline:
                
                src += g.visit(e[i].decl)+' {\n'

                for item in e[i].body.block_items:
                    if (len(v.keydefs)):
                        keydef = v.keydefs[0]
                        line = keydef[2]
                    if item.coord.line == line:
                        funccall = ''
                        if (not hasMain): funccall += "\tInitializeTEEC();\n"
                        if keydef[0] == "AES":
                            funccall += "\tuint32_t "+keydef[4]+" = TEEC_create_bitkey(0xA0000010, "+str(keydef[3])+", EXISTING, "+keydef[1]+");\n"
                        
                        elif keydef[0] == "RSA":
                            funccall += "\tuint32_t "+keydef[4]+" = TEEC_import_RSA_key("+str(keydef[3])+", "+keydef[1]+");\n"
                        
                        elif keydef[0] == "HMAC":
                            funccall += "\tuint32_t "+keydef[4]+" = TEEC_create_bitkey(0xA0000004, "+str(keydef[3])+"*8, EXISTING, (void*)"+keydef[1]+");\n"
                        
                        v.keydefs.pop(0)
                        src += funccall
                        src = writeSrc(src, g, item)
                        if (not hasMain): src += "\tend_3();\n"

                    else:
                        src = writeSrc(src, g, item)

                src += '\n}\n'
            else:
                src += g.visit(e[i])
        
        else:
            src += g.visit(e[i])
   
    src = src.split('\n')
    # Replace evp_mode function call with value
    for i in range(len(src)):
        if "HMAC(" in src[i]:
            tmp = src[i].split('HMAC(')
            param = tmp[1].split(',')
            param[0] = getDigestMode(param[0])
            tmp[1] = ','.join(param)
            src[i] = 'HMAC('.join(tmp)
    
    src = '\n'.join(src)
    return src

def writeSrc(src, g, item):
    if type(item) == c_ast.If or type(item) == c_ast.Return:
        src += "\t"+g.visit(item)
        return src
    src += "\t"+g.visit(item)+";\n"
    return src

def parseCFile(source):
    global CASource, TASource
    generator = c_generator.CGenerator()
    parser = c_parser.CParser()
    
    headDecl = ""
    
    ast = parser.parse(source)
    
    v = CryptoFuncCalls()
    v.visit(ast)
    hasSecureParts(v)

    src = parseOpenSSL(ast, v, generator)
    ast = parser.parse(src)
    
    for e in ast.ext:
        
        # Remove dummy definitions
        if type(e) == c_ast.Typedef:
            if e.name == "AES_KEY" or e.name == "RSA" or e.name == "uint32_t" or e.name == "size_t":
                continue
        
        elif type(e) == c_ast.FuncDef:
            # if name is found from the list of protected functions names
            func = next((funcObj for funcObj in protectedFunctions if funcObj.name == e.decl.name), None)
            
            if func:
                func.addNode(e)

                # Does function take parameters (value or struct)
                if e.decl.type.args != None:
                    funcParams = e.decl.type.args.params
                    index = 0
                    for param in funcParams:
                        pName, pType, pSize = getParameterDetails(param, func)
                        # is parameter marked as shared
                        sharedObj = next((var for funcName, var in sharedVariables if funcName == func.name and var.name == pName), None)
                        
                        if sharedObj:
                            sharedObj.addSize(pSize)
                            sharedObj.addDataType(pType)
                            index = addParamIndex(sharedObj, index)
                            func.addParameter(sharedObj)
                            continue
                                
                        else:
                            paramObj = ParameterObject(pName, pType, size=pSize)
                            func.addParameter(paramObj)
                            index = addParamIndex(paramObj, index)
                
                if returnNotNull(e):
                    retval = ParameterObject(e.body.block_items[-1].expr.name, e.decl.type.type.type.names[0], 1)
                    func.addRetVal(retval)

            # Add initialization and exit calls to main   
            elif 'main' in e.decl.name:
                CASource[3] += generator.visit(e.decl)+' {\n'+'\tInitializeTEEC();\n'+'\tatexit(end_3);\n'+\
                            generator.visit(e.body)[1:]

            else:
                CASource[2] += generator.visit(e)
                
        elif type(e.type) == c_ast.Struct:
            headDecl += generator.visit(e)+';\n\n'
        
        else:
            pName, pType, pSize = getParameterDetails(e, None)
            if pName == '' or pName not in globalVariables:
                CASource[1] += generator.visit(e)+';\n\n'
                continue
            globalVariables.remove(pName)
            globalVariables.append(generator.visit(e)+';\n\n')
    
    generateTA(generator)
    generateProtectedFuncCA(generator)
    return headDecl
    
def parseParameters(argv):
    inputfile = ""
    makefile = False
    outputpath = ""
    
    try:
        opts, args = getopt.getopt(argv,"hi:mo:")
    except getopt.GetoptError:
        print('parser.py -i <inputfile>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('-h\t\thelp\n-m\t\tgenerate makefile\n-i <filename>\tinput file name and path\n-o <path>\toutput path\n')
            sys.exit()
        elif opt in ("-i"):
            inputfile = arg
        elif opt in ("-m"):
            makefile = True
        elif opt in ("-o"):
            outputpath = arg
            if outputpath[-1] != "/":
                outputpath += "/"
            
    return(inputfile, makefile, outputpath)

if __name__ == "__main__":
    params = parseParameters(sys.argv[1:])
    if not params[0]:
        print("parser.py -i <inputfile>")
        
    path = params[2]
    name = params[0].split('/')[-1]
    if not os.path.exists(path+'CA/ca_'+name[:-2]):
        os.makedirs(path+'CA/ca_'+name[:-2])
    if not os.path.exists(path+'TA/ta_'+name[:-2]):
        os.makedirs(path+'TA/ta_'+name[:-2])
        
    headDecl = parseCFile(preprocessFile(params[0]))
    
    writeFile(path+'CA/ca_'+name[:-2]+'/ca_'+name, ''.join(CASource))
    writeFile(path+'TA/ta_'+name[:-2]+'/ta_'+name, ''.join(TASource))
    generateHeader(headDecl, name[:-2])
    
    shutil.copy('framework/CA/autogen_ca_header.h', path+'CA/ca_'+name[:-2])
    shutil.copy('framework/CA/crypto_operations_ca.c', path+'CA/ca_'+name[:-2])
    shutil.copy('framework/CA/param_io_ca.c', path+'CA/ca_'+name[:-2])
    shutil.copy('framework/CA/session_ca.c', path+'CA/ca_'+name[:-2])
    
    shutil.copy('framework/TA/autogen_ta_header.h', path+'TA/ta_'+name[:-2])
    shutil.copy('framework/TA/crypto_operations_ta.c', path+'TA/ta_'+name[:-2])
    shutil.copy('framework/TA/param_io_ta.c', path+'TA/ta_'+name[:-2])
    
    # -m flag
    if params[1]:
        os.system("python gen_makefile.py "+name+" CA")
        shutil.move('Makefile_tmp', path+'CA/ca_'+name[:-2]+'/Makefile')
        os.system("python gen_makefile.py "+name+" TA")
        shutil.move('Makefile_tmp', path+'TA/ta_'+name[:-2]+'/Makefile')
