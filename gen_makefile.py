from __future__ import print_function
import sys

bin_path = "../../bin"
lib_path = "../../lib"
ca_path = "../../CAs/"
opt_path = ""
dir_path = ""

path_opentee = "OPENTEE_PATH ="
path_dir = "\nDIR_PATH ="
incl_dir = "\nIDIR = -I$(DIR_PATH)emulator/include -I$(DIR_PATH)libtee/include -I$(DIR_PATH)emulator/manager "
incl_dir_ta = "-I$"+ca_path

cc = "\nCC = gcc\n"
cflags = "CFLAGS=$(IDIR)"
cflags_ta = " -DTA_PLUGIN -fpic"

deps = "\n\nDEPS = tee_internal_api.h tee_ta_properties.h tee_logging.h tee_client_api.h autogen_ta_header.h"+\
        "autogen_ca_header.h autogen_shared_header.h\n"
ca_obj = "OBJ = session_ca.o param_io_ca.o crypto_operations_ca.o ca_"
ta_obj = "OBJ = param_io_ta.o crypto_operations_ta.o ta_"

c_to_o = "%.o: %.c $(DEPS)\n\t$(CC) -c -o $@ $< $(CFLAGS)\n\n"
ca_o_to_bin = ": $(OBJ)\n\tgcc -Wall -o $@ $^  $(CFLAGS) -L $(OPENTEE_PATH)lib -ltee -lssl -lcrypto \n\tmv $@ "+bin_path+"\n\n"
ta_o_to_so = ".so: $(OBJ)\n\tgcc -Wall -shared -o $@ $^  $(CFLAGS) -L $(OPENTEE_PATH)lib -ltee\n\tmv $@ "+lib_path+"\n\n"


clean = "\nclean:\n\trm *.o"

def readConf():
    global opt_path, dir_path
    with open("opentee_path.conf", "r") as fo:
        conf = fo.readlines()
        for line in conf:
            line = line.strip().split("=")
            if not len(line[1]):
                print("Open-TEE configuration missing")
                sys.exit(0)
            elif "OPENTEE_PATH" in line[0]:
                opt_path = line[1]
            elif "DIR_PATH" in line[0]:
                dir_path = line[1]

def writeFile(data):
    with open("Makefile_tmp", 'a+') as fo:
        fo.write(data)


if __name__ == "__main__":
    if len(sys.argv) > 2:
        source_name = sys.argv[1]
        env = sys.argv[2]
        if source_name[-2:] == ".c":
            source_name = source_name[:-2]
    else:
        print("Usage: python gen_makefile.py <sourcefile> <env>")
        sys.exit(0)
    
    readConf()
    incl = path_opentee+opt_path+path_dir+dir_path+incl_dir
    
    if env == "CA":
        makefile = incl+cc+cflags+deps+ca_obj+source_name+".o\n\n"+c_to_o+source_name+ca_o_to_bin+clean
        writeFile(makefile)
        
    elif env == "TA":
        makefile = incl+incl_dir_ta+source_name+"_ca"+cc+cflags+cflags_ta+\
                deps+ta_obj+source_name+".o\n\n"+c_to_o+source_name+ta_o_to_so+clean
        writeFile(makefile)
