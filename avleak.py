from abc import ABC, abstractmethod
from tempfile import mkstemp
import os
import subprocess
import shutil


class AvLeak(ABC):
    '''
       Abstract class representing an antivirus. Each antivirus will inherit it.
       
       :ivar output_path: Path to output encrypted malwares
       :vartype output_path: str
       
       :ivar program_path: Path to scenario test programs
       :vartype program_path: str
       
       :ivar cmake_path: Path to CMake binaries
       :vartype cmake_path: str
       
       :ivar mingw_path: Path to MinGW binaries
       :vartype cmake_path: str
       
       :ivar rc_path: Path to the ressource file
       :vartype cmake_path: str
       
       :ivar key: Key to encrypt malwares
       :vartype key: bytearray
       
       :ivar byte_per_leak: Maximum number of bytes to be exfiltered per scan
       :vartype byte_per_leak: int
       
       :ivar end_leak_bytes: String defining the end of the leak
       :vartype end_leak_bytes: str
    '''
    
    
    def __init__(self):
        # Usefull directory to memorize
        self.output_path = os.path.join(os.path.dirname(__file__), "./malwares")
        self.program_path = os.path.join(os.path.dirname(__file__), "./program_leaks")
        self.cmake_path = os.path.join(os.path.dirname(__file__), "./compilation_tools/cmake/bin")
        self.mingw_path = os.path.join(os.path.dirname(__file__), "./compilation_tools/mingw/bin")
        self.rc_path =  self.program_path + '/poc.rc'

        #32 bytes key array
        self.key = bytearray(b'\x8f\x3b\x73\xd7\x50\xc8\x40\x18\x57\x2c\x9b\xa7\xc3\x52\xb8\x04\x05\x8d\x06\x69\x97\x51\x02\x79\xe5\x37\x22\xba\xae\xa1\x46\x9a')

        #Default value, changed it in child class
        self.byte_per_leak = 8
        
        #Default end of leak bytes
        self.end_leak_bytes = '\x00'

    def encrypt(self, file_path, filename, output_path = None):
        '''
            Encrypt a file using xor method to an ouput directory
            
            :param file_path: The file's path to encrypt
            :type file_path: str         
            :param filename: File's name after encryption
            :type filename: str           
            :param output_path : Output path (Default malwares folder)
            :type output_path: str
            
            :rtype: None
        '''
        if output_path is None:
            output_path = self.output_path
        #Open file
        f = open(file_path, "rb")

        # declare contents
        content = bytearray(f.read())
        new_content = bytearray()

        # encrypt
        for i in range(0,len(content)):
            new_content.append(content[i] ^ self.key[i % 32])

        #encrypted file
        new_f = open(os.path.join(output_path, filename), "wb+")
        new_f.write(new_content)

        #close both files
        f.close()
        new_f.close()

    def scan(self, source_dir, no_action = False):
        '''
            Scan a file or directory and save the result to the file rapport.txt
            
            :param source_dir: Path to the dir to scan
            :type source_dir: str         
            :param no_action: Specify if the antivirus has to take no action, usefull for generating the malware table. Default False
            :type no_action: bool
            
            :rtype: None
        '''
        pass

    def generate_malware_table(self, do_encrypt = True):
        '''
            Generate the malware table from scan report
            
            :param do_encrypt: Encrypt detected file (default True). May be usefull for generating malware table from already existing encrypted malwares.
            :type do_encrypt: bool
            
            :rtype: None
        '''
        pass

    def generate_rs(self):
        '''
            Generate ressource file responsible to link malwares to the C code
            
            :rtype: None
        '''
        output_path = self.output_path.replace("\\", "/")
        with open(self.rc_path, "w") as f:
            for i in range(0,256):
                f.write('IDR_BINARY'+str(i)+'             RCDATA                  "'+output_path+'/'+str(i)+'" \n')

    def make(self, program_name, byte_number):
        ''' 
            Make a test scenario program.
            
            :param program_name: Name of the test scenario
            :type program_name: str           
            :param byte_number: Position of the first char to exfiltrate
            :type byte_number: int
            
            :rtype: None
        '''
        #Program directory
        working_dir = self.program_path + '/' + program_name
        compile_dir = working_dir + '/cmake-build-debug'

        #Edit the min and max Length
        avleak_path = working_dir + '/avleak.c'

        #Create temp file
        fh, abs_path = mkstemp()
        with open(fh,'w') as new_file:
            with open(avleak_path, 'r') as old_file:
                for line in old_file:
                    if 'define minLength' in line:
                        new_file.write("#define minLength %d\n" % (byte_number))
                    elif 'define maxLength' in line:
                        new_file.write("#define maxLength %d\n" % (byte_number + self.byte_per_leak))
                    else:
                        new_file.write(line)
        #Copy the file permissions from the old file to the new file
        shutil.copymode(avleak_path, abs_path)
        #Remove original file
        os.remove(avleak_path)
        #Move new file
        shutil.move(abs_path, avleak_path)

        #Set env variable
        my_env = os.environ.copy()
        my_env['PATH'] += ';' + self.mingw_path + ';' + self.cmake_path
        my_env['CC'] = self.mingw_path + '/gcc.exe'
        my_env['CXX'] = self.mingw_path + '/g++.exe'

        #Copy rc file in case it changed
        shutil.copyfile(self.rc_path, working_dir+'/poc.rc')

        command = self.cmake_path+'/cmake.exe'

        #If CMakeCache.txt don't exists, set build type
        if not os.path.exists(compile_dir+'/CMakeCache.txt'):
            p = subprocess.check_output([command, "-G", 'MinGW Makefiles', "../"], cwd=compile_dir, env=my_env)

        #Cmake
        p = subprocess.check_output([command, '../'], cwd=compile_dir, env=my_env)
        p = subprocess.check_output([command, '--build', '.', '--target', 'poc','-j', '4', '--', '-d', '-p'], cwd=compile_dir, env=my_env)

    def read(self):
        '''
            Read the scan file to retrieve the data exfiltrated
            
            :return: The data exfiltrated
            :rtype: str
        '''
        pass
