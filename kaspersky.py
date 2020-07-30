from avleak import AvLeak
from shutil import copyfile
from subprocess import check_output, CalledProcessError
import os

class Kaspersky(AvLeak):
    '''
        Kaspersky antivirus class
        
        :ivar av_path: Path to antivirus CLI executable
        :vartype av_path: str
        
        :ivar table_name: The malware table's name
        :vartype table_name: str
    '''
    
    
    def __init__(self):
        super().__init__()
        self.av_path = "C:/Program Files (x86)/Kaspersky Lab/Kaspersky Anti-Virus 20.0/avp.com"
        self.table_name = "malware_table_kaspersky.txt"
        self.byte_per_leak = 30

    def scan(self, source_dir, no_action = False):
        #Construct command to scan
        command = '"'+self.av_path + '" SCAN "' + source_dir + '" /R:rapport.txt /iChecker=off /iSwift=off '
        if no_action:
            command += "/i0"
        else:
            command += "/i4"
            
        print("Scanning in process...")

        #Execute the command        
        try:
            check_output(command, shell=True)
        except CalledProcessError as grepexc:
            if grepexc.returncode != 3:
                print("error code", grepexc.returncode, grepexc.output)
        
        print("Scanning done! \n")

        #Check if the rapport is generated correctly
        if not os.path.exists("rapport.txt"):
            print("Error when oppening the AV rapport file")
            exit()

    def generate_malware_table(self, do_encrypt = True):
        # Var initialization
        malware_array = []
        count = 0

        #File to write the signature files
        malware_file = open(self.table_name, "w+")
        av_rapport = open("rapport.txt", "r")

        print("Generating malware table...")

        #Read the file
        av_lines = av_rapport.readlines()
        for line in av_lines:
            # check if a malware is detected by the av
            if "detected" in line and "Total" not in line:
                #Extract the signature
                splited_line = line.split("\t")
                path_to_malw = splited_line[1]
                signature = splited_line[3]
                if not "Virus.Win32" in signature:
                    continue
                signature = signature.split(".")
                signature = signature[2]

                #Add a end of line char if not present
                if "\n" not in signature:
                    signature += "\n"
                if signature not in malware_array and r"//" not in line:
                    # add the signature to the array
                    malware_array.append(signature)
                    # write to the file
                    malware_file.write(str(count) + " " + signature)
                    
                    # encrypt file to the directory
                    if do_encrypt:
                        self.encrypt(path_to_malw, str(count))

                    count += 1

                    # if we reach the number we needed, stop looping
                    if count == 256:
                        break

        if count < 256:
            print("!!! Insufficient malware signatures found ! Only found %d malwares !!! \n Please find more malwares !" % count)

        #Close files and remove rapport
        malware_file.close()
        av_rapport.close()
        os.remove("rapport.txt")
        print("Malware table done !")

    def read(self):
        # Recreate dictionary from malware file
        malwares = {}
        with open(self.table_name) as f:
            for line in f:
                (val, key) = line.split(" ")
                key = key[:-1]
                malwares[key] = val


        av_rapport = open("rapport.txt", "r")
        av_lines = av_rapport.readlines()
        data = ""

        for line in av_lines:
            if "detected" in line and "Total" not in line:
                splited_line = line.split("\t")
                signature = splited_line[3]
                signature = signature.split(".")
                signature = signature[2]
                signature = signature.replace("\n","")

                data += chr(int(malwares[signature]))

        av_rapport.close()
        os.remove("rapport.txt")

        return data

