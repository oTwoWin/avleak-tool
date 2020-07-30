from avleak import AvLeak
from shutil import copyfile
from subprocess import check_output, CalledProcessError
import os

class Windows_Defender(AvLeak):
    '''
        Windows Defender antivirus class
        
        :ivar av_path: Path to antivirus CLI executable
        :vartype av_path: str
        
        :ivar table_name: The malware table's name
        :vartype table_name: str
    '''
    
    def __init__(self):
        super().__init__()
        self.av_path = "%ProgramFiles%\Windows Defender\MpCmdRun.exe"
        self.table_name = "malweare_table_windows_defender.txt"
        self.byte_per_leak = 4
        
    def scan(self, source_dir, no_action = False):
        #Construct command to scan
        command = '"'+self.av_path + '" -Scan -ScanType 3 -File "' + source_dir + '" -DisableRemediation > rapport.txt'
        print("Scanning in process...")

        #Execute the command
        try:
            check_output(command, shell=True)
        except CalledProcessError as grepexc:
            if grepexc.returncode != 2:
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
        found_virus = False
        line_count = 0
        #File to write the signature files
        malware_file = open(self.table_name, "w+")
        av_rapport = open("rapport.txt", "r")

        print("Generating malware table...")
        av_lines = av_rapport.readlines()
        for line in av_lines:
            line_count += 1
            if "Virus:" in line:
                #print(line)
                signature = line.split("/")[1]
                signature = signature.split(".")[0]
                signature = signature.split("_")[0]
                signature = signature.split("!")[0]
                signature = signature.capitalize()
                signature = signature.replace("\n","")    
                
                if signature not in malware_array:
                    # add the signature to the array
                    malware_array.append(signature)
                    # write to the file
                    malware_file.write(str(count) + " " + signature + "\n")                    
                    
                    # Find path in the next two line
                    found_virus = True
                    line_count = 0
                    
            if found_virus == True and line_count == 2:
                #Recover path to malware
                path_to_malw = line.split(":")[2]
                path_to_malw = path_to_malw.split("->")[0]
                path_to_malw = path_to_malw.replace("\n","") 
                
                # encrypt file to the directory
                if do_encrypt:
                    self.encrypt("C:"+path_to_malw, str(count))
                
                found_virus =  False
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
                key = key[:-1].capitalize()
                malwares[key] = val


        av_rapport = open("rapport.txt", "r")
        av_lines = av_rapport.readlines()
        data = ""

        for line in av_lines:
            if "Virus:" in line:
                signature = line.split("/")[1]
                signature = signature.split(".")[0]
                signature = signature.split("_")[0]
                signature = signature.split("!")[0]
                signature = signature.capitalize()
                signature = signature.replace("\n","")
                data += chr(int(malwares[signature]))
        
        data = data[-1:] + data[:-1]
        av_rapport.close()
        os.remove("rapport.txt")

        return data
