import cmd
from read_packets import parse
import os

class sniffsift(cmd.Cmd):
    
    def __init__(self) :
        super().__init__()

    prompt = "+_+ "
    intro = '\nWelcome to sniffsift, an offline network traffic analyzer.\nThe input of the analyzer is a hexdump text file. Type help for available commands.\n'

    # Your CLI commands and functionality will go here

    def do_hello(self, line):
        """
        `hello`

        Print a greeting.
        """

        print("Hello, World!")


    def do_quit(self, line):
        '''
        `quit`

        Exit the CLI.
        '''
        return True
    

    def do_read(self, arg):
        '''
        `read your_hexdump_file.txt`

        The packets in the plaintext input hexdump file will be read and parsed.
        '''
        # get the file name/path
        file_name = arg
    
        # validate the file name/path
        self.validate_file(file_name)
        
        count = 1
        # read and parse the file content
        summary, layers = parse(file_name)
        for item in summary:
            print("Packet", count)
            for subitem in item:
                print(subitem)
            count+=1
            print()
    

    def do_clear(self, arg):
        '''
        `clear`

        Clear the screen
        '''
        os.system('clear')
    
    
    def do_ls(self, arg):
        '''
        `ls`

        List contents of current directory
        '''
        os.system('ls')
        print()
    

    def validate_file(self, file_name):
        '''
        validate file name and path.
        '''
        # error messages
        INVALID_FILETYPE_MSG = "Error: Invalid file format. %s must be a .txt file."
        INVALID_PATH_MSG = "Error: Invalid file path/name. Path %s does not exist."

        if not self.valid_path(file_name):
            print(INVALID_PATH_MSG%(file_name))
            quit()
        elif not self.valid_filetype(file_name):
            print(INVALID_FILETYPE_MSG%(file_name))
            quit()
        return


    def valid_filetype(self, file_name):
        # validate file type
        return file_name.endswith('.txt')
 

    def valid_path(self, path):
        # validate file path
        return os.path.exists(path)


    # def precmd(self, line):
    #     # Add custom code here
    #     print("Before command execution")
    #     return line  # You must return the modified or original command line
    

    # def postcmd(self, stop, line):
    #     # Add custom code here
    #     print()
    #     return stop  # Return 'stop' to control whether the CLI continues or exits
    

    # def preloop(self):
    #     # Add custom initialization here
    #     print("Initialization before the CLI loop")
    

    # def postloop(self):
    #     # Add custom cleanup or finalization here
    #     print("Finalization after the CLI loop")



if __name__ == "__main__":
    sniffsift().cmdloop()


