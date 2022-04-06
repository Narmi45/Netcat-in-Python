import argparse
# Create command line arguments and parse the arguments to see what the user wants
# Enables you to use -c or --command and such
import socket
import shlex
import subprocess
# Create a subprocess on the system
import sys
# Run system commands
import textwrap
# Nice looking output
import threading
# Enables Multi-threading

def execute(cmd):
    cmd = cmd.strip()
    # strip() removes spaces at the beginning and ending of a string
    
    if not cmd:
        return
    # If the user does not supply a command, it will just return, (exit out)
    
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    # If the user does supply a command, this line runs a command on the local 
    # operating system and then returns the output from that command.

    return output.decode()
# This function receives a command, runs it, and returns the output as a string 

class NetCat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, d1)
    # Refers to THIS args, buffer, and socket, this means we are initializing these
    # variables and passing it in so all of the args refer to the same thing
    # Creation of the Sockets
    
    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()
    # Seeing if we run the listener or not:
    # If we do, execute listen method, if not, execute send method  

    def send(self):
        self.socket.cnnect((self.args.target, self.args.port)) #Connecting to the target IP and Port
        if self.buffer: # If there is anything in the buffer, 
            self.socket.send(self.buffer) #send the buffer
            try:
                while True: #Our loop starts here
                    recv_len = 1        #Set the receive lenght to 1 initially
                    response = ''       #Initialize the response to an empty string
                    while recv_len:     #While there is a length
                        data = self.socket.recv(4096)   #Create a data variable and receive 4096 bytes from target
                        recv_len = len(data)            #Set the receive length to the length of data received
                        response += data.decode()       #Append the decoded data to the response
                        if recv_len < 4096:             #Read all the data in and keep appending it to the response
                            break                       #until there is no more data to process
                        if response:                    #All data processed in the response variable, 3 lines above
                            print(response)             #Then we print out the response data
                            buffer = input('> ')        #Append to the buffer 
                            buffer += '\n'              #Put that information in a new line
                            self.socket.send(buffer.encode())   #Send that data off, and then encode the buffer
            except KeyboardInterrupt:                   #Error handler, exits socket and sys, use CTRL + C to terminate
                print('User terminated.')
                self.socket.close()
                sys.exit()

    def listen(self):
        self.socket.bind((self.args.target, self.args.port))    #Create a socket bind with target ip and port
        self.socket.listen(5)                                   #Support 5 connections at once, multi threaded
        while True:
            client_socket, _ = self.socket.accept()             
            client_thread = threading.Thread(target=self.handle, args=(client_socket,))
            client_thread.start()

    def handle(self, client_socket):
        if self.args.execute:                           #If .execute was passed in, meaning the user specified that flag -e=\"cat /etc/passwd\"
            output = execute(self.args.execute)         #Then, it is going to execute the command \"cat /etc/passwd\" and store it in output
            client_socket.send(output.encode())         #Then it is going to send the output and encode it to the target
        
        elif self.args.upload:                          #If .execute was NOT passed in, it will look in uploads
            file_buffer = b''                           #If it does, then initialize file buffer
            while True:                                 #
                data = client_socket.recv(4096)         #Receive the data as 4096 bytes, set it as a data variable
                if data:                                #If there is data that waws received,
                    file_buffer += data                 #Append that data to the file_buffer
                    print(len(file_buffer))             #Print the flength of the file_buffer
                else:                                   #Terminate if for some reason it didnt receive data
                    break
            with open(self.args.upload, 'wb') as f:     #Open a file as f,
                f.write(file_buffer)                    #Write into the file
            message = f'Saved file {self.args.upload}'  #Save the file, store into a message variable
            client_socket.send(message.encode())        #Encode the message and send it

        elif self.args.command:                         #If the .command was passed in
            cmd_buffer = b''                            #Then we initialize the command buffer
            while True:                                 #
                try:                                            #
                    client_socket.send(b'BHP #> ')              #Send this to make it look like a shell
                    while '\n' not in cmd_buffer.decode():      #Looks for a new line, (so when you click enter, this is activated)
                        cmd_buffer += client_socket.recv(64)    #Prompt that the command finished, and append that to the buffer
                    response = execute(cmd_buffer.decode())     #Execute the command officially
                    if response:                                #If there is a response passed in 
                        client_socket.send(response.encode())   #This will encode and send the response back to the user
                    cmd_buffer = b''                            #Clear out the buffer again, and wait for a new command or termination
                except Exception as e:                          #Termination exception
                    print(f'server killed {e}')         
                    self.socket.close()
                    sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
    # Use the argparse module from the library to create a command line interface
        
        description='BHP Net Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # Meta data used for format and class information
        
        epilog=textwrap.dedent('''Example:
        netcat.py -t 192.168.1.108 -p 5555 -l -c # command shell
        netcat.py -t 192.168.1.108 -p 5555 -l -u=mytest.txt # upload to file
        netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat /etc/passwd\" # execute command
        echo 'ABC' | ./netcat.py -t 192.168.1.108 -p 135 # echo text to server port 135
        netcat.py -t 192.168.1.108 -p 5555 # connect to server
    '''))
        # Example usage that the program will display when the user invokes it with --help 
    
    parser.add_argument('-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int, default=5555, help='specified port')
    parser.add_argument('-t', '--target', default='192.168.1.203', help='specified IP')
    parser.add_argument('-u', '--upload', help='upload file')
    args = parser.parse_args()
    # Creation of our arguments, create their current placeholders

    if args.listen:
        buffer = ''
    # If we’re setting it up as a listener, we invoke the NetCat object with 
    # an empty buffer string if it is listening
    
    else:
        buffer = sys.stdin.read()
    # If we are not using it as a listener:
    # See what is in the standard in, and set that as the buffer variable
    
    nc = NetCat(args, buffer.encode())
    # Pass in all the CMD line arguments that were selected by the user
    # We encode the buffer message and send the arguments
    nc.run()
    # Run the NetCat Class






