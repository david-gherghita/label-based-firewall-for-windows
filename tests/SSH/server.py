import paramiko
import socket
import threading

USER = 'z24wjtrjAwMAzkBznzUyQK7fSL2xzYMiSsH0FgTVJUg6rKuibSOgpd1Cve9uGsDhmdIBc4WcOb1YZxVh'
PASS = 'Xjitl5hip@XzlITCjDe5dIGh9u!k9SLZP!#bBECya8L2Qs8Cha4Jb@R8tehhlyUufsI$I!Z9uyDBppYD'

class SSHServer(paramiko.server.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        if (username == USER) and (password == PASS):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        writemessage = channel.makefile("w")
        writemessage.write(command)
        writemessage.channel.send_exit_status(0)
        return True


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('', 2222))
sock.listen()

while True:
    client, _ = sock.accept()
    transport = paramiko.Transport(client)
    transport.add_server_key(paramiko.RSAKey(filename='test_rsa.key'))
    transport.start_server(server=SSHServer())
