import os
import paramiko

USER = 'z24wjtrjAwMAzkBznzUyQK7fSL2xzYMiSsH0FgTVJUg6rKuibSOgpd1Cve9uGsDhmdIBc4WcOb1YZxVh'
PASS = 'Xjitl5hip@XzlITCjDe5dIGh9u!k9SLZP!#bBECya8L2Qs8Cha4Jb@R8tehhlyUufsI$I!Z9uyDBppYD'

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('169.254.26.45', 2222, username=USER, password=PASS)


TESTS = [1, 256, 1024, 4096, 32768, 262144, 1048576]
TABS = [3, 2, 2, 2, 2, 2, 2]

for i in range(len(TESTS)):
    test = TESTS[i]
    print(f'Testing with {test} byte(s):', end='')
    print(TABS[i] * '\t', end='')
    data = os.urandom(test)

    _, stdout, _ = client.exec_command(data)
    stdout.channel.recv_exit_status()
    stdout.channel.close()
    if stdout.read() == data:
        print('SUCCESS')
    else:
        print('FAILURE')

client.close()
