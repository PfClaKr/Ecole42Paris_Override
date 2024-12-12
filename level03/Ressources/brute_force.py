import os

os.system("echo -n \"hi\" > /tmp/dump.txt")
for i in range(322424824, 322424844):
        os.system("echo -n \"" + str(i) + "\" >> /tmp/dump.txt")
        cmd = "python -c \'print \"" + str(i) + "\"\' | /home/users/level03/level03 >> /tmp/dump.txt"
        os.system(cmd)
