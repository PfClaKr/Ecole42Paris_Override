import os

os.system("echo -n \"\" > /tmp/dump2.txt")
for i in range(322424824, 322424844):
        os.system("echo -n \"" + str(i) + "\" >> /tmp/dump2.txt")
        cmd = "python -c \'print \"" + str(i) + "\"\' | /home/users/level03/level03 >> /tmp/dump2.txt"
        os.system(cmd)
