import datetime
import time

time_var = datetime.datetime.now()

print(time_var)
i = 0
while i < 40:
    i +=1
    time.sleep(1)

new_var = datetime.datetime.now()
print(new_var)

print(new_var - time_var)