import pyshark
import subprocess

#subprocess.check_output(['ls', '-l'])  # All that is technically needed...
subprocess.run(['text2pcap', 'test.txt', 'mycapture.cap'])

cap = pyshark.FileCapture('mycapture.cap')
print(cap[0])