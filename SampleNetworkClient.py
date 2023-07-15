import matplotlib.pyplot as plt
import matplotlib.animation as animation
import time
import math
import socket
import base64
from diffiehellman import DiffieHellman
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class SimpleNetworkClient :
    def __init__(self, port1, port2) :
        self.fig, self.ax = plt.subplots(num="SampleNetworkClient")
        now = time.time()
        self.lastTime = now
        self.times = [time.strftime("%H:%M:%S", time.localtime(now-i)) for i in range(30, 0, -1)]
        self.infTemps = [0]*30
        self.incTemps = [0]*30
        self.infLn, = plt.plot(range(30), self.infTemps, label="Infant Temperature")
        self.incLn, = plt.plot(range(30), self.incTemps, label="Incubator Temperature")
        plt.xticks(range(30), self.times, rotation=45)
        plt.ylim((20,50))
        plt.legend(handles=[self.infLn, self.incLn])
        self.infPort = port1
        self.incPort = port2

        self.infToken = None
        self.incToken = None
        self.gotPass = False
        self.pw = None
        self.user = None
        self.dhkey = None
        self.pubkey = None
        self.sharedkey = None

        if not self.gotPass:
            self.user = bytes(input("Username:"), 'utf-8')
            self.pw = bytes(getpass(prompt="Password: "), 'utf-8')
            self.dhkey = DiffieHellman(group=14,key_bits=540)
            self.pubkey = self.dhkey.get_public_key()
            self.gotPass = True
            
        
        if self.incToken != None and self.infToken != None:
            del self.pw

        self.ani = animation.FuncAnimation(self.fig, self.updateInfTemp, interval=500)
        self.ani2 = animation.FuncAnimation(self.fig, self.updateIncTemp, interval=500)

    def encrypt(self, clearContent):
        encCipher = AES.new(base64.b64decode(self.sharedkey[:32]), AES.MODE_ECB)
        encrypted_message = encCipher.encrypt(pad(clearContent, 32))
        return encrypted_message
    
    def decrypt(self, encryptedContent):
        encCipher = AES.new(base64.b64decode(self.sharedkey[:32]), AES.MODE_ECB)
        decryptedContent = encCipher.decrypt(encryptedContent)
        return str(decryptedContent).rstrip("=")
    
    def updateTime(self) :
        now = time.time()
        if math.floor(now) > math.floor(self.lastTime) :
            t = time.strftime("%H:%M:%S", time.localtime(now))
            self.times.append(t)
            #last 30 seconds of of data
            self.times = self.times[-30:]
            self.lastTime = now
            plt.xticks(range(30), self.times,rotation = 45)
            plt.title(time.strftime("%A, %Y-%m-%d", time.localtime(now)))

    def getTemperatureFromPort(self, p, tok) :
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        encMsg = self.encrypt(bytes(tok + ";GET_TEMP", "utf-8"))
        s.sendto(encMsg, ("127.0.0.1", p))
        msg, addr = s.recvfrom(1024)
        msg = self.decrypt(msg)
        m = msg.decode("utf-8")
        return (float(m))

    def authenticate(self, p) :
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        s.sendto(b"KEX %s" % base64.b64encode(self.pubkey), ("127.0.0.1", p))
        msg, addr = s.recvfrom(1024)
        self.sharedkey = base64.b64encode(self.dhkey.generate_shared_key(base64.b64decode(msg.strip())))
        encMsg = self.encrypt(b"AUTH %s:%s" % (self.user, self.pw))
        s.sendto(encMsg, ("127.0.0.1", p))
        msg, addr = s.recvfrom(1024)
        msg = self.decrypt(msg)
        return msg.strip()

    def updateInfTemp(self, frame) :
        self.updateTime()
        if self.infToken is None : #not yet authenticated
            self.infToken = self.authenticate(self.infPort)

        self.infTemps.append(self.getTemperatureFromPort(self.infPort, self.infToken)-273)
        #self.infTemps.append(self.infTemps[-1] + 1)
        self.infTemps = self.infTemps[-30:]
        self.infLn.set_data(range(30), self.infTemps)
        return self.infLn,

    def updateIncTemp(self, frame) :
        self.updateTime()
        if self.incToken is None : #not yet authenticated
            self.incToken = self.authenticate(self.incPort)

        self.incTemps.append(self.getTemperatureFromPort(self.incPort, self.incToken)-273)
        #self.incTemps.append(self.incTemps[-1] + 1)
        self.incTemps = self.incTemps[-30:]
        self.incLn.set_data(range(30), self.incTemps)
        return self.incLn,

snc = SimpleNetworkClient(23456, 23457)

plt.grid()
plt.show()
