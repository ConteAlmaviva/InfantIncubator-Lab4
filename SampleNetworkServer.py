import threading
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import infinc
import time
import math
import socket
import fcntl
import os
import errno
import random
import string
import base64
from diffiehellman import DiffieHellman
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

#hashlib.sha256("Password123GQn2xGEPPYOrk4jB".encode()).hexdigest()

class SmartNetworkThermometer (threading.Thread) :
    user_logins = {"jgoss":["GQn2xGEPPYOrk4jB","6e6e011fd64d85e5b2fdf8a932efd4c2f020a9f6d26699f878e359c3a4b541c6"],"lfrank":["12tB5ukuHBFCG1O0","4c13197a8410936a637166b601d4bdaaafe8c49821d27bde4b8f8282dd10c250"]}
    
    open_cmds = ["AUTH", "LOGOUT", "KEX"]
    prot_cmds = ["SET_DEGF", "SET_DEGC", "SET_DEGK", "GET_TEMP", "UPDATE_TEMP"]

    def __init__ (self, source, updatePeriod, port) :
        threading.Thread.__init__(self, daemon = True) 
        #set daemon to be true, so it doesn't block program from exiting
        self.source = source
        self.updatePeriod = updatePeriod
        self.curTemperature = 0
        self.updateTemperature()
        self.tokens = {}
        self.session_keys = {}
        self.refreshTokens(self.tokens, self.session_keys)
        self.dhkey = DiffieHellman(group=14,key_bits=540)
        self.pubkey = self.dhkey.get_public_key()

        self.serverSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.serverSocket.bind(("127.0.0.1", port))
        fcntl.fcntl(self.serverSocket, fcntl.F_SETFL, os.O_NONBLOCK)

        self.deg = "K"

    def encrypt(self, clearContent, sharedSessionKey):
        encCipher = AES.new(base64.b64decode(sharedSessionKey[:32]), AES.MODE_ECB)
        encrypted_message = encCipher.encrypt(pad(clearContent, 32))
        return encrypted_message
    
    def decrypt(self, encryptedContent, sharedSessionKey):
        encCipher = AES.new(base64.b64decode(sharedSessionKey[:32]), AES.MODE_ECB)
        decryptedContent = unpad(encCipher.decrypt(encryptedContent), 32)
        return str(decryptedContent).rstrip("=")

    def setSource(self, source) :
        self.source = source

    def setUpdatePeriod(self, updatePeriod) :
        self.updatePeriod = updatePeriod 

    def setDegreeUnit(self, s) :
        self.deg = s
        if self.deg not in ["F", "K", "C"] :
            self.deg = "K"

    def updateTemperature(self) :
        self.curTemperature = self.source.getTemperature()

    def getTemperature(self) :
        if self.deg == "C" :
            return self.curTemperature - 273
        if self.deg == "F" :
            return (self.curTemperature - 273) * 9 / 5 + 32

        return self.curTemperature
    
    def refreshTokens(self, curTokens, curSessionKeys):
        curTime = int(time.time())
        newTokens = {}
        for key in curTokens.keys():
            if curTokens[key][1] >= (int(time.time() - 10)):
                newTokens[key] = curTokens[key]
        
        for key in curTokens.keys():
            if key not in newTokens.keys():
                print("Token",key,"destroyed")
                for session in curSessionKeys.keys():
                    if key == curSessionKeys[session]["Token"]:
                        curSessionKeys.pop(session)

        self.tokens = newTokens

    def processCommands(self, msg, addr, client_pubkey) :
        cmds = msg.split(';')
        for c in cmds :
            cs = c.split(' ')
            if len(cs) == 2 : #should be either AUTH, LOGOUT, or KEX
                if cs[0] == "AUTH":
                    user = cs[1].split(":")[0]
                    passwd = cs[1].split(":")[1]
                    if user in self.user_logins.keys():
                        addSalt = passwd + self.user_logins[user][0]
                        if hashlib.sha256(addSalt.encode()).hexdigest() == self.user_logins[user][1]: 
                            newtoken = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))
                            self.tokens[newtoken] = [str(addr[0]), int(time.time())]
                            self.session_keys[client_pubkey].update({"Token": newtoken})
                            encToken = self.encrypt(newtoken.encode("utf-8"), self.session_keys[client_pubkey]["SharedKey"])
                            self.serverSocket.sendto(encToken, addr)
                        #print (self.tokens[-1])
                elif cs[0] == "LOGOUT":
                    if cs[1] in self.tokens :
                        self.source.tokens.pop(cs[1], None)
                elif cs[0] == "KEX":
                    client_pubkey = base64.b64decode(cs[1])
                    session_shared_key = base64.b64encode(self.dhkey.generate_shared_key(client_pubkey))
                    self.session_keys[cs[1]] = {"SharedKey":session_shared_key}
                    self.serverSocket.sendto(base64.b64encode(self.pubkey), addr)
                else : #unknown command
                    self.serverSocket.sendto(b"Invalid Command\n", addr)
            elif c == "SET_DEGF" :
                self.deg = "F"
            elif c == "SET_DEGC" :
                self.deg = "C"
            elif c == "SET_DEGK" :
                self.deg = "K"
            elif c == "GET_TEMP" :
                encMsg = self.encrypt(b"%f\n" % self.getTemperature(), self.session_keys[client_pubkey]["SharedKey"])
                print
                self.serverSocket.sendto(encMsg, addr)
            elif c == "UPDATE_TEMP" :
                self.updateTemperature()
            elif c :
                self.serverSocket.sendto(b"Invalid Command\n", addr)

    def run(self) : #the running function
        while True : 
            try :
                msg, addr = self.serverSocket.recvfrom(1024)
                msg = msg.decode("utf-8").strip()
                cmds = msg.split(' ')
                client_pubkey = None
                if cmds[0] in self.session_keys.keys(): #We're receiving an encrypted command from someone who should have an established session key
                    client_pubkey = cmds[0]
                    msg = self.decrypt(msg, self.session_keys[client_pubkey]["SharedKey"])
                    cmds = msg.split(' ')
                elif cmds[0] == "KEX":
                    self.processCommands(msg, addr, None) 
                else:
                    self.serverSocket.sendto(b"Exchange Keys first (use command KEX)\n", addr)
                    cmds = ""

                if len(cmds) == 1 : # protected commands case
                    semi = msg.find(';')
                    if semi != -1 : #if we found the semicolon
                        #print (msg)
                        if msg[:semi] in self.tokens.keys() and addr[0] == self.tokens[msg[:semi]][0]: #if its a valid token and the IP address matches the IP that token was assigned to 
                            self.tokens[msg[:semi]][1] = int(time.time())
                            self.session_keys[client_pubkey]["Token"] = msg[:semi]
                            self.processCommands(msg[semi+1:], addr, client_pubkey)
                        else :
                            encMsg = self.encrypt(b"Bad Token\n", self.session_keys[client_pubkey]["SharedKey"])
                            self.serverSocket.sendto(encMsg, addr)
                    else :
                            encMsg = self.encrypt(b"Bad Command\n", self.session_keys[client_pubkey]["SharedKey"])
                            self.serverSocket.sendto(encMsg, addr)
                elif len(cmds) == 2 :
                    if cmds[0] in self.open_cmds : #if its AUTH or LOGOUT
                        self.processCommands(msg, addr, client_pubkey) 
                    else :
                        self.serverSocket.sendto(b"Authenticate First\n", addr)
                elif len(cmds) != 0:
                    # otherwise bad command
                    self.serverSocket.sendto(b"Bad Command\n", addr)
    
            except IOError as e :
                if e.errno == errno.EWOULDBLOCK :
                    #do nothing
                    pass
                else :
                    #do nothing for now
                    pass
                msg = ""

 

            self.updateTemperature()
            self.refreshTokens(self.tokens, self.session_keys)
            time.sleep(self.updatePeriod)


class SimpleClient :
    def __init__(self, therm1, therm2) :
        self.fig, self.ax = plt.subplots(num="SampleNetworkServer")
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
        self.infTherm = therm1
        self.incTherm = therm2

        self.ani = animation.FuncAnimation(self.fig, self.updateInfTemp, interval=500)
        self.ani2 = animation.FuncAnimation(self.fig, self.updateIncTemp, interval=500)

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


    def updateInfTemp(self, frame) :
        self.updateTime()
        self.infTemps.append(self.infTherm.getTemperature()-273)
        #self.infTemps.append(self.infTemps[-1] + 1)
        self.infTemps = self.infTemps[-30:]
        self.infLn.set_data(range(30), self.infTemps)
        return self.infLn,

    def updateIncTemp(self, frame) :
        self.updateTime()
        self.incTemps.append(self.incTherm.getTemperature()-273)
        #self.incTemps.append(self.incTemps[-1] + 1)
        self.incTemps = self.incTemps[-30:]
        self.incLn.set_data(range(30), self.incTemps)
        return self.incLn,

UPDATE_PERIOD = .05 #in seconds
SIMULATION_STEP = .1 #in seconds

#create a new instance of IncubatorSimulator
bob = infinc.Human(mass = 8, length = 1.68, temperature = 36 + 273)
#bobThermo = infinc.SmartThermometer(bob, UPDATE_PERIOD)
bobThermo = SmartNetworkThermometer(bob, UPDATE_PERIOD, 23456)
bobThermo.start() #start the thread

inc = infinc.Incubator(width = 1, depth=1, height = 1, temperature = 37 + 273, roomTemperature = 20 + 273)
#incThermo = infinc.SmartNetworkThermometer(inc, UPDATE_PERIOD)
incThermo = SmartNetworkThermometer(inc, UPDATE_PERIOD, 23457)
incThermo.start() #start the thread

incHeater = infinc.SmartHeater(powerOutput = 1500, setTemperature = 45 + 273, thermometer = incThermo, updatePeriod = UPDATE_PERIOD)
inc.setHeater(incHeater)
incHeater.start() #start the thread

sim = infinc.Simulator(infant = bob, incubator = inc, roomTemp = 20 + 273, timeStep = SIMULATION_STEP, sleepTime = SIMULATION_STEP / 10)

sim.start()

sc = SimpleClient(bobThermo, incThermo)

plt.grid()
plt.show()

