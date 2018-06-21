import socket
import threading
import hashlib
import os
import http.server
import time
import json
import base64
import shutil
import sys



global_table = {'hash_value': [], 'content-type': [],
                'content-length': [], 'ip': [], 'port': []}
"""This dicionary is used to store the all the data like has 
hash content type, length and the ip address and port number
 of the node which has published it. This table is same for 
 node hence it is updated everytime its changed         """


metadata_dictionary = {'hash_value': [], 'content-type': [],
                       'content-length': []}
"""this dictionary is used to store the metadata which is 
latter used to display meta data   """



localdatabase = {'hash_value': [], 'file': []}
"""this database is used to store all the content that is 
published on p2p web. It is also used to find the index in program"""


peers = {'NAME OF PEER': [], 'IP ADDRESS': [], 'PORT': []}
"""this dictionary is used to store all the peers of a node"""








ip_server = []
port_listen = 5000   
"""port on which we listen continuosly to get connection"""

port_income = 6000     
"""port on which file transfer takes place"""

port_browser = 7000     
"""port which is used to connect using http"""


def com_input():
    """this function is used to get the command from the user
    what it wants the node to do. """

    while True:
        print("\nAvailable commands   :(1/2/3/4/5/6) \n 1.PEER \n 2.PUBLISH \n 3.UNPUBLISH "
              "\n 4.SHOW PEERS \n 5.SHOW METADATA \n 6.SHOW PUBLISHED")

        try:
            com_no = int(input("press command number ?  :"))

            if com_no == 1:
                hostname=input("enter  hostname  :")
                port = port_listen
                ip = socket.gethostbyname(hostname)
                dict_up(peers, "NAME OF PEER", hostname)
                dict_up(peers, "IP ADDRESS", ip)
                dict_up(peers, "PORT", port)
                commandPeer(hostname)


            elif com_no == 2:
                com_file=input("enter the file u wish to publish filename.filetype   :")
                commandPublish(com_file)


            elif com_no== 3 :

                hash1=input("enter the hash of the file  :")
                commandUnpublish(hash1)

            elif com_no== 4:
                commandPeers()

            elif com_no==5:
                commandMetadata()

            elif com_no == 6:
                    commandPublished()

            else:
                print("invalid input")
        except ValueError :
            print("invalid command")
            exit1=input("Do you want to exit (y/n) :")
            if exit1=="y":
                exit()
            else:
                pass


    return


def commandPeer(getname):
    """this function is used to add a peer .It takes the hostname
    of the peer and uses DNS to get the corresponding ip. This ip
    is used to form a permanent connection with the peer"""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverAddress = socket.gethostbyname(getname)
        print('Connect to : ', serverAddress)
        global ip_server
        ip_server.append(serverAddress)#saving the ip address into a list
        client.connect((serverAddress, port_listen))#peering with the given host name
        client.send(str.encode("OK"))#both peers acknowledge after peering by sending "OK"
        return
    except ConnectionRefusedError:
        print("invalid host name ")#if the hostname is invalid
        host_name=input("enter correct host name :")
        commandPeer(host_name)
        return



def commandPublish(filename_full):
    """this command is used to publish a file. when this
    command is used we calculate the hash value and store the
    meta data of the content in the global table which is
    sent to every other node on the P2P network"""
    try:
        fileopen = open(filename_full, 'r')#opening a file
    except FileNotFoundError:
        print("File not found")
        return
    digest, con_type, con_len = calc_hash(filename_full)#getting the hash value,along wiith content type and content length from calc_hash function 
    dict_up(global_table, 'hash_value', digest)#entering the hash into dictionary
    dict_up(global_table, 'content-type', con_type)#entering content type into dictionary
    dict_up(global_table, 'content-length', con_len)#entering content length into dictionary
    dict_up(global_table, 'ip', ipAddr)#entering the endpoint information
    dict_up(global_table, 'port', port_listen)
    dict_up(metadata_dictionary, 'hash_value', digest)#entering the hash value into the metadata list
    dict_up(metadata_dictionary, 'content-type', con_type)#entering the content type into the metadata list
    dict_up(metadata_dictionary, 'content-length', con_len)#entering the content length into the metadata list
    dict_up(localdatabase, 'hash_value', digest)#entering the hash value into database
    dict_up(localdatabase, 'file', filename_full)#entering the file name into database|| database is to know what is being published by current host
    data = json.dumps(global_table)
    for p in ip_server:
        if p== ipAddr:#the current host ip address
            pass
        else:
            announcement= socket.socket(socket.AF_INET, socket.SOCK_STREAM)#sending announcement to peers via new connection and tearing down the connection 
            announcement.connect((p, port_listen))#after sending the announcement
            announcement.sendall(str.encode(data))#send announcement to peers
            announcement.close()#tearing down the announcement connection
    return


def commandUnpublish(hash_recv):
    """this function is ud=sed to unpublish the content from the P2P web.
    It takes the hash value to find the content that we want to unpublish.
    Only the node which has originally published the content can unpublish it"""
    i1 = findIndex(global_table, hash_recv)
    i2=findIndex(localdatabase, hash_recv)
    if (i1==-1):
        print(" INVALID HASH")
    else:
        try:
            del global_table["hash_value"][i1]#deleting the hash value,content type ,content length ,end point information from the global table
            del global_table["content-type"][i1]#from the metadata dictionary and from host database
            del global_table["content-length"][i1]
            del global_table["ip"][i1]
            del global_table["port"][i1]
            del metadata_dictionary["hash_value"][i1]
            del metadata_dictionary["content-type"][i1]
            del metadata_dictionary["content-length"][i1]
            del localdatabase["hash_value"][i2]
            del localdatabase["file"][i2]
            data = json.dumps(global_table)
            for c in ip_server:
                if c == ipAddr:
                    pass
                else:
                    updateSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#announce these changes to the peers
                    updateSock.connect((c, port_listen))
                    updateSock.sendall(str.encode(data))
                    updateSock.close()
            return
        except IndexError:
            print("invalid hash")

def commandPublished():
    """this fuction is used to display the content that
        is published by the node on which the command is given"""

    for key, value in metadata_dictionary.items():
        print(key, value)

def commandMetadata():

    """this fuchtion is used to prin the meta data dictionary
    which can be used to knw the hash of a particular content"""

    for key, value in global_table.items():
        print(key, value)



def commandPeers():

    """this command is used to display the peer list of
    the particular nodes"""

    for key, value in peers.items():
        print(key, value)



def dict_up(dictionary, key, value):
    """this function is used to update the various dictionary
    it takes the dictionary, key and the value which needs to be added """
    
    if type(dictionary[key]) == list:
        dictionary[key].append(value)
    else:
        dictionary[key] = [dictionary[key], value]



def findIndex(dictionary, hash_recv):
    """this function is used to find the index of the content 
    in the dictionary. It takes the dictinary and hash value 
    which of the content. It returns -1 if the data is not found"""
    
    list = dictionary['hash_value']
    #print(list)
    if hash_recv in dictionary['hash_value']:
        return dictionary['hash_value'].index(hash_recv)
    else:
        return -1



def returnfile(hash_recv):
    '''this function gives the filename mapping to the given hash value'''
    ind= findIndex(localdatabase, hash_recv)#gets the index of hash value
    file = localdatabase['file'][ind]#gets the file from the calculated index value
    print(file)
    return file

def retrive(ip, hash_received):
    s = socket.socket()#create a socket object
    port = port_income
    s.connect((ip, port))#bind the ip to initiate file serving process
    s.send(str.encode(hash_received))#first send the hash obtained from the GET request of the browser
    index1=findIndex(global_table,hash_received)
    print("content lenght="+str(global_table['content-length'][index1]))
    file_size=global_table['content-length'][index1]
    f1= s.recv(1024)#start reciving the file
    f1=f1.decode('utf-8')
    f2,d,ext3=f1.partition('.')
    tempfile="temp"+"."+ext3
    #t=bytes(tempfile,'utf-8')
    print(tempfile)
    with open(tempfile, 'wb') as f:
        while True:
            data = s.recv(2048)#reciving the remaining amount of file
            #print("complete : " + str(int(((totalrecv) / (file_size)) * 100))+"%")
            if not data:
                break
            f.write(data)
        f.close()
        print('file transfer complete!!!!!!!!!!!!')
        s.close()
        return tempfile



def calc_hash(filename_full):
    """this function is used to calculate the hash value of the file.
    we use sha1 algorithm to calculate hash value"""

    filename, dot, contenttype = str(filename_full).partition(".")#getting the filename and file type by partitioning at '.'
    print(filename_full)
    if (contenttype == "png"):
        image = open(filename_full, 'rb')#opening in bytes
        imgstr = base64.b64encode(image.read())#converting bytes to string since sha-1 accepts str data
        m = hashlib.sha1(imgstr)#calculating hash value
        Msg_Digest = m.hexdigest()#true hash value
        Content_size = os.stat(filename_full).st_size#gives the size of the file
        return (Msg_Digest, contenttype, Content_size)
    else:
        htfile = open(filename_full, "rb")
        Read_File = htfile.read()
        m = hashlib.sha1(Read_File)#sha-1 object
        Msg_Digest = m.hexdigest()#hexdigest gives the hash value
        Content_size = os.path.getsize(filename_full)#file size
        return (Msg_Digest, contenttype, Content_size)



def dict_avail(dict, hash):
    """ this function is used to check whether the content
    entered is available in the dictionary. If it is present
    it returns 1 or else -1 """
    index = findIndex(dict, hash)
    if index == -1:
        return "-1"
    else:
        return "1"

class new_server:

    def __init__(self, clientAddress, clientSocket):
        self.socket = clientSocket#create socket object
        self.clientAddress = clientAddress#assigning the client address
        while True:
            data = self.socket.recv(1024)#receving the data from peer
            data_recv = data.decode("utf-8")
            if data_recv == "OK":#if message is ok then it means you are peered, if not it is an announcement message
                print("Connected to peer: ", clientAddress)
                name = socket.gethostbyaddr(self.clientAddress[0])
                dict_up(peers, "NAME OF PEER", name[0])#entering peer information into the peer list
                dict_up(peers, "IP ADDRESS", self.clientAddress[0])
                dict_up(peers, "PORT", self.clientAddress[1])
            else:
                try:
                    updatemessage= json.loads(data_recv)
                    global global_table
                    global_table =updatemessage
                    announceMessage = json.dumps(global_table)
                    for c in ip_server:
                        if c == ipAddr or c == self.clientAddress[0]:#if it is our own ip dont send me announcement else send others announcement
                            pass
                        else:
                            try:
                                announcement = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#sending announcement on new connection and tearing down
                                announcement.connect((c, port_listen))
                                announcement.sendall(str.encode(announceMessage))
                                announcement.close()#tearing down the announcement connection
                            except TimeoutError:
                                print(" ")
                        break
                except ValueError:
                    print(" ")
                    break
                
def new_thread(serverSock, host, port):#this function is used to create new thread to handle multiple connection at a time
    while True:
        global ip_server 
        serverSock.listen(6)
        clientSock, clientAddress = serverSock.accept()#accept connections
        ip_server.append(clientAddress[0])
        functionThread = threading.Thread(target=new_server, args=(clientAddress, clientSock))#create another thread to handle announcement and peer list handling 
        functionThread.start()
    return

class htttpRequestHandler(http.server.BaseHTTPRequestHandler):
    '''this is use to handle request from http for a file'''
    def do_GET(self):#over writing the GET function in BaseHTTPRequestHandler class to our requirement as follows
        path_loc = self.path#get the "/hash value" from browser
        path_loc = path_loc[1:]#get true hash value
        dict_pres = dict_avail(localdatabase, path_loc)#check if it is present in the localdatabase,if present we will get 1 as return value
        #print(dict_pres)
        if dict_pres == "1":
            fname = returnfile(path_loc)#to get the filename of respc. hash value
            name, dot,ext = str(fname).partition(".")
            if (ext == "png"):              
                openfile= open(fname)#open the file
                self.send_response(200)#send a response 200 to browser
                self.send_header('Content-type', 'image/png')#send header to the browser
                self.end_headers()
                with open(fname, 'rb') as imagedata:
                    shutil.copyfileobj(imagedata, self.wfile)#start sending the file content to browser
                openfile.close()
                self.connection.close()#close the connection
                return True      
            elif(ext=="html" or ext=="txt"):
                openfile= open(fname, 'rb')#open the file and read in bytes
                self.send_response(200)#sending a response of 200
                self.send_header('content-type', 'text/html')#informing http about the file 
                self.end_headers()
                self.wfile.write(openfile.read())#sending the file data to browser
                openfile.close()#close the file after sending the file content
                self.connection.close()#this closes the existing http connection
                return True
            else:
                self.send_error(404, 'FILE NOT FOUND')#send a error respnse 404 if file not found in local database
                self.connection.close()
                return
        else:
            i = findIndex(global_table, path_loc)
            if i== -1:
                self.send_error(404, 'FILE NOT FOUND')#if file is not in global table , that if the file is not there in any of the host in network
                self.connection.close()#end connection
                return True
            else:
                connectip = global_table["ip"][i]
                file = retrive(connectip, path_loc)#to get the file from peer
                openfile = open(file, 'r')#after receving file, open the file and send to browser
                name,p,ext2 = str.partition(file, ".")
                if ext2 == "png":
                    self.send_response(200)#send response 200
                    self.send_header('Content-type', 'image/png')
                    self.end_headers()
                    with open(file, 'rb') as filedata:
                        shutil.copyfileobj(filedata, self.wfile)
                    openfile.close()
                    self.connection.close()
                    return
                else:
                    openfile = open(file, 'rb')#open file other the png ext like html
                    self.send_response(200)#send a response of 200 to browser
                    self.send_header('content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(openfile.read())#wfile write the content of file onto browser
                    openfile.close()
                    self.connection.close()
                    return
                
def http_connect(httpAddr):
    '''this function runs a http server at port 7000 and replies to http requests'''
    create_httpserver = http.server.HTTPServer(httpAddr,htttpRequestHandler)
    create_httpserver.serve_forever()
    return
def f_server():#file transfer server
    port = port_income#port at which file transfer between peers takes place
    fileserv = socket.socket()
    hostip= socket.gethostbyname(socket.gethostname())
    fileserv.bind((hostip, port))
    fileserv.listen(5)
    while True:
        fileclient, address = fileserv.accept()#accept connection from clients
        hvalue= fileclient.recv(1024)#first recive the hash value
        iHash = findIndex(localdatabase, hvalue)#getting the index of hash
        file = localdatabase["file"][iHash]#to get the file mapping to that index
        fileclient.send(str.encode(file))#send the file name
        openfile = open(file, 'rb')
        filedata = openfile.read(1024)#open file and read the data
        while (filedata):
            fileclient.send(filedata)#send the file data
            filedata =openfile.read(1024)
        openfile.close()#close the file
        fileclient.close()#terminate the file server connection
    return


def main():
    print("\n\n Port to connect on :5000 \n Port to send http request :7000")
    com_input_thread = threading.Thread(target=com_input, args=())#start a thread to handle input commands like peers, publish,unpublish etc
    com_input_thread.start()
    host = socket.gethostbyname(socket.gethostname())
    port = port_listen
    global ipAddr
    ipAddr = host
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    serverthreading = threading.Thread(target=new_thread, args=(server, host, port))#start a thread to handle new connections 
    serverthreading.start()
    httpAddr = (host, port_browser)
    httpthread = threading.Thread(target=http_connect, args=(httpAddr,))#start a thread to handle http requests
    httpthread.start()
    fserverThread = threading.Thread(target=f_server())#start a thread to handle the file server
    fserverThread.start()


if __name__ == '__main__':
    main()

