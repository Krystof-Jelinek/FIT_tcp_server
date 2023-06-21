#vubec netusim jak to udelam kdyz jedina moje zkusenost je C z prvniho semestru a python vidim poprve, proc ify nemaji zavorky ??:)) 

import socket
import threading

def receive_data(robot_connection,expected_message):
    #funkce prijima data ze steamu a rovnou je kontroluje + kontroluje i timeout (mnohokrat upravovano)
    data = ""
    tmp = " "
    max_bytes = 100
    if expected_message == "Username":
        max_bytes = 20
    if expected_message == "hash":
        max_bytes = 7
    if expected_message == "key_id":
        max_bytes = 5
    if ((expected_message == "client_ok")or(expected_message == "client_recharging")or(expected_message == "client_full_power")):
        max_bytes = 12
    if expected_message == "secret_message":
        max_bytes = 100                      
        
    bytes = 0
    recharing_flag = 0
    while True:
        prev_tmp = tmp
        robot_connection.settimeout(1)
        if (expected_message == "client_full_power"):
            robot_connection.settimeout(5)
        try:
            tmp = (robot_connection.recv(1).decode(FORMAT))
            data = data + tmp
            bytes +=1
            if(bytes == 4):
                hodnota = str(data).find("REC") #tedy zde overeni pokud rechargujeme nic lepsiho nez toto me nenapadlo a zda se to funkcni
                if (hodnota != -1):
                    max_bytes = 12
                    recharing_flag = 1

            if((bytes == max_bytes) and (tmp != '\b')): #pokud jsme pretekli pres maximalni pocet bytu tak ukoncujeme syntax eror - kvuli optimalizaci
                robot_connection.send(("301 SYNTAX ERROR\a\b").encode(FORMAT))
                robot_connection.close()
                return False
            if prev_tmp == "\a" and tmp == "\b":
                break
        except:
            robot_connection.close()
            return False  

    if (recharing_flag == 1):

        check_msg = receive_data(robot_connection,"client_full_power")
        if(check_msg == False): #pokud jsme nedostali full recharge do 5s proto se menil timeout z 1 vteriny na 5 pokud ocekavame recharge
            return False
        
        if (check_msg != "FULL POWER\a\b"): #neboli dostali jsme neco jineho nez full power ==> logic eror
            robot_connection.send(("302 LOGIC ERROR\a\b").encode(FORMAT))
            robot_connection.close()
            return False
        else:
            return receive_data(robot_connection,expected_message)     
                  
    return str(data)   

def provide_coordinates(robot_connection,tmpmessage):
    #funkce ktera ze zpravy dostane souradnice a osetreni vstupu zda se jedna o cisla
    tmpmessage = tmpmessage.rstrip("\a\b")
    tmpmessage = tmpmessage.lstrip(" OK ")
    tmpmessage = tmpmessage.split(" ")
    #pokud by bylo vice mezer tak se to rozdeli na vice nez 2 pole ==> syntax eror
    if (len(tmpmessage)!=2):
        robot_connection.send(("301 SYNTAX ERROR\a\b").encode(FORMAT))
        robot_connection.close()
        return False
    
    check_0 = tmpmessage[0].lstrip('-').isdigit() #osetrit pripadne znaminko minus, isdigitu se to nelibi 
    check_1 = tmpmessage[1].lstrip('-').isdigit()
    if check_0 and check_1:
        return (int(tmpmessage[0]),int(tmpmessage[1]))
    else:
        robot_connection.send(("301 SYNTAX ERROR\a\b").encode(FORMAT))
        robot_connection.close()
        return False

def check_key(robot_connection,key_ID):
    #kontrola samostatneho stringu
    key_ID = (str(key_ID)).rstrip("\a\b")
    check = key_ID.isnumeric()
    #kontrola zda se jedna o cislo
    if check == False:
        robot_connection.send(("301 SYNTAX ERROR\a\b").encode(FORMAT))
        robot_connection.close()
        return (key_ID,False)
    #kontrola zda je to cislo 0-4
    key_ID = int(key_ID)
    if (key_ID < 0 or key_ID > 4):
        robot_connection.send(("303 KEY OUT OF RANGE\a\b").encode(FORMAT))
        robot_connection.close()
        return (key_ID,False)
    
    return (key_ID,True)     

def autentization_check(robot_connection):
    #tabulky pro keys
    server_keys = [23019,32037,18789,16443,18189]
    client_keys = [32037,29295,13603,29533,21952]
    
    #prijem jmena robota
    robot_name = receive_data(robot_connection,"Username")#(robot_connection.recv(20)).decode(FORMAT)
    if robot_name == False:
        return False
    
    robot_connection.send(("107 KEY REQUEST\a\b").encode(FORMAT))
    
    key_ID = receive_data(robot_connection,"key_id")#(robot_connection.recv(5)).decode(FORMAT)
    if key_ID == False:
        return False
    
    #osetreni klice
    key_ID ,check = check_key(robot_connection,key_ID)
    if check == False:
        return False

    #forcyklus projede cele jmeno a pricte jeho ascii hodnotu
    ascii_name = 0
    
    for a in range(0,len(robot_name)-2):
        ascii_name = ascii_name + ord(robot_name[a])
    hash = (ascii_name*1000) % 65536

    #nyni pricti klic serveru
    if key_ID == 0:
        result_hash = (hash+server_keys[0])% 65536
    if key_ID == 1:
        result_hash = (hash+server_keys[1])% 65536
    if key_ID == 2:
        result_hash = (hash+server_keys[2])% 65536
    if key_ID == 3:
        result_hash = (hash+server_keys[3])% 65536
    if key_ID == 4:
        result_hash = (hash+server_keys[4])% 65536 

    #odeslat vysledny hash robotovi
    result_hash = str(result_hash)
    robot_connection.send((f"{result_hash}\a\b").encode(FORMAT))

    #prijem odpovedi hashe od robota a jeho kontrola
    answear_hash = receive_data(robot_connection,"hash") 
    if answear_hash == False:
        return False
    answear_hash = answear_hash.rstrip("\a\b")
    check = answear_hash.isnumeric()
    if (check == False):
        robot_connection.send(("301 SYNTAX ERROR\a\b").encode(FORMAT))
        robot_connection.close()
        return False

    answear_hash = int(answear_hash)
    
    #vypocitam jaky by mel byt jeho answearhash a zkontroluji
    should_be_hash = (hash + client_keys[key_ID]) % 65536
    if answear_hash == should_be_hash:
        robot_connection.send(("200 OK\a\b").encode(FORMAT))
        return True
    else:
        robot_connection.send(("300 LOGIN FAILED\a\b").encode(FORMAT))
        robot_connection.close()
        return False
    
def secret_message_pickup(robot_connection):

    robot_connection.send(("105 GET MESSAGE\a\b").encode(FORMAT))
    secret_message = receive_data(robot_connection,"secret_message")
    if secret_message == False:
        return False
    robot_connection.send(("106 LOGOUT\a\b").encode(FORMAT))
    print(secret_message)
    robot_connection.close()

def go_forward(robot_connection,facing):
    #poslani vyzvy o pohyb dopredu nasledne oriznuti zpravy a dostanu z ni souradnice
    #navratova hodnota urcuje souradnice a kterym smerem se robot "kouka"

    robot_connection.send(("102 MOVE\a\b").encode(FORMAT))

    tmpmessage = receive_data(robot_connection,"client_ok")    
    if tmpmessage == False:
        return (False,False)
    
    coordinates = provide_coordinates(robot_connection,tmpmessage)
    if coordinates == False:
        return (False,False)

    return (coordinates,facing)

def go_left(robot_connection,facing):
    #obdobne jako u pohybu dopredu jen jeste hlidat kam jsem se natocil
    robot_connection.send(("103 TURN LEFT\a\b").encode(FORMAT))
    check = receive_data(robot_connection,"client_ok")
    if check == False:
        return (False,False)
    
    robot_connection.send(("102 MOVE\a\b").encode(FORMAT))
    tmpmessage = receive_data(robot_connection,"client_ok")
    if tmpmessage == False:
        return (False,False)
    
    coordinates = provide_coordinates(robot_connection,tmpmessage)
    if coordinates == False:
        return (False,False)

    if facing == "-x":
        facing = "-y"
    elif facing == "+x":
        facing = "+y"
    elif facing == "-y":
        facing = "+x"        
    elif facing == "+y":
        facing = "-x"

    return (coordinates,facing)

def go_right(robot_connection,facing):
    #obdobne jako u pohybu dopredu
    robot_connection.send(("104 TURN RIGHT\a\b").encode(FORMAT))
    check = receive_data(robot_connection,"client_ok")
    if check == False:
        return (False,False)
    
    robot_connection.send(("102 MOVE\a\b").encode(FORMAT))
    tmpmessage = receive_data(robot_connection,"client_ok")
    if tmpmessage == False:
        return (False,False)
    
    coordinates = provide_coordinates(robot_connection,tmpmessage)
    if coordinates == False:
        return (False,False)

    if facing == "-x":
        facing = "+y"
    elif facing == "+x":
        facing = "-y"
    elif facing == "-y":
        facing = "-x"        
    elif facing == "+y":
        facing = "+x"

    return (coordinates,facing)

def do_180(robot_connection,facing):
    #stejny princip jen probihaji dve otocky doprava
    robot_connection.send(("104 TURN RIGHT\a\b").encode(FORMAT))
    check_0 = receive_data(robot_connection,"client_ok")
    if check_0 == False:
        return (False,False)
    
    robot_connection.send(("104 TURN RIGHT\a\b").encode(FORMAT))
    check_1 = receive_data(robot_connection,"client_ok")
    if check_1 == False:
        return (False,False)
    
    robot_connection.send(("102 MOVE\a\b").encode(FORMAT))
    tmpmessage = receive_data(robot_connection,"client_ok")   
    
    coordinates = provide_coordinates(robot_connection,tmpmessage)
    if coordinates == False:
        return (False,False)

    if facing == "-x":
        facing = "+x"
    elif facing == "+x":
        facing = "-x"
    elif facing == "-y":
        facing = "+y"        
    elif facing == "+y":
        facing = "-y"
    return (coordinates,facing)

def get_direction(robot_connection):
    #tato funkce se spusti na zacatku kvuli orientaci na jakem poli a kterym smerem je robot natoceny

    position,facing = go_forward(robot_connection,"jetojedno")
    if (position == False) or (facing == False):
        return (False,False)
    prev_position = position 
    position,facing = go_forward(robot_connection,"jetojedno")
    if (position == False) or (facing == False):
        return (False,False)
    if (position[0]< prev_position[0]):
        facing = "-x"
    if (position[0]> prev_position[0]):
        facing = "+x"
    if (position[1]< prev_position[1]):
        facing = "-y"
    if (position[1]> prev_position[1]):
        facing = "+y"   

    #pokud jsem hned narazil             
    if (position == prev_position):
        position,facing = go_right(robot_connection,facing)

        if (position == False) or (facing == False):
            return (False,False)
        
        if (position[0]< prev_position[0]):
            facing = "-x"
        if (position[0]> prev_position[0]):
            facing = "+x"
        if (position[1]< prev_position[1]):
            facing = "-y"
        if (position[1]> prev_position[1]):
            facing = "+y"  

    return (position,facing)

def do_correct_move(robot_connection,position,facing):
    #myslim si ze prehlednost nasledujicich radku naprosto jasne dokazuje ze kod nemohl byt nidke ukraden
    #popis neni potreba je to tak prehledne ze kazdy dalsi komentar by to pouze zneprehlednil
    #opravdu na to nejsem pysny ale funguje to

    if (int(position[0]) < 0 and facing == "+x")or(int(position[0]) > 0 and facing == "-x"):
            position, facing = go_forward(robot_connection,facing)
    elif (position[0] < 0 and facing == "-x")or(position[0] > 0 and facing == "+x"):
            position, facing = do_180(robot_connection,facing)
    elif (position[1] < 0 and facing == "+y")or(position[1] > 0 and facing == "-y"):
            position, facing = go_forward(robot_connection,facing)
    elif (position[1] < 0 and facing == "-y")or(position[1] > 0 and facing == "+y"):
            position, facing = do_180(robot_connection,facing)
    elif (position[0] == 0):
        if position[1] < 0 and facing == "-x":
            position, facing = go_right(robot_connection,facing)
        elif position[1] < 0 and facing == "+x":
            position, facing = go_left(robot_connection,facing)
        elif position[1] > 0 and facing == "-x":
            position, facing = go_left(robot_connection,facing)
        elif position[1] > 0 and facing == "+x":
            position, facing = go_right(robot_connection,facing)     
    elif (position[1] == 0):
        if position[0] < 0 and facing == "-y":
            position, facing = go_left(robot_connection,facing)
        elif position[0] < 0 and facing == "+y":
            position, facing = go_right(robot_connection,facing)
        elif position[0] > 0 and facing == "-y":
            position, facing = go_right(robot_connection,facing)
        elif position[0] > 0 and facing == "+y":
            position, facing = go_left(robot_connection,facing)     
        

    return (position,facing)  

def do_L_dodge_move_left(robot_connection,position,facing):
    position, facing = go_left(robot_connection,facing)
    position, facing = go_right(robot_connection,facing)

    return (position,facing)

def do_L_dodge_move_right(robot_connection,position,facing):
    position, facing = go_right(robot_connection,facing)
    position, facing = go_left(robot_connection,facing)

    return (position,facing)

def do_correct_L_dodge_move(robot_connection,position,facing):
    #nestacilo delat pouze do_L_dodge_move_left obcas nestacil pocet tahu proto tato funkce ktera vybira jestli je optimalnejsi obchazet prekazku
    #  zleva nebo zprava

    if facing == "+x":
        if position[1] < 0:
            do_L_dodge_move_left(robot_connection,position,facing)
        elif position[1] >= 0:
            do_L_dodge_move_right(robot_connection,position,facing)

    elif facing == "-x":
        if position[1] < 0:
            do_L_dodge_move_right(robot_connection,position,facing)
        elif position[1] >= 0:
            do_L_dodge_move_left(robot_connection,position,facing)             

    elif facing == "+y":
        if position[0] < 0:
            do_L_dodge_move_right(robot_connection,position,facing)
        elif position[0] >= 0:
            do_L_dodge_move_left(robot_connection,position,facing)

    elif facing == "-y":
        if position[0] < 0:
            do_L_dodge_move_left(robot_connection,position,facing)
        elif position[0] >= 0:
            do_L_dodge_move_right(robot_connection,position,facing)            

    return (position,facing)

def do_360_happy_flip_move(robot_connection):
    i = 0
    while(i<4):
        robot_connection.send(("104 TURN RIGHT\a\b").encode(FORMAT))
        check_0 = receive_data(robot_connection,"client_ok")
        if check_0 == False:
            return (False,False)
        i +=1

def robot_managing(robot_connection):
    #poskladani jednotlivych funkci dohromady 

    #kontrola klice
    check = autentization_check(robot_connection)
    if check == False:
        return

    #ziskani prvotnich souradnic a smeru orientace
    position, facing = get_direction(robot_connection)
    if(position == False) or (facing == False):
        return 

    #delani pohybu dokud nedojdu do cile
    while(position[0]!= 0 or position[1]!=0):
        prev_position = position
        position, facing = do_correct_move(robot_connection,position,facing)
        if(position == False) or (facing == False):
            return 
        
        if prev_position == position: #tedy pokud narazil

            position, facing = do_correct_L_dodge_move(robot_connection,position,facing)
            if(position == False) or (facing == False):
                return 

    #robutek ma velikou radost ze nasel tajnou spravu a proto to nalezite oslavi veselou otockou
    do_360_happy_flip_move(robot_connection)

    #vyzvednuti zpravy
    secret_message_pickup(robot_connection)

def start_server(server):
    server.listen()
    #spousteni jednotlivych vlaken pro roboty
    while True:
        robot_connection,robot_address = server.accept()
        thread = threading.Thread(target=robot_managing,args =(robot_connection,))
        thread.start()

#adresa pocitace a port serveru
SERVER = socket.gethostbyname(socket.gethostname())
PORT = 5050
print(SERVER)

ADDR = (SERVER,PORT)
FORMAT = "utf-8"

#zakotveni serveru
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind(ADDR)

start_server(server)
