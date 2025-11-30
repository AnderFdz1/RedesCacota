'''
    ip.py
    
    Funciones necesarias para implementar el nivel IP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
import logging

SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
# IPv4 version.
IPv4_VERSION = 0x04
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60
# IP ethertype
IP_ETHERTYPE = 0x0800
# Default type of service.
TYPE_OF_SERVICE = 1
# Default time to live.
TIME_TO_LIVE = 65
# Pair number
PAIR_NUM = 6
# Maximum IP options length.
IP_OPTS_MAX_LEN = IP_MAX_HLEN - IP_MIN_HLEN
# Header struct format.
__IP_HDR_FORMAT = '!BBHHHBBHII'

class IPv4Datagram:
    def __init__(self, version, ihl, srv_type, length, id, df, mf, offset, tm_to_live, prtcl, chcksum, src, dest, opts, pl):

        self.version = version
        self.ihl = ihl
        self.srv_type = srv_type
        self.length = length
        self.ipid = id
        self.do_not_fragment = df
        self.more_fragments = mf
        self.offset = offset
        self.time_to_live = tm_to_live
        self.protocol = prtcl
        self.checksum = chcksum
        self.src_address = src
        self.dest_address = dest
        self.options = opts
        self.payload = pl

    def build_header(self, checksum=0):
        # Flags and offset.
        flags = ((0 << 2) | (self.do_not_fragment << 1) | self.more_fragments)
        flags_and_offset = (flags << 13) | (self.offset >> 3)

        # Complete IP header.
        header = struct.pack(
            __IP_HDR_FORMAT,
            (self.version << 4) | (self.ihl >> 2),
            self.srv_type,
            self.length,
            self.ipid,
            flags_and_offset,
            self.time_to_live,
            self.protocol,
            checksum,
            self.src_address,
            self.dest_address
        )
        if self.options:
            header += self.options
        return header
    
    def to_bytes(self):
        return self.build_header(checksum=self.checksum) + self.payload

    def compute_checksum(self):
        hdr = self.build_header(checksum=0)
        self.checksum = chksum(hdr)         # Update checksum.
        return self.checksum

def chksum(msg):
    '''
        Nombre: chksum
        Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    '''
    s = 0
    y = 0xa29f    
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i] 
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise 'Error calculando el checksum'
    y = y & 0x00ff
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def getMTU(interface):
    '''
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    '''
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]
   
    s.close()
   
    return mtu
   
def getNetmask(interface):
    '''
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz 
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
    '''
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    '''
    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8')
    print(dfw)
    return struct.unpack('!I',socket.inet_aton(dfw))[0]

def __valid_checksum(hdr, obtained) -> tuple:
    header_bytes = bytearray(hdr)               # Copy header.
    
    # Remove previous checksum from cpoy.
    header_bytes[10] = 0
    header_bytes[11] = 0

    ret = chksum(header_bytes)
    return (ret == obtained, ret)

def __parse_IP_datagram(data):
    # Get fields (Some are combined).
    try:
        (ver_and_ihl, srv_type, length, id, flags_and_offset, tm_to_live, prtcl, chcksum, src, dest) = struct.unpack(__IP_HDR_FORMAT, data[:20])
    except struct.error:
        return None
    
    # Version must be IPv4.
    version = ver_and_ihl >> 4
    if version != IPv4_VERSION :
        return None
    
    # Minimum IHL must be 20 (after multiplication).
    ihl = (ver_and_ihl & 0x0F) << 2
    if ihl < IP_MIN_HLEN:
        return None

    # Checksum.
    hdr = data[:ihl]
    valid, calculated = __valid_checksum(hdr, chcksum)
    if not valid:
        logging.debug('IP checksum mismatch: expected: %04x; obtained: %04x' % (calculated, chcksum))
        return None
    
    # Obtain flags and offset.
    flags = flags_and_offset >> 13

    # Check reserved bit.
    if (flags >> 2) == 1:
        # Zero field must be 0 (False) -> (Default in constructor).
        return None
    
    # Flags.
    df = ((flags & 0x2) >> 1) == 1
    mf = (flags & 0x1) == 1

    # Offset.
    offset = (flags_and_offset & 0x1FFF) << 3

    # Options.
    opts = data[IP_MIN_HLEN:ihl]

    # Payload.
    pl = data[ihl:length]

    # Return the datagram.
    return IPv4Datagram(version, ihl, srv_type, length, id, df, mf, offset, tm_to_live, prtcl, chcksum, src, dest, opts, pl)

def __log_IP_datagram(datagram: IPv4Datagram):
    logging.debug(
        "\n+-----------------------------------------------------------------------------+\n"
        "IP Datagram\n"
        "+-----------------------------------------------------------------------------+\n"
        f"IHL={datagram.ihl}, \n"
        f"IPID={datagram.ipid}, \n"
        f"TTL={datagram.time_to_live}, \n"
        f"DF={datagram.do_not_fragment}, \n"
        f"MF={datagram.more_fragments}, \n"
        f"Offset={datagram.offset}, \n"
        f"Src={socket.inet_ntoa(struct.pack('!I', datagram.src_address))}, \n"
        f"Dest={socket.inet_ntoa(struct.pack('!I', datagram.dest_address))}, \n"
        f"Protocol={datagram.protocol}\n"
        "+-----------------------------------------------------------------------------+\n"
    )

def process_IP_datagram(us,header,data,srcMac) -> None:
    '''
        Nombre: process_IP_datagram
        Descripción: Esta función procesa datagramas IP recibidos.
            Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
                -Calcular el checksum y comprobar que es correcto                    
                -Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
                -Loggear (usando logging.debug) el valor de los siguientes campos:
                    -Longitud de la cabecera IP
                    -IPID
                    -TTL
                    -Valor de las banderas DF y MF
                    -Valor de offset
                    -IP origen y destino
                    -Protocolo
                -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
                clave el valor del campo protocolo del datagrama IP.
                    -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha funciñón 
                    pasando los datos (payload) contenidos en el datagrama IP.
        
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido del datagrama IP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''
    # Check and parse datagram.
    if len(data) < IP_MIN_HLEN:
        return
    datagram: IPv4Datagram = __parse_IP_datagram(data)
    if datagram is None:
        # Datagram could not be parsed.
        return
    elif datagram.offset != 0 or datagram.more_fragments:
        # Fragmented datagram.
        return
    
    # Log datagram.
    __log_IP_datagram(datagram)

    # Process with callback function (if exists).
    callback = protocols.get(datagram.protocol, default=None)
    if callback:
        callback(us, header, datagram.payload, datagram.src_address)
    
def registerIPProtocol(callback,protocol) -> None:
    '''
        Nombre: registerIPProtocol
        Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla 
            (diccionario) de protocolos de nivel superior dicha asociación. 
            Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un 
            determinado valor del campo protocolo (por ejemplo TCP o UDP).
            Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra 
            llamada process_ICMP_message asocaida al valor de protocolo 1. 
        Argumentos:
            -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado. 
                La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
                Dónde:
                    -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                    -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                    -srcIP: dirección IP que ha enviado el datagrama actual.
                La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
            -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
        Retorno: Ninguno
    '''
    global protocols
    if callback is None or protocol is None :
        return
    protocols[protocol] = callback

def initIP(interface,opts=None) -> bool:
    global myIP, MTU, netmask, defaultGW, ipOpts, IPID
    '''
        Nombre: initIP
        Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
            -Llamar a initARP para inicializar el nivel ARP
            -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
                -IP propia
                -MTU
                -Máscara de red (netmask)
                -Gateway por defecto
            -Almacenar el valor de opts en la variable global ipOpts
            -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
            -Inicializar el valor de + con el número de pareja
        Argumentos:
            -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
            -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
        Retorno: True o False en función de si se ha inicializado el nivel o no
    '''
    if opts:
        # With options.
        if len(opts) > IP_OPTS_MAX_LEN:
            # Options are too long.
            return False

        pad_len = (4 - (len(opts) % 4)) % 4
        ipOpts = opts + b'\x00' * pad_len
    else:
        # Without options.
        ipOpts = None

    if initARP(interface) != 0:
        return False
    
    myIP = getIP(interface)
    MTU = getMTU(interface)
    netmask = getNetmask(interface)
    defaultGW = getDefaultGW(interface)
    registerEthCallback(process_IP_datagram, IP_ETHERTYPE)

    '''
    Identification (2 Bytes): Identificador del datagrama IP (también llamado IPID). Este campo es útil cuando hay fragmentación IP.
    En este caso todos los fragmentos tienen el mismo valor de IPID. Para los envíos, este valor se fija inicialmente al arrancar el
    nivel IP. En la práctica lo fijaremos al número de pareja (es necesario modificar el código).
    '''
    IPID = PAIR_NUM

    return True

def sendIPDatagram(dstIP,data,protocol):
    global IPID, ipOpts, MTU, myIP, netmask, defaultGW
    '''
        Nombre: sendIPDatagram
        Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
        debe generar y enviar el número de fragmentos IP que sean necesarios.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Determinar si se debe fragmentar o no y calcular el número de fragmentos
            -Para cada datagrama o fragmento:
                -Construir la cabecera IP con los valores que corresponda.Incluir opciones en caso de que ipOpts sea distinto de None
                -Calcular el checksum sobre la cabecera y añadirlo a la cabecera
                -Añadir los datos a la cabecera IP
                -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
                -Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
                al enviar los datagramas se debe hacer unso de la máscara de red:                  
            -Para cada datagrama (no fragmento):
                -Incrementar la variable IPID en 1.
        Argumentos:
            -dstIP: entero de 32 bits con la IP destino del datagrama 
            -data: array de bytes con los datos a incluir como payload en el datagrama
            -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
            contenidos en el payload. Por ejemplo 1, 6 o 17.
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
    '''
    # Get sizes (Header and payload).
    ihl = IP_MIN_HLEN + (len(ipOpts) if ipOpts else 0)
    max_pl = MTU - ihl

    # Divide the payload.
    fragments: list = [data[i:i + max_pl] for i in range(0, len(data), max_pl)]
    
    # Creat IPv4Datagram to simplify the process.
    to_send: IPv4Datagram = IPv4Datagram(
        IPv4_VERSION,                                           # IPv4.
        ihl,                                                    # IP header length.
        TYPE_OF_SERVICE,                                        # Type of service.
        0,                                                      # Total length. 
        IPID,                                                   # IP ID.
        False,                                                  # Don't fragment flag.                                              
        True,                                                   # More fragments flag.
        0,                                                      # Offset.
        TIME_TO_LIVE,                                           # Time to live.
        protocol,                                               # Protocol.
        0,                                                      # Checksum.
        myIP,                                                   # Origin IP.
        dstIP,                                                  # Destination IP.
        ipOpts,                                                 # IP options.
        None                                                    # Payload.
    )

    # Send IP fragments.
    dstMAC = None
    for i, frgmnt in enumerate(fragments):
        # Update datagram.
        to_send.payload = frgmnt
        to_send.length = ihl + len(frgmnt)
        to_send.offset = (i * max_pl) >> 3

        # Last fragment.
        if i == len(fragments) - 1:
            to_send.more_fragments = False
        
        # Update checksum.
        to_send.compute_checksum()

        # Build datagram.
        datagram = to_send.to_bytes()

        # Get MAC address.
        if dstMAC is None:
            # Check whether to use GateWay or send directly.
            nxt_ip = dstIP if (dstIP & netmask) == (myIP & netmask) else defaultGW
            
            # ARP resolution.
            dstMAC = ARPResolution(nxt_ip)
            if dstMAC == None:
                return False
        
        # Send datagram.
        if sendEthernetFrame(datagram, len(datagram), IP_ETHERTYPE, dstMAC) != 0:
            return False
        
    return True