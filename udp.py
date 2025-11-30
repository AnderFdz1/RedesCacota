'''
    udp.py
    
    Funciones necesarias para implementar el nivel UDP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ip import *
import struct
import logging

UDP_HLEN = 8
UDP_PROTO = 17

UDP_HDR_FORMAT = "!HHHH"

class UDPDatagram:
    def __init__(self, src_prt, dst_prt, length, chcksm, data):
        self.src_port = src_prt
        self.dst_port = dst_prt
        self.length = length
        self.checksum = chcksm
        self.payload = data

    def build_header(self):
        return struct.pack(
            UDP_HDR_FORMAT,
            self.src_port,
            self.dst_port,
            self.length,
            self.checksum
        )

    def to_bytes(self):
        return self.build_header() + self.payload

def getUDPSourcePort():
    '''
        Nombre: getUDPSourcePort
        Descripción: Esta función obtiene un puerto origen libre en la máquina actual.
        Argumentos:
            -Ninguno
        Retorno: Entero de 16 bits con el número de puerto origen disponible
          
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    portNum =  s.getsockname()[1]
    s.close()
    return portNum

def __parse_UDP_datagram(data):
    # Get fields (Some are combined).
    try:
        (src_prt, dst_prt, length, chcksm) = struct.unpack(UDP_HDR_FORMAT, data[:UDP_HLEN])
    except struct.error:
        return None
    
    # Build UDPDatagram object.
    return UDPDatagram(src_prt, dst_prt, length, chcksm, data[UDP_HLEN:])

def __log_UDP_datagram(datagram: UDPDatagram):
    logging.debug(
        "\n+-----------------------------------------------------------------------------+\n"
        "UDP Datagram\n"
        "+-----------------------------------------------------------------------------+\n"
        f"Source={datagram.src_port}, \n"
        f"Destination={datagram.dst_port}, \n"
        f"Data={datagram.payload}  \n"
        "+-----------------------------------------------------------------------------+\n"
    )

def process_UDP_datagram(us,header,data,srcIP):
    '''
        Nombre: process_UDP_datagram
        Descripción: Esta función procesa un datagrama UDP. Esta función se ejecutará por cada datagrama IP que contenga
        un 17 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer los campos de la cabecera UDP
            -Loggear (usando logging.debug) los siguientes campos:
                -Puerto origen
                -Puerto destino
                -Datos contenidos en el datagrama UDP

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del datagrama UDP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno
          
    '''
    if data is None or len(data) < UDP_HLEN:
        return
    
    datagram: UDPDatagram = __parse_UDP_datagram(data)
    if datagram is None:
        return

    __log_UDP_datagram(datagram)

def sendUDPDatagram(data,dstPort,dstIP):
    '''
        Nombre: sendUDPDatagram
        Descripción: Esta función construye un datagrama UDP y lo envía
        Esta función debe realizar, al menos, las siguientes tareas:
            -Construir la cabecera UDP:
                -El puerto origen lo obtendremos llamando a getUDPSourcePort
                -El valor de checksum lo pondremos siempre a 0
            -Añadir los datos
            -Enviar el datagrama resultante llamando a sendIPDatagram

        Argumentos:
            -data: array de bytes con los datos a incluir como payload en el datagrama UDP
            -dstPort: entero de 16 bits que indica el número de puerto destino a usar
            -dstIP: entero de 32 bits con la IP destino del datagrama UDP
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
          
    '''
    # Build datagram.
    to_send : UDPDatagram = UDPDatagram(
        getUDPSourcePort(),
        dstPort,
        UDP_HLEN + len(data),
        0,
        data
    )

    return sendIPDatagram(dstIP, to_send.to_bytes(), UDP_PROTO)



def initUDP():
    '''
        Nombre: initUDP
        Descripción: Esta función inicializa el nivel UDP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_UDP_datagram con el valor de protocolo 17

        Argumentos:
            -Ninguno
        Retorno: Ninguno
          
    '''
    registerIPProtocol(process_UDP_datagram, UDP_PROTO)