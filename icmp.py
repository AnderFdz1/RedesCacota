'''
    icmp.py
    
    Funciones necesarias para implementar el nivel ICMP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ip import *
import time
from threading import Lock
import struct

ICMP_PROTO = 1

ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0

ICMP_HDR_FORMAT = '!BBHHH'
ICMP_HLEN = 8

timeLock = Lock()
icmp_send_times = {}

class ICMPDatagram:
    def __init__(self, type, code, chcksm, id, seq, data):
        self.type = type
        self.code = code
        self.checksum = chcksm
        self.identifier = id
        self.seq_num = seq
        self.payload = data

    def build_header(self, checksum = 0):
        return struct.pack(
            ICMP_HDR_FORMAT,
            self.type,
            self.code,
            checksum,
            self.seq_num,
            self.identifier
        )

    def to_bytes(self, checksum = 0):
        return self.build_header(checksum) + self.payload
    
def __parse_ICMP_datagram(data):
    # Get fields (Some are combined).
    try:
        (type, code, chcksm, id, seq) = struct.unpack(ICMP_HDR_FORMAT, data[:ICMP_HLEN])
    except struct.error:
        return None
    
    # Build ICMPDatagram object.
    return ICMPDatagram(type, code, chcksm, id, seq, data[ICMP_HLEN:])

def __log_ICMP_datagram(datagram: ICMPDatagram):
    logging.debug(
        "\n+-----------------------------------------------------------------------------+\n"
        "ICMP Datagram\n"
        "+-----------------------------------------------------------------------------+\n"
        f"Type={datagram.type}, \n"
        f"Code={datagram.code}  \n"
        "+-----------------------------------------------------------------------------+\n"
    )

def __process_ICMP_echo_request(us, header, datagram: ICMPDatagram, srcIp):
    # Send echo reply.
    sendICMPMessage(datagram.data, ICMP_ECHO_REPLY_TYPE, 1, datagram.identifier, datagram.seq_num, srcIp)

def __process_ICMP_echo_reply(us, header, datagram: ICMPDatagram, srcIp):
    # Get arrival time and key for dictionary.
    key = (srcIp, datagram.identifier, datagram.seq_num)

    # Access dictionary.
    with timeLock:
        if key in icmp_send_times:
            # Get times.
            snd_time = icmp_send_times[key]
            rcv_time = header.ts.tv_sec + (header.ts.tv_usec / 1000000.0)

            # Get RTT.
            rtt = (rcv_time - snd_time) * 1000
        
            # Print.
            ip_str = socket.inet_ntoa(struct.pack('!I', srcIp))
            print(f'Echo reply sent from {ip_str} in {rtt} ms')
        
            # Remove dictionary entry.
            del icmp_send_times[key]
        else:
            logging.debug(f'Unknown entry for key {key}')

def process_ICMP_message(us,header,data,srcIp):
    '''
        Nombre: process_ICMP_message
        Descripción: Esta función procesa un mensaje ICMP. Esta función se ejecutará por cada datagrama IP que contenga
        un 1 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Calcular el checksum de ICMP y comprobar si es correcto:
            -Extraer campos tipo y código de la cabecera ICMP
            -Loggear (con logging.debug) el valor de tipo y código
            -Si el tipo es ICMP_ECHO_REQUEST_TYPE:
                -Generar un mensaje de tipo ICMP_ECHO_REPLY como respuesta. Este mensaje debe contener
                los datos recibidos en el ECHO_REQUEST. Es decir, "rebotamos" los datos que nos llegan.
                -Enviar el mensaje usando la función sendICMPMessage
            -Si el tipo es ICMP_ECHO_REPLY_TYPE:
                -Extraer del diccionario icmp_send_times el valor de tiempo de envío usando como clave los campos srcIP e icmp_id e icmp_seqnum
                contenidos en el mensaje ICMP. Restar el tiempo de envio extraído con el tiempo de recepción (contenido en la estructura pcap_pkthdr)
                -Se debe proteger el acceso al diccionario de tiempos usando la variable timeLock
                -Mostrar por pantalla la resta. Este valor será una estimación del RTT
            -Si es otro tipo:
                -No hacer nada

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del mensaje ICMP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno
          
    '''
    if data is None or len(data) < ICMP_HLEN:
        return

    # Parse datagram.
    datagram: ICMPDatagram = __parse_ICMP_datagram(data)
    if datagram is None:
        return
    
    # Verify checksum.
    check_msg = datagram.to_bytes()
    if len(check_msg) & 1 == 1:
        check_msg += b'\x00'

    calculated = chksum(check_msg)
    if calculated != datagram.checksum:
        logging.debug('ICMP checksum mismatch: expected: %04x; obtained: %04x' % (calculated, datagram.chcksum))
        return

    # Log datagram.
    __log_ICMP_datagram(datagram)

    # Process.
    if datagram.code == ICMP_ECHO_REQUEST_TYPE:
        __process_ICMP_echo_request(us, header, datagram, srcIp)    # Echo Request.
    elif datagram.code == ICMP_ECHO_REPLY_TYPE:
        __process_ICMP_echo_reply(us, header, datagram, srcIp)      # Echo Reply.

def sendICMPMessage(data,type,code,icmp_id,icmp_seqnum,dstIP):
    '''
        Nombre: sendICMPMessage
        Descripción: Esta función construye un mensaje ICMP y lo envía.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Si el campo type es ICMP_ECHO_REQUEST_TYPE o ICMP_ECHO_REPLY_TYPE:
                -Construir la cabecera ICMP
                -Añadir los datos al mensaje ICMP
                -Calcular el checksum y añadirlo al mensaje donde corresponda
                -Si type es ICMP_ECHO_REQUEST_TYPE
                    -Guardar el tiempo de envío (llamando a time.time()) en el diccionario icmp_send_times
                    usando como clave el valor de dstIp+icmp_id+icmp_seqnum
                    -Se debe proteger al acceso al diccionario usando la variable timeLock

                -Llamar a sendIPDatagram para enviar el mensaje ICMP
                
            -Si no:
                -Tipo no soportado. Se devuelve False

        Argumentos:
            -data: array de bytes con los datos a incluir como payload en el mensaje ICMP
            -type: valor del campo tipo de ICMP
            -code: valor del campo code de ICMP 
            -icmp_id: entero que contiene el valor del campo ID de ICMP a enviar
            -icmp_seqnum: entero que contiene el valor del campo Seqnum de ICMP a enviar
            -dstIP: entero de 32 bits con la IP destino del mensaje ICMP
        Retorno: True o False en función de si se ha enviado el mensaje correctamente o no
          
    '''
    global timeLock, icmp_send_times

    # Check type.
    if type != ICMP_ECHO_REQUEST_TYPE and type != ICMP_ECHO_REPLY_TYPE:
        return False

    # Build datagram.
    datagram: ICMPDatagram = ICMPDatagram(type, code, 0, icmp_id, icmp_seqnum, data)
    datagram.checksum = chksum(datagram.to_bytes())

    to_send = datagram.to_bytes(datagram.checksum)

    # Store request time.
    if type == ICMP_ECHO_REQUEST_TYPE:
        snd_time = time.time()
        key = (dstIP, icmp_id, icmp_seqnum)

        with timeLock:
            icmp_send_times[key] = snd_time

    # Send.
    return sendIPDatagram(dstIP, to_send, ICMP_PROTO)

def initICMP():
    '''
        Nombre: initICMP
        Descripción: Esta función inicializa el nivel ICMP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_ICMP_message con el valor de protocolo 1

        Argumentos:
            -Ninguno
        Retorno: Ninguno
          
    '''
    registerIPProtocol(process_ICMP_message, ICMP_PROTO)