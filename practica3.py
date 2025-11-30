# -*- coding: utf-8 -*-
'''
    practica3.py
    Envía datagramas UDP o ICMP sobre protocolo IP. 

    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from udp import *
from icmp import *
from ip import PAIR_NUM
import sys
import binascii
import signal
import argparse
import struct
from argparse import RawTextHelpFormatter
import time
import logging
import socket

DST_PORT = 53
ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REQUEST_CODE = 0
# NOTE: Cambiar ICMP_ID según enunciado
ICMP_ID = PAIR_NUM

ipRROption = bytes([7,11,4,0,0,0,0,0,0,0,0,0])

ALPHABET = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

if __name__ == "__main__":
	ICMP_SEQNUM = 0
	parser = argparse.ArgumentParser(description='Envía datagramas UDP o mensajes ICMP con diferentes opciones',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	parser.add_argument('--dstIP',dest='dstIP',default = False,help='Dirección IP destino')
	parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
	parser.add_argument('--addOptions', dest='addOptions', default=False, action='store_true',help='Añadir opciones a los datagranas IP')
	parser.add_argument('--dataFile',dest='dataFile',default = False,help='Fichero con datos a enviar')
	#NOTE: Opción --icmpsize
	parser.add_argument('--icmpsize',dest='icmpSize',default = 12, type=int, help='Tamaño del paquete ICMP. Debe ser mayor que 0.')

	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

	if args.interface is False:
		logging.error('No se ha especificado interfaz')
		parser.print_help()
		sys.exit(-1)

	if args.dstIP is False:
		logging.error('No se ha especificado dirección IP')
		parser.print_help()
		sys.exit(-1)

	if args.icmpSize <= 0:
		logging.error('El tamaño del paquete ICMP debe ser mayor que 0')
		parser.print_help()
		sys.exit(-1)

	ipOpts = None
	if args.addOptions:
		ipOpts = ipRROption

	# En bytes: b'\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01'
	udp_data = bytes([0,6,1,0,0,1,0,0,0,0,0,0,3,0x77,0x77,0x77,6,0x67,0x6f,0x6f,0x67,0x6c,0x65,3,0x63,0x6f,0x6d,0,0,1,0,1])  
	if args.dataFile:
		with open(args.dataFile,'r') as f:
			#Leemos el contenido del fichero
			data=f.read()
			#Pasamos los datos de cadena a bytes
			udp_data = data.encode()
	
	#NOTE: construir mensaje ICMP según opción --icmpsize
	iterations = args.icmpSize // len(ALPHABET)
	rest = args.icmpSize % len(ALPHABET)
	icmp_data = ALPHABET * iterations + ALPHABET[:rest]
	
	startEthernetLevel(args.interface)
	initICMP()
	initUDP()
	if initIP(args.interface,ipOpts) == False:
		logging.error('Inicializando nivel IP')
		sys.exit(-1)
	
	while True:
		try:
			msg = input('\n\t0x16\n\tIntroduzca opcion:\n\t1.Enviar ping\n\t2.Enviar datagrama UDP:')
			if msg == 'q':
				break
			elif msg == '1':
				sendICMPMessage(icmp_data,ICMP_ECHO_REQUEST_TYPE,ICMP_ECHO_REQUEST_CODE,ICMP_ID,ICMP_SEQNUM,struct.unpack('!I',socket.inet_aton(args.dstIP))[0])
				ICMP_SEQNUM += 1
			elif msg == '2':
				sendUDPDatagram(udp_data,DST_PORT,struct.unpack('!I',socket.inet_aton(args.dstIP))[0])
		except KeyboardInterrupt:
			print('\n')
			break

	logging.info('Cerrando ....')
	stopEthernetLevel()
