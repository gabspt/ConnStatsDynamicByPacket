from __future__ import print_function

import logging
import time
import ipaddress
import pandas as pd
import grpc
import connstats_pb2
import connstats_pb2_grpc
import argparse

# Create the parser
parser = argparse.ArgumentParser(description='Python client for the connstats service')

# Add server_ip argument
parser.add_argument('--server_ip', type=str, default='192.168.1.204', help='grpc server ip address')
#parser.add_argument('--server_ip', type=str, required=True, help='grpc server ip address')
parser.add_argument('--rtime', type=int, default=5, help='refresh time in seconds to collect the stats')

# Analize the arguments passed to the script
args = parser.parse_args()

# Assign the arguments to variables
server_ip = args.server_ip
rtime = args.rtime

REFRESH_TIME = rtime  # seconds
SERVER_IP_PORT = f"{server_ip}:50051"

def convert_to_ipv4(ipv6_address):
    try:
        ipv6 = ipaddress.IPv6Address(ipv6_address)
        if ipv6.ipv4_mapped:
            ipv4_address = ipv6.ipv4_mapped
            return str(ipv4_address)
        else:
            return str(ipv6)  # If is not mapped, return the original IPv6 as string
    except ipaddress.AddressValueError:
        return "Invalid IP address"

def run():
   
    print("Will try to collect stats ...")

    with grpc.insecure_channel(SERVER_IP_PORT) as channel:
        stub = connstats_pb2_grpc.StatsServiceStub(channel)
        
        while True:
            try:
                response = stub.CollectStats(connstats_pb2.StatsRequest())
                print("Server response received")
            except grpc._channel._InactiveRpcError as e:
                #print(f"Error failed to connect with the remote server: {e}")
                print(f"Error failed to connect with the remote server")
                time.sleep(REFRESH_TIME)
                continue  # Vuelve al inicio del bucle while para intentar de nuevo
            

            # Crear listas vacías para almacenar los datos estadísticos
            Protocol = []
            Local = []
            Remote = []
            PacketsIn = []
            PacketsOut = []
            BytesIn = []
            BytesOut = []
            TsStart = []
            TsCurrent = []
            Inpps = []
            Outpps = []
            InBpp = []
            OutBpp = []
            InBoutB = []
            InPoutP = []
            # usar response para calcular las estadisticas
            for connection in response.connstat:
                Protocol.append(connection.protocol)
                Local.append(f"{convert_to_ipv4(connection.l_ip)}:{connection.l_port}")
                Remote.append(f"{convert_to_ipv4(connection.r_ip)}:{connection.r_port}")
                PacketsIn.append(connection.packets_in)
                PacketsOut.append(connection.packets_out)
                BytesIn.append(connection.bytes_in)
                BytesOut.append(connection.bytes_out)
                TsStart.append(connection.ts_start)
                TsCurrent.append(connection.ts_current)
                
                time_diff = (connection.ts_current - connection.ts_start) / 1000000000
                if time_diff> 0:
                    Inpps.append(round(connection.packets_in / time_diff, 3))
                    Outpps.append(round(connection.packets_out / time_diff, 3))
                else:                 
                    Inpps.append(0)
                    Outpps.append(0)
                
                if connection.packets_in > 0:
                    InBpp.append(round(connection.bytes_in / connection.packets_in, 3))
                else:
                    InBpp.append(0)
                
                if connection.packets_out > 0:
                    OutBpp.append(round(connection.bytes_out / connection.packets_out, 3))
                    InPoutP.append(round(connection.packets_in / connection.packets_out, 3))
                    InBoutB.append(round(connection.bytes_in / connection.bytes_out, 3))
                else:
                    OutBpp.append(0)
                    InPoutP.append(0)
                    InBoutB.append(0)

            dfStats = pd.DataFrame({
                'Protocol': Protocol,
                'Local': Local,
                'Remote': Remote,
                'inpps': Inpps,
                'outpps': Outpps,
                'inBpp': InBpp,
                'outBpp': OutBpp,
                'inBoutB': InBoutB,
                'inPoutP': InPoutP
            })

            df = pd.DataFrame({
                'Protocol': Protocol,
                'Local': Local,
                'Remote': Remote,
                'PacketsIN': PacketsIn,
                'PacketsOUT': PacketsOut,
                'BytesIN': BytesIn,
                'BytesOUT': BytesOut,
                'TsStart': TsStart,
                'TsCurrent': TsCurrent
            })
                        
            print(df)  
            print("")  
            print(dfStats)  
            print("")  

            # Guardar el DataFrame en un archivo CSV
            dfStats.to_csv('datos.csv', index=False)  
               

            time.sleep(REFRESH_TIME)


if __name__ == "__main__":
    logging.basicConfig()
    run()
