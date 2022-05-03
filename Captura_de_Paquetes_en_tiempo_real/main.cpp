#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <locale>
#include <bitset>
#include <cstring>
#include <clocale>

#define LINE_LEN 16

#define TAMANIO 10000
#define TAMANIO_BYTE 8

enum{ICMPV4=1, TCP=6, UDP =17, ICMPV6=58, STP=118, SMP =121};

using namespace std;

void encabezadoEthernet();
void encabezadoIpv4();
void encabezadoARP();
void encabezadoRARP();
void encabezadoIPv6();
void encabezadoICMPv4();
void encabezadoICMPv6();
void versionCabecera();
void tipoServicio();
void flagsPosicionFragmento();
void protocolo();
void encabezadoTCP();
void encabezadoTCPv6();
void encabezadoUDP();
void encabezadoUDPv6();
void encabezadoDNS(int n);

unsigned char bytes[TAMANIO+1];
int tamanio = 0;

int main(int argc, char **argv)
{
    setlocale(LC_ALL,"spanish_mexico");
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	u_int inum, i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	printf("pktdump_ex: prints the packets of the network using WinPcap.\n");
	printf("   Usage: pktdump_ex [-s source]\n\n"
		"   Examples:\n"
		"      pktdump_ex -s file.acp\n"
		"      pktdump_ex -s \\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998}\n\n");

	if(argc < 3)
	{
		printf("\nNo adapter selected: printing the device list:\n");
		/* The user didn't provide a packet source: Retrieve the local device list */
		if(pcap_findalldevs(&alldevs, errbuf) == -1)
		{
			fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
			exit(1);
		}

		/* Print the list */
		for(d=alldevs; d; d=d->next)
		{
			printf("%d. %s\n    ", ++i, d->name);

			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}

		if (i==0)
		{
			printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
			return -1;
		}

		printf("Enter the interface number (1-%d):",i);
		scanf("%d", &inum);

		if (inum < 1 || inum > i)
		{
			printf("\nInterface number out of range.\n");

			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}

		/* Jump to the selected adapter */
		for (d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

		/* Open the adapter */
		if ((fp = pcap_open_live(d->name,	// name of the device
			65536,							// portion of the packet to capture.
											// 65536 grants that the whole packet will be captured on all the MACs.
			1,								// promiscuous mode (nonzero means promiscuous)
			1000,							// read timeout
			errbuf							// error buffer
			)) == NULL)
		{
			fprintf(stderr,"\nError opening adapter\n");
			return -1;
		}
	}
	else
	{
		/* Do not check for the switch type ('-s') */
		if ((fp = pcap_open_live(argv[2],	// name of the device
			65536,							// portion of the packet to capture.
											// 65536 grants that the whole packet will be captured on all the MACs.
			1,								// promiscuous mode (nonzero means promiscuous)
			1000,							// read timeout
			errbuf							// error buffer
			)) == NULL)
		{
			fprintf(stderr,"\nError opening adapter\n");
			return -1;
		}
	}

	/* Read the packets */
    //int k(0);
    char opc = 's';
	while(((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0) && (opc == 'S' || opc == 's')){
        if(res == 0)
        /* Timeout elapsed */
        continue;

        /* print pkt timestamp and pkt len */
        printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

        /* Print the packet */
        for (i=1, tamanio = 0; (i < header->caplen + 1 ) ; i++)
        {
            printf("%.2x ", pkt_data[i-1]);
            if ( (i % LINE_LEN) == 0) printf("\n");
            bytes[i-1] = pkt_data[i-1];
        }
        tamanio = i - 1;

        printf("\n\n");
        encabezadoEthernet();
        cout << "Desea continuar leyendo paquetes? (S/N): ";
        cin >> opc;
        cout << endl;
	}

	if(res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
		return -1;
	}

	pcap_close(fp);
	cout << "Hasta luego :)" << endl;
	return 0;
}

void encabezadoEthernet(){ //14 bytes leídos
    cout << endl << "\t\tEncabezado Ethernet" << endl;
    int i, p, q, contBit;
    cout << "Dirección destino (6 bytes): ";
    for(i=0;i<6;i++){
       cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i];
       if(i <5){
            cout << ":";
       }
    }

    cout << endl << "Dirección origen (6 bytes): ";
    for(;i<12;i++){
       cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i];
       if(i <11){
            cout << ":";
       }
    }

    bitset<TAMANIO_BYTE> primer(bytes[12]);
    bitset<TAMANIO_BYTE> segundo(bytes[13]);

    bitset<16> tipo;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte 13 al final
        tipo[contBit] = segundo[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 12 al principio
        tipo[contBit] = primer[q];
    }
    cout << endl << "Tipo: ";
    switch(tipo.to_ulong()){
        case 2048://0800
            cout << "IPv4 (0800)" << endl;
            encabezadoIpv4();
            break;
        case 2054://0806
            cout << "ARP (0806)" << endl;
            encabezadoARP();
            break;
        case 32821://8035
            cout << "RARP (8035)" << endl;
            encabezadoRARP();
            break;
        case 34525://86DD
            cout << "IPv6 (86DD)" << endl;
            encabezadoIPv6();
            break;
        default:
            cout << "Raro: " << dec << tipo.to_ulong() << endl;
    }
    cout << endl;
}

void encabezadoARP(){ // a partir del 14
    int tipoHardware(0);
    tipoHardware = bytes[14] + bytes[15];
    cout << "\tEncabezado ARP" << endl;
    cout << "Tipo de harware: "; //<< setw(2) <<  dec << tipoHardware << endl;
    switch(tipoHardware){
        case 1:
            cout << "(1) Ethernet (10MB)" << endl;
            break;
        case 6:
            cout << "(6) IEEE 802 Networks" << endl;
            break;
        case 7:
            cout << "(7) ARCNET" << endl;
            break;
        case 15:
            cout << "(15) Frame Relay" << endl;
            break;
        case 16:
            cout << "(16) Asynchronous Transfer Mode (ATM)" << endl;
            break;
        case 17:
            cout << "(17) HDLC" << endl;
            break;
        case 18:
            cout << "(18) Fibre Channel" << endl;
            break;
        case 19:
            cout << "(19) Asynchronous Transfer Mode (ATM)" << endl;
            break;
        case 20:
            cout << "(20) Serial Line" << endl;
            break;
        default:
            cout << "Raro: " << setw(2) << dec << tipoHardware << endl;

    }
    long tipo(0);
    tipo = bytes[16] + bytes[17];
    cout << "Tipo: ";
    switch(tipo){
        case 8:
            cout << "IPv4 (0800)" << endl;
            break;
        case 14:
            cout << "ARP (0806)" << endl;
            break;
        case 181:
            cout << "RARP (8035)" << endl;
            break;
        case 355:
            cout << "IPv6 (86DD)" << endl;
            break;
        default:
            cout << "Raro: " << tipo << endl;
    }

    int longDireccionHardware;
    longDireccionHardware = bytes[18]; // x
    cout << "Longitud de dirección hardware: "<< longDireccionHardware << endl;
    int longDireccionProtocolo;
    longDireccionProtocolo = bytes[19]; //y
    cout << "Longitud de dirección hardware: "<< longDireccionProtocolo << endl;

    int codigoOp;
    codigoOp = (int)bytes[20] + (int)bytes[21];
    bitset<16> codigoOperacion = codigoOp;
    cout << "Codigo op:"; //<< codigoOperacion << endl;
    switch(codigoOperacion.to_ulong()){
        case 1:
            cout << "(1) ARP Request" << endl;
            break;
        case 2:
            cout << "(2) ARP Reply" << endl;
            break;
        case 3:
            cout << "(3) RARP Request" << endl;
            break;
        case 4:
            cout << "(4) RARP Reply" << endl;
            break;
        case 5:
            cout << "(5) DRARP Request" << endl;
            break;
        case 6:
            cout << "(6) DRARP Reply" << endl;
            break;
        case 7:
            cout << "(7) DRARP Error" << endl;
            break;
        case 8:
            cout << "(8) InARP Request" << endl;
            break;
        case 9:
            cout << "(9) InARP Reply" << endl;
            break;


    }
    cout << endl << "Dirección hardware del emisor (6 bytes): ";
    for(int i=22;i<28;i++){
       cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i];
       if(i<27){
            cout << ":";
       }
    }
    cout << endl << "Dirección IP del emisor (4 bytes): ";
    for(int i=28;i<32;i++){
       cout << setfill('0')<< setw(2) << dec << (int)bytes[i];
       if(i<31){
            cout << ".";
       }
    }

    cout << endl << "Dirección hardware del receptor (6 bytes): ";
    for(int i=32;i<38;i++){
       cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i];
       if(i<37){
            cout << ":";
       }
    }
    cout << endl << "Dirección IP del receptor (4 bytes): ";
    for(int i=38;i<42;i++){
       cout << setfill('0')<< setw(2) << dec << (int)bytes[i];
       if(i<41){
            cout << ".";
       }
    }

    cout << endl <<"\tDATA" << endl;
    for(int i=42;i<tamanio;i++){
       cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i] << "|";
    }
    cout << endl;

}

void encabezadoRARP(){ // a partir del 14
    int tipoHardware(0);
    tipoHardware = bytes[14] + bytes[15];
    cout << "\tEncabezado RARP" << endl;
    cout << "Tipo de harware: "; //<< setw(2) <<  dec << tipoHardware << endl;
    switch(tipoHardware){
        case 1:
            cout << "(1) Ethernet (10MB)" << endl;
            break;
        case 6:
            cout << "(6) IEEE 802 Networks" << endl;
            break;
        case 7:
            cout << "(7) ARCNET" << endl;
            break;
        case 15:
            cout << "(15) Frame Relay" << endl;
            break;
        case 16:
            cout << "(16) Asynchronous Transfer Mode (ATM)" << endl;
            break;
        case 17:
            cout << "(17) HDLC" << endl;
            break;
        case 18:
            cout << "(18) Fibre Channel" << endl;
            break;
        case 19:
            cout << "(19) Asynchronous Transfer Mode (ATM)" << endl;
            break;
        case 20:
            cout << "(20) Serial Line" << endl;
            break;
        default:
            cout << "Raro: " << setw(2) << dec << tipoHardware << endl;

    }
    long tipo(0);
    tipo = bytes[16] + bytes[17];
    cout << "Tipo: ";
    switch(tipo){
        case 8:
            cout << "IPv4 (0800)" << endl;
            break;
        case 14:
            cout << "ARP (0806)" << endl;
            break;
        case 181:
            cout << "RARP (8035)" << endl;
            //rarp
            break;
        case 355:
            cout << "IPv6 (86DD)" << endl;
            //ipv6
            break;
        default:
            cout << "Raro: " << tipo << endl;
    }

    int longDireccionHardware;
    longDireccionHardware = bytes[18]; // x
    cout << "Longitud de dirección hardware: "<< longDireccionHardware << endl;
    int longDireccionProtocolo;
    longDireccionProtocolo = bytes[19]; //y
    cout << "Longitud de dirección hardware: "<< longDireccionProtocolo << endl;

    int codigoOp;
    codigoOp = (int)bytes[20] + (int)bytes[21];
    bitset<16> codigoOperacion = codigoOp;
    cout << "Codigo op:"; //<< codigoOperacion << endl;
    switch(codigoOperacion.to_ulong()){
        case 1:
            cout << "(1) ARP Request" << endl;
            break;
        case 2:
            cout << "(2) ARP Reply" << endl;
            break;
        case 3:
            cout << "(3) RARP Request" << endl;
            break;
        case 4:
            cout << "(4) RARP Reply" << endl;
            break;
        case 5:
            cout << "(5) DRARP Request" << endl;
            break;
        case 6:
            cout << "(6) DRARP Reply" << endl;
            break;
        case 7:
            cout << "(7) DRARP Error" << endl;
            break;
        case 8:
            cout << "(8) InARP Request" << endl;
            break;
        case 9:
            cout << "(9) InARP Reply" << endl;
            break;


    }
    cout << endl << "Dirección hardware del emisor (6 bytes): ";
    for(int i=22;i<28;i++){
       cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i];
       if(i<27){
            cout << ":";
       }
    }
    cout << endl << "Dirección IP del emisor (4 bytes): ";
    for(int i=28;i<32;i++){
       cout << setfill('0')<< setw(2) << dec << (int)bytes[i];
       if(i<31){
            cout << ".";
       }
    }

    cout << endl << "Dirección hardware del receptor (6 bytes): ";
    for(int i=32;i<38;i++){
       cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i];
       if(i<37){
            cout << ":";
       }
    }
    cout << endl << "Dirección IP del receptor (4 bytes): ";
    for(int i=38;i<42;i++){
       cout << setfill('0')<< setw(2) << dec << (int)bytes[i];
       if(i<41){
            cout << ".";
       }
    }
    cout << endl <<"\tDATA" << endl;
    for(int i=42;i<tamanio;i++){
       cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i] << "|";
    }
    cout << endl;

}

void encabezadoIpv4(){ //a partir del byte 14 +20 bytes = 34 bytes leídos
    int contBit, p, q;
    cout << endl << "\t\tEncabezado IPv4" << endl;
    ///Version y cabecera
    versionCabecera();
    ///Tipo de servicio
    tipoServicio();
    ///Longitud total
    bitset<TAMANIO_BYTE> primer(bytes[16]);
    bitset<TAMANIO_BYTE> segundo(bytes[17]);

    bitset<16> longitudTotal;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte 17 al final
        longitudTotal[contBit] = segundo[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 16 al principio
        longitudTotal[contBit] = primer[q];
    }
    cout << "Longitud total: " << longitudTotal.to_ulong() << endl;
    ///Identificador

    bitset<TAMANIO_BYTE> primerId(bytes[18]);
    bitset<TAMANIO_BYTE> segundoId(bytes[19]);

    bitset<16> identificador;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte 19 al final
        identificador[contBit] = segundoId[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 18 al principio
        identificador[contBit] = primerId[q];
    }
    cout << "Identificador: " << identificador.to_ulong() << endl;
    ///Banderas y posicion Fragmento
    flagsPosicionFragmento();
    ///Tiempo de vida
    bitset<TAMANIO_BYTE> ttl(bytes[22]);
    cout << "TTL: " << dec << ttl.to_ulong() << endl;
    ///Protocolo
    protocolo();
    ///Checksum, Direccion IP origen, Direccion IP destino
    //long checkSum(0);
    //checkSum = bytes[24] + bytes[25]; ///173 hex en "ethernet_ipv4_icmp.bin"
    bitset<TAMANIO_BYTE> primerCheck(bytes[24]);
    bitset<TAMANIO_BYTE> segundoCheck(bytes[25]);

    bitset<16> checkSum;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte 19 al final
        checkSum[contBit] = segundoCheck[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 18 al principio
        checkSum[contBit] = primerCheck[q];
    }
    cout << "CheckSum IPv4: " << setw(2) << hex << uppercase << checkSum.to_ulong() << endl; ///173

    cout << "Dirección IP origen:  " <<  dec << setw(3) << (int)bytes[26] << "."
        << setw(3) << (int)bytes[27] << "." << setw(3) << (int)bytes[28] << "."
        << setw(3) << (int)bytes[29] << endl;

    cout << "Dirección IP destino: " <<  dec << setw(3) << (int)bytes[30] << "."
        << setw(3) << (int)bytes[31] << "." << setw(3) << (int)bytes[32] << "."
        << setw(3) << (int)bytes[33] << endl;
    bitset<TAMANIO_BYTE> protocolo(bytes[23]);
    switch(protocolo.to_ulong()){
        case ICMPV4:
            encabezadoICMPv4();
            break;
        case TCP:
            encabezadoTCP();
            break;
        case UDP:
            encabezadoUDP();
            break;
        case ICMPV6:
            break;
        case STP:
            break;
        case SMP:
            break;
        default:
            cout << "El protocolo leído no esta en la lista, revise documentación" << endl;
    }

}

void encabezadoTCP(){ //34 + 20 = 54 bytes
    int p,q,contBit;
    bitset<TAMANIO_BYTE> primer(bytes[34]);
    bitset<TAMANIO_BYTE> segundo(bytes[35]);

    bitset<16> puertoOrigen;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        puertoOrigen[contBit] = segundo[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        puertoOrigen[contBit] = primer[q];
    }
    cout << endl << "\t\t TCP" << endl;
    cout << "Puerto origen: " << dec << puertoOrigen.to_ulong();
    if(puertoOrigen.to_ulong() >= 0 && puertoOrigen.to_ulong() <= 1023){ // Bien conocidos
        cout << " -> Puertos bien conocidos " << endl;
        switch(puertoOrigen.to_ulong()){
            case 20: case 21: cout << "Servicio: FTP \t Protocolo: TCP" << endl;    break;
            case 22: cout << "Servicio: SSH \t Protocolo: TCP" << endl;             break;
            case 23: cout << "Servicio: TELNET \t Protocolo: TCP" << endl;          break;
            case 25: cout << "Servicio: SMTP \t Protocolo: TCP" << endl;            break;
            case 53: cout << "Servicio: DNS \t Protocolo: TCP/UDP" << endl;         break;
            case 67: case 68: cout << "Servicio: DHCP \t Protocolo: UDP" << endl;   break;
            case 69: cout << "Servicio: TFTP \t Protocolo: UDP" << endl;            break;
            case 80: cout << "Servicio: HTTP \t Protocolo: TCP" << endl;            break;
            case 110: cout << "Servicio: POP3 \t Protocolo: TCP" << endl;           break;
            case 143: cout << "Servicio: IMAP \t Protocolo: TCP" << endl;           break;
            case 443: cout << "Servicio: HTTPS \t Protocolo: TCP" << endl;          break;
            case 993: cout << "Servicio: IMAP SSL \t Protocolo: TCP" << endl;       break;
            case 995: cout << "Servicio: POP SSL \t Protocolo: TCP" << endl;        break;
            default: cout << "Protocolo desconocido " << endl;
        }
    }
    else if(puertoOrigen.to_ulong() >= 1024 && puertoOrigen.to_ulong() <= 49151){//
        cout << " -> Puertos registrados" << endl;
    }
    else{
        cout << " -> Puertos dinámicos o privados" << endl;
    }


    bitset<TAMANIO_BYTE> primerD(bytes[36]);
    bitset<TAMANIO_BYTE> segundoD(bytes[37]);
    bitset<16> puertoDestino;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        puertoDestino[contBit] = segundoD[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        puertoDestino[contBit] = primerD[q];
    }

    cout << "Puerto destino: " << dec << puertoDestino.to_ulong();

    if(puertoDestino.to_ulong() >= 0 && puertoDestino.to_ulong() <= 1023){ // Bien conocidos
        cout << " -> Puertos bien conocidos " << endl;
        switch(puertoDestino.to_ulong()){
            case 20: case 21: cout << "Servicio: FTP \t Protocolo: TCP" << endl;    break;
            case 22: cout << "Servicio: SSH \t Protocolo: TCP" << endl;             break;
            case 23: cout << "Servicio: TELNET \t Protocolo: TCP" << endl;          break;
            case 25: cout << "Servicio: SMTP \t Protocolo: TCP" << endl;            break;
            case 53: cout << "Servicio: DNS \t Protocolo: TCP/UDP" << endl;         break;
            case 67: case 68: cout << "Servicio: DHCP \t Protocolo: UDP" << endl;   break;
            case 69: cout << "Servicio: TFTP \t Protocolo: UDP" << endl;            break;
            case 80: cout << "Servicio: HTTP \t Protocolo: TCP" << endl;            break;
            case 110: cout << "Servicio: POP3 \t Protocolo: TCP" << endl;           break;
            case 143: cout << "Servicio: IMAP \t Protocolo: TCP" << endl;           break;
            case 443: cout << "Servicio: HTTPS \t Protocolo: TCP" << endl;          break;
            case 993: cout << "Servicio: IMAP SSL \t Protocolo: TCP" << endl;       break;
            case 995: cout << "Servicio: POP SSL \t Protocolo: TCP" << endl;        break;
            default: cout << "Protocolo desconocido " << endl;
        }
    }
    else if(puertoDestino.to_ulong() >= 1024 && puertoDestino.to_ulong() <= 49151){//
        cout << " -> Puertos registrados" << endl;
    }
    else{
        cout << " -> Puertos dinámicos o privados" << endl;
    }

    bitset<32> numSecuencia;
    bitset<16> parte1,parte2;
    bitset<TAMANIO_BYTE> sub1= bytes[38];
    bitset<TAMANIO_BYTE> sub2= bytes[39];
    bitset<TAMANIO_BYTE> sub3= bytes[40];
    bitset<TAMANIO_BYTE> sub4= bytes[41];

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        parte1[contBit] = sub2[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        parte1[contBit] = sub1[q];
    }

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        parte2[contBit] = sub4[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        parte2[contBit] = sub3[q];
    }

    for(p =0 , q = 15, contBit = 15; q >= p; q--, contBit--){
        numSecuencia[contBit] = parte2[q];
    }
    for(p = 0 , q = 15, contBit = 31; q >= p; q--, contBit--){
        numSecuencia[contBit] = parte1[q];
    }

    cout << "Numero secuencia: " << dec << numSecuencia.to_ulong() << endl;

    bitset<32> numAcuse;
    bitset<16> parte1A,parte2A;
    bitset<TAMANIO_BYTE> sub1A= bytes[42];
    bitset<TAMANIO_BYTE> sub2A= bytes[43];
    bitset<TAMANIO_BYTE> sub3A= bytes[44];
    bitset<TAMANIO_BYTE> sub4A= bytes[45];

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        parte1A[contBit] = sub2A[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        parte1A[contBit] = sub1A[q];
    }

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        parte2A[contBit] = sub4A[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        parte2A[contBit] = sub3A[q];
    }

    for(p =0 , q = 15, contBit = 15; q >= p; q--, contBit--){
        numAcuse[contBit] = parte2A[q];
    }
    for(p = 0 , q = 15, contBit = 31; q >= p; q--, contBit--){
        numAcuse[contBit] = parte1A[q];
    }

    cout << "Numero de acuse de recibo: " << dec << numAcuse.to_ulong() << endl;

    bitset<TAMANIO_BYTE> longRev= bytes[46];
    bitset<4> longitudCabecera;
    for(p =4 , q = 7, contBit = 3; q >= p; q--, contBit--){
        longitudCabecera[contBit] = longRev[q];
    }

    cout << "Longitud de cabecera: " << longitudCabecera.to_ulong() << endl;

    bitset<3> reservado;

    for(p =1 , q = 3, contBit = 3; q >= p; q--, contBit--){
        reservado[contBit] = longRev[q];
    }
    cout << "Reservado: " << dec << reservado.to_ulong() << endl;

    bitset<TAMANIO_BYTE> flags(bytes[47]);
    cout << "NS  : " << longRev[0] << endl;
    cout << "CWR : " << flags[7] << endl;
    cout << "ECE : " << flags[6] << endl;
    cout << "URG : " << flags[5] << endl;
    cout << "ACK : " << flags[4] << endl;
    cout << "PSH : " << flags[3] << endl;
    cout << "RST : " << flags[2] << endl;
    cout << "SYN : " << flags[1] << endl;
    cout << "FIN : " << flags[0] << endl;

    bitset<TAMANIO_BYTE> primerVentana(bytes[48]);
    bitset<TAMANIO_BYTE> segundaVentana(bytes[49]);
    bitset<16> tamanioVentana;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        tamanioVentana[contBit] = segundaVentana[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        tamanioVentana[contBit] = primerVentana[q];
    }

    cout << "Tamaño de ventana: " << dec << tamanioVentana.to_ulong() << endl;

    bitset<TAMANIO_BYTE> primerCheck(bytes[50]);
    bitset<TAMANIO_BYTE> segundoCheck(bytes[51]);
    bitset<16> checkSum;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        checkSum[contBit] = segundoCheck[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        checkSum[contBit] = primerCheck[q];
    }

    cout << "CheckSum: " << hex << checkSum.to_ulong() << endl;

    bitset<TAMANIO_BYTE> primerUr(bytes[52]);
    bitset<TAMANIO_BYTE> segundoUr(bytes[53]);
    bitset<16> puertoUrgente;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        puertoUrgente[contBit] = segundoUr[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        puertoUrgente[contBit] = primerUr[q];
    }

    cout << "Puerto urgente: " << dec << puertoUrgente.to_ulong() << endl;

    if(puertoDestino.to_ulong() == 53 || puertoOrigen.to_ulong() == 53){
        encabezadoDNS(54);
    }
    else{
        cout << endl <<"\tDATA" << endl;
        for(int i=54;i<tamanio;i++){
           cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i] << "|";
        }
    }
    cout << endl;
}

void encabezadoTCPv6(){ // 54 +20 = 73 bytes
    int p,q,contBit;
    bitset<TAMANIO_BYTE> primer(bytes[54]);
    bitset<TAMANIO_BYTE> segundo(bytes[55]);

    bitset<16> puertoOrigen;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  55 al final
        puertoOrigen[contBit] = segundo[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 54 al principio
        puertoOrigen[contBit] = primer[q];
    }
    cout << endl << "\t\t TCP" << endl;
    cout << "Puerto origen: " << dec << puertoOrigen.to_ulong();

    if(puertoOrigen.to_ulong() >= 0 && puertoOrigen.to_ulong() <= 1023){ // Bien conocidos
        cout << " -> Puertos bien conocidos " << endl;
        switch(puertoOrigen.to_ulong()){
            case 20: case 21: cout << "Servicio: FTP \t Protocolo: TCP" << endl;    break;
            case 22: cout << "Servicio: SSH \t Protocolo: TCP" << endl;             break;
            case 23: cout << "Servicio: TELNET \t Protocolo: TCP" << endl;          break;
            case 25: cout << "Servicio: SMTP \t Protocolo: TCP" << endl;            break;
            case 53: cout << "Servicio: DNS \t Protocolo: TCP/UDP" << endl;         break;
            case 67: case 68: cout << "Servicio: DHCP \t Protocolo: UDP" << endl;   break;
            case 69: cout << "Servicio: TFTP \t Protocolo: UDP" << endl;            break;
            case 80: cout << "Servicio: HTTP \t Protocolo: TCP" << endl;            break;
            case 110: cout << "Servicio: POP3 \t Protocolo: TCP" << endl;           break;
            case 143: cout << "Servicio: IMAP \t Protocolo: TCP" << endl;           break;
            case 443: cout << "Servicio: HTTPS \t Protocolo: TCP" << endl;          break;
            case 993: cout << "Servicio: IMAP SSL \t Protocolo: TCP" << endl;       break;
            case 995: cout << "Servicio: POP SSL \t Protocolo: TCP" << endl;        break;
            default: cout << "Protocolo desconocido " << endl;
        }
    }
    else if(puertoOrigen.to_ulong() >= 1024 && puertoOrigen.to_ulong() <= 49151){//
        cout << " -> Puertos registrados" << endl;
    }
    else{
        cout << " -> Puertos dinámicos o privados" << endl;
    }

    bitset<TAMANIO_BYTE> primerD(bytes[56]);
    bitset<TAMANIO_BYTE> segundoD(bytes[57]);
    bitset<16> puertoDestino;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        puertoDestino[contBit] = segundoD[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        puertoDestino[contBit] = primerD[q];
    }

    cout << "Puerto destino: " << dec << puertoDestino.to_ulong();
    if(puertoDestino.to_ulong() >= 0 && puertoDestino.to_ulong() <= 1023){ // Bien conocidos
        cout << " -> Puertos bien conocidos " << endl;
        switch(puertoDestino.to_ulong()){
            case 20: case 21: cout << "Servicio: FTP \t Protocolo: TCP" << endl;    break;
            case 22: cout << "Servicio: SSH \t Protocolo: TCP" << endl;             break;
            case 23: cout << "Servicio: TELNET \t Protocolo: TCP" << endl;          break;
            case 25: cout << "Servicio: SMTP \t Protocolo: TCP" << endl;            break;
            case 53: cout << "Servicio: DNS \t Protocolo: TCP/UDP" << endl;         break;
            case 67: case 68: cout << "Servicio: DHCP \t Protocolo: UDP" << endl;   break;
            case 69: cout << "Servicio: TFTP \t Protocolo: UDP" << endl;            break;
            case 80: cout << "Servicio: HTTP \t Protocolo: TCP" << endl;            break;
            case 110: cout << "Servicio: POP3 \t Protocolo: TCP" << endl;           break;
            case 143: cout << "Servicio: IMAP \t Protocolo: TCP" << endl;           break;
            case 443: cout << "Servicio: HTTPS \t Protocolo: TCP" << endl;          break;
            case 993: cout << "Servicio: IMAP SSL \t Protocolo: TCP" << endl;       break;
            case 995: cout << "Servicio: POP SSL \t Protocolo: TCP" << endl;        break;
            default: cout << "Protocolo desconocido " << endl;
        }
    }
    else if(puertoDestino.to_ulong() >= 1024 && puertoDestino.to_ulong() <= 49151){//
        cout << " -> Puertos registrados" << endl;
    }
    else{
        cout << " -> Puertos dinámicos o privados" << endl;
    }

    bitset<32> numSecuencia;
    bitset<16> parte1,parte2;
    bitset<TAMANIO_BYTE> sub1= bytes[58];
    bitset<TAMANIO_BYTE> sub2= bytes[59];
    bitset<TAMANIO_BYTE> sub3= bytes[60];
    bitset<TAMANIO_BYTE> sub4= bytes[61];

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        parte1[contBit] = sub2[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        parte1[contBit] = sub1[q];
    }

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        parte2[contBit] = sub4[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        parte2[contBit] = sub3[q];
    }

    for(p =0 , q = 15, contBit = 15; q >= p; q--, contBit--){
        numSecuencia[contBit] = parte2[q];
    }
    for(p = 0 , q = 15, contBit = 31; q >= p; q--, contBit--){
        numSecuencia[contBit] = parte1[q];
    }

    cout << "Numero secuencia: " << dec << numSecuencia.to_ulong() << endl;

    bitset<32> numAcuse;
    bitset<16> parte1A,parte2A;
    bitset<TAMANIO_BYTE> sub1A= bytes[62];
    bitset<TAMANIO_BYTE> sub2A= bytes[63];
    bitset<TAMANIO_BYTE> sub3A= bytes[64];
    bitset<TAMANIO_BYTE> sub4A= bytes[65];

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        parte1A[contBit] = sub2A[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        parte1A[contBit] = sub1A[q];
    }

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        parte2A[contBit] = sub4A[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        parte2A[contBit] = sub3A[q];
    }

    for(p =0 , q = 15, contBit = 15; q >= p; q--, contBit--){
        numAcuse[contBit] = parte2A[q];
    }
    for(p = 0 , q = 15, contBit = 31; q >= p; q--, contBit--){
        numAcuse[contBit] = parte1A[q];
    }

    cout << "Numero de acuse de recibo: " << dec << numAcuse.to_ulong() << endl;

    bitset<TAMANIO_BYTE> longRev= bytes[66];
    bitset<4> longitudCabecera;
    for(p =4 , q = 7, contBit = 3; q >= p; q--, contBit--){
        longitudCabecera[contBit] = longRev[q];
    }

    cout << "Longitud de cabecera: " << longitudCabecera.to_ulong() << endl;

    bitset<3> reservado;

    for(p =1 , q = 3, contBit = 3; q >= p; q--, contBit--){
        reservado[contBit] = longRev[q];
    }
    cout << "Reservado: " << dec << reservado.to_ulong() << endl;


    bitset<TAMANIO_BYTE> flags(bytes[67]);
    cout << "NS  : " << longRev[0] << endl;
    cout << "CWR : " << flags[7] << endl;
    cout << "ECE : " << flags[6] << endl;
    cout << "URG : " << flags[5] << endl;
    cout << "ACK : " << flags[4] << endl;
    cout << "PSH : " << flags[3] << endl;
    cout << "RST : " << flags[2] << endl;
    cout << "SYN : " << flags[1] << endl;
    cout << "FIN : " << flags[0] << endl;

    bitset<TAMANIO_BYTE> primerVentana(bytes[68]);
    bitset<TAMANIO_BYTE> segundaVentana(bytes[69]);
    bitset<16> tamanioVentana;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        tamanioVentana[contBit] = segundaVentana[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        tamanioVentana[contBit] = primerVentana[q];
    }

    cout << "Tamaño de ventana: " << dec << tamanioVentana.to_ulong() << endl;

    bitset<TAMANIO_BYTE> primerCheck(bytes[70]);
    bitset<TAMANIO_BYTE> segundoCheck(bytes[71]);
    bitset<16> checkSum;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        checkSum[contBit] = segundoCheck[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        checkSum[contBit] = primerCheck[q];
    }

    cout << "CheckSum: " << hex << checkSum.to_ulong() << endl;

    bitset<TAMANIO_BYTE> primerUr(bytes[72]);
    bitset<TAMANIO_BYTE> segundoUr(bytes[73]);
    bitset<16> puertoUrgente;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        puertoUrgente[contBit] = segundoUr[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        puertoUrgente[contBit] = primerUr[q];
    }

    cout << "Puerto urgente: " << dec << puertoUrgente.to_ulong() << endl;


    if(puertoDestino.to_ulong() == 53 || puertoOrigen.to_ulong() == 53){
        encabezadoDNS(74);
    }
    else{
        cout << endl <<"\tDATA" << endl;
        for(int i=74;i<tamanio;i++){
           cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i] << "|";
        }
    }
    cout << endl;
}

void encabezadoICMPv4(){// +4 bytes = 38 bytes leídos
    cout << endl << "\t\tEncabezado ICMPv4" << endl;
    cout << "Tipo de mensaje informativo: "; //34
    switch((int)bytes[34]){
        case 0:
            cout << "(0) Echo Reply" << endl;
            break;
        case 3:
            cout << "(3) Destination Unreacheable" << endl;
            break;
        case 4:
            cout << "(4) Source Quench" << endl;
            break;
        case 5:
            cout << "(5) Redirect" << endl;
            break;
        case 8:
            cout << "(8) Echo" << endl;
            break;
        case 11:
            cout << "(11) Time Exceeded" << endl;
            break;
        case 12:
            cout << "(12) Parameter Problem" << endl;
            break;
        case 13:
            cout << "(13) TimeStamp" << endl;
            break;
        case 14:
            cout << "(14) TimeStamp Reply" << endl;
            break;
        case 15:
            cout << "(15) Information Request" << endl;
            break;
        case 16:
            cout << "(16) Information Reply" << endl;
            break;
        case 17:
            cout << "(17) Addressmask" << endl;
            break;
        case 18:
            cout << "(18) Addressmask Reply" << endl;
            break;
        default:
            cout << "El mensaje no se encuentra en la lista!" << endl;
    }
    cout << "Códigos de error: ";//35
    switch((int)bytes[35]){
        case 0:
            cout << "(0) No se puede llegar a la red." << endl;
            break;
        case 1:
            cout << "(1) No se puede llegar al host o aplicación de desitno" << endl;
            break;
        case 2:
            cout << "(2) El destino no dispone del protocolo solicitado."<< endl;
            break;
        case 3:
            cout << "(3) No se puede llegar al puerto destino o la aplicación destino no está libre." << endl;
            break;
        case 4:
            cout << "(4) Se necesita aplicar fragmentación, pero el flag correspondiente indica lo contrario." << endl;
            break;
        case 5:
            cout << "(5) La ruta de origen no es correcta." << endl;
            break;
        case 6:
            cout << "(6) No se conoce la red destino." << endl;
            break;
        case 7:
            cout << "(7) No se conoce el host destino." << endl;
            break;
        case 8:
            cout << "(8) El host origen está aislado. " << endl;
            break;
        case 9:
            cout << "(9) La comunicación con la red destino está prohíbida por razones administrativas." << endl;
            break;
        case 10:
            cout << "(10) La comunicación con el host está prohíbida por razones administrativas." << endl;
            break;
        case 11:
            cout << "(11) No se puede llegar a la red destino debido al tipo de servicio." << endl;
            break;
        case 12:
            cout << "(12) No se puede llegar al host destino debido al tipo de servicio." << endl;
            break;
        default:
            cout << "El error no se encuentra en la lista!" << endl;
    }
    long checkSum(0);
    checkSum = bytes[36] + bytes[37]; // 36 y 37
    cout << "CheckSum ICMPv4: " << setw(2) << hex << uppercase << checkSum << endl;

    cout << endl <<"\tDATA" << endl;
    for(int i=38;i<tamanio;i++){
       cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i] << "|";
    }
    cout << endl;
}

void encabezadoUDP(){ // 33 + 8 = 41 bytes
    int p,q,contBit;
    bitset<TAMANIO_BYTE> primer(bytes[34]);
    bitset<TAMANIO_BYTE> segundo(bytes[35]);

    bitset<16> puertoOrigen;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        puertoOrigen[contBit] = segundo[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        puertoOrigen[contBit] = primer[q];
    }
    cout << endl << "\t\t UDP" << endl;
    cout << "Puerto origen: " << dec << puertoOrigen.to_ulong();
    if(puertoOrigen.to_ulong() >= 0 && puertoOrigen.to_ulong() <= 1023){ // Bien conocidos
        cout << " -> Puertos bien conocidos " << endl;
        switch(puertoOrigen.to_ulong()){
            case 20: case 21: cout << "Servicio: FTP \t Protocolo: TCP" << endl;    break;
            case 22: cout << "Servicio: SSH \t Protocolo: TCP" << endl;             break;
            case 23: cout << "Servicio: TELNET \t Protocolo: TCP" << endl;          break;
            case 25: cout << "Servicio: SMTP \t Protocolo: TCP" << endl;            break;
            case 53: cout << "Servicio: DNS \t Protocolo: TCP/UDP" << endl;         break;
            case 67: case 68: cout << "Servicio: DHCP \t Protocolo: UDP" << endl;   break;
            case 69: cout << "Servicio: TFTP \t Protocolo: UDP" << endl;            break;
            case 80: cout << "Servicio: HTTP \t Protocolo: TCP" << endl;            break;
            case 110: cout << "Servicio: POP3 \t Protocolo: TCP" << endl;           break;
            case 143: cout << "Servicio: IMAP \t Protocolo: TCP" << endl;           break;
            case 443: cout << "Servicio: HTTPS \t Protocolo: TCP" << endl;          break;
            case 993: cout << "Servicio: IMAP SSL \t Protocolo: TCP" << endl;       break;
            case 995: cout << "Servicio: POP SSL \t Protocolo: TCP" << endl;        break;
            default: cout << "Protocolo desconocido " << endl;
        }
    }
    else if(puertoOrigen.to_ulong() >= 1024 && puertoOrigen.to_ulong() <= 49151){//
        cout << " -> Puertos registrados" << endl;
    }
    else{
        cout << " -> Puertos dinámicos o privados" << endl;
    }


    bitset<TAMANIO_BYTE> primerD(bytes[36]);
    bitset<TAMANIO_BYTE> segundoD(bytes[37]);
    bitset<16> puertoDestino;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        puertoDestino[contBit] = segundoD[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        puertoDestino[contBit] = primerD[q];
    }

    cout << "Puerto destino: " << dec << puertoDestino.to_ulong();

    if(puertoDestino.to_ulong() >= 0 && puertoDestino.to_ulong() <= 1023){ // Bien conocidos
        cout << " -> Puertos bien conocidos " << endl;
        switch(puertoDestino.to_ulong()){
            case 20: case 21: cout << "Servicio: FTP \t Protocolo: TCP" << endl;    break;
            case 22: cout << "Servicio: SSH \t Protocolo: TCP" << endl;             break;
            case 23: cout << "Servicio: TELNET \t Protocolo: TCP" << endl;          break;
            case 25: cout << "Servicio: SMTP \t Protocolo: TCP" << endl;            break;
            case 53: cout << "Servicio: DNS \t Protocolo: TCP/UDP" << endl;         break;
            case 67: case 68: cout << "Servicio: DHCP \t Protocolo: UDP" << endl;   break;
            case 69: cout << "Servicio: TFTP \t Protocolo: UDP" << endl;            break;
            case 80: cout << "Servicio: HTTP \t Protocolo: TCP" << endl;            break;
            case 110: cout << "Servicio: POP3 \t Protocolo: TCP" << endl;           break;
            case 143: cout << "Servicio: IMAP \t Protocolo: TCP" << endl;           break;
            case 443: cout << "Servicio: HTTPS \t Protocolo: TCP" << endl;          break;
            case 993: cout << "Servicio: IMAP SSL \t Protocolo: TCP" << endl;       break;
            case 995: cout << "Servicio: POP SSL \t Protocolo: TCP" << endl;        break;
            default: cout << "Protocolo desconocido " << endl;
        }
    }
    else if(puertoDestino.to_ulong() >= 1024 && puertoDestino.to_ulong() <= 49151){//
        cout << " -> Puertos registrados" << endl;
    }
    else{
        cout << " -> Puertos dinámicos o privados" << endl;
    }

    bitset<TAMANIO_BYTE> primerl(bytes[38]);
    bitset<TAMANIO_BYTE> segundol(bytes[39]);

    bitset<16> longitudTotal;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        longitudTotal[contBit] = segundol[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        longitudTotal[contBit] = primerl[q];
    }
    cout << "Longitud total : " << hex << longitudTotal.to_ulong() << endl;

    bitset<TAMANIO_BYTE> primerCheck(bytes[40]);
    bitset<TAMANIO_BYTE> segundoCheck(bytes[41]);

    bitset<16> checkSum;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        checkSum[contBit] = segundoCheck[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        checkSum[contBit] = primerCheck[q];
    }
    cout << "Suma de verificacion: " << hex << checkSum.to_ulong() << endl;

    if(puertoDestino.to_ulong() == 53 || puertoOrigen.to_ulong() == 53){
        encabezadoDNS(42);
    }
    else{
        cout << endl <<"\tDATA" << endl;
        for(int i=42;i<tamanio;i++){
           cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i] << "|";
        }
    }
    cout << endl;

}

void encabezadoDNS(int n){
    int p,q,contBit;
    bitset<TAMANIO_BYTE> primer(bytes[n++]);
    bitset<TAMANIO_BYTE> segundo(bytes[n++]);

    bitset<16> id;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        id[contBit] = segundo[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        id[contBit] = primer[q];
    }
    cout << endl << "\t\t DNS" << endl;
    cout << "ID: " << hex << id.to_ulong() << endl;

    bitset<TAMANIO_BYTE> primerasFlags(bytes[n++]);

    cout << "   Banderas: " << endl;
    cout << "QR: " << primerasFlags[7];
    primerasFlags[7] == 0 ? cout << " Consulta. " << endl : cout << " Respuesta " << endl;

    cout << "Op Code: ";
    bitset<4> opCode;
    for(p =3 , q = 6, contBit = 3; q >= p; q--, contBit--){
        opCode[contBit] = primerasFlags[q];
    }
    cout << opCode.to_ulong();
    switch(opCode.to_ulong()){
        case 0:
            cout << " - Consulta estándar (QUERY)" << endl;
            break;
        case 1:
            cout << " - Consulta Inversa (IQUERY)" << endl;
            break;
        case 2:
            cout << " - Solicitud del estado del servidor (STATUS)" << endl;
            break;
        default:
            cout << " - Reservados para su uso futuro : "  << endl;
            break;
    }
    cout << "AA: " << primerasFlags[2];
    primerasFlags[2] == 0 ? cout << " No tiene respuesta. " << endl : cout << " Respuesta " << endl;
    int aa = primerasFlags[2];
    cout << "TC: " << primerasFlags[1];
    primerasFlags[1] == 0 ? cout << " Completo. " << endl : cout << " Truncado " << endl;

    cout << "RD: " << primerasFlags[0];
    primerasFlags[0] == 0 ? cout << " No recursivo. " << endl : cout << " Recursivo " << endl;

    bitset<TAMANIO_BYTE> segundasFlags(bytes[n++]);
    cout << "RA: " << segundasFlags[7];
    segundasFlags[7] == 0 ? cout << " No soporta resolución recursiva. " << endl
                            : cout << " Soporta resolución recursiva " << endl;

    bitset<3> reservado;
    for(p =4 , q = 6, contBit = 3; q >= p; q--, contBit--){
        reservado[contBit] = segundasFlags[q];
    }
    cout << "Z: " << dec << reservado << " Reservados para uso futuro" << endl;

    cout << "RCode: ";
    bitset<4> rCode;
    for(p =0 , q = 3, contBit = 3; q >= p; q--, contBit--){
        rCode[contBit] = segundasFlags[q];
    }
    cout << rCode.to_ulong();
    switch(rCode.to_ulong()){
        case 0:
            cout << " - Ningún error" << endl;
            break;
        case 1:
            cout << " - Error de formato. " << endl;
            break;
        case 2:
            cout << " - Fallo en el servidor. " << endl;
            break;
        case 3:
            cout << " - Error en nombre. " << endl;
            break;
        case 4:
            cout << " - No implementado. " << endl;
            break;
        case 5:
            cout << " - Rechazado. " << endl;
            break;
        default:
            cout << " - Reservados para su uso futuro : "  << endl;
            break;
    }
    cout << "   Contadores " << endl;
    bitset<TAMANIO_BYTE> primerQD(bytes[n++]);
    bitset<TAMANIO_BYTE> segundoQD(bytes[n++]);
    bitset<16> qdCount;

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        qdCount[contBit] = segundoQD[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        qdCount[contBit] = primerQD[q];
    }

    cout << "QDCount: " << qdCount.to_ulong() << endl;

    bitset<TAMANIO_BYTE> primerAN(bytes[n++]);
    bitset<TAMANIO_BYTE> segundoAN(bytes[n++]);
    bitset<16> anCount;

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        anCount[contBit] = segundoAN[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        anCount[contBit] = primerAN[q];
    }

    cout << "ANCount: " << anCount.to_ulong() << endl;

    bitset<TAMANIO_BYTE> primerNS(bytes[n++]);
    bitset<TAMANIO_BYTE> segundoNS(bytes[n++]);
    bitset<16> nsCount;

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        nsCount[contBit] = segundoNS[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        nsCount[contBit] = primerNS[q];
    }

    cout << "NSCount: " << nsCount.to_ulong() << endl;

    bitset<TAMANIO_BYTE> primerAR(bytes[n++]);
    bitset<TAMANIO_BYTE> segundoAR(bytes[n++]);
    bitset<16> arCount;

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        arCount[contBit] = segundoAR[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        arCount[contBit] = primerAR[q];
    }

    cout << "ARCount: " << arCount.to_ulong() << endl;
    cout << "   Pregunta " << endl;
    cout << "DNS: ";
    int k(0);
    string dns;
    do{
        k = (int)bytes[n];

        for(int cont=0 ; cont <= k; cont++){
            n++;
            if(k == cont){
                break;
            }
            dns += bytes[n];
            cout << bytes[n];
        }
        if(bytes[n] != ((char)0)){
            dns += ".";
            cout << ".";
        }

    }while(bytes[n] != ((char)0));
    n++;
    cout << endl;

    bitset<TAMANIO_BYTE> typePrimer(bytes[n++]);
    bitset<TAMANIO_BYTE> typeSegundo(bytes[n++]);
    bitset<16> type;

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        type[contBit] = typeSegundo[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        type[contBit] = typePrimer[q];
    }

    cout << "Type: " << type.to_ulong();
    switch(type.to_ulong()){
        case 1:
            cout << " -> A" << endl;
            break;
        case 5:
            cout << " -> CNAME" << endl;
            break;
        case 13:
            cout << " -> HINFO" << endl;
            break;
        case 15:
            cout << " -> MX" << endl;
            break;
        case 22 : case 23:
            cout << " -> NS" << endl;
            break;
        default:
            cout << " -> Desconocido" << endl;
    }

    bitset<TAMANIO_BYTE> clasePrimer(bytes[n++]);
    bitset<TAMANIO_BYTE> claseSegundo(bytes[n++]);
    bitset<16> clase;

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        clase[contBit] = claseSegundo[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        clase[contBit] = clasePrimer[q];
    }

    cout << "Clase: " << clase.to_ulong();
    switch(clase.to_ulong()){
        case 1:
            cout << " -> IN" << endl;
            break;
        case 3:
            cout << " -> CH" << endl;
            break;
        default:
            cout << " -> Desconocido" << endl;
    }

    cout << "   Respuesta " << endl;

    bitset<TAMANIO_BYTE> ptrPrimer(bytes[n++]);
    bitset<TAMANIO_BYTE> ptrSegundo(bytes[n++]);
    bitset<16> ptr;

    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        ptr[contBit] = ptrSegundo[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        ptr[contBit] = ptrPrimer[q];
    }
    if(aa == 1){
        cout << "DNS (puntero): " << hex << ptr.to_ulong() << endl;
        cout << "DNS: " <<  dns << endl;

        bitset<TAMANIO_BYTE> typeRPrimer(bytes[n++]);
        bitset<TAMANIO_BYTE> typeRSegundo(bytes[n++]);
        bitset<16> typeR;

        for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
            typeR[contBit] = typeRSegundo[q];
        }
        for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
            typeR[contBit] = typeRPrimer[q];
        }

        cout << "Type: " << typeR.to_ulong();
        switch(typeR.to_ulong()){
            case 1:
                cout << " -> A" << endl;
                break;
            case 5:
                cout << " -> CNAME" << endl;
                break;
            case 13:
                cout << " -> HINFO" << endl;
                break;
            case 15:
                cout << " -> MX" << endl;
                break;
            case 22 : case 23:
                cout << " -> NS" << endl;
                break;
            default:
                cout << " -> Desconocido" << endl;
        }

        bitset<TAMANIO_BYTE> claseRPrimer(bytes[n++]);
        bitset<TAMANIO_BYTE> claseRSegundo(bytes[n++]);
        bitset<16> claseR;

        for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
            claseR[contBit] = claseRSegundo[q];
        }
        for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
            claseR[contBit] = claseRPrimer[q];
        }

        cout << "Clase: " << claseR.to_ulong();
        switch(claseR.to_ulong()){
            case 1:
                cout << " -> IN" << endl;
                break;
            case 3:
                cout << " -> CH" << endl;
                break;
            default:
                cout << " -> Desconocido" << endl;
        }

        bitset<32> ttl;
        bitset<16> parte1A,parte2A;
        bitset<TAMANIO_BYTE> sub1A= bytes[n++];
        bitset<TAMANIO_BYTE> sub2A= bytes[n++];
        bitset<TAMANIO_BYTE> sub3A= bytes[n++];
        bitset<TAMANIO_BYTE> sub4A= bytes[n++];

        for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
            parte1A[contBit] = sub2A[q];
        }
        for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
            parte1A[contBit] = sub1A[q];
        }

        for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
            parte2A[contBit] = sub4A[q];
        }
        for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
            parte2A[contBit] = sub3A[q];
        }

        for(p =0 , q = 15, contBit = 15; q >= p; q--, contBit--){
            ttl[contBit] = parte2A[q];
        }
        for(p = 0 , q = 15, contBit = 31; q >= p; q--, contBit--){
            ttl[contBit] = parte1A[q];
        }

        cout << "TTL: " << dec << ttl.to_ulong() << endl;


        bitset<TAMANIO_BYTE> longitudPrimer(bytes[n++]);
        bitset<TAMANIO_BYTE> longitudSegundo(bytes[n++]);
        bitset<16> longitud;

        for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
            longitud[contBit] = longitudSegundo[q];
        }
        for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
            longitud[contBit] = longitudPrimer[q];
        }

        cout << "Longitud: " << longitud.to_ulong();

        cout << endl <<"\tDATA" << endl;
        for(int i=n;i<TAMANIO;i++){
           cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i] << "|";
        }
    }
    else{
        cout << "DNS: no" << endl;
        cout << endl <<"\tDATA" << endl;

        for(int i=n-2;i<tamanio;i++){
           cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i] << "|";
        }
        cout << endl;
    }

}

void encabezadoUDPv6(){
    int p,q,contBit;
    bitset<TAMANIO_BYTE> primer(bytes[54]);
    bitset<TAMANIO_BYTE> segundo(bytes[55]);

    bitset<16> puertoOrigen;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        puertoOrigen[contBit] = segundo[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        puertoOrigen[contBit] = primer[q];
    }
    cout << endl << "\t\t UDP" << endl;
    cout << "Puerto origen: " << dec << puertoOrigen.to_ulong();
    if(puertoOrigen.to_ulong() >= 0 && puertoOrigen.to_ulong() <= 1023){ // Bien conocidos
        cout << " -> Puertos bien conocidos " << endl;
        switch(puertoOrigen.to_ulong()){
            case 20: case 21: cout << "Servicio: FTP \t Protocolo: TCP" << endl;    break;
            case 22: cout << "Servicio: SSH \t Protocolo: TCP" << endl;             break;
            case 23: cout << "Servicio: TELNET \t Protocolo: TCP" << endl;          break;
            case 25: cout << "Servicio: SMTP \t Protocolo: TCP" << endl;            break;
            case 53: cout << "Servicio: DNS \t Protocolo: TCP/UDP" << endl;         break;
            case 67: case 68: cout << "Servicio: DHCP \t Protocolo: UDP" << endl;   break;
            case 69: cout << "Servicio: TFTP \t Protocolo: UDP" << endl;            break;
            case 80: cout << "Servicio: HTTP \t Protocolo: TCP" << endl;            break;
            case 110: cout << "Servicio: POP3 \t Protocolo: TCP" << endl;           break;
            case 143: cout << "Servicio: IMAP \t Protocolo: TCP" << endl;           break;
            case 443: cout << "Servicio: HTTPS \t Protocolo: TCP" << endl;          break;
            case 993: cout << "Servicio: IMAP SSL \t Protocolo: TCP" << endl;       break;
            case 995: cout << "Servicio: POP SSL \t Protocolo: TCP" << endl;        break;
            default: cout << "Protocolo desconocido " << endl;
        }
    }
    else if(puertoOrigen.to_ulong() >= 1024 && puertoOrigen.to_ulong() <= 49151){//
        cout << " -> Puertos registrados" << endl;
    }
    else{
        cout << " -> Puertos dinámicos o privados" << endl;
    }


    bitset<TAMANIO_BYTE> primerD(bytes[56]);
    bitset<TAMANIO_BYTE> segundoD(bytes[57]);
    bitset<16> puertoDestino;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){
        puertoDestino[contBit] = segundoD[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){
        puertoDestino[contBit] = primerD[q];
    }

    cout << "Puerto destino: " << dec << puertoDestino.to_ulong();

    if(puertoDestino.to_ulong() >= 0 && puertoDestino.to_ulong() <= 1023){ // Bien conocidos
        cout << " -> Puertos bien conocidos " << endl;
        switch(puertoDestino.to_ulong()){
            case 20: case 21: cout << "Servicio: FTP \t Protocolo: TCP" << endl;    break;
            case 22: cout << "Servicio: SSH \t Protocolo: TCP" << endl;             break;
            case 23: cout << "Servicio: TELNET \t Protocolo: TCP" << endl;          break;
            case 25: cout << "Servicio: SMTP \t Protocolo: TCP" << endl;            break;
            case 53: cout << "Servicio: DNS \t Protocolo: TCP/UDP" << endl;         break;
            case 67: case 68: cout << "Servicio: DHCP \t Protocolo: UDP" << endl;   break;
            case 69: cout << "Servicio: TFTP \t Protocolo: UDP" << endl;            break;
            case 80: cout << "Servicio: HTTP \t Protocolo: TCP" << endl;            break;
            case 110: cout << "Servicio: POP3 \t Protocolo: TCP" << endl;           break;
            case 143: cout << "Servicio: IMAP \t Protocolo: TCP" << endl;           break;
            case 443: cout << "Servicio: HTTPS \t Protocolo: TCP" << endl;          break;
            case 993: cout << "Servicio: IMAP SSL \t Protocolo: TCP" << endl;       break;
            case 995: cout << "Servicio: POP SSL \t Protocolo: TCP" << endl;        break;
            default: cout << "Protocolo desconocido " << endl;
        }
    }
    else if(puertoDestino.to_ulong() >= 1024 && puertoDestino.to_ulong() <= 49151){//
        cout << " -> Puertos registrados" << endl;
    }
    else{
        cout << " -> Puertos dinámicos o privados" << endl;
    }

    bitset<TAMANIO_BYTE> primerl(bytes[58]);
    bitset<TAMANIO_BYTE> segundol(bytes[59]);

    bitset<16> longitudTotal;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        longitudTotal[contBit] = segundol[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        longitudTotal[contBit] = primerl[q];
    }
    cout << "Longitud total : " << hex << longitudTotal.to_ulong() << endl;

    bitset<TAMANIO_BYTE> primerCheck(bytes[60]);
    bitset<TAMANIO_BYTE> segundoCheck(bytes[61]);

    bitset<16> checkSum;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte  35 al final
        checkSum[contBit] = segundoCheck[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 34 al principio
        checkSum[contBit] = primerCheck[q];
    }
    cout << "Suma de verificacion: " << hex << checkSum.to_ulong() << endl;

    if(puertoDestino.to_ulong() == 53 || puertoOrigen.to_ulong() == 53){
        encabezadoDNS(62);
    }
    else{
        cout << endl <<"\tDATA" << endl;
        for(int i=62;i<tamanio;i++){
           cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i] << "|";
        }
        cout << endl;
    }

}

void encabezadoIPv6(){//a partir del byte 14 +40 bytes = 54 bytes leídos
    int p, q, contBit;
    bitset<TAMANIO_BYTE> versionCabecera(bytes[14]);
    cout << "Version: ";
    bitset<4> version;

    for(p =4 , q = 7, contBit = 0; q >= p; q--, contBit++){
        version[contBit] = versionCabecera[q];
    }
    cout << version.to_ulong() << endl;

    bitset<TAMANIO_BYTE> clase;
    for(p =0 , q = 3, contBit=3; q >= p; q--, contBit--){ // tomamos los 4 bits restantes
        clase[contBit] = versionCabecera[q];
    }
    ///cout << setw(2) << dec << cabecera.to_ulong() << endl;

    bitset<TAMANIO_BYTE> claseTipoFlujo(bytes[15]);

    for(p =5 , q = 8, contBit = 1; q >= p; q--, contBit++){//tomamos 4 bits ultimos (primeros en realidad)
        clase[contBit] = claseTipoFlujo[q];
    }

    bitset<3> prioridad;
    bitset<5> desglose;
    cout << "***Clase de tráfico***" << endl;
    cout << "Prioridad: ";
    for(p =5 , q = 7, contBit = 1; q >= p; q--, contBit++){
        prioridad[contBit] = clase[q];
    }
    switch(prioridad.to_ulong()){
        case 000:
            cout << "De rutina" << endl;
            break;
        case 1:
            cout << "Prioritario" << endl;
            break;
        case 2:
            cout << "Inmediato" << endl;
            break;
        case 3:
            cout << "Relámpago" << endl;
            break;
        case 4:
            cout << "Invalidación Relámpago" << endl;
            break;
        case 5:
            cout << "Procesando llamada crítica y de emergencia" << endl;
            break;
        case 6:
            cout << "Control de trabajo de Internet" << endl;
            break;
        case 7:
            cout << "Control de red" << endl;
            break;
        default:
            cout << "Error inesperado L:v" << endl;
    }

    cout << "====Desglose====" << endl;
    for(p =0 , q = 4, contBit=3; q >= p; q--, contBit--){
        desglose[contBit] = clase[q];
    }
    switch(desglose.to_ulong()){
        case 0:
            cout << "Retardo: normal" << endl; //0
            cout << "Rendimiento: normal" << endl; //0
            cout << "Fiabilidad: normal" << endl; //0
            break;
        case 1:
            cout << "Retardo: bajo" << endl; //1
            cout << "Rendimiento: normal" << endl; //0
            cout << "Fiabilidad: normal" << endl; //0
            break;
        case 2:
            cout << "Retardo: normal" << endl; //0
            cout << "Rendimiento: alto" << endl; //1
            cout << "Fiabilidad: normal" << endl; //0
            break;
        case 3:
            cout << "Retardo: bajo" << endl; //1
            cout << "Rendimiento: alto" << endl; //1
            cout << "Fiabilidad: normal" << endl; //0
            break;
        case 4:
            cout << "Retardo: normal" << endl; //0
            cout << "Rendimiento: normal" << endl; //0
            cout << "Fiabilidad: alta" << endl; //1
            break;
        case 5:
            cout << "Retardo: bajo" << endl; //1
            cout << "Rendimiento: normal" << endl; //0
            cout << "Fiabilidad: alto" << endl; //1
            break;
        case 6:
            cout << "Retardo: normal" << endl; //0
            cout << "Rendimiento: alto" << endl; //1
            cout << "Fiabilidad: alta" << endl; //1
            break;
        case 7:
            cout << "Retardo: bajo" << endl; //1
            cout << "Rendimiento: alto" << endl; //1
            cout << "Fiabilidad: alto" << endl; //1
            break;
        default:
            cout << "Error" << endl;
    }

    /// Etiqueta de flujo decimal
    bitset<TAMANIO_BYTE> aux1(bytes[16]);
    bitset<TAMANIO_BYTE> aux2(bytes[17]);

    bitset<16> completa;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte 17 al final
        completa[contBit] = aux2[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 16 al principio
        completa[contBit] = aux1[q];
    }
    bitset<20> etiquetaFlujo;
    for(p =0 , q = 15, contBit = 20; q >= p; q--, contBit--){ // agregamos 2 bytes al final
        etiquetaFlujo[contBit] = completa[q];
    }

    for(p =0 , q = 3, contBit = 4; q >= p; q--, contBit++){//agregamos 4 bits al principio
        etiquetaFlujo[contBit] = claseTipoFlujo[q];
    }
    cout << "Etiqueta de flujo decimal: ";
    cout << etiquetaFlujo.to_ulong() << endl;

    cout << "Tamaño de datos: ";
    bitset<TAMANIO_BYTE> primer(bytes[18]);
    bitset<TAMANIO_BYTE> segundo(bytes[19]);

    bitset<16> tamDatos;
    for(p =0 , q = 7, contBit = 7; q >= p; q--, contBit--){ //byte 13 al final
        tamDatos[contBit] = segundo[q];
    }
    for(p = 0 , q = 7, contBit = 15; q >= p; q--, contBit--){ //byte 12 al principio
        tamDatos[contBit] = primer[q];
    }
    cout << dec << tamDatos.to_ulong() << endl;

    bitset<TAMANIO_BYTE> protocoloAux(bytes[20]);
    cout << "Encabezado siguiente (Protocolo): ";
    switch(protocoloAux.to_ulong()){
        case ICMPV4:
            cout << "(1) ICMP v4 " << endl;
            break;
        case TCP:
            cout << "(6) TCP " << endl;
            break;
        case UDP:
            cout << "(17) UDP " << endl;
            break;
        case ICMPV6:
            cout << "(58) ICMP v6 " << endl;
            break;
        case STP:
            cout << "(118) STP " << endl;
        case SMP:
            cout << "(121) SMP " << endl;
        default:
            cout << "El protocolo leído no esta en la lista, revise documentación" << endl;
    }
    bitset<TAMANIO_BYTE> ttl(bytes[21]);
    cout << "Limite de salto: " << dec << ttl.to_ulong() << endl;

    cout << "Dirección IP origen:  ";
    for(int incr = 22; incr < 38; incr++){
        cout << hex << (int)bytes[incr];
        if(incr %2 != 0 && incr != 37){
            cout << ":";
        }
    }
    cout << endl;

    cout << "Dirección IP destino:  ";
    for(int incr = 38; incr < 54; incr++){
        cout << hex << (int)bytes[incr];
        if(incr %2 != 0 && incr != 53){
            cout << ":";
        }
    }
    cout << endl;
    bitset<TAMANIO_BYTE> protocolo(bytes[20]);
    switch(protocolo.to_ulong()){
        case ICMPV4:
            break;
        case TCP:
            encabezadoTCPv6();
            break;
        case UDP:
            encabezadoUDPv6();
            break;
        case ICMPV6:
            encabezadoICMPv6();
            break;
        case STP:
            break;
        case SMP:
            break;
        default:
            cout << "El protocolo leído no esta en la lista, revise documentación" << endl;
            break;

    }
}

void encabezadoICMPv6(){
    cout << endl << "\t\tEncabezado ICMPv6" << endl;
    cout << "Tipo: " << (int)bytes[54] << ". "; //54
    switch((int)bytes[54]){
        case 1:
            cout << "Mensaje de destino inalcanzable" << endl;
            cout << "Código de error: " << (int)bytes[55] << ". "; //55
            switch((int)bytes[55]){
                case 0:
                    cout << "No existe ruta de destino" << endl;
                    break;
                case 1:
                    cout << "Comunicación con el destino administrativamente prohibida" << endl;
                    break;
                case 2:
                    cout << "No asignado" << endl;
                    break;
                case 3:
                    cout << "Dirección inalcanzable" << endl;
                    break;
                default:
                    cout << "Raro" << endl;
            }
            break;
        case 2:
            cout << "Mensaje de paquete demasiado grande" << endl;
            cout << "Código de error: " << (int)bytes[55] << ". "  << " 0 ";
            break;
        case 3:
            cout << "Time exceeded Message" << endl;
            cout << "Código de error: " << (int)bytes[55] << ". ";
            switch((int)bytes[55]){
                case 0:
                    cout << "El límite del salto excedido" << endl;
                    break;
                case 1:
                    cout << "Tiempo de reensamble de fragmento excedido" << endl;
                    break;
                default:
                    cout << "Raro" << endl;
            }
            break;
        case 4:
            cout << "Mensaje de problema de parámetro" << endl;
            cout << "Código de error: " << (int)bytes[55] << ". ";
            switch((int)bytes[55]){
                case 0:
                    cout << "El campo del encabezado erróneo encontró" << endl;
                    break;
                case 1:
                    cout << "El tipo siguiente desconocido del encabezado encontró" << endl;
                    break;
                case 2:
                    cout << "Opción desconocida del IPv6 encontrada" << endl;
                    break;
                default:
                    cout << "Raro" << endl;
            }
            break;
        case 128:
            cout << "Mensaje del pedido de eco" << endl;
            cout << "Código de error: " << (int)bytes[55] << ". "  << " 0 ";
            break;
        case 129:
            cout << "Mensaje de respuesta de eco" << endl;
            cout << "Código de error: " << (int)bytes[55] << ". "  << " 0 ";
            break;
        case 133:
            cout << "Mensaje de solicitud del router" << endl;
            cout << "Código de error: " << (int)bytes[55] << ". "  << " 0 ";
            break;
        case 134:
            cout << "Mensaje de anuncio del router" << endl;
            cout << "Código de error: " << (int)bytes[55] << ". "  << " 0 ";
            break;
        case 135:
            cout << "Mensaje de solicitud vecino" << endl;
            cout << "Código de error: " << (int)bytes[55] << ". "  << " 0 ";
            break;
        case 136:
            cout << "Mensaje de aununcio de vecino" << endl;
            cout << "Código de error: " << (int)bytes[55] << ". "  << " 0 ";
            break;
        case 137:
            cout << "Reoriente el mensaje" << endl;
            cout << "Código de error: " << (int)bytes[55] << ". "  << " 0 ";
            break;
        default:
            cout << "Tipo no listado " << endl;
            cout << "Código de error: " << (int)bytes[55] << ". "  << " 0 ";

    }
    cout << "CheckSum ICMPv6: " << setw(2) << hex << uppercase << (int)bytes[56]// 56 y 57
            << (int)bytes[57] << endl;

    cout << endl <<"\tDATA" << endl;
    for(int i=58;i<tamanio;i++){
       cout << setfill('0')<< setw(2) << hex << uppercase<< (int)bytes[i] << "|";
    }
    cout << endl;

}

void versionCabecera(){
    int p, q, contBit;
    bitset<TAMANIO_BYTE> versionCabecera(bytes[14]);
    cout << "Version: ";
    bitset<4> version;
    bitset<4> cabecera;
    for(p =4 , q = 7, contBit = 1; q >= p; q--, contBit++){
        version[contBit] = versionCabecera[q];
    }
    cout << version.to_ulong() << endl;
    cout << "Tamaño cabecera: ";
    for(p =0 , q = 3, contBit=3; q >= p; q--, contBit--){
        cabecera[contBit] = versionCabecera[q];
    }
    cout << setw(2) << dec << cabecera.to_ulong() << endl;
}

void tipoServicio(){
    int p, q, contBit;
    bitset<TAMANIO_BYTE> tipoServicio(bytes[15]);
    bitset<3> prioridad;
    bitset<5> desglose;
    cout << "***Tipo de servicio***" << endl;
    cout << "Prioridad: ";
    for(p =5 , q = 7, contBit = 1; q >= p; q--, contBit++){
        prioridad[contBit] = tipoServicio[q];
    }
    switch(prioridad.to_ulong()){
        case 000:
            cout << "De rutina" << endl;
            break;
        case 1:
            cout << "Prioritario" << endl;
            break;
        case 2:
            cout << "Inmediato" << endl;
            break;
        case 3:
            cout << "Relámpago" << endl;
            break;
        case 4:
            cout << "Invalidación Relámpago" << endl;
            break;
        case 5:
            cout << "Procesando llamada crítica y de emergencia" << endl;
            break;
        case 6:
            cout << "Control de trabajo de Internet" << endl;
            break;
        case 7:
            cout << "Control de red" << endl;
            break;
        default:
            cout << "Desconocida" << endl;
    }

    cout << "====Desglose====" << endl;
    for(p =0 , q = 4, contBit=3; q >= p; q--, contBit--){
        desglose[contBit] = tipoServicio[q];
    }
    switch(desglose.to_ulong()){
        case 0:
            cout << "Retardo: normal" << endl; //0
            cout << "Rendimiento: normal" << endl; //0
            cout << "Fiabilidad: normal" << endl; //0
            break;
        case 1:
            cout << "Retardo: bajo" << endl; //1
            cout << "Rendimiento: normal" << endl; //0
            cout << "Fiabilidad: normal" << endl; //0
            break;
        case 2:
            cout << "Retardo: normal" << endl; //0
            cout << "Rendimiento: alto" << endl; //1
            cout << "Fiabilidad: normal" << endl; //0
            break;
        case 3:
            cout << "Retardo: bajo" << endl; //1
            cout << "Rendimiento: alto" << endl; //1
            cout << "Fiabilidad: normal" << endl; //0
            break;
        case 4:
            cout << "Retardo: normal" << endl; //0
            cout << "Rendimiento: normal" << endl; //0
            cout << "Fiabilidad: alta" << endl; //1
            break;
        case 5:
            cout << "Retardo: bajo" << endl; //1
            cout << "Rendimiento: normal" << endl; //0
            cout << "Fiabilidad: alto" << endl; //1
            break;
        case 6:
            cout << "Retardo: normal" << endl; //0
            cout << "Rendimiento: alto" << endl; //1
            cout << "Fiabilidad: alta" << endl; //1
            break;
        case 7:
            cout << "Retardo: bajo" << endl; //1
            cout << "Rendimiento: alto" << endl; //1
            cout << "Fiabilidad: alto" << endl; //1
            break;
        default:
            cout << "Error" << endl;
    }
}

void flagsPosicionFragmento(){
    int p, q, contBit;
    long banderasPosicionFragmento =0;
    banderasPosicionFragmento = (int)bytes[20] + (int)bytes[21];
    bitset<16> banderasFragmento = banderasPosicionFragmento;
    bitset<3> banderas;
    cout << "Flags: " ;
    for(p =5, q = 7, contBit = 0; q >= p; q--, contBit++){
        banderas[contBit] = banderasFragmento[q];
    }
    cout << banderas << ": " << endl;
    switch(banderas.to_ulong()){
        case 0:
            cout << "\t"<< banderas[0] << ": Reservado" << endl ;//000
            cout << "\t"<< banderas[1] << ": Divisible" << endl;
            cout << "\t"<< banderas[2] << ": Último fragmento" << endl;
            break;
        case 1:
            cout << "\t"<< banderas[0] << ": Reservado" << endl ;//001
            cout << "\t"<< banderas[2] << ": Divisible" << endl;
            cout << "\t"<< banderas[3] << ": Fragmento Intermedio" << endl;
            break;
        case 2:
            cout << "\t"<< banderas[0] << ": Reservado" << endl ; //010
            cout << "\t"<< banderas[1] << ": No Divisible" << endl;
            cout << "\t"<< banderas[2] << ": Último fragmento" << endl;
            break;
        case 3:
            cout << "\t"<< banderas[0] << ": Reservado" << endl ; //011
            cout << "\t"<< banderas[1] << ": No Divisible" << endl;
            cout << "\t"<< banderas[2] << ": Fragmento Intermedio" << endl;
            break;
        default:
            cout << "Error desconocido" << endl;
    }
    bitset<13> posicionFragmento;
    cout << "Posición de Fragmento: "; /// Se llena con el primer byte
    for(p =8, q = 15, contBit = 0; q >= p; q--, contBit++){
       posicionFragmento[contBit] = banderasFragmento[q];
    }
    ///Se termina de llenar con los 5 bits que quedaron
    for(p =11, q = 15, contBit = 8; q >= p; q--, contBit++){
       posicionFragmento[contBit] = banderasFragmento[q];
    }
    cout << dec << posicionFragmento.to_ulong() << endl;
}

void protocolo(){
    bitset<TAMANIO_BYTE> protocolo(bytes[23]);
    cout << "Protocolo: ";
    switch(protocolo.to_ulong()){
        case ICMPV4:
            cout << "(1) ICMP v4 " << endl;
            break;
        case TCP:
            cout << "(6) TCP " << endl;
            break;
        case UDP:
            cout << "(17) UDP " << endl;
            break;
        case ICMPV6:
            cout << "(58) ICMP v6 " << endl;
            break;
        case STP:
            cout << "(118) STP " << endl;
            break;
        case SMP:
            cout << "(121) SMP " << endl;
            break;
        default:
            cout << "El protocolo leído no esta en la lista, revise documentación" << endl;
    }
}
