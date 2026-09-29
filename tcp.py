import asyncio
from tcputils import *
import random

TIMEOUT = 1

class TcpPacket:
    def __init__(self, src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr,
                 payload):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seqn = seq_no
        self.ackn = ack_no
        self.flags = flags
        self.win_size = window_size
        self.checksum = checksum
        self.urg_ptr = urg_ptr
        self.payload = payload

    def __str__(self):
        return f"[[ src_port={self.src_port}, dst_port={self.dst_port} seqn={self.seqn} ackn={self.ackn} flags={self.flags} ]]"
    

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.established_connections = {}
        self.pending_connections = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    # Armazenar conexão só após o ACK final

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        packet = TcpPacket(src_port, dst_port, seq_no, ack_no, flags,
                           window_size, checksum, urg_ptr, payload)

        if (packet.flags & FLAGS_SYN) == FLAGS_SYN:
            # Inicia o handshake
            conexao = self.pending_connections[id_conexao] = Conexao(self, id_conexao, packet.seqn)
            syn_ack_header = make_header(packet.dst_port, packet.src_port, conexao.seq, conexao.ack, (FLAGS_SYN | FLAGS_ACK))

            print(f"Pacote SYN recebido: {packet}")

            complete_header = fix_checksum(syn_ack_header, dst_addr, src_addr)

            self.rede.enviar(complete_header, src_addr)
            conexao.seq += 1
            print(f"Pacote SYN+ACK enviado: {syn_ack_header} -> {src_addr}")
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.pending_connections and (packet.flags & FLAGS_ACK) == FLAGS_ACK:
            # Estabalecer conexão
            print(f"Estabelecendo conexão: {id_conexao}")
            conexao = self.pending_connections.pop(id_conexao)
            self.established_connections[id_conexao] = conexao
            conexao._rdt_rcv(packet)
        elif id_conexao in self.established_connections:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.established_connections[id_conexao]._rdt_rcv(packet)
        else:
            print(f"Pacote associado a uma conexão desconhecida: {str(packet)}")
            print(f"Conexões pendentes: {self.pending_connections}")
            print(f"Conexões estabelecidas: {self.established_connections}")


class Conexao:
    def __init__(self, servidor, id_conexao, src_seq):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        # self.timer = asyncio.get_event_loop().call_later(10, self._exemplo_timer)
        # self.timeout_timer = asyncio.get_event_loop().call_later(5, self._connection_timeout)
        self.ack = src_seq + 1
        self.seq = random.randint(1000000, 9999999)
        self.fin_wait = False
        self.unacked = []
        self.pending = []
        self.timer = None

    def _cancel_timer(self):
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

    def _timeout(self):
        self.timer = None
        if self.unacked:
            seq, dados = self.unacked[0]
            header = make_header(self.servidor.porta, self.id_conexao[1], seq, self.ack, FLAGS_ACK)
            self.servidor.rede.enviar(fix_checksum(header + dados, self.id_conexao[2], self.id_conexao[0]), self.id_conexao[0])
        self._reset_timer()

    def _reset_timer(self):
        self._cancel_timer()
        if not self.unacked:
            return
        
        self.timer = asyncio.get_event_loop().call_later(TIMEOUT, self._timeout)

    def _rdt_rcv(self, packet: TcpPacket):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.

        if (packet.flags & FLAGS_ACK) == FLAGS_ACK:
            tmp = []
            for s in self.unacked:
                if s[0] + len(s[1]) > packet.ackn:
                    tmp.append(s)

            self.unacked = tmp
            while self.pending and len(self.unacked) < 1:
                seq, dados = self.pending.pop(0)
                header = make_header(self.servidor.porta, self.id_conexao[1], seq, self.ack, FLAGS_ACK)
                self.servidor.rede.enviar(fix_checksum(header + dados, self.id_conexao[2], self.id_conexao[0]), self.id_conexao[0])
                self.unacked.append([seq, dados])


        if (packet.seqn == self.ack):

            if packet.payload:
                self.ack += len(packet.payload)
                ack_header = make_header(self.servidor.porta, self.id_conexao[1], self.seq, self.ack, FLAGS_ACK)
                complete_header = fix_checksum(ack_header, self.id_conexao[2], self.id_conexao[0])
                self.servidor.rede.enviar(complete_header, self.id_conexao[0])


            if (packet.flags & FLAGS_FIN) != FLAGS_FIN and not packet.payload:
                return

            if (packet.flags & FLAGS_FIN) == FLAGS_FIN:
                self.ack += 1
                ack_header = make_header(self.servidor.porta, self.id_conexao[1], self.seq, self.ack, FLAGS_ACK)
                complete_header = fix_checksum(ack_header, self.id_conexao[2], self.id_conexao[0])
                self.servidor.rede.enviar(complete_header, self.id_conexao[0])
                if self.callback:
                    self.callback(self, b'')
                return

            if (packet.flags & FLAGS_ACK) == FLAGS_ACK and self.fin_wait:
                print(f"Conexão[{self.id_conexao}] encerrada.")
                self.servidor.established_connections.pop(self.id_conexao)
                return

            
            
            if self.callback:
                self.callback(self, packet.payload)
        
        # SEQ atualiza sempre que responder
        # ACK atualiza sempre que receber

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        if not dados:
            return

        for i in range(0, len(dados), MSS):
            block = dados[i:i+MSS]
            self.pending.append([self.seq, block])
            self.seq += len(block)

        while self.pending and len(self.unacked) < 1:
            seq, dados = self.pending.pop(0)
            header = make_header(self.servidor.porta, self.id_conexao[1], seq, self.ack, FLAGS_ACK)
            self.servidor.rede.enviar(fix_checksum(header + dados, self.id_conexao[2], self.id_conexao[0]), self.id_conexao[0])
            self.unacked.append([seq, dados])
        

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        print(f"Encerrando Conexao[{self.id_conexao}]!")
        fin_ack_header = make_header(self.servidor.porta, self.id_conexao[1], self.seq, self.ack, FLAGS_ACK | FLAGS_FIN)
        complete_header = fix_checksum(fin_ack_header, self.id_conexao[2], self.id_conexao[0])
        self.servidor.rede.enviar(complete_header, self.id_conexao[0])
        self.servidor.established_connections.pop(self.id_conexao)
        return
