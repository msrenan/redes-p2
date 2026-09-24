import asyncio
from tcputils import *
import random
import time

INTERVALO = 1

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
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            conexao = self.pending_connections[id_conexao] = Conexao(self, id_conexao, False, packet.seqn)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.
            syn_ack_header = make_header(packet.dst_port, packet.src_port, conexao.seq, conexao.ack, (FLAGS_SYN | FLAGS_ACK))

            print(f"Pacote SYN recebido: {packet}")

            complete_header = fix_checksum(syn_ack_header, dst_addr, src_addr)

            self.rede.enviar(complete_header, src_addr)
            conexao.seq += 1
            conexao.send_base = conexao.seq

            print(f"Pacote ACK enviado: {syn_ack_header} -> {src_addr}")

        elif id_conexao in self.pending_connections and (packet.flags & FLAGS_ACK) == FLAGS_ACK:
            # Estabalecer conexão
            print(f"Estabelecendo conexão: {id_conexao}")
            conexao = self.pending_connections.pop(id_conexao)
            self.established_connections[id_conexao] = conexao
            conexao._rdt_rcv(packet)

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.established_connections:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.established_connections[id_conexao]._rdt_rcv(packet)
        else:
            print(f"Pacote associado a uma conexão desconhecida: {str(packet)}")
            print(f"Conexões pendentes: {self.pending_connections}")


class Conexao:
    def __init__(self, servidor, id_conexao, established, src_seq):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.established = established
        self.timer = None
        # self.timer = asyncio.get_event_loop().call_later(10, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        # self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida
        self.seq = random.randint(1000000, 9999999)
        self.ack = src_seq + 1
        self.nack_queue = {}
        self.send_base = 0

        print(f"    INIT: [SEQ={self.seq} & ACK={self.ack}]")

    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        print(f"Conexão[{self.id_conexao}]: ", end="")
        print('Este é um exemplo de como fazer um timer')

    def _rdt_rcv(self, packet: TcpPacket):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.

        if (packet.flags & FLAGS_ACK) and packet.ackn > self.send_base:
            self.send_base = packet.ackn
            for seq in list(self.nack_queue):
                if seq + self.nack_queue[seq]['len'] <= packet.ackn:
                    del self.nack_queue[seq]

            self.timer = None
            if self.nack_queue:                 # ainda falta confirmar, reinicia o timer
                self.timer = asyncio.get_event_loop().call_later(INTERVALO, self._timeout)

        if (packet.seqn == self.ack):
            self.ack += len(packet.payload)

            if (packet.flags & FLAGS_FIN) == FLAGS_FIN:
                self.ack += 1
                print(f"Encerrando Conexao[{self.id_conexao}]!")
                fin_ack_header = make_header(self.servidor.porta, self.id_conexao[1], self.seq, self.ack, FLAGS_ACK)
                complete_header = fix_checksum(fin_ack_header, self.id_conexao[0], self.id_conexao[2])
                self.servidor.rede.enviar(complete_header, self.id_conexao[0])
                self.callback(self, b'')
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

        ack_header = make_header(self.servidor.porta, self.id_conexao[1], self.seq, self.ack, FLAGS_ACK)

        complete_header = fix_checksum(ack_header+dados, self.id_conexao[2], self.id_conexao[0])

        print(f"Enviando dados: {dados}")

        self.nack_queue[self.seq] = {'segmento': complete_header, 'len': len(dados), 't_envio': time.time(),'retransmitido': False}

        self.servidor.rede.enviar(complete_header, self.id_conexao[0])

        self.seq += len(dados)

        if self.timer is None:   # o timer só roda enquanto houver algo não confirmado
                self.timer = asyncio.get_event_loop().call_later(INTERVALO, self._timeout)


    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        pass

    def reset_timer(self, delay):
        self.timer = asyncio.get_event_loop().call_later(delay, self._timeout)

    def _timeout(self):
        self.timer = None
        if not self.nack_queue:
            return
        seq = min(self.nack_queue)          # o mais antigo, deve ser igual ao send_base
        entrada = self.nack_queue[seq]
        entrada['retransmitido'] = True
        self.servidor.rede.enviar(entrada['segmento'], self.id_conexao[0])
        self.timer = asyncio.get_event_loop().call_later(INTERVALO, self._timeout)
