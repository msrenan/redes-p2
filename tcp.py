import asyncio
from tcputils import *
import random

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
            print(f"Pacote ACK enviado: {syn_ack_header} -> {src_addr}")
            conexao.reset_timer(20)
        elif id_conexao in self.pending_connections and (packet.flags & FLAGS_ACK) == FLAGS_ACK:
            # Estabalecer conexão
            print(f"Estabelecendo conexão: {id_conexao}")
            conexao = self.pending_connections.pop(id_conexao)
            self.established_connections[id_conexao] = conexao

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
        self.timer = asyncio.get_event_loop().call_later(10, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida
        self.seq = random.randint(1000000, 9999999)
        self.ack = src_seq + 1
        self.queue = {}

        print(f"    INIT: [SEQ={self.seq} & ACK={self.ack}]")

    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        print(f"Conexão[{self.id_conexao}]: ", end="")
        print('Este é um exemplo de como fazer um timer')

    def _rdt_rcv(self, packet: TcpPacket):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.

        if (packet.seqn == self.ack):
            self.ack += len(packet.payload)
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
        self.timer.cancel()
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        
        

        ack_header = make_header(self.servidor.porta, self.id_conexao[1], self.seq, self.ack, FLAGS_ACK)

        self.seq += len(dados)

        complete_header = fix_checksum(ack_header+dados, self.id_conexao[0], self.id_conexao[2])

        print(f"Enviando dados: {dados}")

        self.servidor.rede.enviar(complete_header, self.id_conexao[0])
        

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        pass

    def reset_timer(self, delay):
        self.timer.cancel()
        self.timer = asyncio.get_event_loop().call_later(delay, self._exemplo_timer)
