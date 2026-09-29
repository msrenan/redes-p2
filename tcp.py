import asyncio
from tcputils import *
import random

TIMEOUT_INTERVAL = 0.2  # segundos

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
            conexao = self.pending_connections[id_conexao] = Conexao(self, id_conexao, False, packet.seqn)
            syn_ack_header = make_header(packet.dst_port, packet.src_port, conexao.seq, conexao.ack, (FLAGS_SYN | FLAGS_ACK))

            print(f"Pacote SYN recebido: {packet}")

            complete_header = fix_checksum(syn_ack_header, dst_addr, src_addr)

            self.rede.enviar(complete_header, src_addr)
            conexao.seq += 1
            print(f"Pacote ACK enviado: {syn_ack_header} -> {src_addr}")
            conexao.reset_timer(20)
        elif id_conexao in self.pending_connections and (packet.flags & FLAGS_ACK) == FLAGS_ACK:
            # estabelecer conexão
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
        self.seq = random.randint(1000000, 9999999)
        self.ack = src_seq + 1
        self.queue = {}
        self.cwnd = MSS  # congestion window começa com 1 MSS
        self.acks_recebidos = 0  # quantos ACKs já recebemos na janela atual
        self.dados_pendentes = b''
        self.dados_enviados = {}
        self.base_seq = None
        self.timer = None

        print(f"    INIT: [SEQ={self.seq} & ACK={self.ack}]")

    def _timeout_handler(self):
        # quando der timeout, reduzimos a janela pela metade (Multiplicative Decrease)
        print(f"  [TIMEOUT] Deu timeout! Reduzindo janela de {self.cwnd // MSS} MSS...")
        # mantém a janela como múltiplo inteiro de MSS
        self.cwnd = max(MSS, (self.cwnd // (2 * MSS)) * MSS)
        self.acks_recebidos = 0

        if self.dados_enviados:
            seq_mais_antigo = min(self.dados_enviados)
            dados = self.dados_enviados[seq_mais_antigo]

            header = make_header(self.servidor.porta, self.id_conexao[1],
                                 seq_mais_antigo, self.ack, FLAGS_ACK)
            segmento = fix_checksum(header + dados,
                                    self.id_conexao[0], self.id_conexao[2])
            print(f"Retransmitindo {len(dados)} bytes...")
            self.servidor.rede.enviar(segmento, self.id_conexao[0])
            self.reset_timer(TIMEOUT_INTERVAL)
        else:
            if self.timer:
                self.timer.cancel()

    def _enviar_pendentes(self):
        if self.base_seq is None:
            self.base_seq = self.seq

        # enquanto couber na janela e houver dados pendentes, envia MSS por vez
        while self.dados_pendentes and (self.seq - self.base_seq) < self.cwnd:
            pedaco = self.dados_pendentes[:MSS]
            self.dados_pendentes = self.dados_pendentes[MSS:]

            seq_atual = self.seq
            self.seq += len(pedaco)
            self.dados_enviados[seq_atual] = pedaco

            header = make_header(self.servidor.porta, self.id_conexao[1],
                                 seq_atual, self.ack, FLAGS_ACK)
            segmento = fix_checksum(header + pedaco,
                                    self.id_conexao[0], self.id_conexao[2])
            print(f"Enviando {len(pedaco)} bytes...")
            self.servidor.rede.enviar(segmento, self.id_conexao[0])

        if self.dados_enviados:
            self.reset_timer(TIMEOUT_INTERVAL)

    def _processar_ack(self, ackn):
        if self.base_seq is None:
            return
        if ackn <= self.base_seq:
            return

        confirmados = 0
        for seq, dados in list(self.dados_enviados.items()):
            if seq + len(dados) <= ackn:
                del self.dados_enviados[seq]
                confirmados += 1

        if confirmados == 0:
            return

        self.base_seq = ackn
        self.acks_recebidos += confirmados

        # se confirmou uma janela inteira, aumenta 1 MSS
        if self.acks_recebidos >= self.cwnd // MSS:
            self.cwnd += MSS
            self.acks_recebidos = 0
            print(f"  [AIMD] Janela aumentada para {self.cwnd // MSS} MSS")

        self._enviar_pendentes()

        if not self.dados_enviados and self.timer:
            self.timer.cancel()

    def _rdt_rcv(self, packet: TcpPacket):
        # primeiro trata ACK dos nossos dados enviados
        if (packet.flags & FLAGS_ACK) == FLAGS_ACK:
            self._processar_ack(packet.ackn)

        # depois trata dados vindos do cliente
        if packet.seqn == self.ack:
            self.ack += len(packet.payload)

            if (packet.flags & FLAGS_FIN) == FLAGS_FIN:
                self.ack += 1
                print(f"Encerrando Conexao[{self.id_conexao}]!")
                fin_ack_header = make_header(self.servidor.porta, self.id_conexao[1],
                                             self.seq, self.ack, FLAGS_ACK)
                complete_header = fix_checksum(fin_ack_header,
                                               self.id_conexao[0], self.id_conexao[2])
                self.servidor.rede.enviar(complete_header, self.id_conexao[0])
                return

            if self.callback and packet.payload:
                self.callback(self, packet.payload)

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
        self.dados_pendentes += dados
        self._enviar_pendentes()

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        pass

    def reset_timer(self, delay):
        if self.timer:
            self.timer.cancel()
        self.timer = asyncio.get_event_loop().call_later(delay, self._timeout_handler)