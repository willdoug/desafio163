import random
import hashlib
import base58
from ecdsa import SECP256k1, SigningKey
import multiprocessing
import time

# Configuração inicial
#1=0
#2=B
#3=D
#4=F
#5=F
#6=5
#7=A
#8=2
#9=3
#10=
#11=
#12=
#13=
#14=
#15=
#######DICAS######## 0 B D F F 5 A 2 3
#######ORIGINAL#####4x3x3x4xcxfx6x9xfx3xaxcx5x0x4xbxbx7x2x6x8x7x8xax4x0x8x3x3x3x7x3x
CHAVE_INCOMPLETA = "403b3d4fcff56a92f33xaxcx5x0x4xbxbx7x2x6x8x7x8xax4x0x8x3x3x3x7x3x"
ENDERECO_ALVO = "1Hoyt6UBzwL5vvUSTLMQC2mwvvE5PpeSC"
NUM_CLIENTES = int(multiprocessing.cpu_count() * 0.70) # Número de processos simulando clientes, baseado em núcleos da CPU


def chave_para_endereco(chave_privada):
    """Gera um endereço Bitcoin a partir de uma chave privada."""
    chave_publica = chave_privada.get_verifying_key().to_string()

    chave_publica_hash = hashlib.sha256(chave_publica).digest()
    chave_publica_hash = hashlib.new('ripemd160', chave_publica_hash).digest()

    chave_publica_hash_prefix = b'\x00' + chave_publica_hash
    checksum = hashlib.sha256(hashlib.sha256(chave_publica_hash_prefix).digest()).digest()[:4]

    endereco_bytes = chave_publica_hash_prefix + checksum
    endereco_base58 = base58.b58encode(endereco_bytes)

    return endereco_base58.decode()


def chave_para_wif(chave_privada):
    """Converte a chave privada para o formato WIF (Wallet Import Format)."""
    chave_privada_bytes = chave_privada.to_string()
    chave_privada_prefixada = b'\x80' + chave_privada_bytes
    checksum = hashlib.sha256(hashlib.sha256(chave_privada_prefixada).digest()).digest()[:4]
    chave_wif = base58.b58encode(chave_privada_prefixada + checksum)
    return chave_wif.decode()


def validar_chave(chave, endereco_alvo):
    """Valida se a chave privada corresponde ao endereço alvo."""
    endereco_gerado = chave_para_endereco(chave)
    return endereco_gerado == endereco_alvo


def substituir_x_por_hex(chave_incompleta, intervalo_inicio, intervalo_fim):
    """Substitui os caracteres 'x' da chave incompleta por valores hexadecimais aleatórios dentro do intervalo."""
    chave_completa = list(chave_incompleta)

    for i in range(len(chave_completa)):
        if chave_completa[i] == 'x':
            # Substitui 'x' por valor aleatório hexadecimal dentro do intervalo
            while True:
                hex_value = random.choice('0123456789abcdef')
                temp_chave = ''.join(chave_completa).replace('x', hex_value)
                temp_chave_int = int(temp_chave, 16)
                if intervalo_inicio <= temp_chave_int <= intervalo_fim:
                    chave_completa[i] = hex_value
                    break

    return ''.join(chave_completa)


def chave_para_intervalo(chave_incompleta):
    """Converte a chave incompleta para um intervalo de valores possíveis."""
    intervalo_inicio = int(chave_incompleta.replace('x', '0'), 16)
    intervalo_fim = int(chave_incompleta.replace('x', 'f'), 16)
    return intervalo_inicio, intervalo_fim


def buscar_chave(intervalo_inicio, intervalo_fim, cliente_id, resultado_global):
    """Simula um cliente que busca pela chave no intervalo fornecido."""
    print(f"Cliente-{cliente_id} iniciou busca no intervalo {hex(intervalo_inicio)}-{hex(intervalo_fim)}.")

    start_time = time.time()  # Hora de início da busca
    total_tentativas = 0  # Contador de tentativas realizadas

    while not resultado_global["encontrado"]:  # Loop até encontrar a chave correta
        for tentativa in range(100000):  # Número de tentativas por cliente antes de pedir novo intervalo
            if resultado_global["encontrado"]:
                print(f"Cliente-{cliente_id} interrompeu busca: chave encontrada por outro cliente.")
                return

            try:
                # Substituir "x" por valores hexadecimais aleatórios dentro do intervalo
                chave_privada_hex = substituir_x_por_hex(CHAVE_INCOMPLETA, intervalo_inicio, intervalo_fim)
                chave_privada_int = int(chave_privada_hex, 16)
                chave_privada = SigningKey.from_secret_exponent(chave_privada_int, curve=SECP256k1)

                # Contabiliza as tentativas
                total_tentativas += 1

                # Calcular a taxa de tentativas por segundo (TPS)
                elapsed_time = time.time() - start_time
                tps = total_tentativas / elapsed_time if elapsed_time > 0 else 0

                # Mostrar a última chave testada e o TPS a cada 10 mil tentativas
                if tentativa % 10000 == 0:
                    print(f"Cliente-{cliente_id} última chave testada: {chave_privada_hex} | TPS: {tps:.2f}")

                # Validar chave
                if validar_chave(chave_privada, ENDERECO_ALVO):
                    resultado_global["encontrado"] = True
                    resultado_global["chave"] = chave_privada_int
                    chave_wif = chave_para_wif(chave_privada)
                    print(f"Cliente-{cliente_id} encontrou a chave correta:")
                    print(f"Chave Privada (Hex): {chave_privada_hex}")
                    print(f"Chave Privada (WIF): {chave_wif}")

                    # Salvar resultados no arquivo
                    with open("resultado_163.txt", "w") as arquivo:
                        arquivo.write(f"Chave encontrada:\n")
                        arquivo.write(f"Chave Privada (Hex): {chave_privada_hex}\n")
                        arquivo.write(f"Chave Privada (WIF): {chave_wif}\n")
                        arquivo.write(f"Chave em Decimal: {chave_privada_int}\n")
                    return

            except Exception as e:
                print(f"Erro na thread Cliente-{cliente_id}: {e}")
                return


def iniciar_servidor():
    """Inicia o servidor e distribui intervalos entre os clientes (processos)."""
    print("Servidor iniciado. Gerando intervalos...")

    intervalo_inicio, intervalo_fim = chave_para_intervalo(CHAVE_INCOMPLETA)
    print(f"Intervalo de busca: {hex(intervalo_inicio)} - {hex(intervalo_fim)}")

    # Criar o Manager para compartilhar dados entre processos
    manager = multiprocessing.Manager()
    resultado_global = manager.dict()
    resultado_global["encontrado"] = False
    resultado_global["chave"] = None

    # Lista para gerenciar processos (clientes)
    processos = []

    for cliente_id in range(NUM_CLIENTES):
        intervalo_tamanho = (intervalo_fim - intervalo_inicio) // NUM_CLIENTES
        intervalo_cliente_inicio = intervalo_inicio + cliente_id * intervalo_tamanho
        intervalo_cliente_fim = intervalo_cliente_inicio + intervalo_tamanho
        processo = multiprocessing.Process(target=buscar_chave,
                                           args=(intervalo_cliente_inicio, intervalo_cliente_fim, cliente_id,
                                                 resultado_global))
        processos.append(processo)
        processo.start()

    # Aguardar todos os processos concluírem
    for processo in processos:
        processo.join()

    if resultado_global["encontrado"]:
        print(f"Busca concluída. Chave encontrada: {resultado_global['chave']}")
    else:
        print("Busca concluída. Nenhuma chave encontrada.")


if __name__ == "__main__":
    # Certificando-se de que o código será executado corretamente no Windows
    multiprocessing.set_start_method('spawn')  # Definindo o método correto para iniciar os processos
    multiprocessing.freeze_support()  # Suporte para congelamento de processos no Windows
    iniciar_servidor()
