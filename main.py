import random
import hashlib
import base58
from ecdsa import SECP256k1, SigningKey
import multiprocessing
import time

# Configuração inicial
#DICAS DOS "X" EM ORDEM DE SAÍDA
# 1=0 *
# 2=B *
# 3=D
# 4=F *
# 5=F *
# 6=5 * 
# 7=A * 
# 8=2 * 
# 9=3 *
# 10=5
# 11=0
# 12=F
# 13=7
# 14=E * 
# 15=
# 16=
# 17=1 * 
# 18=B *
# 19=A * 
# 20=
# 21=6
# 22=
# 23=6
# 24=8
# 25=
# 26=
# 27=
# 28=
# 29=
# 30=
 #31=
# 32=

#######DICAS######## 0 B D F F 5 A 2 3 5 0 F 7 E     1 B A   6   6 8
#######ORIGINAL#####4x3x3x4xcxfx6x9xfx3xaxcx5x0x4xbxbx7x2x6x8x7x8xax4x0x8x3x3x3x7x3x

# Chave privada com caracteres desconhecidos representados como 'x'
CHAVE_INCOMPLETA = "4x3x3x4xcxfx6x9xfx3xaxcx5x0x4xbxbx7x2x6x8x7x8xax4x0x8x3x3x3x7x3x"
# Endereço Bitcoin alvo a ser validado
ENDERECO_ALVO = "1Hoyt6UBzwL5vvUSTLMQC2mwvvE5PpeSC"
# Define o número de processos (clientes) como 70% do total de núcleos da CPU
NUM_CLIENTES = int(multiprocessing.cpu_count() * 0.70)


def chave_para_endereco(chave_privada):
    """Gera um endereço Bitcoin a partir de uma chave privada."""
    # Obtém a chave pública a partir da chave privada
    chave_publica = chave_privada.get_verifying_key().to_string()

    # Hash SHA-256 seguido por RIPEMD-160 para a chave pública
    chave_publica_hash = hashlib.sha256(chave_publica).digest()
    chave_publica_hash = hashlib.new('ripemd160', chave_publica_hash).digest()

    # Adiciona o prefixo de rede Bitcoin (0x00)
    chave_publica_hash_prefix = b'\x00' + chave_publica_hash

    # Calcula o checksum (primeiros 4 bytes do hash duplo SHA-256)
    checksum = hashlib.sha256(hashlib.sha256(chave_publica_hash_prefix).digest()).digest()[:4]

    # Concatena o prefixo, hash da chave pública e checksum
    endereco_bytes = chave_publica_hash_prefix + checksum

    # Codifica o resultado em Base58
    endereco_base58 = base58.b58encode(endereco_bytes)
    return endereco_base58.decode()


def chave_para_wif(chave_privada):
    """Converte a chave privada para o formato WIF (Wallet Import Format)."""
    # Adiciona o prefixo Bitcoin (0x80) à chave privada
    chave_privada_bytes = chave_privada.to_string()
    chave_privada_prefixada = b'\x80' + chave_privada_bytes

    # Calcula o checksum (primeiros 4 bytes do hash duplo SHA-256)
    checksum = hashlib.sha256(hashlib.sha256(chave_privada_prefixada).digest()).digest()[:4]

    # Concatena chave privada prefixada e checksum
    chave_wif = base58.b58encode(chave_privada_prefixada + checksum)
    return chave_wif.decode()


def validar_chave(chave, endereco_alvo):
    """Valida se a chave privada corresponde ao endereço Bitcoin alvo."""
    endereco_gerado = chave_para_endereco(chave)
    return endereco_gerado == endereco_alvo


def substituir_x_por_hex(chave_incompleta, intervalo_inicio, intervalo_fim):
    """Substitui os caracteres 'x' da chave incompleta por valores hexadecimais aleatórios dentro do intervalo."""
    chave_completa = list(chave_incompleta)

    for i in range(len(chave_completa)):
        if chave_completa[i] == 'x':
            while True:
                # Escolhe um valor hexadecimal aleatório
                hex_value = random.choice('0123456789abcdef')
                temp_chave = ''.join(chave_completa).replace('x', hex_value)
                temp_chave_int = int(temp_chave, 16)
                # Garante que o valor gerado está dentro do intervalo permitido
                if intervalo_inicio <= temp_chave_int <= intervalo_fim:
                    chave_completa[i] = hex_value
                    break

    return ''.join(chave_completa)


def chave_para_intervalo(chave_incompleta):
    """Converte a chave incompleta em um intervalo numérico hexadecimal."""
    intervalo_inicio = int(chave_incompleta.replace('x', '0'), 16)
    intervalo_fim = int(chave_incompleta.replace('x', 'f'), 16)
    return intervalo_inicio, intervalo_fim


def buscar_chave(intervalo_inicio, intervalo_fim, cliente_id, resultado_global):
    """Simula a busca de uma chave válida por um cliente (processo)."""
    print(f"Cliente-{cliente_id} iniciou busca no intervalo {hex(intervalo_inicio)}-{hex(intervalo_fim)}.")
    start_time = time.time()  # Início da busca
    total_tentativas = 0  # Contador de tentativas realizadas

    while not resultado_global["encontrado"]:  # Continua até encontrar a chave correta
        for tentativa in range(100000):  # Limita as tentativas antes de atualizar o intervalo
            if resultado_global["encontrado"]:
                print(f"Cliente-{cliente_id} interrompeu busca: chave encontrada por outro cliente.")
                return

            try:
                # Gera uma chave privada substituindo 'x' por valores hexadecimais
                chave_privada_hex = substituir_x_por_hex(CHAVE_INCOMPLETA, intervalo_inicio, intervalo_fim)
                chave_privada_int = int(chave_privada_hex, 16)
                chave_privada = SigningKey.from_secret_exponent(chave_privada_int, curve=SECP256k1)

                total_tentativas += 1
                elapsed_time = time.time() - start_time
                tps = total_tentativas / elapsed_time if elapsed_time > 0 else 0

                if tentativa % 10000 == 0:  # Exibe estatísticas a cada 10 mil tentativas
                    print(f"Cliente-{cliente_id} última chave testada: {chave_privada_hex} | TPS: {tps:.2f}")

                if validar_chave(chave_privada, ENDERECO_ALVO):  # Verifica se é a chave correta
                    resultado_global["encontrado"] = True
                    resultado_global["chave"] = chave_privada_int
                    chave_wif = chave_para_wif(chave_privada)
                    print(f"Cliente-{cliente_id} encontrou a chave correta:")
                    print(f"Chave Privada (Hex): {chave_privada_hex}")
                    print(f"Chave Privada (WIF): {chave_wif}")

                    # Salva os resultados em arquivo
                    with open("resultado_163_novo.txt", "w") as arquivo:
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

    manager = multiprocessing.Manager()
    resultado_global = manager.dict()  # Dicionário compartilhado entre processos
    resultado_global["encontrado"] = False
    resultado_global["chave"] = None

    processos = []

    for cliente_id in range(NUM_CLIENTES):
        intervalo_tamanho = (intervalo_fim - intervalo_inicio) // NUM_CLIENTES
        intervalo_cliente_inicio = intervalo_inicio + cliente_id * intervalo_tamanho
        intervalo_cliente_fim = intervalo_cliente_inicio + intervalo_tamanho
        processo = multiprocessing.Process(
            target=buscar_chave,
            args=(intervalo_cliente_inicio, intervalo_cliente_fim, cliente_id, resultado_global)
        )
        processos.append(processo)
        processo.start()

    for processo in processos:
        processo.join()

    if resultado_global["encontrado"]:
        print(f"Busca concluída. Chave encontrada: {resultado_global['chave']}")
    else:
        print("Busca concluída. Nenhuma chave encontrada.")


if __name__ == "__main__":
    # Configuração para garantir compatibilidade com Windows
    multiprocessing.set_start_method('spawn')
    multiprocessing.freeze_support()
    iniciar_servidor()
