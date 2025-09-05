import sys
import csv
from collections import Counter

# --- Configurações ---
CODIGOS_FALHA = {'401', '403', '407', '503'}  # Pode editar aqui
ARQUIVO_SAIDA = "resultado.csv"  # Nome do arquivo de saída CSV


def extrair_status_code(campo_status):
    """
    Extrai o código de status HTTP do campo de status do log.
    Exemplo: 'TCP_DENIED/403' -> '403'
    """
    if '/' in campo_status:
        return campo_status.split('/')[-1]
    return campo_status  # Caso já seja só o código


def analisar_log(caminho_arquivo):
    """
    Lê um arquivo de log do Squid e analisa os acessos.

    Args:
        caminho_arquivo (str): Caminho para o arquivo de log.

    Retorna:
        tuple: Dois Counter, um para tentativas falhas por IP e outro para URLs acessadas.
    """
    tentativas_falhas = Counter()
    urls_acessadas = Counter()

    try:
        with open(caminho_arquivo, 'r', encoding='utf-8') as f:
            for linha_num, linha in enumerate(f, 1):
                partes = linha.strip().split()
                if len(partes) < 7:
                    print(f"[AVISO] Linha {linha_num} mal formatada, ignorando.")
                    continue

                try:
                    ip_cliente = partes[2]
                    status_code = extrair_status_code(partes[4])
                    url = partes[6]

                    if status_code in CODIGOS_FALHA:
                        tentativas_falhas[ip_cliente] += 1

                    urls_acessadas[url] += 1
                except IndexError:
                    print(f"[AVISO] Erro ao processar linha {linha_num}: {linha.strip()}")
                    continue

    except FileNotFoundError:
        print(f"Erro: O arquivo '{caminho_arquivo}' não foi encontrado.")
        sys.exit(1)
    except Exception as e:
        print(f"Ocorreu um erro ao processar o arquivo: {e}")
        sys.exit(1)

    return tentativas_falhas, urls_acessadas


def imprimir_resultados(tentativas_falhas, urls_acessadas, top_n=10):
    """
    Imprime os resultados da análise.

    Args:
        tentativas_falhas (Counter): Contagem de tentativas falhas por IP.
        urls_acessadas (Counter): Contagem de acessos por URL.
        top_n (int): Quantidade de itens a mostrar.
    """
    print("\n### Análise de Log do Squid ###\n")

    print(f"IPs com Múltiplas Tentativas Falhas (TOP {top_n}):")
    for ip, count in tentativas_falhas.most_common(top_n):
        print(f"- {ip}: {count} tentativas")

    print(f"\nURLs Mais Acessadas (TOP {top_n}):")
    for url, count in urls_acessadas.most_common(top_n):
        print(f"- {url}: {count} acessos")


def salvar_resultados_csv(tentativas_falhas, urls_acessadas, arquivo=ARQUIVO_SAIDA):
    """
    Salva os resultados em formato CSV.
    """
    try:
        with open(arquivo, "w", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Tentativas Falhas"])
            for ip, count in tentativas_falhas.most_common():
                writer.writerow([ip, count])
            writer.writerow([])
            writer.writerow(["URL", "Acessos"])
            for url, count in urls_acessadas.most_common():
                writer.writerow([url, count])

        print(f"\n[+] Resultados salvos em {arquivo}")
    except Exception as e:
        print(f"Erro ao salvar CSV: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python nome_do_script.py <caminho_do_arquivo_de_log> [TOP_N]")
        sys.exit(1)

    caminho_log = sys.argv[1]
    top_n = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    tentativas_falhas, urls_acessadas = analisar_log(caminho_log)
    imprimir_resultados(tentativas_falhas, urls_acessadas, top_n)
    salvar_resultados_csv(tentativas_falhas, urls_acessadas)
