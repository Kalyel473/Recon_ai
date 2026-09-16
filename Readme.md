# AIRecon v2.0 — AI System Reconnaissance Tool

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/Uso-Somente%20Autorizado-red)
![Dependencies](https://img.shields.io/badge/Depend%C3%AAncias-Zero-success)
![Architecture](https://img.shields.io/badge/Arquitetura-Modular-purple)

**AIRecon** é uma ferramenta de **reconhecimento e auditoria de sistemas** para avaliações de segurança autorizadas (pentests) e auditorias de infraestrutura, equipada com um **motor de IA 100% local e offline** — sem APIs externas, sem chaves e sem pacotes externos (`pip`).

> ⚠️ **Aviso Legal:** Esta ferramenta deve ser usada **exclusivamente** em ambientes onde você possui autorização explícita para testar (seus próprios sistemas ou contratos de pentest assinados). O uso não autorizado é ilegal.

---

## ✨ Funcionalidades

| Módulo | Descrição |
|---|---|
| 🔌 **Async Port Scanner** | Varredura de portas não bloqueante com `asyncio`, controle de concorrência (`Semaphore`) e compatibilidade universal |
| 🔒 **Advanced TLS/SSL Analysis** | Extração de SANs (*Subject Alternative Names*), análise de validade (dias para expirar / expirado), emissor e versão TLS |
| ✉️ **Email Security Audit** | Auditoria automática de registros anti-spoofing **SPF** (sintaxe e qualificadores permissivos) e **DMARC** (`p=reject/quarantine/none`) |
| 🏷️ **Service Fingerprinting** | Banner grabbing ativo, sanitização de saídas binárias e detecção de versões por regex |
| 🌐 **DNS Enumeration** | Queries DNS UDP nativas (RFC 1035: A, AAAA, MX, NS, TXT, SOA), bruteforce de subdomínios e reverse DNS (/24) |
| 🕸️ **Web Recon** | Headers HTTP, tecnologias, security headers ausentes e fuzzing de paths sensíveis |
| 🤖 **Motor de IA Local** | 3 camadas: Fuzzy Risk + Naive Bayes online + Sistema Especial de inferência com correlação de evidências |
| 🛡️ **Base Offline de CVEs** | Mapeamento automático de banners para CVEs e CVSS notórios (regreSSHion, Terrapin, Apache Path Traversal, etc.) |
| 📄 **Relatórios Multi-Formato** | Exportação simultânea para **JSON estruturado**, **Dashboard HTML standalone moderno** e **Markdown** |

---

### 🤖 Motor de IA (100% Offline)

A inteligência do AIRecon opera em **três camadas complementares**:

1. **Fuzzy Risk Engine & Base de CVEs**: Pontua serviços de 0 a 10 combinando pesos de exposição em pentest, métricas de certificados TLS (certificados expirados/prestes a vencer) e assinaturas de CVEs conhecidos com severidade CVSS.
2. **Naive Bayes Online**: Classificador bayesiano incremental com suavização de Laplace que aprende perfis de hosts confirmados por você (`--learn <alvo> <classe>`). O modelo persiste em `airecon_model.json`.
3. **Sistema Especial de Inferência**: Regras multi-evidência (`IF-THEN`) priorizadas (de P10 a P4). Exemplos:
   - Portas 80/443 + 3306/5432 no mesmo host → *"Stack Web+DB: SQLi no app expõe diretamente o banco de dados."*
   - Domínio sem registro DMARC ou SPF permissivo → *"Alerta de risco de e-mail spoofing e phishing facilitado."*
   - Certificado TLS expirado ou autoassinado → *"Alerta de MITM e quebra de cadeia de confiança."*

---

## 📦 Instalação

Apenas Python 3.8+ instalado. Nenhuma biblioteca externa é necessária:

```bash
git clone https://github.com/Kalyel473/Recon_ai.git
cd airecon
chmod +x airecon.py

# Opcional: instalar globalmente no Linux/macOS
sudo cp airecon.py /usr/local/bin/airecon
```

---

## 🚀 Exemplos de Uso

```bash
# 1. Reconhecimento de domínio com DNS, SPF/DMARC e Web gerando relatórios em HTML, Markdown e JSON
python airecon.py --target amern.org.br --dns --web --format all

# 2. Varredura completa de uma rede local com ICMP ping sweep e top 100 portas
sudo python airecon.py --target 192.168.1.0/24 --discover --top --format html

# 3. Alvo único com range específico de portas e alta concorrência
python airecon.py -t 10.0.0.5 -p 1-10000 --threads 300

# 4. Modo FULL: portas 1-1024 + DNS + Web + E-mail + Reverse DNS
python airecon.py -t 10.0.0.5 --full

# 5. Treinar a IA com um perfil confirmado
python airecon.py --learn 10.0.0.5 windows_dc
```

### Opções da Linha de Comando (CLI)

```text
  -t, --target TARGET      IP, domínio ou CIDR (obrigatório, exceto com --learn)
  -p, --ports PORTS        Portas: '80,443,1000-2000'
  --top                    Usar top ~100 portas mais comuns
  --discover               Forçar descoberta de hosts ativos
  --icmp                   Usar ICMP ping sweep (requer root/admin; fallback automático para TCP)
  --dns                    Enumerar registros DNS + Auditoria SPF e DMARC
  --subdomains             Bruteforce de subdomínios via wordlist
  --reverse                Reverse DNS no bloco /24 do alvo
  --web                    Reconhecimento web (headers, tecnologias, paths)
  --local                  Incluir informações do sistema local
  -F, --full               Modo completo: portas 1-1024 + DNS + Web + E-mail + Reverse
  --learn ALVO CLASSE      Treinar modelo da IA: --learn 10.0.0.5 windows_dc
  --no-ai                  Desativar motor de IA
  --threads THREADS        Concorrência máxima / threads (padrão: 200)
  --timeout TIMEOUT        Timeout por conexão em segundos (padrão: 1.5)
  --resolver RESOLVER      Servidor DNS para consultas UDP (padrão: 8.8.8.8)
  --format {all,json,html,md}  Formato do relatório de saída (padrão: all)
  -o, --output FILE        Nome ou caminho base do arquivo de saída
  -q, --quiet              Modo silencioso: exibir apenas achados e erros
```

---

## 📊 Relatórios Gerados

Ao executar com `--format all` (ou `--format html`, `--format md`), o AIRecon gera:

1. **Dashboard HTML Standalone (`.html`)**:
   - Tema escuro moderno, totalmente autocontido (zero requisições a CDNs externas).
   - Cards de estatísticas (Hosts ativos, portas, risco da IA, status anti-spoofing).
   - Tabela de portas com banners, certificados TLS, CVEs associados e badges de severidade.
   - Recomendações priorizadas da IA e listas de subdomínios / SANs.
2. **Relatório em Markdown (`.md`)**:
   - Tabelas legíveis prontas para GitHub, GitLab, Notion ou documentações de auditoria.
3. **Relatório JSON (`.json`)**:
   - Dados brutos estruturados para integração com pipelines DevSecOps.

---

## 🗂️ Estrutura do Projeto

```text
Recon_ia/
├── airecon.py                        # Ponto de entrada CLI e orquestrador principal
├── Readme.md                         # Documentação completa
└── airecon/                          # Pacote modular
    ├── __init__.py
    ├── core/
    │   ├── config.py                 # Portas padrão, wordlists e utilitários de IP
    │   ├── logger.py                 # Console logger com fallback seguro de encoding
    │   └── models.py                 # Dataclasses com suporte a dicionário
    ├── modules/
    │   ├── discovery.py              # Host Discovery (ICMP ping sweep + fallback TCP)
    │   ├── scanner.py                # AsyncPortScanner (asyncio + banner + TLS SANs/validade)
    │   ├── dns_recon.py              # DNSEnum (RFC 1035 UDP + auditoria SPF e DMARC)
    │   └── web_recon.py              # WebRecon (HTTP probing, headers e path fuzzing)
    ├── ai/
    │   ├── cve_db.py                 # Base offline de assinaturas CVE/CPE
    │   ├── fuzzy.py                  # FuzzyRiskEngine (pontuação de risco 0-10)
    │   ├── bayes.py                  # NaiveBayesLearner (classificador online)
    │   ├── inference.py              # InferenceEngine (regras especialistas IF-THEN)
    │   └── engine.py                 # Orquestrador da IA
    └── reports/
        ├── json_reporter.py          # Exportador JSON estruturado
        ├── markdown_reporter.py      # Exportador Markdown
        └── html_reporter.py          # Dashboard HTML moderno e autocontido
```

---

## 📜 Licença e Ética

Este projeto é destinado a **profissionais de segurança e administradores de rede** em avaliações autorizadas. O autor não se responsabiliza por uso indevido. Sempre obtenha autorização antes de auditar qualquer infraestrutura.