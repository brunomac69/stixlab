import webbrowser
import customtkinter as ctk
from stix2validator import validate_instance,  validate_string
from tkinter import StringVar, messagebox, filedialog
from datetime import datetime, timezone
import uuid
import json

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

current_observed_data = None

# =========================
# Utilitários
# =========================

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def gen_id(t):
    return f"{t}--{uuid.uuid4()}"

def placeholder_str():
    return "<preencher>"

def change_theme(choice):
    # choice vem da ComboBox
    ctk.set_appearance_mode(choice)


CATEGORY_LABELS = {
    "SDO (Domain Object)": "SDO",
    "SRO (Relationship Object)": "SRO",
    "SCO (Cyber Observable Object)": "SCO"
}

def default_value(field: str, obj_type: str):
    """Valores por defeito (didáticos) já no tipo certo para JSON."""
    # campos comuns (SDO/SRO)
    if field == "type":
        return obj_type
    if field == "spec_version":
        return "2.1"
    if field == "id":
        return gen_id(obj_type)
    if field in ("created", "modified", "published", "valid_from", "first_observed", "last_observed"):
        return now()

    # object_refs (caso especial – didático)
    if field == "object_refs":
        return [
            "indicator-----UUID",
            "attack-pattern-----UUID",
            "....."
        ]

    # listas comuns de referências (*_refs)
    if field.endswith("_refs") or field in ("where_sighted_refs",):
        return [
            "indicator-----UUID",
            "malware-----UUID",
            "...."
        ]
    
    if field == "identity_class":
        return "organization  # opções: individual, group, organization, class, unknown"

    if field == "roles":
        return [
            "agent",
            "Opções::agent,director,infrastructure-architect,malware-author,sponsor"
        ]

    if field == "sectors":
        return [
            "government",
            "Opções::aerospace,automotive,chemical,commercial,communications,construction,defense,education,energy,entertainment,financial-services,government,healthcare,hospitality-leisure,infrastructure,insurance,manufacturing,mining,non-profit,pharmaceuticals,retail,technology,telecommunications,transportation,utilities"
        ]

    if field == "relationship_type":
        return "uses  # opções: uses,indicates,targets,mitigates,exploits,delivers,hosts,controls,authored-by,attributed-to,located-at,communicates-with,consists-of,compromises,variant-of,duplicate-of,derived-from,related-to"

    if field == "tool_types":
        return [
            "remote-access","credential-exploitation",
            "Opções::credential-exploitation,denial-of-service,exploitation,information-gathering,network-capture,remote-access,vulnerability-scanning"
        ]

    if field == "malware_types":
        return [
            "ransomware","backdoor","keylogger","dropper",
            "Opções::adware,bot,bootkit,credential-harvesting,downloader,exploit-kit,keylogger,ransomware,remote-access-trojan,rootkit,screen-capture,spyware,trojan,virus,worm"
        ]

    if field == "infrastructure_types":
        return [
            "command-and-control","botnet",
            "Opções::anonymization,botnet,command-and-control,hosting-malware,hosting-target-lists,phishing,reconnaissance,staging,victim-identification"
        ]

    if field == "protocols":
        return [
            "tcp","udp",
            "Opções::tcp,udp,icmp,http,https,ftp,smtp,dns"
        ]

    if field == "threat_actor_types":
        # threat actor types (STIX 2.1 – VOCABULÁRIO OFICIAL)
        return ["activist","Opções::competitor,crime-syndicate,criminal,hacker,insider-accidental,insider-disgruntled,nation-state,sensationalist,spy,terrorist"]
    
    if field == "aliases":
        return ["alias-exemplo"]
    
    if field == "kill_chain_phases":
        return [
            {
                "kill_chain_name": "Eg. lockheed-martin-cyber-kill-chain",
                "phase_name": "delivery"
            },
            {
                "kill_chain_name": "Eg. lockheed-martin-cyber-kill-chain",
                "phase_name": "exploitation"
            },
            {
                "kill_chain_name": "Eg. lockheed-martin-cyber-kill-chain",
                "phase_name": "installation"
            },
        ]

    # números comuns
    if field in ("confidence",):
        return 50
    if field in ("count", "number_observed"):
        return 1
    if field in ("latitude", "longitude"):
        return 0.0
    if field in ("src_port", "dst_port", "pid", "size"):
        return 0

    # booleanos comuns
    if field == "is_family":
        return False

    # SCO específicos
    if obj_type in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "mac-addr", "mutex"):
        if field == "value":
            examples = {
                "ipv4-addr": "8.8.8.8",
                "ipv6-addr": "2001:db8::1",
                "domain-name": "example.com",
                "url": "http://example.com/login",
                "email-addr": "attacker@example.com",
                "mac-addr": "00:11:22:33:44:55",
                "mutex": "Global\\ExampleMutex"
            }
            return examples.get(obj_type, placeholder_str())

    if obj_type == "file":
        if field == "hashes":
            return {"MD5": "", "SHA-1": "", "SHA-256": ""}
        if field == "name":
            return "malware.exe"
        if field == "mime_type":
            return "application/octet-stream"

    if obj_type == "user-account":
        if field == "account_login":
            return "user"
        if field == "account_type":
            return ""

    if obj_type == "network-traffic":
        if field == "protocols":
            return ["tcp"]
        if field in ("src_ref", "dst_ref"):
            return ""
        if field in ("src_port", "dst_port"):
            return 0


    # por defeito: string vazia ou placeholder
    if field in ("description","objective", "content", "relationship_type", "source_ref", "target_ref",
                 "sighting_of_ref", "product", "result", "opinion", "country", "region", "city", "name",
                 "pattern", "pattern_type", "valid_until", "start_time", "stop_time"):
        # alguns campos preferimos deixar um exemplo útil
        if field == "pattern":
            return "[ipv4-addr:value = '1.2.3.4']"
        if field == "pattern_type":
            return "stix"
        if field in ("relationship_type",):
            return "uses"
        if field in ("source_ref", "target_ref", "sighting_of_ref"):
            return "<ref--UUID>"
        if field == "name" and obj_type == "vulnerability":
            return "CVE-YYYY-XXXX"
        if field == "name":
            return "Nome do objeto"
        if field == "content":
            return "Texto da nota"
        if field == "opinion":
            return "strongly-agree"
        if field == "product":
            return "Nome do produto/engine"
        if field == "objective":
            return "Eg. Steal Sensitive intellectual information and exfiltrate"
        return ""
    

    if field == "goals":
        return [
            "organizational-gain","ideology",
            "Opções::accidental,coercion,dominance,ideology,notoriety,organizational-gain,personal-gain"
        ]   

    if field == "secondary_motivations":
        return [
            "ideology",
            "Opções::accidental,coercion,dominance,ideology,notoriety,organizational-gain,personal-gain,revenge,unpredictable"
        ]

    if field == "capabilities":
        return ["low","medium","high","advanced","expert"]

    if field == "resource_level":
        return "organization  # opções: individual, club, contest, team, organization, government"

    if field == "primary_motivation":
        return "organizational-gain  # opções: accidental, coercion, dominance, ideology, notoriety, organizational-gain, personal-gain, revenge, unpredictable"

    if field in ("first_seen", "last_seen"):
        return now()

    if field == "report_types":
        return [
            "malware",
            "Opções::attack-pattern,campaign,identity,indicator,malware,observed-data,threat-actor,tool,vulnerability"
        ]
    
    if field == "labels":
        return ["espionage", "ransomware", "etc..."]
    
    if field == "confidence":
        return 50
    
    if field == "context":
        return "suspicious-activity # opções: , malware-analysis, incident, threat-report, campaign, investigation, other"

    return placeholder_str()

# =========================
# Catálogo STIX (campos)
# =========================
# Nota: aqui tens muitos objetos; se quiseres mesmo TODOS os SCO “exóticos” também dá,
# mas para ensino isto já cobre a esmagadora maioria dos casos e é estável.

STIX_OBJECTS = {
   "SDO": {
        "attack-pattern": {
            "mandatory": [
                "type", "spec_version", "id", "created", "modified",
                "name"
            ],
            "optional": [
                "description",
                "aliases",
                "kill_chain_phases",
                "confidence",
                "labels",
                "\n\n__HELP__\nO Attack Pattern descreve uma técnica ou método usado para comprometer um alvo. Modela o 'como' do ataque.\n\nRelações comuns:\n• Threat Actor → uses → Attack Pattern\n• Malware → uses → Attack Pattern\n• Intrusion Set → uses → Attack Pattern\n\nExemplo:\nThreat Actor → uses → Attack Pattern (Phishing)"
            ]
        },

        "campaign": {
            "mandatory": [
                "type", "spec_version", "id", "created", "modified",
                "name"
            ],
            "optional": [
                "description",
                "first_seen",
                "last_seen",
                "objective",
                "confidence",
                "labels",
                "\n\n__HELP__\nCampaign representa um conjunto coordenado de atividades maliciosas com um objetivo específico ao longo do tempo.\n\nRelações comuns:\n• Threat Actor → attributed-to → Campaign\n• Campaign → uses → Malware\n• Campaign → targets → Identity / Infrastructure\n\nExemplo:\nCampaign → uses → Malware (Ransomware)"
            ]
        },

        "course-of-action": {
            "mandatory": ["type","spec_version","id","created","modified","name"],
            "optional": [
                "description",
                "\n\n__HELP__\nCourse of Action descreve medidas de mitigação ou resposta.\n\nRelações comuns:\n• Course of Action → mitigates → Attack Pattern\n• Course of Action → mitigates → Malware\n\nExemplo:\nCourse of Action (Bloquear IPs) → mitigates → Brute Force"
            ]
        },

        "grouping": {
            "mandatory": ["type","spec_version","id","created","modified","name","context","object_refs"],
            "optional": [
                "description",
                "confidence",
                "\n\n__HELP__\nGrouping é usado para agrupar objetos STIX relacionados num contexto específico (incidente, investigação, caso forense).\n\nNão representa uma entidade real, apenas organização lógica."
            ]
        },

        "identity": {
            "mandatory": ["type","spec_version","id","created","modified","name","identity_class"],
            "optional": [
                "description",
                "roles",
                "sectors",
                "confidence",
                "\n\n__HELP__\nIdentity representa pessoas, organizações ou setores.\n\nRelações comuns:\n• Threat Actor → targets → Identity\n• Campaign → targets → Identity\n\nExemplo:\nCampaign → targets → Empresa Financeira"
            ]
        },

        "indicator": {
            "mandatory": [
                "type", "spec_version", "id", "created", "modified",
                "name", "pattern", "pattern_type", "valid_from"
            ],
            "optional": [
                "description",
                "labels",
                "confidence",
                "valid_until",
                "\n\n__HELP__\nIndicator representa IOCs usados para deteção.\n\nRelações comuns:\n• Indicator → indicates → Malware\n• Indicator → indicates → Attack Pattern\n• Indicator → based-on → Observed Data\n\nExemplo:\nIndicator (hash) → indicates → Malware"
            ]
        },

        "infrastructure": {
            "mandatory": [
                "type", "spec_version", "id", "created", "modified",
                "name"
            ],
            "optional": [
                "description",
                "infrastructure_types",
                "first_seen",
                "last_seen",
                "confidence",
                "labels",
                "\n\n__HELP__\nInfrastructure representa recursos técnicos usados em ataques (C2, domínios, VPS).\n\nRelações comuns:\n• Threat Actor → uses → Infrastructure\n• Malware → communicates-with → Infrastructure"
            ]
        },

        "intrusion-set": {
            "mandatory": [
                "type", "spec_version", "id", "created", "modified",
                "name"
            ],
            "optional": [
                "description",
                "first_seen",
                "last_seen",
                "goals",
                "resource_level",
                "primary_motivation",
                "secondary_motivations",
                "aliases",
                "labels",
                "\n\n__HELP__\nIntrusion Set representa um conjunto consistente de ataques (ex: APT).\n\nRelações comuns:\n• Intrusion Set → uses → Attack Pattern\n• Intrusion Set → uses → Malware\n• Intrusion Set → attributed-to → Threat Actor"
            ]
        },

        "location": {
            "mandatory": ["type","spec_version","id","created","modified"],
            "optional": [
                "description",
                "country",
                "region",
                "city",
                "latitude",
                "longitude",
                "\n\n__HELP__\nLocation representa uma localização geográfica relevante como alvo ou origem.\n\nRelações comuns:\n• Campaign → targets → Location\n• Threat Actor → targets → Location"
            ]
        },

        "malware": {
            "mandatory": [
                "type", "spec_version", "id", "created", "modified",
                "name", "is_family"
            ],
            "optional": [
                "description",
                "malware_types",
                "aliases",
                "first_seen",
                "last_seen",
                "capabilities",
                "confidence",
                "labels",
                "\n\n__HELP__\nMalware representa software malicioso ou família.\n\nRelações comuns:\n• Threat Actor → uses → Malware\n• Malware → uses → Tool\n• Indicator → indicates → Malware"
            ]
        },

        "malware-analysis": {
            "mandatory": ["type","spec_version","id","created","modified","product"],
            "optional": [
                "result",
                "confidence",
                "\n\n__HELP__\nMalware Analysis contém resultados técnicos da análise de malware.\n\nRelação comum:\n• Malware Analysis → analyzes → Malware"
            ]
        },

        "note": {
            "mandatory": ["type","spec_version","id","created","modified","content","object_refs"],
            "optional": [
                "confidence",
                "\n\n__HELP__\nNote permite adicionar observações humanas, conclusões ou comentários analíticos."
            ]
        },

        "observed-data": {
            "mandatory": ["type","spec_version","id","created","modified","first_observed","last_observed","number_observed"],
            "optional": [
                "object_refs",
                "\n\n__HELP__\nObserved Data representa dados recolhidos diretamente de sistemas ou sensores.\n\nRelações comuns:\n• Indicator → based-on → Observed Data"
            ]
        },

        "opinion": {
            "mandatory": ["type","spec_version","id","created","modified","opinion","object_refs"],
            "optional": [
                "confidence",
                "\n\n__HELP__\nOpinion expressa uma avaliação analítica ou grau de confiança sobre outros objetos STIX."
            ]
        },

        "report": {
            "mandatory": [
                "type", "spec_version", "id", "created", "modified",
                "name", "published", "object_refs"
            ],
            "optional": [
                "description",
                "report_types",
                "confidence",
                "labels",
                "\n\n__HELP__\nReport agrega múltiplos objetos STIX num relatório final de inteligência, incidente ou análise forense."
            ]
        },

        "threat-actor": {
            "mandatory": [
                "type", "spec_version", "id", "created", "modified",
                "name", "threat_actor_types"
            ],
            "optional": [
                "description",
                "aliases",
                "roles",
                "goals",
                "resource_level",
                "primary_motivation",
                "secondary_motivations",
                "confidence",
                "labels",
                "\n\n__HELP__\nThreat Actor representa o adversário.\n\nRelações comuns:\n• Threat Actor → uses → Tool\n• Threat Actor → uses → Malware\n• Threat Actor → attributed-to → Campaign\n• Threat Actor → targets → Identity / Infrastructure"
            ]
        },

        "tool": {
            "mandatory": [
                "type", "spec_version", "id", "created", "modified",
                "name"
            ],
            "optional": [
                "description",
                "tool_types",
                "aliases",
                "confidence",
                "labels",
                "\n\n__HELP__\nTool representa software usado em ataques ou defesa.\n\nRelações comuns:\n• Threat Actor → uses → Tool\n• Malware → uses → Tool"
            ]
        },

        "vulnerability": {
            "mandatory": [
                "type", "spec_version", "id", "created", "modified",
                "name"
            ],
            "optional": [
                "description",
                "confidence",
                "labels",
                "\n\n__HELP__\nVulnerability representa uma falha explorável (ex: CVE).\n\nRelações comuns:\n• Attack Pattern → exploits → Vulnerability\n• Malware → exploits → Vulnerability"
            ]
        }
    },

    "SRO": {
        "relationship": {
            "mandatory": ["type","spec_version","id","created","modified","relationship_type","source_ref","target_ref"],
            "optional": ["description","start_time","stop_time","confidence"]
        },
        "sighting": {
            "mandatory": ["type","spec_version","id","created","modified","sighting_of_ref"],
            "optional": ["where_sighted_refs","count","confidence"]
        }
    },

   "SCO": {
        "ipv4-addr": {"mandatory":["type","value"],"optional":[]},
        "ipv6-addr": {"mandatory":["type","value"],"optional":[]},
        "domain-name": {"mandatory":["type","value"],"optional":["resolves_to_refs"]},
        "url": {"mandatory":["type","value"],"optional":["resolves_to_refs"]},
        "email-addr": {"mandatory":["type","value"],"optional":[]},
        "mac-addr": {"mandatory":["type","value"],"optional":[]},
        "mutex": {"mandatory":["type","value"],"optional":[]},
        "file": {"mandatory":["type"],"optional":["name","size","hashes","mime_type"]},
        "process": {"mandatory":["type"],"optional":["pid","command_line","image_ref"]},
        "user-account": {"mandatory":["type","account_login"],"optional":["account_type"]},
        "network-traffic": {"mandatory":["type","protocols"],"optional":["src_ref","dst_ref","src_port","dst_port"]}
}

}

# =========================
# Bundle (simples)
# =========================

bundle = {
    "type": "bundle",
    "id": f"bundle--{uuid.uuid4()}",
    "objects": []
}

# =========================
# UI actions
# =========================

def is_help_field(field: str) -> bool:
    return field.strip().startswith("__HELP__")

def gen_empty_observed_data():
    now_ts = now()
    return {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": gen_id("observed-data"),
        "created": now_ts,
        "modified": now_ts,
        "first_observed": now_ts,
        "last_observed": now_ts,
        "number_observed": 1,
        "objects": {}
    }

def is_sco(obj_type):
    return obj_type in STIX_OBJECTS["SCO"]

def update_object_types(*_):
    global current_observed_data

    category_label = category_var.get()
    category = CATEGORY_LABELS[category_label]

    object_combo.configure(values=list(STIX_OBJECTS[category].keys()))
    object_var.set("")
    clear_fields()

    if category == "SCO":
        current_observed_data = gen_empty_observed_data()
        mandatory_text.insert(
            "end",
            json.dumps(current_observed_data, indent=4, ensure_ascii=False)
        )

def clear_fields():
    mandatory_text.delete("1.0", "end")
    optional_text.delete("1.0", "end")

def build_full_template(category: str, obj_type: str):
    fields = STIX_OBJECTS[category][obj_type]

    real_optional_fields = [
        f for f in fields["optional"]
        if not is_help_field(f)
    ]

    all_fields = fields["mandatory"] + real_optional_fields

    obj = {}
    for f in all_fields:
        obj[f] = default_value(f, obj_type)

    return obj, fields["optional"]  # DEVOLVE opcionais completos (com HELP)

def show_templates(*_):
    global current_observed_data

    clear_fields()
    category = CATEGORY_LABELS[category_var.get()]
    obj_type = object_var.get()
    if not obj_type:
        return

    # --- CASO SCO ---
    if category == "SCO":
        sco, _ = build_full_template(category, obj_type)

        idx = str(len(current_observed_data["objects"]))
        current_observed_data["objects"][idx] = sco

        mandatory_text.insert(
            "end",
            json.dumps(current_observed_data, indent=4, ensure_ascii=False)
        )
        optional_text.insert("end", "(SCO adicionado ao observed-data)")
        return

    # --- CASO SDO / SRO (igual ao actual) ---
    obj, optional_list = build_full_template(category, obj_type)
    mandatory_text.insert("end", json.dumps(obj, indent=4, ensure_ascii=False))
    optional_text.insert("end", "\n".join(optional_list) if optional_list else "(sem opcionais)")


def create_new_bundle():
    global bundle
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": []
    }
    messagebox.showinfo("Bundle", "Novo bundle criado (vazio).")

def add_to_bundle():
    global current_observed_data

    raw = mandatory_text.get("1.0", "end").strip()
    if not raw:
        messagebox.showerror("Erro", "O JSON está vazio.")
        return

    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        messagebox.showerror("JSON inválido", str(e))
        return

    # Caso SCO → adicionar observed-data
    if obj.get("type") == "observed-data":
        if not obj.get("objects"):
            messagebox.showwarning("Observed-data", "Não há SCOs dentro do observed-data.")
            return

        bundle["objects"].append(obj)
        current_observed_data = None
        messagebox.showinfo("Bundle", "Observed-data adicionado ao bundle.")
        return

    # Caso normal (SDO / SRO)
    bundle["objects"].append(obj)
    messagebox.showinfo("Bundle", f"Objeto adicionado. Total: {len(bundle['objects'])}")


def export_bundle_json():
    if not bundle["objects"]:
        messagebox.showwarning("Exportar", "O bundle está vazio. Adiciona pelo menos um objeto.")
        return

    path = filedialog.asksaveasfilename(
        title="Guardar bundle",
        defaultextension=".json",
        filetypes=[("JSON", "*.json")]
    )
    if not path:
        return

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=4, ensure_ascii=False)
    except Exception as e:
        messagebox.showerror("Erro", f"Falha ao guardar:\n{e}")
        return

    messagebox.showinfo("Exportar", "Bundle exportado com sucesso.")


def copy_text_to_clipboard(text: str):
    app.clipboard_clear()
    app.clipboard_append(text)
    app.update()  # garante que fica no clipboard

def open_stix_visualizer_site():
    webbrowser.open("https://oasis-open.github.io/cti-stix-visualization/")

def view_bundle():
    if not bundle["objects"]:
        messagebox.showinfo("Bundle", "O bundle está vazio.")
        return

    win = ctk.CTkToplevel(app)
    win.title("Bundle atual (JSON)")
    win.geometry("1000x600")

    win.transient(app)
    win.lift()
    win.focus_force()

    # ----- Barra de topo -----
    top = ctk.CTkFrame(win)
    top.pack(fill="x", padx=10, pady=5)

    # Label de estado (CRIADO AQUI)
    status_label = ctk.CTkLabel(top,text="", text_color="green")
    status_label.pack(side="right", padx=10)

    # ----- Textbox com o JSON (CRIADO ANTES da função copy) -----
    txt = ctk.CTkTextbox(win)
    txt.pack(fill="both", expand=True, padx=10, pady=10)

    txt.insert(
        "end",
        json.dumps(bundle, indent=4, ensure_ascii=False)
    )
    txt.configure(state="normal")

    # ----- Função de copiar (DEPOIS de status_label e txt existirem) -----
    def copy_bundle():
        text = txt.get("1.0", "end").strip()
        copy_text_to_clipboard(text)
        status_label.configure(text="✔ Texto copiado para o clipboard")

        # limpar mensagem após 3 segundos
        win.after(3000, lambda: status_label.configure(text=""))

    # Botões
    ctk.CTkButton(top, text="📋 Copiar tudo", command=copy_bundle, width=150).pack(side="left", padx=5)

    ctk.CTkButton(
        top,
        text="🌐 STIX Visualizer",
        command=open_stix_visualizer_site,
        width=150
    ).pack(side="left", padx=5)



def _format_validation_result(result) -> str:
    """
    Converte o output do stix2-validator para texto legível,
    independentemente da versão.
    """

    # Caso 1: objeto ValidationResults
    if hasattr(result, "is_valid"):
        valid = result.is_valid
        errors = getattr(result, "errors", [])
        warnings = getattr(result, "warnings", [])

    # Caso 2: dicionário
    elif isinstance(result, dict):
        valid = result.get("valid")
        errors = result.get("errors", [])
        warnings = result.get("warnings", [])

    # Caso 3: formato desconhecido
    else:
        return f"ℹ️ Resultado de validação recebido:\n{result}"

    lines = []

    if valid is True:
        lines.append("✅ STIX válido (sem erros).")
    elif valid is False:
        lines.append("❌ STIX inválido.")
    else:
        lines.append("ℹ️ Validação executada.")

    if errors:
        lines.append("\nErros:")
        for i, e in enumerate(errors, 1):
            if hasattr(e, "message"):
                lines.append(f"  {i}. {e.message}")
            elif isinstance(e, dict):
                lines.append(f"  {i}. {e.get('message', str(e))}")
            else:
                lines.append(f"  {i}. {e}")

    if warnings:
        lines.append("\nAvisos:")
        for i, w in enumerate(warnings, 1):
            if hasattr(w, "message"):
                lines.append(f"  {i}. {w.message}")
            elif isinstance(w, dict):
                lines.append(f"  {i}. {w.get('message', str(w))}")
            else:
                lines.append(f"  {i}. {w}")

    return "\n".join(lines)


def validate_current_object():
    raw = mandatory_text.get("1.0", "end").strip()
    if not raw:
        messagebox.showwarning("Validar", "Não há JSON no painel do objeto.")
        return

    try:
        instance = json.loads(raw)
    except json.JSONDecodeError as e:
        messagebox.showerror("JSON inválido", str(e))
        return

    try:
        # Caso observed-data → embrulhar em bundle
        if instance.get("type") == "observed-data":
            if not instance.get("objects"):
                messagebox.showwarning("Observed-data","O observed-data não contém SCOs.")
                return

            temp_bundle = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "objects": [instance]
            }
            result = validate_instance(temp_bundle)
        else:
            result = validate_instance(instance)

    except Exception as e:
        messagebox.showerror(
            "Erro de validação STIX",
            f"O validador falhou:\n\n{e}"
        )
        return

    messagebox.showinfo("Validação STIX",_format_validation_result(result)
    )


def validate_bundle():
    if not bundle.get("objects"):
        messagebox.showinfo("Validar", "O bundle está vazio.")
        return

    try:
        # 1️⃣ tentativa normal (validação semântica completa)
        result = validate_instance(bundle)

    except Exception as e:
        # 2️⃣ fallback para validação textual (bug do validator)
        try:
            bundle_str = json.dumps(bundle, ensure_ascii=False)
            result = validate_string(bundle_str)

            messagebox.showinfo("Validação STIX (Bundle)","⚠️ Validação feita em modo compatibilidade "
                "(bug conhecido do stix2-validator).\n\n"+ _format_validation_result(result)
            )
            return

        except Exception as e2:
            messagebox.showerror(
                "Erro de validação STIX",
                f"O validador falhou internamente.\n\n"
                f"Erro 1: {e}\nErro 2: {e2}"
            )
            return

    # caminho normal (sem erro)
    messagebox.showinfo(
        "Validação STIX (Bundle)",
        _format_validation_result(result)
    )


def validate_external_file():
    path = filedialog.askopenfilename(title="Selecionar ficheiro STIX (.json)", filetypes=[("STIX JSON", "*.json"), ("JSON", "*.json")])
    if not path:
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        messagebox.showerror("Erro", f"Falha ao abrir ficheiro:\n{e}")
        return

    try:
        result = validate_instance(data)
    except Exception as e:
        messagebox.showerror("Erro", f"Falha ao validar STIX:\n{e}")
        return

    mandatory_text.delete("1.0", "end")
    mandatory_text.insert("end", json.dumps(data, indent=4, ensure_ascii=False))

    messagebox.showinfo("Validação STIX (Ficheiro Externo)",_format_validation_result(result))

# =========================
# UI layout
# =========================

app = ctk.CTk()
app.title("STIX 2.1 Helper – Ensino (JSON pronto a copiar) - C-Academy - Curso PMD#1 - Bruno Cardoso (open-source)")
app.geometry("1100x650")

category_var = StringVar(value="SDO (Domain Object)")
object_var = StringVar()

top_frame = ctk.CTkFrame(app)
top_frame.pack(fill="x", padx=20, pady=10)

ctk.CTkLabel(top_frame, text="Categoria").pack(side="left", padx=10)
category_combo = ctk.CTkComboBox(
    top_frame,
    values=list(CATEGORY_LABELS.keys()),
    variable=category_var,
    command=update_object_types,
    width=220
)
category_combo.pack(side="left", padx=10)

ctk.CTkLabel(top_frame, text="Objeto").pack(side="left", padx=10)
object_combo = ctk.CTkComboBox(
    top_frame,
    values=list(STIX_OBJECTS["SDO"].keys()),
    variable=object_var,
    command=show_templates
)
object_combo.pack(side="left", padx=10)

#Abrir site STIX Visualizer
ctk.CTkButton(top_frame, text="🌐 STIX Visualizer",command=open_stix_visualizer_site).pack(side="left", padx=5)

# ---- Tema (Dark / Light) ----
#ctk.CTkLabel(top_frame, text="Tema").pack(side="right", padx=(5, 5))
theme_combo = ctk.CTkComboBox(
    top_frame,
    values=["Dark", "Light", "System"],
    command=change_theme,
    width=120
)
theme_combo.set("Dark")  # tema inicial
theme_combo.pack(side="right", padx=(5, 15))


main_frame = ctk.CTkFrame(app)
main_frame.pack(fill="both", expand=True, padx=20, pady=10)

# Esquerda: JSON completo
left_frame = ctk.CTkFrame(main_frame)
left_frame.pack(side="left", fill="both", expand=True, padx=10)

ctk.CTkLabel(left_frame, text="Objeto STIX (JSON completo: obrigatórios + opcionais)", font=("Arial", 14, "bold")).pack(pady=5)
mandatory_text = ctk.CTkTextbox(left_frame)
mandatory_text.pack(fill="both", expand=True, padx=5, pady=5)

# Direita: lista opcionais
right_frame = ctk.CTkFrame(main_frame)
right_frame.pack(side="left", fill="both", expand=False, padx=10)

ctk.CTkLabel(right_frame, text="Propriedades opcionais (referência)", font=("Arial", 14, "bold")).pack(pady=5)
optional_text = ctk.CTkTextbox(right_frame, width=300)
optional_text.pack(fill="both", expand=True, padx=5, pady=5)

bottom_frame = ctk.CTkFrame(app)
bottom_frame.pack(fill="x", padx=20, pady=10)


ctk.CTkButton(bottom_frame, text="Criar Bundle (novo)", command=create_new_bundle).pack(side="left", padx=5)
ctk.CTkButton(bottom_frame, text="Adicionar ao Bundle", command=add_to_bundle).pack(side="left", padx=5)
ctk.CTkButton(bottom_frame, text="Ver Bundle", command=view_bundle).pack(side="left", padx=5)
ctk.CTkButton(bottom_frame, text="Exportar Bundle JSON", command=export_bundle_json).pack(side="left", padx=5)
ctk.CTkButton(bottom_frame, text="Validar Objeto", command=validate_current_object).pack(side="left", padx=5)
ctk.CTkButton(bottom_frame, text="Validar Bundle", command=validate_bundle).pack(side="left", padx=5)
ctk.CTkButton(bottom_frame, text="Validar STIX Externo", command=validate_external_file).pack(side="left", padx=15)

app.mainloop()


#Compilar o executavel para a pasta /dist com --> pyinstaller STIX_2.1_Helper.spec
