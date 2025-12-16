import customtkinter as ctk
from stix2validator import validate_instance
from tkinter import StringVar, messagebox, filedialog
from datetime import datetime, timezone
import uuid
import json

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

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

    # listas comuns
    if field.endswith("_refs") or field in ("object_refs", "where_sighted_refs"):
        return []
    if field in ("roles", "sectors", "tool_types", "malware_types", "infrastructure_types",
                 "protocols", "threat_actor_types"):
        return []
    
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
    

    if field in ("goals", "secondary_motivations", "capabilities"):
        return []

    if field == "resource_level":
        return "organization"

    if field == "primary_motivation":
        return "espionage"

    if field in ("first_seen", "last_seen"):
        return now()

    if field == "report_types":
        return ["threat-report"]

    if field == "labels":
        return ["espionage", "ransomware", "etc..."]

    if field == "confidence":
        return 50

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
                "labels"
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
                "labels"
            ]
        },
        "course-of-action": {
            "mandatory": ["type","spec_version","id","created","modified","name"],
            "optional": ["description"]
        },
        "grouping": {
            "mandatory": ["type","spec_version","id","created","modified","name","object_refs"],
            "optional": ["description","confidence"]
        },
        "identity": {
            "mandatory": ["type","spec_version","id","created","modified","name","identity_class"],
            "optional": ["description","roles","sectors","confidence"]
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
                "valid_until"
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
                "labels"
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
                "labels"
            ]
        },
        
        "location": {
            "mandatory": ["type","spec_version","id","created","modified"],
            "optional": ["description","country","region","city","latitude","longitude"]
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
                "labels"
            ]
        },

        "malware-analysis": {
            "mandatory": ["type","spec_version","id","created","modified","product"],
            "optional": ["result","confidence"]
        },
        "note": {
            "mandatory": ["type","spec_version","id","created","modified","content","object_refs"],
            "optional": ["confidence"]
        },
        "observed-data": {
            "mandatory": ["type","spec_version","id","created","modified","first_observed","last_observed","number_observed"],
            "optional": ["object_refs"]
        },
        "opinion": {
            "mandatory": ["type","spec_version","id","created","modified","opinion","object_refs"],
            "optional": ["confidence"]
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
                "labels"
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
                "labels"
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
                "labels"
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
                "labels"
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
        "ipv4-addr": {"mandatory":["type","value"],"optional":["resolves_to_refs"]},
        "ipv6-addr": {"mandatory":["type","value"],"optional":[]},
        "domain-name": {"mandatory":["type","value"],"optional":[]},
        "url": {"mandatory":["type","value"],"optional":[]},
        "email-addr": {"mandatory":["type","value"],"optional":[]},
        "mac-addr": {"mandatory":["type","value"],"optional":[]},
        "mutex": {"mandatory":["type","value"],"optional":[]},
        "file": {"mandatory":["type"],"optional":["name","size","hashes","mime_type"]},
        "process": {"mandatory":["type"],"optional":["pid","name","command_line"]},
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

def update_object_types(*_):
    category_label = category_var.get()
    category = CATEGORY_LABELS[category_label]

    object_combo.configure(values=list(STIX_OBJECTS[category].keys()))
    object_var.set("")
    clear_fields()

def clear_fields():
    mandatory_text.delete("1.0", "end")
    optional_text.delete("1.0", "end")

def build_full_template(category: str, obj_type: str):
    fields = STIX_OBJECTS[category][obj_type]
    all_fields = fields["mandatory"] + fields["optional"]  # opcionais também no “obrigatório” (JSON completo)
    obj = {}
    for f in all_fields:
        obj[f] = default_value(f, obj_type)
    return obj, fields["optional"]

def show_templates(*_):
    clear_fields()
    category = CATEGORY_LABELS[category_var.get()]
    obj_type = object_var.get()
    if not obj_type:
        return

    obj, optional_list = build_full_template(category, obj_type)

    # Coluna esquerda: JSON pronto a copiar (aspas incluídas via json.dumps)
    mandatory_text.insert("end", json.dumps(obj, indent=4, ensure_ascii=False))

    # Coluna direita: lista de opcionais (referência)
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
    raw = mandatory_text.get("1.0", "end").strip()
    if not raw:
        messagebox.showerror("Erro", "O JSON do objeto está vazio.")
        return

    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        messagebox.showerror("JSON inválido", f"Corrige o JSON antes de adicionar ao bundle.\n\n{e}")
        return

    # mínimo essencial: type
    if not isinstance(obj, dict) or "type" not in obj:
        messagebox.showerror("Erro", "O JSON tem de ser um objeto (dict) e conter pelo menos o campo \"type\".")
        return

    bundle["objects"].append(obj)
    messagebox.showinfo("Bundle", f"Objeto adicionado. Total no bundle: {len(bundle['objects'])}")

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

def view_bundle():
    if not bundle["objects"]:
        messagebox.showinfo("Bundle", "O bundle está vazio.")
        return

    win = ctk.CTkToplevel(app)
    win.title("Bundle atual (JSON)")
    win.geometry("1000x600")

    # Garante que fica sempre à frente
    win.attributes("-topmost", True)
    win.focus_force()

    txt = ctk.CTkTextbox(win)
    txt.pack(fill="both", expand=True, padx=10, pady=10)

    txt.insert(
        "end",
        json.dumps(bundle, indent=4, ensure_ascii=False)
    )

    # Apenas leitura
    #txt.configure(state="enabled")
    txt.configure(state="disabled")

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