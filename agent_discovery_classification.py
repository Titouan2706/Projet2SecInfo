"""
Agent de découverte des actifs + Agent de classification de la criticité (CICIDS2017)

Entrées  : processed/hosts.csv, processed/edges.csv  (issus de preprocess_cicids2017.py)
Sorties  : outputs/assets.csv           inventaire des actifs internes (avec criticité)
           outputs/external_hosts.csv   hôtes externes observés (hors périmètre à protéger)
           outputs/assets.json          même inventaire, pour l'agent suivant (vulnérabilités)

Usage :
    python agents_discovery_classification.py --processed ./processed --output ./outputs
    python agents_discovery_classification.py --processed ./processed --output ./outputs --llm

Principe : les décisions (type, rôle, score) sont déterministes et reproductibles.
Le LLM (option --llm) ne sert qu'à rédiger la justification métier des actifs les plus
critiques ; il ne modifie jamais les scores.
"""
import argparse
import ipaddress
import json
import os

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
# Configuration (à adapter à votre analyse du dataset)
# --------------------------------------------------------------------------- #
# Réseau interne de CICIDS2017 (réseau "victime"). Vérifiez avec vos données.
INTERNAL_NETS = [ipaddress.ip_network("192.168.10.0/24")]
# Dans CICIDS2017, le trafic externe apparaît souvent derrière une passerelle NAT/pare-feu.
NAT_GATEWAYS = {"172.16.0.1"}

# Services -> rôles
ROLE_RULES = {
    "dns_server": {"DNS"},
    "web_server": {"HTTP", "HTTPS", "HTTP-alt", "HTTPS-alt"},
    "database_server": {"MSSQL", "MySQL", "PostgreSQL"},
    "mail_server": {"SMTP", "SMTP-sub", "POP3", "POP3S", "IMAP", "IMAPS"},
    "file_server": {"SMB", "FTP", "FTP-data"},
    "remote_access": {"SSH", "RDP", "Telnet"},
}
AD_SERVICES = {"Kerberos", "LDAP", "LDAPS", "Kerberos-pwd"}
WINDOWS_SERVICES = {"MS-RPC", "NetBIOS", "NetBIOS-SSN", "SMB", "RDP"} | AD_SERVICES

# Poids du rôle métier (0 à 1)
ROLE_WEIGHT = {
    "domain_controller": 1.00,
    "network_device": 0.90,
    "database_server": 0.90,
    "dns_server": 0.85,
    "file_server": 0.75,
    "web_server": 0.70,
    "mail_server": 0.70,
    "remote_access": 0.60,
    "workstation": 0.30,
    "unknown": 0.20,
}

# Sensibilité des données selon le service manipulé (0 à 1)
DATA_WEIGHT = {
    "LDAP": 1.0, "LDAPS": 1.0, "Kerberos": 1.0, "Kerberos-pwd": 1.0,
    "MSSQL": 1.0, "MySQL": 1.0, "PostgreSQL": 1.0,
    "SMB": 0.8, "FTP": 0.7, "FTP-data": 0.7,
    "HTTPS": 0.6, "HTTPS-alt": 0.6, "RDP": 0.6, "SMTP": 0.6, "SMTP-sub": 0.6,
    "IMAP": 0.6, "IMAPS": 0.6, "POP3": 0.6, "POP3S": 0.6,
    "HTTP": 0.5, "HTTP-alt": 0.5, "SSH": 0.5, "Telnet": 0.5,
    "DNS": 0.4,
}

# Pondération des 4 critères de l'énoncé
W_ROLE, W_DATA, W_USAGE, W_EXPOSURE = 0.35, 0.25, 0.20, 0.20

LEVELS = [(75, "Critique"), (55, "Élevée"), (35, "Moyenne"), (0, "Faible")]


def _ip_obj(ip):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def is_internal(ip: str) -> bool:
    o = _ip_obj(ip)
    return bool(o) and any(o in net for net in INTERNAL_NETS)


# --------------------------------------------------------------------------- #
# Agent 1 : découverte des actifs
# --------------------------------------------------------------------------- #
class AssetDiscoveryAgent:
    def __init__(self, hosts: pd.DataFrame, edges: pd.DataFrame):
        self.hosts = hosts.copy()
        self.edges = edges.copy()

    def run(self):
        h = self.hosts
        h["services_exposed"] = h["services_exposed"].fillna("")
        h["services"] = h["services_exposed"].apply(lambda s: set(x for x in s.split(",") if x))
        h["internal"] = h["ip"].apply(is_internal)

        h["roles"] = h.apply(self._roles, axis=1)
        h["asset_type"] = h.apply(self._asset_type, axis=1)
        h["os_guess"] = h["services"].apply(self._os_guess)

        self._add_dependencies(h)

        managed = h[(h["internal"]) | (h["asset_type"] == "network_device")].copy()
        external = h[~h.index.isin(managed.index)].copy()
        managed.insert(0, "asset_id", [f"A{i:03d}" for i in range(1, len(managed) + 1)])
        return managed.reset_index(drop=True), external.reset_index(drop=True)

    # -- règles ------------------------------------------------------------- #
    @staticmethod
    def _is_network_device(r) -> bool:
        if r["ip"] in NAT_GATEWAYS:
            return True
        return r["ip"].endswith(".1") and r["peers_in"] >= 5 and r["peers_out"] >= 5

    def _roles(self, r):
        roles = []
        if self._is_network_device(r):
            return ["network_device"]
        svc = r["services"]
        if len(svc & AD_SERVICES) >= 2:  # Kerberos + LDAP => contrôleur de domaine
            roles.append("domain_controller")
        for role, names in ROLE_RULES.items():
            if svc & names:
                roles.append(role)
        if not roles and r["internal"] and r["peers_out"] > 0:
            roles.append("workstation")
        return roles or ["unknown"]

    @staticmethod
    def _asset_type(r):
        if "network_device" in r["roles"]:
            return "network_device"
        if not r["internal"]:
            total = max(r["flows_out"], 1)
            return "external_attacker" if r["attack_flows_out"] / total > 0.5 else "external_host"
        if r["roles"] == ["workstation"]:
            return "workstation"
        if r["roles"] == ["unknown"]:
            return "unknown"
        return "server"

    @staticmethod
    def _os_guess(svc):
        if svc & WINDOWS_SERVICES:
            return "Windows (probable)"
        if "SSH" in svc:
            return "Linux/Unix (probable)"
        return "Indéterminé"

    # -- dépendances -------------------------------------------------------- #
    def _add_dependencies(self, h):
        e = self.edges
        e = e[e["service"] != "unknown"]
        internal_mask = e["Source IP"].apply(is_internal) & e["Destination IP"].apply(is_internal)
        ie = e[internal_mask]

        used_by = ie.groupby("Destination IP")["Source IP"].nunique()
        h["used_by_count"] = h["ip"].map(used_by).fillna(0).astype(int)

        def top_deps(ip_df):
            top = ip_df.sort_values("flows", ascending=False).head(5)
            return ";".join(f"{d}:{s}" for d, s in zip(top["Destination IP"], top["service"]))
        deps = ie.groupby("Source IP").apply(top_deps, include_groups=False)
        h["depends_on"] = h["ip"].map(deps).fillna("")

        # Exposition externe : sources hors périmètre (ou passerelle NAT) atteignant l'actif
        ext_mask = (~e["Source IP"].apply(is_internal)) & e["Destination IP"].apply(is_internal)
        ext_sources = e[ext_mask].groupby("Destination IP")["Source IP"].nunique()
        h["external_sources"] = h["ip"].map(ext_sources).fillna(0).astype(int)


# --------------------------------------------------------------------------- #
# Agent 2 : classification de la criticité
# --------------------------------------------------------------------------- #
class CriticalityAgent:
    def __init__(self, assets: pd.DataFrame):
        self.a = assets.copy()

    def run(self) -> pd.DataFrame:
        a = self.a

        # 1. Rôle dans les processus d'affaires
        a["s_role"] = a["roles"].apply(lambda rs: max(ROLE_WEIGHT.get(r, 0.2) for r in rs))

        # 2. Données manipulées (sensibilité du service + volume relatif)
        vol = np.log1p(a["bytes_in"] + a["bytes_out"])
        vol_pct = vol.rank(pct=True) if len(a) > 1 else pd.Series(0.5, index=a.index)
        svc_score = a["services"].apply(
            lambda s: max([DATA_WEIGHT.get(x, 0.3) for x in s], default=0.2))
        a["s_data"] = (0.8 * svc_score + 0.2 * vol_pct).clip(0, 1)

        # 3. Fréquence d'utilisation (rang percentile du nombre de flux, échelle log)
        usage = np.log1p(a["flows_in"] + a["flows_out"])
        a["s_usage"] = usage.rank(pct=True) if len(a) > 1 else 0.5

        # 4. Exposition réseau
        ext = np.minimum(1.0, np.log1p(a["external_sources"]) / np.log1p(20))
        nsvc = np.minimum(1.0, a["services"].apply(len) / 5)
        attacked = (a["attack_flows_in"] > 0).astype(float)
        a["s_exposure"] = (0.6 * ext + 0.2 * nsvc + 0.2 * attacked).clip(0, 1)

        a["criticality_score"] = (100 * (W_ROLE * a["s_role"] + W_DATA * a["s_data"]
                                         + W_USAGE * a["s_usage"] + W_EXPOSURE * a["s_exposure"])
                                  ).round(1)
        # Règle métier : un contrôleur de domaine est toujours au moins "Critique"
        is_dc = a["roles"].apply(lambda rs: "domain_controller" in rs)
        a.loc[is_dc, "criticality_score"] = a.loc[is_dc, "criticality_score"].clip(lower=75)
        a["criticality_level"] = a["criticality_score"].apply(self._level)
        a["justification"] = a.apply(self._explain, axis=1)
        return a.sort_values("criticality_score", ascending=False).reset_index(drop=True)

    @staticmethod
    def _level(score):
        return next(label for threshold, label in LEVELS if score >= threshold)

    @staticmethod
    def _explain(r):
        return (f"rôle={'+'.join(r['roles'])} ({r['s_role']:.2f}), "
                f"données={r['s_data']:.2f}, usage={r['s_usage']:.2f}, "
                f"exposition={r['s_exposure']:.2f} "
                f"[{r['external_sources']} source(s) externe(s), "
                f"{int(r['attack_flows_in'])} flux d'attaque reçus]")


# --------------------------------------------------------------------------- #
# Enrichissement optionnel par LLM (justification métier, sans toucher aux scores)
# --------------------------------------------------------------------------- #
def llm_justify(assets: pd.DataFrame, top_n: int = 10, model: str = None) -> pd.DataFrame:
    try:
        import anthropic
        client = anthropic.Anthropic()  # lit ANTHROPIC_API_KEY
    except Exception as exc:
        print(f"[llm] indisponible ({exc}) : étape ignorée")
        assets["justification_llm"] = ""
        return assets

    model = model or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")
    texts = {}
    for _, r in assets.head(top_n).iterrows():
        payload = {
            "ip": r["ip"], "type": r["asset_type"], "roles": r["roles"],
            "os_probable": r["os_guess"], "services": sorted(r["services"]),
            "score": r["criticality_score"], "niveau": r["criticality_level"],
            "utilisé_par_n_machines": int(r["used_by_count"]),
            "sources_externes": int(r["external_sources"]),
            "flux_attaque_recus": int(r["attack_flows_in"]),
        }
        prompt = (
            "Tu es analyste SOC. Voici un actif découvert dans des logs réseau (CICIDS2017) "
            "avec sa criticité calculée.\n"
            f"{json.dumps(payload, ensure_ascii=False)}\n"
            "Rédige en français 2 à 3 phrases : (1) rôle probable de l'actif dans l'organisation, "
            "(2) pourquoi son niveau de criticité est justifié, (3) le risque principal. "
            "N'invente aucune donnée absente du JSON."
        )
        try:
            resp = client.messages.create(
                model=model, max_tokens=300,
                messages=[{"role": "user", "content": prompt}])
            texts[r["asset_id"]] = resp.content[0].text.strip()
        except Exception as exc:
            print(f"[llm] échec pour {r['ip']} : {exc}")
    assets["justification_llm"] = assets["asset_id"].map(texts).fillna("")
    return assets


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--processed", default="./processed")
    ap.add_argument("--output", default="./outputs")
    ap.add_argument("--llm", action="store_true", help="justifications rédigées par LLM")
    ap.add_argument("--top", type=int, default=10, help="nb d'actifs justifiés par LLM")
    args = ap.parse_args()
    os.makedirs(args.output, exist_ok=True)

    hosts = pd.read_csv(os.path.join(args.processed, "hosts.csv"), dtype={"ip": str})
    edges = pd.read_csv(os.path.join(args.processed, "edges.csv"),
                        dtype={"Source IP": str, "Destination IP": str})

    managed, external = AssetDiscoveryAgent(hosts, edges).run()
    assets = CriticalityAgent(managed).run()
    if args.llm:
        assets = llm_justify(assets, top_n=args.top)

    # Export (les ensembles/listes sont convertis en texte pour le CSV)
    flat = assets.copy()
    flat["roles"] = flat["roles"].apply(lambda r: ",".join(r))
    flat["services"] = flat["services"].apply(lambda s: ",".join(sorted(s)))
    flat.to_csv(os.path.join(args.output, "assets.csv"), index=False)
    external.drop(columns=["services", "roles"], errors="ignore").to_csv(
        os.path.join(args.output, "external_hosts.csv"), index=False)
    with open(os.path.join(args.output, "assets.json"), "w", encoding="utf-8") as f:
        json.dump(json.loads(flat.to_json(orient="records", date_format="iso")),
                  f, ensure_ascii=False, indent=2)

    print(f"[done] {len(assets)} actifs internes, {len(external)} hôtes externes")
    print(assets["asset_type"].value_counts().to_string())
    print(assets["criticality_level"].value_counts().to_string())
    print(assets[["asset_id", "ip", "asset_type", "roles", "criticality_score",
                  "criticality_level"]].head(10).to_string(index=False))


if __name__ == "__main__":
    main()
