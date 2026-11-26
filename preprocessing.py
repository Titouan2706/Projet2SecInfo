"""
Prétraitement de CICIDS2017 (version TrafficLabelling) pour la découverte d'actifs.

Entrées  : dossier contenant les 8 CSV (Monday-WorkingHours.pcap_ISCX.csv, ...)
Sorties  : flows_clean.parquet (ou .csv), hosts.csv (inventaire brut des IP),
           edges.csv (relations IP source -> IP destination : base du graphe de dépendances)

Usage :
    python preprocessing.py --input ./TrafficLabelling --output ./processed
"""
import argparse
import glob
import ipaddress
import os

import numpy as np
import pandas as pd

# Colonnes utiles pour la découverte d'actifs (on écarte les ~60 features ML)
KEEP = [
    "Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port",
    "Protocol", "Timestamp", "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "SYN Flag Count", "ACK Flag Count", "Label",
]

# Port -> service (pour deviner le rôle des machines)
SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 80: "HTTP", 88: "Kerberos", 110: "POP3", 123: "NTP",
    135: "MS-RPC", 137: "NetBIOS", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kerberos-pwd",
    587: "SMTP-sub", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-alt", 8443: "HTTPS-alt",
}

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}


def load_files(folder: str) -> pd.DataFrame:
    frames = []
    for path in sorted(glob.glob(os.path.join(folder, "*.csv"))):
        # Les fichiers contiennent des caractères non UTF-8 -> latin-1
        df = pd.read_csv(path, encoding="latin-1", low_memory=False)
        df.columns = df.columns.str.strip()  # noms de colonnes avec espaces
        missing = [c for c in KEEP if c not in df.columns]
        if missing:
            raise ValueError(
                f"{os.path.basename(path)} : colonnes absentes {missing}. "
                "Utilisez bien la version TrafficLabelling (avec IP)."
            )
        df = df[KEEP].copy()
        df["source_file"] = os.path.basename(path)
        print(f"[load] {os.path.basename(path):55s} {len(df):>9,} lignes")
        frames.append(df)
    if not frames:
        raise FileNotFoundError(f"Aucun CSV trouvé dans {folder}")
    return pd.concat(frames, ignore_index=True)


def clean(df: pd.DataFrame) -> pd.DataFrame:
    n0 = len(df)

    # Label : corriger l'encodage ("Web Attack � Brute Force")
    df["Label"] = (
        df["Label"].astype(str)
        .str.replace(r"[^\x00-\x7F]+", "-", regex=True)
        .str.replace(r"\s*-\s*", " - ", regex=True)
        .str.strip()
    )

    # Types numériques
    num_cols = [c for c in KEEP if c not in
                ("Flow ID", "Source IP", "Destination IP", "Timestamp", "Label")]
    for c in num_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Lignes inutilisables (en-têtes répétés, valeurs manquantes sur les clés)
    df.dropna(subset=["Source IP", "Destination IP", "Destination Port",
                      "Protocol", "Timestamp"], inplace=True)
    df[["Source Port", "Destination Port", "Protocol"]] = (
        df[["Source Port", "Destination Port", "Protocol"]].fillna(0).astype(int)
    )

    # Valeurs aberrantes (durées / compteurs négatifs)
    df = df[(df["Flow Duration"] >= 0) &
            (df["Total Fwd Packets"] >= 0) &
            (df["Total Backward Packets"] >= 0)].copy()
    df.fillna(0, inplace=True)

    # Doublons
    df.drop_duplicates(inplace=True)

    # Timestamp (format jour/mois/année, sans AM/PM)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="mixed", dayfirst=True,
                                     errors="coerce")
    df.dropna(subset=["Timestamp"], inplace=True)
    # Les heures sont en 12 h sans AM/PM : la capture va d'environ 8h à 17h,
    # donc une heure < 8 correspond à l'après-midi.
    df.loc[df["Timestamp"].dt.hour < 8, "Timestamp"] += pd.Timedelta(hours=12)

    print(f"[clean] {n0:,} -> {len(df):,} lignes ({n0 - len(df):,} supprimées)")
    return df.reset_index(drop=True)


def enrich(df: pd.DataFrame) -> pd.DataFrame:
    df["proto_name"] = df["Protocol"].map(PROTOCOLS).fillna("OTHER")
    df["service"] = df["Destination Port"].map(SERVICES).fillna("unknown")
    df["is_attack"] = (df["Label"].str.upper() != "BENIGN").astype(int)
    df["total_bytes"] = df["Total Length of Fwd Packets"] + df["Total Length of Bwd Packets"]
    # Flux "établi" : il y a eu une réponse (utile pour ignorer les scans)
    df["answered"] = (df["Total Backward Packets"] > 0).astype(int)

    # IP privée / publique (calculé sur les IP uniques seulement, c'est rapide)
    ips = pd.unique(pd.concat([df["Source IP"], df["Destination IP"]]))
    def is_priv(ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
    priv = {ip: is_priv(ip) for ip in ips}
    df["src_private"] = df["Source IP"].map(priv)
    df["dst_private"] = df["Destination IP"].map(priv)
    return df


def build_hosts(df: pd.DataFrame) -> pd.DataFrame:
    """Une ligne par IP : base de l'inventaire des actifs."""
    out = df.groupby("Source IP").agg(
        flows_out=("Flow ID", "size"),
        bytes_out=("total_bytes", "sum"),
        peers_out=("Destination IP", "nunique"),
        ports_contacted=("Destination Port", "nunique"),
        attack_flows_out=("is_attack", "sum"),
    )
    inn = df.groupby("Destination IP").agg(
        flows_in=("Flow ID", "size"),
        bytes_in=("total_bytes", "sum"),
        peers_in=("Source IP", "nunique"),
        attack_flows_in=("is_attack", "sum"),
    )
    hosts = out.join(inn, how="outer").fillna(0)
    hosts.index.name = "ip"

    # Services exposés : trafic bénin ET répondu, pour ne pas confondre avec un scan
    ok = df[(df["is_attack"] == 0) & (df["answered"] == 1) &
            (df["service"] != "unknown")]
    svc = (ok.groupby(["Destination IP", "service"]).size()
             .reset_index(name="n"))
    svc = svc[svc["n"] >= 5]  # seuil minimal pour éviter le bruit
    exposed = svc.groupby("Destination IP")["service"].apply(lambda s: ",".join(sorted(s)))
    hosts["services_exposed"] = exposed.reindex(hosts.index).fillna("")

    hosts["is_private"] = [ipaddress.ip_address(i).is_private if _valid(i) else False
                           for i in hosts.index]
    hosts["first_seen"] = pd.concat([df.groupby("Source IP")["Timestamp"].min(),
                                     df.groupby("Destination IP")["Timestamp"].min()],
                                    axis=1).min(axis=1).reindex(hosts.index)
    hosts["last_seen"] = pd.concat([df.groupby("Source IP")["Timestamp"].max(),
                                    df.groupby("Destination IP")["Timestamp"].max()],
                                   axis=1).max(axis=1).reindex(hosts.index)

    # Heuristique de rôle préliminaire (l'Agent de découverte l'affinera)
    def role(r):
        if r["services_exposed"] and r["peers_in"] >= 3 and r["peers_in"] > r["peers_out"]:
            return "server"
        if r["peers_out"] > 0 and r["is_private"]:
            return "workstation"
        if not r["is_private"]:
            return "external"
        return "unknown"
    hosts["role_guess"] = hosts.apply(role, axis=1)
    return hosts.reset_index()


def _valid(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def build_edges(df: pd.DataFrame) -> pd.DataFrame:
    """Relations IP source -> IP destination : base du graphe de dépendances."""
    e = (df.groupby(["Source IP", "Destination IP", "Destination Port", "service", "proto_name"])
           .agg(flows=("Flow ID", "size"),
                bytes=("total_bytes", "sum"),
                attack_flows=("is_attack", "sum"),
                first_seen=("Timestamp", "min"),
                last_seen=("Timestamp", "max"))
           .reset_index())
    return e


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Dossier TrafficLabelling")
    ap.add_argument("--output", default="./processed")
    args = ap.parse_args()
    os.makedirs(args.output, exist_ok=True)

    df = load_files(args.input)
    df = clean(df)
    df = enrich(df)

    print("\n[labels]\n", df["Label"].value_counts().to_string())

    hosts = build_hosts(df)
    edges = build_edges(df)

    try:
        df.to_parquet(os.path.join(args.output, "flows_clean.parquet"), index=False)
    except ImportError:
        df.to_csv(os.path.join(args.output, "flows_clean.csv"), index=False)
    hosts.to_csv(os.path.join(args.output, "hosts.csv"), index=False)
    edges.to_csv(os.path.join(args.output, "edges.csv"), index=False)

    print(f"\n[done] {len(df):,} flux | {len(hosts):,} IP uniques | {len(edges):,} relations")
    print(hosts["role_guess"].value_counts().to_string())


if __name__ == "__main__":
    main()
