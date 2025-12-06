#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import itertools

# Output file
OUTPUT_FILE = "weighted_lexicon_clean.txt"

# ----------------------------------------------------------------------
# 1. Seed terms – curated domain words (no fake morphology)
# ----------------------------------------------------------------------

seed_terms = [
    "account","accounting","accreditation","acquisition","address","admission",
    "administrator","adoption","agreement","allocation","amendment","analysis",
    "appeal","application","appointment","archive","assessment","asset","audit",
    "authentication","authorization","authority","bank","banking","beneficiary",
    "benefit","bill","billing","bond","broker","budget","bureau","business",
    "calculation","calendar","capacity","card","cargo","carrier","case","cash",
    "certificate","certification","change","charge","charter","claim",
    "classification","clearance","client","closure","code","collection",
    "commercial","commission","communication","community","company",
    "compensation","complaint","compliance","component","confirmation",
    "conformity","consent","consumer","contract","contractor","contribution",
    "control","conversion","correspondence","cost","council","counterparty",
    "course","court","coverage","credit","currency","customer","customs","data",
    "database","date","declaration","deduction","default","delivery","department",
    "deposit","description","designation","detail","detection","device",
    "diagnosis","disability","disbursement","disclosure","discount","dispatch",
    "dispute","distribution","document","documentation","domicile","donation",
    "duty","education","eligibility","email","emergency","employee","employer",
    "employment","endorsement","enforcement","engagement","enquiry",
    "entitlement","entity","entry","environment","equipment","estate",
    "evaluation","evidence","exception","exchange","execution","exemption",
    "expense","expiration","export","facility","family","fee","feedback","file",
    "filing","finance","financial","fingerprint","foreign","form","format",
    "fraud","fund","government","grant","guidance","guarantee","health",
    "healthcare","holder","identification","identity","immigration","incident",
    "income","indemnity","index","individual","industry","information",
    "inheritance","injury","inspection","insurance","insurer","interface",
    "interest","invoice","issue","item","jurisdiction","justification","key",
    "labour","land","language","law","legal","letter","licence","life","limit",
    "liquidation","liability","loan","location","loss","mail","maintenance",
    "management","mandate","manufacturer","margin","market","marriage","medical",
    "member","membership","migration","mobile","mortgage","name","nationality",
    "network","notice","number","occupation","offer","officer","official",
    "operation","opinion","option","organisation","outcome","outlay","ownership",
    "paper","parcel","parent","participant","partnership","party","passport",
    "payment","penalty","pension","people","performance","period","permission",
    "person","personal","petition","phone","policy","portfolio","position",
    "post","postal","postcode","power","practice","premium","preparation",
    "prescription","presentation","price","principal","priority","procedure",
    "process","processing","producer","product","production","professional",
    "profile","program","progress","project","property","prosecution",
    "protection","provider","purchase","qualification","quality","quota","quote",
    "rate","rating","receipt","recipient","record","recovery","reference",
    "refund","register","registration","regulation","reinsurance","relation",
    "release","remittance","renewal","report","reporting","representation",
    "request","requirement","resolution","resource","response","responsibility",
    "restriction","result","retail","return","revenue","review","revision",
    "risk","role","salary","schedule","school","score","section","sector",
    "security","service","settlement","shareholder","shipment","shipping",
    "signature","site","situation","slip","social","software","solution",
    "source","statement","status","submission","subsidiary","subsidy","summary",
    "supplier","support","survey","system","tax","taxation","team","technical",
    "technology","telephone","tenant","termination","territory","ticket","time",
    "title","trade","trader","transaction","transfer","transport","travel",
    "treatment","tribunal","trust","unit","update","utility","validation",
    "value","valuation","vehicle","verification","voucher","wage","warranty",
    "welfare","wire","worker","workforce","workflow",
    # extra ICT / security / identity terms (also real words)
    "access","accountability","acknowledgement","advisory","alert","attorney",
    "backlog","blacklist","breach","checksum","cipher","comparator",
    "credential","cryptography","cyber","decryption","directory","discovery",
    "endpoint","encryption","entitlement","expiry","firewall","forensic",
    "governance","hash","indicator","integrity","keypair","logging","monitoring",
    "multifactor","password","pseudonym","revocation","rotation","scope",
    "session","token","tunneling","whitelist"
]

# ----------------------------------------------------------------------
# 2. Curated phrases (these are high-signal anchors)
# ----------------------------------------------------------------------

phrase_pairs = [
    ("bank", "statement"),
    ("account", "number"),
    ("policy", "number"),
    ("passport", "number"),
    ("member", "number"),
    ("tax", "file"),
    ("tax", "return"),
    ("credit", "card"),
    ("debit", "card"),
    ("driver", "licence"),
    ("email", "address"),
    ("postal", "address"),
    ("billing", "address"),
    ("delivery", "address"),
    ("medical", "record"),
    ("insurance", "policy"),
    ("insurance", "claim"),
    ("loan", "approval"),
    ("transaction", "record"),
    ("account", "balance"),
    ("security", "code"),
    ("verification", "code"),
    ("reference", "number"),
    ("support", "ticket"),
    ("incident", "report")
]

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def normalise(term):
    term = term.strip().lower().replace(" ", "_")
    cleaned = ""
    for ch in term:
        if ch.isalpha() or ch == "_":
            cleaned += ch
    return cleaned

def write_term(f, term, weight, seen):
    t = normalise(term)
    if not t or t == "_" or t in seen:
        return
    seen.add(t)
    f.write("%s|weight=%d\n" % (t, weight))

# ----------------------------------------------------------------------
# Main builder
# ----------------------------------------------------------------------

def build():
    seen = set()
    f = open(OUTPUT_FILE, "w")

    # 1. Base domain terms (clean, curated)
    for stem in seed_terms:
        write_term(f, stem, 100, seen)

    # 2. Curated multi-word phrases
    for a, b in phrase_pairs:
        write_term(f, a + "_" + b, 120, seen)
        write_term(f, a + "_" + b + "_details", 110, seen)

    # 3. Real-word bigram combinations (no fake morphology)
    #    This is how you scale out without inventing garbage like "postcodeial".
    #    Adjust slice sizes to grow the lexicon.
    sample_a = seed_terms[:250]   # first 250 terms
    sample_b = seed_terms[250:750]  # next 500 terms

    for a, b in itertools.product(sample_a, sample_b):
        write_term(f, a + "_" + b, 60, seen)

    f.close()
    return len(seen)

# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------

if __name__ == "__main__":
    count = build()
    print("Generated:", OUTPUT_FILE)
    print("Total unique entries:", count)
