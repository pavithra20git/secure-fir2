import os, json, hashlib, uuid
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymongo import MongoClient
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import brotli, requests
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

def collection():
    client = MongoClient(os.getenv("MONGODB_URI","mongodb://127.0.0.1:27017/"), serverSelectionTimeoutMS=2500)
    client.admin.command("ping")
    return client[os.getenv("MONGODB_DATABASE","secureFIR")]["fir_records"]

def key():
    k = bytes.fromhex(os.getenv("FIR_ENCRYPTION_KEY_HEX",""))
    if len(k) != 32: raise ValueError("FIR_ENCRYPTION_KEY_HEX must be 32 bytes (64 hex characters).")
    return k

def protect(data):
    compressed = brotli.compress(json.dumps(data, ensure_ascii=False).encode("utf-8"))
    iv = get_random_bytes(16)
    return iv + AES.new(key(), AES.MODE_CBC, iv).encrypt(pad(compressed, AES.block_size))

def unprotect(blob):
    iv, ciphertext = blob[:16], blob[16:]
    compressed = unpad(AES.new(key(), AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)
    return json.loads(brotli.decompress(compressed).decode("utf-8"))

def put_blob(blob):
    api = os.getenv("IPFS_API_URL","http://127.0.0.1:5001").rstrip("/")
    try:
        r = requests.post(api+"/api/v0/add", files={"file":("fir.enc",blob)}, timeout=15); r.raise_for_status()
        cid = r.json().get("Hash")
        if not cid: raise RuntimeError("IPFS did not return a CID")
        return cid, "ipfs"
    except Exception:
        if os.getenv("ALLOW_LOCAL_STORAGE_FALLBACK","True").lower() != "true": raise
        folder = BASE_DIR / os.getenv("LOCAL_STORAGE_DIR","local_secure_storage"); folder.mkdir(exist_ok=True)
        name = uuid.uuid4().hex+".enc"; (folder/name).write_bytes(blob)
        return "local:"+name, "local"

def get_blob(cid):
    if cid.startswith("local:"):
        return (BASE_DIR/os.getenv("LOCAL_STORAGE_DIR","local_secure_storage")/cid[6:]).read_bytes()
    r = requests.post(os.getenv("IPFS_API_URL","http://127.0.0.1:5001").rstrip("/")+"/api/v0/cat", params={"arg":cid}, timeout=15); r.raise_for_status()
    return r.content

def suggest(text):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    # Demonstration descriptions only; not actual legal section mappings.
    corpus = [("Theft-related", "dishonestly takes movable property without consent theft"), ("Cheating-related", "deception dishonestly induces delivery of property"), ("Threat-related", "threatens injury or harm to person or property"), ("Assault-related", "physical attack or use of criminal force"), ("Property-damage-related", "intentionally damages or destroys property")]
    matrix = TfidfVectorizer(stop_words="english").fit_transform([text]+[x[1] for x in corpus])
    scores = cosine_similarity(matrix[0:1],matrix[1:]).flatten()
    return [{"label":corpus[i][0],"score":round(float(scores[i]),3)} for i in scores.argsort()[::-1][:3] if scores[i] > 0]

def register_chain(fir_id, digest, cid):
    # Optional integration: returns not_configured unless contract settings are provided.
    rpc=os.getenv("ETH_RPC_URL",""); private=os.getenv("ETH_PRIVATE_KEY",""); address=os.getenv("CONTRACT_ADDRESS","")
    abi_path=BASE_DIR/os.getenv("CONTRACT_ABI_PATH","contracts/FIRRegistry.abi.json")
    if not (rpc and private and address and abi_path.exists()): return {"status":"not_configured","tx":""}
    try:
        from web3 import Web3
        w3=Web3(Web3.HTTPProvider(rpc))
        if not w3.is_connected(): return {"status":"unavailable","tx":""}
        abi=json.loads(abi_path.read_text(encoding="utf-8")); contract=w3.eth.contract(address=Web3.to_checksum_address(address),abi=abi)
        account=w3.eth.account.from_key(private); nonce=w3.eth.get_transaction_count(account.address)
        tx=contract.functions.registerFIR(fir_id,digest,cid).build_transaction({"from":account.address,"nonce":nonce,"chainId":int(os.getenv("ETH_CHAIN_ID","1337")),"gas":300000,"gasPrice":w3.eth.gas_price})
        signed=account.sign_transaction(tx); txhash=w3.eth.send_raw_transaction(signed.raw_transaction); receipt=w3.eth.wait_for_transaction_receipt(txhash,timeout=120)
        return {"status":"confirmed" if receipt.status==1 else "failed","tx":txhash.hex()}
    except Exception as e: return {"status":"error","tx":"","error":str(e)}

def create(data, username):
    fir_id="FIR-"+datetime.now().strftime("%Y%m%d")+"-"+uuid.uuid4().hex[:8].upper()
    payload={**data,"fir_id":fir_id,"registered_by":username,"registered_at":datetime.now(timezone.utc).isoformat()}
    blob=protect(payload); digest=hashlib.sha256(blob).hexdigest(); cid, storage=put_blob(blob); chain=register_chain(fir_id,digest,cid)
    rec={"fir_id":fir_id,"complainant_name":data["complainant_name"],"incident_date":data["incident_date"],"incident_location":data["incident_location"],"registered_by":username,"registered_at":payload["registered_at"],"status":"Registered","sha256":digest,"cid":cid,"storage_type":storage,"blockchain_status":chain["status"],"transaction_hash":chain.get("tx","")}
    collection().insert_one(rec); return rec

def all_records():
    return list(collection().find({},{"_id":0}).sort("registered_at",-1).limit(200))
def get_record(fid): return collection().find_one({"fir_id":fid},{"_id":0})
def verify_record(fid):
    rec=get_record(fid)
    if not rec: raise LookupError("FIR not found")
    blob=get_blob(rec["cid"]); digest=hashlib.sha256(blob).hexdigest()
    if digest != rec["sha256"]: return False, "Hash mismatch: file may have changed", None
    return True, "Hash verified; integrity matches", unprotect(blob)
